//! Assembly display attributes in CLR metadata.

use crate::scan::FileView;

use super::super::{Kind, Reason};
use super::{Evidence, Rewrite, Source, read_full};

fn u16_at(b: &[u8], at: usize) -> Option<usize> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?) as usize)
}

fn u32_at(b: &[u8], at: usize) -> Option<usize> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?) as usize)
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

fn index(b: &[u8], at: usize, width: usize) -> Option<usize> {
    if width == 2 {
        u16_at(b, at)
    } else {
        u32_at(b, at)
    }
}

fn compressed(b: &[u8], at: usize) -> Option<(usize, usize)> {
    let first = *b.get(at)?;
    if first & 0x80 == 0 {
        Some((first as usize, 1))
    } else if first & 0xc0 == 0x80 {
        Some((((first & 0x3f) as usize) << 8 | *b.get(at + 1)? as usize, 2))
    } else if first & 0xe0 == 0xc0 {
        Some((
            ((first & 0x1f) as usize) << 24
                | (*b.get(at + 1)? as usize) << 16
                | (*b.get(at + 2)? as usize) << 8
                | *b.get(at + 3)? as usize,
            4,
        ))
    } else {
        None
    }
}

fn heap_string(heap: &[u8], at: usize) -> Option<&str> {
    let tail = heap.get(at..)?;
    let end = tail.iter().position(|&b| b == 0)?;
    std::str::from_utf8(&tail[..end]).ok()
}

fn coded(rows: &[usize; 64], tables: &[usize], bits: usize) -> usize {
    let max = tables.iter().map(|&i| rows[i]).max().unwrap_or(0);
    if max < (1usize << (16 - bits)) { 2 } else { 4 }
}

/// Return same-length edits for known assembly string attributes.
pub(super) fn attributes(
    view: &dyn FileView,
    md: u64,
    md_size: u64,
) -> (Vec<Rewrite>, Evidence, Vec<Reason>) {
    let Some(result) = parse(view, md, md_size) else {
        return (Vec::new(), Vec::new(), vec![Reason::MalformedMetadata]);
    };
    (result.0, result.1, Vec::new())
}

fn parse(view: &dyn FileView, md: u64, md_size: u64) -> Option<(Vec<Rewrite>, Evidence)> {
    if md_size > 64 * 1024 * 1024 {
        return None;
    }
    let head = read_full(view, md, 16)?;
    if head.get(..4)? != b"BSJB" {
        return None;
    }
    let mut at = 16 + u32_at(&head, 12)?;
    let flags = read_full(view, md + at as u64, 4)?;
    let streams = u16_at(&flags, 2)?.min(32);
    at += 4;
    let mut table = None;
    let mut names = None;
    let mut blobs = None;
    for _ in 0..streams {
        let h = read_full(view, md + at as u64, 40)?;
        let off = u32_at(&h, 0)?;
        let len = u32_at(&h, 4)?;
        let name_end = h[8..].iter().position(|&b| b == 0)?;
        let name = &h[8..8 + name_end];
        if off.checked_add(len)? as u64 > md_size || len > 16 * 1024 * 1024 {
            return None;
        }
        match name {
            b"#~" | b"#-" => table = Some((md + off as u64, len)),
            b"#Strings" => names = Some(read_full(view, md + off as u64, len)?),
            b"#Blob" => blobs = Some((md + off as u64, read_full(view, md + off as u64, len)?)),
            _ => {}
        }
        at += 8 + ((name_end + 4) & !3);
    }
    let (table_off, table_len) = table?;
    let raw = read_full(view, table_off, table_len)?;
    let names = names?;
    let (blob_off, blobs) = blobs?;
    let valid = u64_at(&raw, 8)?;
    let heaps = *raw.get(6)?;
    let sw = if heaps & 1 != 0 { 4 } else { 2 };
    let gw = if heaps & 2 != 0 { 4 } else { 2 };
    let bw = if heaps & 4 != 0 { 4 } else { 2 };
    let mut rows = [0usize; 64];
    let mut row_at = 24;
    for (i, row) in rows.iter_mut().enumerate() {
        if valid & (1u64 << i) != 0 {
            *row = u32_at(&raw, row_at)?;
            row_at += 4;
        }
    }
    let simple = |i: usize| if rows[i] < 65_536 { 2 } else { 4 };
    let resolution = coded(&rows, &[0, 26, 35, 1], 2);
    let typeref = coded(&rows, &[2, 1, 27], 2);
    let memberparent = coded(&rows, &[2, 1, 26, 6, 27], 3);
    let hasconstant = coded(&rows, &[4, 8, 23], 2);
    let hascustom = coded(
        &rows,
        &[
            6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43,
        ],
        5,
    );
    let customtype = coded(&rows, &[6, 10], 3);
    let sizes = [
        2 + sw + gw * 3,
        resolution + sw * 2,
        4 + sw * 2 + typeref + simple(4) + simple(6),
        simple(4),
        2 + sw + bw,
        simple(6),
        8 + sw + bw + simple(8),
        simple(8),
        4 + sw,
        simple(2) + typeref,
        memberparent + sw + bw,
        2 + hasconstant + bw,
    ];
    let mut starts = [0usize; 13];
    let mut pos = row_at;
    for i in 0..12 {
        starts[i] = pos;
        pos = pos.checked_add(rows[i].checked_mul(sizes[i])?)?;
        if pos > raw.len() {
            return None;
        }
    }
    starts[12] = pos;
    let ca_size = hascustom + customtype + bw;
    if rows[12] > 65_536 || pos.checked_add(rows[12].checked_mul(ca_size)?)? > raw.len() {
        return None;
    }
    let mut rewrites = Vec::new();
    let mut evidence = Vec::new();
    for i in 0..rows[12] {
        let at = starts[12] + i * ca_size;
        let parent = index(&raw, at, hascustom)?;
        if parent & 31 != 14 || parent >> 5 != 1 {
            continue;
        }
        let ty = index(&raw, at + hascustom, customtype)?;
        if ty & 7 != 3 || ty >> 3 == 0 || ty >> 3 > rows[10] {
            continue;
        }
        let member = starts[10] + ((ty >> 3) - 1) * sizes[10];
        let owner = index(&raw, member, memberparent)?;
        if owner & 7 != 1 || owner >> 3 == 0 || owner >> 3 > rows[1] {
            continue;
        }
        let method_name = index(&raw, member + memberparent, sw)?;
        if heap_string(&names, method_name)? != ".ctor" {
            continue;
        }
        let tref = starts[1] + ((owner >> 3) - 1) * sizes[1];
        let type_name = index(&raw, tref + resolution, sw)?;
        let type_ns = index(&raw, tref + resolution + sw, sw)?;
        if heap_string(&names, type_ns)? != "System.Reflection" {
            continue;
        }
        let label = match heap_string(&names, type_name)? {
            "AssemblyCompanyAttribute" => (b"Company".as_slice(), Source::Company),
            "AssemblyProductAttribute" => (b"Product".as_slice(), Source::Product),
            "AssemblyTitleAttribute" => (b"Title".as_slice(), Source::Product),
            "AssemblyDescriptionAttribute" => (b"Description".as_slice(), Source::Product),
            "AssemblyCopyrightAttribute" => (b"Copyright".as_slice(), Source::Product),
            _ => continue,
        };
        let blob_idx = index(&raw, at + hascustom + customtype, bw)?;
        let (blob_len, prefix) = compressed(&blobs, blob_idx)?;
        let body = blob_idx + prefix;
        let blob = blobs.get(body..body + blob_len)?;
        if blob.get(..2) != Some(&[1, 0][..]) || blob.get(2) == Some(&0xff) {
            continue;
        }
        let (text_len, text_prefix) = compressed(blob, 2)?;
        let text_at = body + 2 + text_prefix;
        let text = blobs.get(text_at..text_at + text_len)?;
        let Ok(value) = std::str::from_utf8(text) else {
            continue;
        };
        if !value.trim().is_empty() {
            evidence.push((value.to_string(), label.1));
        }
        let mut replacement = label.0.iter().copied().take(text_len).collect::<Vec<_>>();
        replacement.resize(text_len, b' ');
        if replacement != text {
            rewrites.push((Kind::Brand, blob_off + text_at as u64, replacement));
        }
    }
    Some((rewrites, evidence))
}
