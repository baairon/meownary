//! HEIC and AVIF still images: the item-based metadata of a top-level `meta`
//! box. An `Exif` item holds the camera's EXIF block and a `mime` item typed
//! `application/rdf+xml` holds an XMP packet; both live in the file body, and
//! `iinf` names them while `iloc` says where. C2PA and XMP boxes that sit
//! directly inside `meta` are reported too.
//!
//! Dropping an item moves nothing, because `iloc` holds absolute offsets to
//! every other item: the item is retyped `free` in its `infe` entry (a reader
//! ignores types it does not know), its content type string is zeroed, and
//! its data is zero-filled. Only items stored in the file body (construction
//! method 0, one extent, no external data reference) are handled.

use std::ops::Range;

use super::iso::{BoxHdr, c2pa, is_c2pa_box, parse_header, uuid_len, xmp};
use super::{Draft, evidence, is_blank, push, read};
use crate::model::{
    Category, Confidence, ContainerKind, Finding, JunkKind, Marker, Region, RemovalStrategy,
    Severity,
};
use crate::parsers::image::exif;
use crate::parsers::image::shared::{TITLE_CHARS, clip};
use crate::parsers::provenance::XMP_BMFF_UUID;
use crate::scan::FileView;
use crate::util::bytes::{slice, u16_be, u32_be};
use crate::util::fmt::human_size;

/// Largest `meta` box read.
const MAX_META: usize = 4 * 1024 * 1024;
const MAX_ITEMS: usize = 4096;
const MAX_EXTENTS: usize = 64;
/// Most item data read for a note.
const MAX_PAYLOAD: usize = 64 * 1024;

#[derive(Debug, Clone)]
struct Item {
    id: u32,
    kind: [u8; 4],
    /// Offset of the 4-byte item type in the `meta` box.
    type_at: usize,
    /// The content type string of a `mime` item, without its NUL.
    content: Option<Range<usize>>,
}

#[derive(Debug, Clone, Copy)]
struct Loc {
    id: u32,
    offset: u64,
    len: u64,
}

struct Meta {
    /// Child boxes: header and offset in the `meta` buffer.
    children: Vec<(BoxHdr, usize)>,
    items: Vec<Item>,
    locs: Vec<Loc>,
}

/// What a metadata item is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Exif,
    Xmp,
}

impl Item {
    fn metadata(&self, buf: &[u8]) -> Option<Kind> {
        match &self.kind {
            b"Exif" => Some(Kind::Exif),
            b"mime" => {
                let ct = buf.get(self.content.clone()?)?;
                ct.get(..19)
                    .is_some_and(|c| c.eq_ignore_ascii_case(b"application/rdf+xml"))
                    .then_some(Kind::Xmp)
            }
            _ => None,
        }
    }
}

/// Big-endian unsigned integer of `n` bytes (0 gives 0).
fn uint(buf: &[u8], off: usize, n: usize) -> Option<u64> {
    if n > 8 {
        return None;
    }
    let bytes = slice(buf, off, n)?;
    Some(bytes.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b)))
}

/// Where the children of a `meta` box start: a full box skips its version and
/// flags, a QuickTime `meta` starts straight with `hdlr`.
fn children_start(buf: &[u8], header: usize) -> usize {
    if slice(buf, header + 4, 4) == Some(b"hdlr") {
        header
    } else {
        header + 4
    }
}

fn parse_meta(buf: &[u8], start: u64, header: usize) -> Meta {
    let mut meta = Meta {
        children: Vec::new(),
        items: Vec::new(),
        locs: Vec::new(),
    };
    let mut off = children_start(buf, header);
    while off + 8 <= buf.len() && meta.children.len() < MAX_ITEMS {
        let Some(c) = buf
            .get(off..)
            .and_then(|b| parse_header(b, start + off as u64, (buf.len() - off) as u64))
        else {
            break;
        };
        let pay = off + c.header as usize;
        let end = off + c.size as usize;
        match &c.kind {
            b"iinf" => parse_iinf(buf, pay, end, &mut meta.items),
            b"iloc" => parse_iloc(buf, pay, end, &mut meta.locs),
            _ => {}
        }
        meta.children.push((c, off));
        if end <= off {
            break;
        }
        off = end;
    }
    meta
}

/// The `infe` entries of an `iinf` box whose payload is `buf[pay..end]`.
fn parse_iinf(buf: &[u8], pay: usize, end: usize, items: &mut Vec<Item>) {
    let version = buf.get(pay).copied().unwrap_or(0);
    let mut off = pay + if version == 0 { 6 } else { 8 };
    while off + 8 <= end && items.len() < MAX_ITEMS {
        let Some(c) = buf
            .get(off..end)
            .and_then(|b| parse_header(b, 0, (end - off) as u64))
        else {
            return;
        };
        let inner = off + c.header as usize;
        let inner_end = off + c.size as usize;
        if &c.kind == b"infe"
            && let Some(item) = parse_infe(buf, inner, inner_end)
        {
            items.push(item);
        }
        if inner_end <= off {
            return;
        }
        off = inner_end;
    }
}

/// One `infe` entry, versions 2 and 3 (the ones that carry an item type).
fn parse_infe(buf: &[u8], at: usize, end: usize) -> Option<Item> {
    let version = *buf.get(at)?;
    if version < 2 {
        return None;
    }
    let (id, mut pos) = if version == 2 {
        (u32::from(u16_be(buf, at + 4)?), at + 6)
    } else {
        (u32_be(buf, at + 4)?, at + 8)
    };
    pos += 2;
    let type_at = pos;
    let kind: [u8; 4] = slice(buf, type_at, 4)?.try_into().ok()?;
    pos += 4;
    let limit = buf.get(..end)?;
    let name_len = limit.get(pos..)?.iter().position(|&b| b == 0)?;
    pos += name_len + 1;
    let content = if &kind == b"mime" {
        let len = limit.get(pos..)?.iter().position(|&b| b == 0)?;
        Some(pos..pos + len)
    } else {
        None
    };
    Some(Item {
        id,
        kind,
        type_at,
        content,
    })
}

/// The file-body extents of an `iloc` box whose payload is `buf[pay..end]`.
fn parse_iloc(buf: &[u8], pay: usize, end: usize, locs: &mut Vec<Loc>) {
    let _ = parse_iloc_inner(buf, pay, end, locs);
}

fn parse_iloc_inner(buf: &[u8], pay: usize, end: usize, locs: &mut Vec<Loc>) -> Option<()> {
    let body = buf.get(..end)?;
    let version = *body.get(pay)?;
    if version > 2 {
        return None;
    }
    let sizes = *body.get(pay + 4)?;
    let more = *body.get(pay + 5)?;
    let (offset_size, length_size) = (usize::from(sizes >> 4), usize::from(sizes & 15));
    let base_size = usize::from(more >> 4);
    let index_size = if version >= 1 {
        usize::from(more & 15)
    } else {
        0
    };
    let (count, mut pos) = if version < 2 {
        (u64::from(u16_be(body, pay + 6)?), pay + 8)
    } else {
        (u64::from(u32_be(body, pay + 6)?), pay + 10)
    };
    for _ in 0..count.min(MAX_ITEMS as u64) {
        let id = if version < 2 {
            let v = u32::from(u16_be(body, pos)?);
            pos += 2;
            v
        } else {
            let v = u32_be(body, pos)?;
            pos += 4;
            v
        };
        let mut method = 0u16;
        if version >= 1 {
            method = u16_be(body, pos)? & 0xF;
            pos += 2;
        }
        let data_ref = u16_be(body, pos)?;
        pos += 2;
        let base = uint(body, pos, base_size)?;
        pos += base_size;
        let extents = usize::from(u16_be(body, pos)?);
        pos += 2;
        if extents > MAX_EXTENTS {
            return None;
        }
        let mut first = None;
        for _ in 0..extents {
            pos += index_size;
            let offset = uint(body, pos, offset_size)?;
            pos += offset_size;
            let len = uint(body, pos, length_size)?;
            pos += length_size;
            first.get_or_insert((offset, len));
        }
        if let (0, 0, 1, Some((offset, len))) = (method, data_ref, extents, first)
            && len > 0
            && let Some(abs) = base.checked_add(offset)
            && abs.checked_add(len).is_some()
        {
            locs.push(Loc {
                id,
                offset: abs,
                len,
            });
        }
    }
    Some(())
}

/// Report the C2PA and XMP boxes and the EXIF and XMP items of a top-level
/// `meta` box.
pub(super) fn meta(view: &dyn FileView, b: &BoxHdr, out: &mut Vec<Finding>) {
    let Ok(len) = usize::try_from(b.size) else {
        return;
    };
    if len > MAX_META || len <= b.header as usize {
        return;
    }
    let Some(buf) = read(view, b.start, len).filter(|buf| buf.len() == len) else {
        return;
    };
    let m = parse_meta(&buf, b.start, b.header as usize);
    for (c, off) in &m.children {
        let pre = c.header as usize - uuid_len(c);
        let pay = off + c.header as usize;
        let prefix = buf
            .get(pay..(off + c.size as usize).min(pay + 64))
            .unwrap_or_default();
        if c.uuid == Some(XMP_BMFF_UUID) {
            xmp(c, prefix, out);
        } else if is_c2pa_box(&c.kind, buf.get(off + pre..)) {
            c2pa(c, prefix, out);
        }
    }
    for item in &m.items {
        let Some(kind) = item.metadata(&buf) else {
            continue;
        };
        let Some(loc) = m.locs.iter().find(|l| l.id == item.id) else {
            continue;
        };
        if overlaps_meta(loc, b) {
            continue;
        }
        item_finding(view, kind, loc, out);
    }
}

fn overlaps_meta(loc: &Loc, b: &BoxHdr) -> bool {
    loc.offset < b.end() && b.start < loc.offset.saturating_add(loc.len)
}

fn item_finding(view: &dyn FileView, kind: Kind, loc: &Loc, out: &mut Vec<Finding>) {
    let want = usize::try_from(loc.len)
        .unwrap_or(usize::MAX)
        .min(MAX_PAYLOAD);
    let Some(data) = read(view, loc.offset, want).filter(|d| d.len() == want) else {
        return;
    };
    if is_blank(&data) || data.iter().all(|&b| b == 0) {
        return;
    }
    let marker = Marker {
        region: Region::new(loc.offset, loc.len),
        removal: RemovalStrategy::StructuralRemove,
        container: ContainerKind::IsoBox,
        reversible: true,
    };
    let (id, category, title, note) = match kind {
        Kind::Exif => {
            // A 4-byte offset to the TIFF header, then (usually) the block.
            let skip = u32_be(&data, 0).map_or(4, |o| 4usize.saturating_add(o as usize));
            let tiff = data.get(skip..).unwrap_or_default();
            let tiff = tiff.strip_prefix(b"Exif\0\0").unwrap_or(tiff);
            let summary = exif::parse_tiff(tiff);
            let title = match summary.as_ref().and_then(exif::ExifSummary::camera) {
                Some(cam) => format!("HEIF EXIF item ({})", clip(&cam, TITLE_CHARS)),
                None => "HEIF EXIF item".to_string(),
            };
            let mut note = format!("{} EXIF item in the image body", human_size(loc.len));
            if let Some(d) = summary.as_ref().and_then(exif::ExifSummary::describe) {
                note.push_str(&format!(": {d}"));
            }
            ("mp4.exif_item", Category::Junk(JunkKind::Exif), title, note)
        }
        Kind::Xmp => (
            "mp4.xmp_item",
            Category::Junk(JunkKind::Xmp),
            "HEIF XMP item".to_string(),
            format!("{} XMP packet stored as a mime item", human_size(loc.len)),
        ),
    };
    push(
        out,
        Draft {
            category,
            confidence: Confidence::Strong,
            severity: Severity::Notice,
            id,
            title,
            evidence: evidence(
                loc.offset,
                &data,
                format!("{note}; scrubbing retypes the item as free and zero-fills its data"),
            ),
            marker: Some(marker),
        },
    );
}

/// Structural removal of one EXIF or XMP item: `region` is the item's data in
/// the file body. The item's `infe` type becomes `free`, a `mime` content type
/// string is zeroed, and the data is zero-filled; no offset moves. `None` when
/// no top-level `meta` box has such an item at exactly this region, or the
/// data overlaps the `meta` box.
pub(super) fn remove_item(data: &[u8], region: Region) -> Option<Vec<u8>> {
    let start = usize::try_from(region.offset).ok()?;
    let end = start.checked_add(usize::try_from(region.len).ok()?)?;
    if region.len == 0 || end > data.len() {
        return None;
    }
    let mut off = 0usize;
    for _ in 0..MAX_ITEMS {
        let rest = data.get(off..)?;
        let b = parse_header(rest, off as u64, rest.len() as u64)?;
        if &b.kind == b"meta"
            && b.size as usize <= MAX_META
            && let Some(out) = remove_in_meta(data, &b, region)
        {
            return Some(out);
        }
        let box_end = off + b.size as usize;
        if box_end <= off || box_end >= data.len() {
            break;
        }
        off = box_end;
    }
    None
}

fn remove_in_meta(data: &[u8], b: &BoxHdr, region: Region) -> Option<Vec<u8>> {
    let meta_start = usize::try_from(b.start).ok()?;
    let buf = data.get(meta_start..meta_start.checked_add(usize::try_from(b.size).ok()?)?)?;
    let m = parse_meta(buf, b.start, b.header as usize);
    let (item, _) = m.items.iter().find_map(|it| {
        let kind = it.metadata(buf)?;
        let loc = m
            .locs
            .iter()
            .find(|l| l.id == it.id && l.offset == region.offset && l.len == region.len)?;
        (!overlaps_meta(loc, b)).then_some((it, kind))
    })?;
    let mut out = data.to_vec();
    out.get_mut(meta_start + item.type_at..meta_start + item.type_at + 4)?
        .copy_from_slice(b"free");
    if let Some(r) = &item.content {
        out.get_mut(meta_start + r.start..meta_start + r.end)?
            .fill(0);
    }
    let start = usize::try_from(region.offset).ok()?;
    let end = start.checked_add(usize::try_from(region.len).ok()?)?;
    out.get_mut(start..end)?.fill(0);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::super::iso::tests_support::{bx, ftyp};
    use super::super::testutil::{apply, find, format_of, ids, run};
    use super::*;
    use crate::parsers::image::exif::build_tiff;

    fn infe(id: u16, kind: &[u8; 4], mime: bool) -> Vec<u8> {
        let mut p = vec![2, 0, 0, 0];
        p.extend_from_slice(&id.to_be_bytes());
        p.extend_from_slice(&[0, 0]);
        p.extend_from_slice(kind);
        p.push(0);
        if mime {
            p.extend_from_slice(b"application/rdf+xml\0\0");
        }
        bx(b"infe", &p)
    }

    fn iloc(items: &[(u16, u32, u32)]) -> Vec<u8> {
        let mut p = vec![1, 0, 0, 0, 0x44, 0x00];
        p.extend_from_slice(&(items.len() as u16).to_be_bytes());
        for &(id, offset, len) in items {
            p.extend_from_slice(&id.to_be_bytes());
            p.extend_from_slice(&[0, 0, 0, 0, 0, 1]);
            p.extend_from_slice(&offset.to_be_bytes());
            p.extend_from_slice(&len.to_be_bytes());
        }
        bx(b"iloc", &p)
    }

    /// A HEIC-shaped file: ftyp, meta (hdlr, iinf, iloc) and an mdat holding
    /// an EXIF item, an XMP item and the "image".
    fn heic() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut exif = vec![0, 0, 0, 0];
        exif.extend(build_tiff(
            &[(0x010F, "Apple"), (0x0110, "iPhone 15")],
            true,
        ));
        let xmp = b"<x:xmpmeta xmp:CreatorTool=\"Test Editor\"/>".to_vec();
        let image = vec![9u8; 40];
        let build = |base: u32| {
            let items = [
                (1u16, base + 8, exif.len() as u32),
                (2, base + 8 + exif.len() as u32, xmp.len() as u32),
                (
                    3,
                    base + 8 + (exif.len() + xmp.len()) as u32,
                    image.len() as u32,
                ),
            ];
            let iinf = {
                let mut p = vec![0, 0, 0, 0, 0, 3];
                p.extend(infe(1, b"Exif", false));
                p.extend(infe(2, b"mime", true));
                p.extend(infe(3, b"hvc1", false));
                bx(b"iinf", &p)
            };
            let mut meta = vec![0, 0, 0, 0];
            meta.extend(bx(b"hdlr", &[0u8; 25]));
            meta.extend(iinf);
            meta.extend(iloc(&items));
            let mut mdat = exif.clone();
            mdat.extend(&xmp);
            mdat.extend(&image);
            [ftyp(), bx(b"meta", &meta), bx(b"mdat", &mdat)].concat()
        };
        let probe = build(0);
        let base = (probe.len() - 8 - exif.len() - xmp.len() - image.len()) as u32;
        (build(base), exif, xmp)
    }

    #[test]
    fn exif_and_xmp_items_are_found() {
        let (data, exif, xmp) = heic();
        let f = run("a.heic", "mp4", &data);
        assert_eq!(ids(&f), ["mp4.brand", "mp4.exif_item", "mp4.xmp_item"]);
        let e = find(&f, "mp4.exif_item");
        assert_eq!(e.title, "HEIF EXIF item (Apple iPhone 15)");
        assert_eq!(e.category, Category::Junk(JunkKind::Exif));
        let m = e.marker.as_ref().unwrap();
        assert_eq!(m.removal, RemovalStrategy::StructuralRemove);
        assert_eq!(m.container, ContainerKind::IsoBox);
        assert_eq!(m.region.len, exif.len() as u64);
        let x = find(&f, "mp4.xmp_item");
        assert_eq!(x.category, Category::Junk(JunkKind::Xmp));
        assert_eq!(x.marker.as_ref().unwrap().region.len, xmp.len() as u64);
    }

    #[test]
    fn items_are_retyped_and_zeroed_without_moving_anything() {
        let (data, exif, xmp) = heic();
        let mut cur = data.clone();
        for f in run("a.heic", "mp4", &data)
            .iter()
            .filter(|f| f.marker.is_some())
        {
            apply(&mut cur, f.marker.as_ref().unwrap());
        }
        assert_eq!(cur.len(), data.len());
        assert_eq!(format_of("a.heic", &cur), Some("mp4"));
        assert_eq!(ids(&run("a.heic", "mp4", &cur)), ["mp4.brand"]);
        let at = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).position(|w| w == needle);
        assert!(at(&cur, b"Exif").is_none() && at(&cur, b"rdf+xml").is_none());
        assert!(at(&cur, b"Apple").is_none() && at(&cur, b"Test Editor").is_none());
        assert_eq!(cur.matches_free(), 2);
        // The iloc table and the image item are byte for byte as before.
        let iloc_at = at(&data, b"iloc").unwrap();
        assert_eq!(data[iloc_at..iloc_at + 60], cur[iloc_at..iloc_at + 60]);
        let tail = data.len() - 40;
        assert_eq!(data[tail..], cur[tail..]);
        let first = at(&data, &exif).unwrap();
        assert!(
            cur[first..first + exif.len() + xmp.len()]
                .iter()
                .all(|&b| b == 0)
        );
    }

    #[test]
    fn item_remover_is_strict() {
        let (data, exif, _) = heic();
        let f = run("a.heic", "mp4", &data);
        let r = find(&f, "mp4.exif_item").marker.as_ref().unwrap().region;
        assert!(remove_item(&data, r).is_some());
        assert!(remove_item(&data, Region::new(r.offset, r.len - 1)).is_none());
        assert!(remove_item(&data, Region::new(r.offset + 1, r.len)).is_none());
        // The image item is not metadata.
        let image = Region::new((data.len() - 40) as u64, 40);
        assert!(remove_item(&data, image).is_none());
        // Nor is a region over the meta box itself.
        assert!(remove_item(&data, Region::new(ftyp().len() as u64, exif.len() as u64)).is_none());
    }

    #[test]
    fn c2pa_inside_meta_and_truncation() {
        let (mut data, _, _) = heic();
        // Put a jumb box inside the meta box and grow its size field.
        let meta_at = ftyp().len();
        let jumb = bx(b"jumb", b"manifest");
        let hdlr_end = meta_at + 8 + 4 + 33;
        data.splice(hdlr_end..hdlr_end, jumb.iter().copied());
        let size = u32::from_be_bytes(data[meta_at..meta_at + 4].try_into().unwrap());
        data[meta_at..meta_at + 4].copy_from_slice(&(size + jumb.len() as u32).to_be_bytes());
        let f = run("a.heic", "mp4", &data);
        assert!(ids(&f).contains(&"mp4.c2pa"));
        for cut in 0..data.len() {
            let _ = run("a.heic", "mp4", &data[..cut]);
        }
    }

    trait CountFree {
        fn matches_free(&self) -> usize;
    }

    impl CountFree for Vec<u8> {
        fn matches_free(&self) -> usize {
            self.windows(4).filter(|w| *w == b"free").count()
        }
    }
}
