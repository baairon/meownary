//! OLE compound files (legacy Word, Excel and PowerPoint, and Windows
//! Installer packages): the header, the directory chain (capped at 1,024
//! entries) and its UTF-16 stream names, then the `\x05SummaryInformation`
//! property set when it lives in regular sectors. Streams in the mini stream
//! (smaller than the header's cutoff, normally 4,096 bytes) are not read.

use std::collections::HashMap;

use crate::model::{
    BrandKind, Category, Confidence, ContainerKind, Evidence, Finding, JunkKind, Marker, Region,
    RemovalStrategy, Severity,
};
use crate::scan::FileView;
use crate::util::bytes::{slice, u16_le, u32_le, u64_le, utf16le};

use crate::parsers::image::shared::{
    NOTE_CHARS, TITLE_CHARS, clip, excerpt, fetch, finding, latin1,
};

const SIG: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
const HEADER_LEN: usize = 512;
const ENTRY_LEN: usize = 128;
const MAX_ENTRIES: usize = 1024;
/// Highest regular sector number; larger values are chain markers.
const MAX_REG_SECT: u32 = 0xFFFF_FFFA;
const END_OF_CHAIN: u32 = 0xFFFF_FFFE;
/// Most FAT sector locations collected (each maps 128 or 1,024 sectors).
const MAX_FAT_SECTORS: usize = 1 << 16;
/// Most DIFAT sectors followed.
const MAX_DIFAT_SECTORS: usize = 1024;
/// FAT sectors kept in the lookup cache.
const FAT_CACHE: usize = 256;
/// Largest property set stream read.
const MAX_SUMMARY: u64 = 256 * 1024;
/// Most properties read from one property set.
const MAX_PROPS: usize = 256;
/// Longest string property accepted, in bytes.
const MAX_PROP_STRING: usize = 64 * 1024;

const TYPE_STREAM: u8 = 2;
const TYPE_ROOT: u8 = 5;

/// `{F29F85E0-4FF9-1068-AB91-08002B27B3D9}`, the SummaryInformation FMTID.
const FMTID_SUMMARY: [u8; 16] = [
    0xE0, 0x85, 0x9F, 0xF2, 0xF9, 0x4F, 0x68, 0x10, 0xAB, 0x91, 0x08, 0x00, 0x2B, 0x27, 0xB3, 0xD9,
];

/// Root storage CLSIDs of Windows Installer files, `{000C10xx-0000-0000-
/// C000-000000000046}` with xx 84 (package), 86 (patch) and 82 (transform).
const MSI_CLASSES: &[(u8, &str)] = &[
    (0x84, "Windows Installer package"),
    (0x86, "Windows Installer patch"),
    (0x82, "Windows Installer transform"),
];

const PID_CODEPAGE: u32 = 0x01;
const PID_AUTHOR: u32 = 0x04;
const PID_LASTAUTHOR: u32 = 0x08;
const PID_APPNAME: u32 = 0x12;
const VT_I2: u16 = 0x02;
const VT_LPSTR: u16 = 0x1E;
const VT_LPWSTR: u16 = 0x1F;
const CP_UTF16: u16 = 1200;
const CP_UTF8: u16 = 65001;

/// One directory entry.
#[derive(Debug, Clone)]
struct DirEntry {
    /// Absolute offset of the 128-byte entry.
    off: u64,
    name: String,
    /// The raw UTF-16LE name bytes, without the terminator.
    raw_name: Vec<u8>,
    ty: u8,
    clsid: [u8; 16],
    start: u32,
    size: u64,
}

/// The parsed header plus a cached FAT lookup.
struct Cfb<'a> {
    view: &'a dyn FileView,
    ssz: u64,
    dir_start: u32,
    mini_cutoff: u64,
    major: u16,
    fat_sectors: Vec<u32>,
    cache: HashMap<u32, Vec<u8>>,
}

impl<'a> Cfb<'a> {
    fn open(view: &'a dyn FileView) -> Option<Self> {
        let h = fetch(view, 0, HEADER_LEN)?;
        if h.get(..8)? != SIG || u16_le(&h, 0x1C)? != 0xFFFE {
            return None;
        }
        let major = u16_le(&h, 0x1A)?;
        let shift = u16_le(&h, 0x1E)?;
        if !matches!((major, shift), (3, 9) | (4, 12)) || u16_le(&h, 0x20)? != 6 {
            return None;
        }
        let ssz = 1u64 << shift;
        let num_fat = u32_le(&h, 0x2C)? as usize;
        let mut fat_sectors: Vec<u32> = (0..109)
            .filter_map(|i| u32_le(&h, 0x4C + i * 4))
            .take(num_fat.min(109))
            .collect();
        let mut difat = u32_le(&h, 0x44)?;
        let per = (ssz / 4) as usize;
        for _ in 0..MAX_DIFAT_SECTORS {
            if fat_sectors.len() >= num_fat.min(MAX_FAT_SECTORS) || difat > MAX_REG_SECT {
                break;
            }
            let Some(sec) = fetch(view, sector_off(ssz, difat)?, ssz as usize) else {
                break;
            };
            for i in 0..per - 1 {
                if fat_sectors.len() >= num_fat.min(MAX_FAT_SECTORS) {
                    break;
                }
                fat_sectors.push(u32_le(&sec, i * 4)?);
            }
            difat = u32_le(&sec, (per - 1) * 4)?;
        }
        Some(Cfb {
            view,
            ssz,
            dir_start: u32_le(&h, 0x30)?,
            mini_cutoff: u32_le(&h, 0x38)? as u64,
            major,
            fat_sectors,
            cache: HashMap::new(),
        })
    }

    /// The sector after `s` in its chain.
    fn next(&mut self, s: u32) -> Option<u32> {
        let per = (self.ssz / 4) as u32;
        let fs = *self.fat_sectors.get((s / per) as usize)?;
        if fs > MAX_REG_SECT {
            return None;
        }
        if !self.cache.contains_key(&fs) {
            if self.cache.len() >= FAT_CACHE {
                self.cache.clear();
            }
            let sec = fetch(self.view, sector_off(self.ssz, fs)?, self.ssz as usize)?;
            self.cache.insert(fs, sec);
        }
        u32_le(self.cache.get(&fs)?, ((s % per) * 4) as usize)
    }

    /// Up to `max` sectors of the chain from `start`. `None` when the chain
    /// breaks before reaching `max` sectors or its end.
    fn chain(&mut self, start: u32, max: usize) -> Option<Vec<u32>> {
        let mut out = Vec::new();
        let mut s = start;
        while out.len() < max {
            if s == END_OF_CHAIN {
                return Some(out);
            }
            if s > MAX_REG_SECT {
                return None;
            }
            out.push(s);
            s = self.next(s)?;
        }
        Some(out)
    }

    /// The directory entries, in order, up to [`MAX_ENTRIES`].
    fn directory(&mut self) -> Option<Vec<DirEntry>> {
        let per_sector = self.ssz as usize / ENTRY_LEN;
        let max_sectors = MAX_ENTRIES.div_ceil(per_sector);
        let sectors = self.chain(self.dir_start, max_sectors)?;
        let mut out = Vec::new();
        for s in sectors {
            let base = sector_off(self.ssz, s)?;
            let sec = fetch(self.view, base, self.ssz as usize)?;
            for k in 0..per_sector {
                if out.len() >= MAX_ENTRIES {
                    break;
                }
                let e = slice(&sec, k * ENTRY_LEN, ENTRY_LEN)?;
                out.push(self.entry(base + (k * ENTRY_LEN) as u64, e)?);
            }
        }
        Some(out)
    }

    fn entry(&self, off: u64, e: &[u8]) -> Option<DirEntry> {
        let name_len = (u16_le(e, 0x40)? as usize).min(64);
        let units = name_len.saturating_sub(2) / 2;
        let mut size = u64_le(e, 0x78)?;
        if self.major == 3 {
            size &= 0xFFFF_FFFF;
        }
        Some(DirEntry {
            off,
            name: utf16le(e, 0, units)?,
            raw_name: e.get(..units * 2)?.to_vec(),
            ty: *e.get(0x42)?,
            clsid: slice(e, 0x50, 16)?.try_into().ok()?,
            start: u32_le(e, 0x74)?,
            size,
        })
    }
}

/// Absolute offset of sector `s`.
fn sector_off(ssz: u64, s: u32) -> Option<u64> {
    (s as u64).checked_add(1)?.checked_mul(ssz)
}

/// A stream read through its sector chain, with the file offset of each
/// sector so stream offsets can be mapped back.
struct Stream {
    data: Vec<u8>,
    sectors: Vec<u64>,
    ssz: u64,
}

impl Stream {
    /// The file offset of stream bytes `off..off + len`, when they are one
    /// contiguous run in the file (no jump between non-adjacent sectors).
    fn file_range(&self, off: usize, len: usize) -> Option<u64> {
        if len == 0 || off.checked_add(len)? > self.data.len() {
            return None;
        }
        let ssz = self.ssz as usize;
        let (first, last) = (off / ssz, (off + len - 1) / ssz);
        for k in first..last {
            if *self.sectors.get(k + 1)? != self.sectors.get(k)? + self.ssz {
                return None;
            }
        }
        Some(self.sectors.get(first)? + (off % ssz) as u64)
    }
}

fn read_stream(c: &mut Cfb, e: &DirEntry) -> Option<Stream> {
    if e.size == 0 || e.size > MAX_SUMMARY {
        return None;
    }
    let n = e.size.div_ceil(c.ssz) as usize;
    let chain = c.chain(e.start, n)?;
    if chain.len() < n {
        return None;
    }
    let mut data = Vec::with_capacity(e.size as usize);
    let mut sectors = Vec::with_capacity(n);
    for s in chain {
        let off = sector_off(c.ssz, s)?;
        data.extend(fetch(c.view, off, c.ssz as usize)?);
        sectors.push(off);
    }
    data.truncate(e.size as usize);
    Some(Stream {
        data,
        sectors,
        ssz: c.ssz,
    })
}

/// A string property: where its text bytes sit in the stream, their length
/// (terminator excluded), whether they are UTF-16LE, and the decoded text.
struct PropString {
    pid: u32,
    at: usize,
    len: usize,
    wide: bool,
    text: String,
}

/// The string properties of the SummaryInformation property set in `buf`.
fn summary_strings(buf: &[u8]) -> Option<Vec<PropString>> {
    if u16_le(buf, 0)? != 0xFFFE || u32_le(buf, 24)? == 0 || slice(buf, 28, 16)? != FMTID_SUMMARY {
        return None;
    }
    let ps = u32_le(buf, 44)? as usize;
    let count = (u32_le(buf, ps + 4)? as usize).min(MAX_PROPS);
    let mut props = Vec::new();
    for k in 0..count {
        let pid = u32_le(buf, ps + 8 + k * 8)?;
        let off = u32_le(buf, ps + 12 + k * 8)? as usize;
        props.push((pid, ps.checked_add(off)?));
    }
    let codepage = props
        .iter()
        .find(|(pid, _)| *pid == PID_CODEPAGE)
        .filter(|&&(_, v)| u16_le(buf, v) == Some(VT_I2))
        .and_then(|&(_, v)| u16_le(buf, v + 4))
        .unwrap_or(1252);
    let mut out = Vec::new();
    for (pid, v) in props {
        if !matches!(pid, PID_AUTHOR | PID_LASTAUTHOR | PID_APPNAME) {
            continue;
        }
        let Some(ty) = u16_le(buf, v) else {
            continue;
        };
        let Some(count) = u32_le(buf, v + 4).map(|c| c as usize) else {
            continue;
        };
        let at = v + 8;
        let (bytes, wide) = match ty {
            VT_LPSTR => (count, codepage == CP_UTF16),
            VT_LPWSTR => (count.saturating_mul(2), true),
            _ => continue,
        };
        if bytes > MAX_PROP_STRING {
            continue;
        }
        let Some(raw) = slice(buf, at, bytes) else {
            continue;
        };
        let (len, text) = if wide {
            let units = raw.len() / 2;
            let s = utf16le(raw, 0, units).unwrap_or_default();
            let len = raw
                .as_chunks::<2>()
                .0
                .iter()
                .position(|u| u == &[0, 0])
                .unwrap_or(units)
                * 2;
            (len, s)
        } else {
            let len = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
            let body = &raw[..len];
            let s = if codepage == CP_UTF8 {
                String::from_utf8_lossy(body).to_string()
            } else {
                latin1(body)
            };
            (len, s)
        };
        if len == 0 || text.trim().is_empty() {
            continue;
        }
        out.push(PropString {
            pid,
            at,
            len,
            wide,
            text: text.trim().to_string(),
        });
    }
    Some(out)
}

/// What the directory says this file is, with the entry and bytes that say so.
fn class_of(dir: &[DirEntry]) -> Option<(&'static str, u64, Vec<u8>)> {
    let root = dir.first()?;
    let msi_tail = [
        0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0, 0, 0, 0, 0, 0, 0x46,
    ];
    if root.clsid[2..] == msi_tail[..]
        && root.clsid[1] == 0x10
        && let Some(&(_, label)) = MSI_CLASSES.iter().find(|(b, _)| *b == root.clsid[0])
    {
        return Some((label, root.off + 0x50, root.clsid.to_vec()));
    }
    for (names, label) in [
        (&["WordDocument"][..], "Word binary document"),
        (&["Workbook", "Book"][..], "Excel binary workbook"),
        (&["PowerPoint Document"][..], "PowerPoint binary deck"),
    ] {
        if let Some(e) = dir
            .iter()
            .find(|e| e.ty == TYPE_STREAM && names.contains(&e.name.as_str()))
        {
            return Some((label, e.off, e.raw_name.clone()));
        }
    }
    None
}

pub(super) fn run(view: &dyn FileView, out: &mut Vec<Finding>) {
    let Some(mut c) = Cfb::open(view) else {
        return;
    };
    let Some(dir) = c.directory() else {
        return;
    };
    if dir.first().is_none_or(|r| r.ty != TYPE_ROOT) {
        return;
    }
    let streams = dir.iter().filter(|e| e.ty == TYPE_STREAM).count();
    let class = class_of(&dir);
    let installer = class
        .as_ref()
        .is_some_and(|(l, _, _)| l.starts_with("Windows"));
    if let Some((label, at, matched)) = &class {
        out.push(finding(
            "cfb.class",
            Category::Brand(BrandKind::DocProducer),
            Confidence::Strong,
            Severity::Info,
            *label,
            Evidence::at(*at)
                .with_bytes(excerpt(matched))
                .with_note(format!(
                    "compound file v{} with {}-byte sectors and {streams} streams in {} \
                     directory entries",
                    c.major,
                    c.ssz,
                    dir.len()
                )),
            None,
        ));
    }

    let Some(si) = dir
        .iter()
        .find(|e| e.ty == TYPE_STREAM && e.name == "\u{5}SummaryInformation")
    else {
        return;
    };
    if si.size < c.mini_cutoff {
        return;
    }
    let Some(stream) = read_stream(&mut c, si) else {
        return;
    };
    let Some(props) = summary_strings(&stream.data) else {
        return;
    };
    for p in props {
        let Some(file_at) = stream.file_range(p.at, 1) else {
            continue;
        };
        let contiguous = stream.file_range(p.at, p.len);
        // Evidence bytes must match the file at `file_at`, so a string that
        // crosses a sector jump shows only its part in the first sector.
        let ssz = c.ssz as usize;
        let shown = if contiguous.is_some() {
            p.len
        } else {
            p.len.min(ssz - p.at % ssz)
        };
        let text_bytes = stream.data.get(p.at..p.at + shown).unwrap_or_default();
        let evidence = Evidence::at(file_at).with_bytes(excerpt(text_bytes));
        if p.pid == PID_APPNAME {
            out.push(finding(
                "cfb.summary",
                Category::Brand(BrandKind::DocProducer),
                Confidence::Moderate,
                Severity::Info,
                format!("Application \"{}\"", clip(&p.text, TITLE_CHARS)),
                evidence.with_note(format!(
                    "SummaryInformation PIDSI_APPNAME = \"{}\"",
                    clip(&p.text, NOTE_CHARS)
                )),
                None,
            ));
            continue;
        }
        let (label, pid_name) = if p.pid == PID_AUTHOR {
            ("Document author", "PIDSI_AUTHOR")
        } else {
            ("Last saved by", "PIDSI_LASTAUTHOR")
        };
        let mut note = format!(
            "SummaryInformation {pid_name} = \"{}\"",
            clip(&p.text, NOTE_CHARS)
        );
        if installer && p.pid == PID_AUTHOR {
            note.push_str("; in an installer this field names the manufacturer");
        }
        // UTF-16 text is cleared to NULs (an empty string); 8-bit text
        // becomes spaces. The length field is kept either way.
        let marker = match contiguous {
            Some(at) => Some(Marker {
                region: Region::new(at, p.len as u64),
                removal: RemovalStrategy::RawBlank {
                    fill: if p.wide { 0x00 } else { b' ' },
                },
                container: ContainerKind::CfbStream,
                reversible: true,
            }),
            None => {
                note.push_str("; the text crosses a sector jump, so it is not blanked in place");
                None
            }
        };
        out.push(finding(
            "cfb.summary",
            Category::Junk(JunkKind::DocInfo),
            Confidence::Moderate,
            Severity::Notice,
            format!("{label} \"{}\"", clip(&p.text, TITLE_CHARS)),
            evidence.with_note(note),
            marker,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::doc::probes;
    use crate::parsers::image::shared::testkit::{apply, garbage, run, with_id};

    const FREE: u32 = 0xFFFF_FFFF;
    const FAT_SECT: u32 = 0xFFFF_FFFD;
    const MSI_CLSID: [u8; 16] = [
        0x84, 0x10, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0, 0, 0, 0, 0, 0, 0x46,
    ];

    fn dir_entry(name: &str, ty: u8, clsid: [u8; 16], start: u32, size: u64) -> Vec<u8> {
        let mut e = vec![0u8; 128];
        let units: Vec<u16> = name.encode_utf16().collect();
        for (i, u) in units.iter().enumerate() {
            e[i * 2..i * 2 + 2].copy_from_slice(&u.to_le_bytes());
        }
        let name_len = if name.is_empty() {
            0
        } else {
            (units.len() + 1) * 2
        };
        e[0x40..0x42].copy_from_slice(&(name_len as u16).to_le_bytes());
        e[0x42] = ty;
        e[0x43] = 1;
        for at in [0x44, 0x48, 0x4C] {
            e[at..at + 4].copy_from_slice(&FREE.to_le_bytes());
        }
        e[0x50..0x60].copy_from_slice(&clsid);
        e[0x74..0x78].copy_from_slice(&start.to_le_bytes());
        e[0x78..0x80].copy_from_slice(&size.to_le_bytes());
        e
    }

    /// A string property value: LPSTR bytes or LPWSTR text.
    enum Pv<'a> {
        A(&'a [u8]),
        W(&'a str),
    }

    /// A SummaryInformation stream with codepage 1252 and `props`, padded to
    /// 4,096 bytes so it lives in regular sectors.
    fn summary(props: &[(u32, Pv)]) -> Vec<u8> {
        let mut values: Vec<Vec<u8>> = vec![{
            let mut v = VT_I2.to_le_bytes().to_vec();
            v.extend_from_slice(&[0, 0]);
            v.extend_from_slice(&1252u16.to_le_bytes());
            v.extend_from_slice(&[0, 0]);
            v
        }];
        for (_, pv) in props {
            let mut v = Vec::new();
            match pv {
                Pv::A(b) => {
                    v.extend_from_slice(&VT_LPSTR.to_le_bytes());
                    v.extend_from_slice(&[0, 0]);
                    v.extend_from_slice(&((b.len() + 1) as u32).to_le_bytes());
                    v.extend_from_slice(b);
                    v.push(0);
                }
                Pv::W(s) => {
                    let units: Vec<u16> = s.encode_utf16().collect();
                    v.extend_from_slice(&VT_LPWSTR.to_le_bytes());
                    v.extend_from_slice(&[0, 0]);
                    v.extend_from_slice(&((units.len() + 1) as u32).to_le_bytes());
                    for u in units {
                        v.extend_from_slice(&u.to_le_bytes());
                    }
                    v.extend_from_slice(&[0, 0]);
                }
            }
            while v.len() % 4 != 0 {
                v.push(0);
            }
            values.push(v);
        }
        let pids: Vec<u32> = std::iter::once(PID_CODEPAGE)
            .chain(props.iter().map(|(p, _)| *p))
            .collect();
        let table = 8 + pids.len() * 8;
        let mut set = Vec::new();
        let mut body = Vec::new();
        for (pid, v) in pids.iter().zip(&values) {
            set.extend_from_slice(&pid.to_le_bytes());
            set.extend_from_slice(&((table + body.len()) as u32).to_le_bytes());
            body.extend_from_slice(v);
        }
        let mut s = vec![0xFE, 0xFF, 0, 0, 6, 0, 2, 0];
        s.extend_from_slice(&[0u8; 16]);
        s.extend_from_slice(&1u32.to_le_bytes());
        s.extend_from_slice(&FMTID_SUMMARY);
        s.extend_from_slice(&48u32.to_le_bytes());
        s.extend_from_slice(&((table + body.len()) as u32).to_le_bytes());
        s.extend_from_slice(&(pids.len() as u32).to_le_bytes());
        s.extend(set);
        s.extend(body);
        s.resize(4096, 0);
        s
    }

    /// A v3 compound file: FAT in sector 0, directory in sector 1, and the
    /// 4,096-byte summary stream in sectors 2 to 9, chained in reverse when
    /// `scatter` is set so the stream is not contiguous in the file.
    fn build(root_clsid: [u8; 16], main: Option<&str>, summary: &[u8], scatter: bool) -> Vec<u8> {
        let order: Vec<u32> = if scatter {
            (2..10).rev().collect()
        } else {
            (2..10).collect()
        };
        let mut fat = vec![FREE; 128];
        fat[0] = FAT_SECT;
        fat[1] = END_OF_CHAIN;
        for w in order.windows(2) {
            fat[w[0] as usize] = w[1];
        }
        fat[*order.last().unwrap() as usize] = END_OF_CHAIN;

        let mut h = vec![0u8; 512];
        h[..8].copy_from_slice(&SIG);
        h[0x18..0x1A].copy_from_slice(&0x3Eu16.to_le_bytes());
        h[0x1A..0x1C].copy_from_slice(&3u16.to_le_bytes());
        h[0x1C..0x1E].copy_from_slice(&0xFFFEu16.to_le_bytes());
        h[0x1E..0x20].copy_from_slice(&9u16.to_le_bytes());
        h[0x20..0x22].copy_from_slice(&6u16.to_le_bytes());
        h[0x2C..0x30].copy_from_slice(&1u32.to_le_bytes());
        h[0x30..0x34].copy_from_slice(&1u32.to_le_bytes());
        h[0x38..0x3C].copy_from_slice(&4096u32.to_le_bytes());
        h[0x3C..0x40].copy_from_slice(&END_OF_CHAIN.to_le_bytes());
        h[0x44..0x48].copy_from_slice(&END_OF_CHAIN.to_le_bytes());
        for i in 0..109 {
            let v = if i == 0 { 0 } else { FREE };
            h[0x4C + i * 4..0x50 + i * 4].copy_from_slice(&v.to_le_bytes());
        }

        let mut dir = dir_entry("Root Entry", TYPE_ROOT, root_clsid, END_OF_CHAIN, 0);
        dir.extend(dir_entry(
            main.unwrap_or(""),
            main.map_or(0, |_| 2),
            [0; 16],
            END_OF_CHAIN,
            0,
        ));
        dir.extend(dir_entry(
            "\u{5}SummaryInformation",
            2,
            [0; 16],
            order[0],
            4096,
        ));
        dir.extend(dir_entry("", 0, [0; 16], FREE, 0));

        let mut out = h;
        for f in &fat {
            out.extend_from_slice(&f.to_le_bytes());
        }
        out.extend(dir);
        let mut sectors = vec![vec![0u8; 512]; 8];
        for (k, s) in order.iter().enumerate() {
            sectors[*s as usize - 2] = summary[k * 512..(k + 1) * 512].to_vec();
        }
        for s in sectors {
            out.extend(s);
        }
        out
    }

    /// Filler that pushes the last-author text to stream offset 500, so it
    /// crosses into the second sector.
    const FILLER: &[u8] = &[b'x'; 323];

    fn word_summary() -> Vec<u8> {
        summary(&[
            (0x02, Pv::A(b"Quarterly report")),
            (PID_AUTHOR, Pv::A(b"Jane Doe")),
            (0x06, Pv::A(FILLER)),
            (PID_LASTAUTHOR, Pv::A(b"Johnathan Q. Roe-Smith")),
            (PID_APPNAME, Pv::A(b"Microsoft Office Word")),
        ])
    }

    fn scan(name: &str, data: &[u8], fmt: &str) -> Vec<Finding> {
        run(probes(), name, data, fmt)
    }

    #[test]
    fn word_document_class_and_summary() {
        let data = build([0; 16], Some("WordDocument"), &word_summary(), false);
        let fs = scan("memo.doc", &data, "cfb");
        let class = with_id(&fs, "cfb.class");
        assert_eq!(class.len(), 1);
        assert_eq!(class[0].title, "Word binary document");
        assert_eq!(class[0].confidence, Confidence::Strong);
        assert_eq!(class[0].evidence.offset, 512 + 512 + 128);

        let summary = with_id(&fs, "cfb.summary");
        let titles: Vec<&str> = summary.iter().map(|f| f.title.as_str()).collect();
        assert_eq!(
            titles,
            [
                "Document author \"Jane Doe\"",
                "Last saved by \"Johnathan Q. Roe-Smith\"",
                "Application \"Microsoft Office Word\"",
            ]
        );
        assert_eq!(summary[2].category, Category::Brand(BrandKind::DocProducer));
        assert!(summary[2].marker.is_none());
        // The stream is contiguous, so even the text spanning two sectors
        // gets a marker.
        for f in &summary[..2] {
            assert_eq!(f.category, Category::Junk(JunkKind::DocInfo));
            let m = f.marker.as_ref().unwrap();
            assert_eq!(m.removal, RemovalStrategy::RawBlank { fill: b' ' });
            assert_eq!(m.container, ContainerKind::CfbStream);
            let at = m.region.offset as usize;
            assert_eq!(&data[at..at + 8], &f.evidence.matched[..8]);
        }
        let last = summary[1].marker.as_ref().unwrap();
        assert!(last.region.offset < 1536 + 512 && last.region.end() > 1536 + 512);

        let mut cur = data.clone();
        for f in &summary[..2] {
            cur = apply(&cur, f);
            assert_eq!(cur.len(), data.len());
        }
        let again = scan("memo.doc", &cur, "cfb");
        assert_eq!(again.len(), 2);
        assert_eq!(with_id(&again, "cfb.class").len(), 1);
        assert_eq!(
            with_id(&again, "cfb.summary")[0].title,
            "Application \"Microsoft Office Word\""
        );
    }

    #[test]
    fn scattered_stream_is_mapped_through_the_chain() {
        let data = build([0; 16], Some("Workbook"), &word_summary(), true);
        let fs = scan("book.xls", &data, "cfb");
        assert_eq!(with_id(&fs, "cfb.class")[0].title, "Excel binary workbook");
        let summary = with_id(&fs, "cfb.summary");
        assert_eq!(summary.len(), 3);
        // The first stream sector is file sector 9.
        let author = summary[0].marker.as_ref().unwrap();
        assert!(author.region.offset >= 512 * 10 && author.region.end() <= 512 * 11);
        // The last author crosses from sector 9 into sector 8: no marker.
        assert!(summary[1].marker.is_none());
        assert!(
            summary[1]
                .evidence
                .note
                .as_deref()
                .unwrap()
                .contains("sector jump")
        );
        // Every evidence excerpt matches the file at its offset, including
        // the one cut short at the sector jump.
        for f in &summary {
            let at = f.evidence.offset as usize;
            assert_eq!(
                &data[at..at + f.evidence.matched.len()],
                &f.evidence.matched[..]
            );
        }
        assert_eq!(summary[1].evidence.matched, b"Johnathan Q.");
        let cleaned = apply(&data, summary[0]);
        let again = scan("book.xls", &cleaned, "cfb");
        assert_eq!(with_id(&again, "cfb.summary").len(), 2);
    }

    #[test]
    fn msi_class_and_wide_strings() {
        let s = summary(&[
            (PID_AUTHOR, Pv::W("Example Corp")),
            (PID_APPNAME, Pv::W("Windows Installer XML Toolset")),
        ]);
        let data = build(MSI_CLSID, None, &s, false);
        let fs = scan("setup.msi", &data, "msi");
        let class = with_id(&fs, "cfb.class");
        assert_eq!(class[0].title, "Windows Installer package");
        assert_eq!(class[0].evidence.matched, MSI_CLSID.to_vec());
        let summary = with_id(&fs, "cfb.summary");
        assert_eq!(summary.len(), 2);
        assert_eq!(summary[0].title, "Document author \"Example Corp\"");
        assert!(
            summary[0]
                .evidence
                .note
                .as_deref()
                .unwrap()
                .contains("manufacturer")
        );
        let m = summary[0].marker.as_ref().unwrap();
        assert_eq!(m.removal, RemovalStrategy::RawBlank { fill: 0 });
        assert_eq!(m.region.len, 24);
        let cleaned = apply(&data, summary[0]);
        let again = scan("setup.msi", &cleaned, "msi");
        assert_eq!(again.len(), 2);
        assert!(again.iter().all(|f| f.marker.is_none()));
        // The same file scanned as plain cfb reads the same.
        assert_eq!(scan("setup.cfb", &data, "cfb").len(), 3);
    }

    #[test]
    fn mini_stream_summary_is_skipped() {
        let mut data = build([0; 16], Some("PowerPoint Document"), &word_summary(), false);
        // Shrink the summary stream below the cutoff: it now claims the mini
        // stream, which is not read.
        let size_at = 1024 + 2 * 128 + 0x78;
        data[size_at..size_at + 8].copy_from_slice(&400u64.to_le_bytes());
        let fs = scan("deck.ppt", &data, "cfb");
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].title, "PowerPoint binary deck");
    }

    #[test]
    fn garbage_and_truncation_are_safe() {
        let data = build([0; 16], Some("WordDocument"), &word_summary(), false);
        for cut in 0..data.len() {
            let fs = scan("memo.doc", &data[..cut], "cfb");
            if cut < 1024 + 128 {
                assert!(fs.is_empty(), "prefix {cut}");
            }
        }
        for seed in 0..32 {
            assert!(scan("g.doc", &garbage(seed, 4096), "cfb").is_empty());
            let mut g = SIG.to_vec();
            g.extend(garbage(seed, 4096));
            assert!(scan("g.doc", &g, "cfb").is_empty());
        }
        for i in (0..data.len()).step_by(3) {
            for v in [0x00, 0x05, 0xFE, 0xFF] {
                let mut m = data.clone();
                m[i] = v;
                let _ = scan("m.doc", &m, "cfb");
            }
        }
        // A FAT that loops back on itself stops at the cap.
        let mut looped = data.clone();
        let fat9 = 512 + 9 * 4;
        looped[fat9..fat9 + 4].copy_from_slice(&2u32.to_le_bytes());
        let _ = scan("loop.doc", &looped, "cfb");
        let mut bad = data.clone();
        bad[0x1C] = 0;
        assert!(scan("bad.doc", &bad, "cfb").is_empty());
    }
}
