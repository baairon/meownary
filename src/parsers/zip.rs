//! ZIP container probes (`zip`, and the zip-based `jar`, `apk`, `ooxml`).
//!
//! The end-of-central-directory record is located in the tail window by a
//! backward scan for `PK\x05\x06` whose comment length is consistent, with the
//! ZIP64 locator followed when the classic fields are saturated. The central
//! directory is then walked through `read_at`, capped at 4 MiB and 65,535
//! entries. Identity labels belong to the identity probe; nothing here
//! relabels a format.

use crate::model::{
    Category, Confidence, ContainerKind, DeceptionKind, Evidence, JunkKind, Marker, Region,
    RemovalStrategy, Severity, TamperKind,
};
use crate::parsers::image::shared::{
    NOTE_CHARS, TITLE_CHARS, excerpt, fetch, finding, is_blank, pw_in_name, quote,
};
use crate::scan::{FileView, Probe, ProbeCtx};
use crate::util::bytes::{slice, u16_le, u32_le, u64_le};
use crate::util::fmt::human_size;

const EOCD_SIG: &[u8] = b"PK\x05\x06";
const CENTRAL_SIG: &[u8] = b"PK\x01\x02";
const LOCAL_SIG: &[u8] = b"PK\x03\x04";
const ZIP64_LOCATOR_SIG: &[u8] = b"PK\x06\x07";
const ZIP64_EOCD_SIG: &[u8] = b"PK\x06\x06";
const EOCD_LEN: u64 = 22;
const CENTRAL_LEN: usize = 46;
/// Most central-directory bytes read in one scan.
const MAX_CD_BYTES: usize = 4 * 1024 * 1024;
/// Most central entries walked.
const MAX_ENTRIES: usize = 65_535;
/// How many leading entries are checked for well-known marker names.
const MARKER_SCAN: usize = 256;
/// Entry names longer than this are kept truncated.
const MAX_NAME: usize = 1024;
/// Most end-record candidates validated per file.
const MAX_CANDIDATES: usize = 16;

/// Entry names that hint at what a zip-based package is for.
const MARKER_NAMES: &[&str] = &[
    "META-INF/MANIFEST.MF",
    "AndroidManifest.xml",
    "classes.dex",
    "[Content_Types].xml",
    "mimetype",
];

/// One central-directory entry.
#[derive(Debug, Clone)]
pub(crate) struct ZipEntry {
    /// Entry name bytes (truncated to 1 KiB).
    pub name: Vec<u8>,
    pub flags: u16,
    pub method: u16,
    pub compressed: u64,
    pub uncompressed: u64,
    /// Absolute offset of the entry's local header.
    pub local_offset: u64,
    /// Absolute offset of the entry's central header.
    pub central_offset: u64,
}

impl ZipEntry {
    pub fn encrypted(&self) -> bool {
        self.flags & 1 != 0
    }
}

/// The parsed archive layout.
#[derive(Debug, Clone)]
pub(crate) struct ZipArchive {
    /// Absolute offset of the archive comment.
    pub comment_offset: u64,
    pub comment_len: u64,
    /// One past the comment: where the archive declares its end.
    pub end: u64,
    /// Absolute offset of the first central header.
    pub cd_offset: u64,
    pub cd_size: u64,
    /// Entry count the end record declares.
    pub declared_entries: u64,
    /// Entries actually walked (capped).
    pub entries: Vec<ZipEntry>,
    pub zip64: bool,
    /// Bytes prepended before the archive (a self-extractor stub), by which
    /// every stored offset is shifted.
    pub shift: u64,
}

impl ZipArchive {
    /// Find an entry by exact name.
    pub fn entry(&self, name: &str) -> Option<&ZipEntry> {
        self.entries.iter().find(|e| e.name == name.as_bytes())
    }
}

/// Parse the archive behind `view`, or `None` when no consistent end record is
/// found in the tail window.
pub(crate) fn parse(view: &dyn FileView) -> Option<ZipArchive> {
    let tail = view.tail();
    let ts = view.tail_start();
    let size = view.size();
    if tail.len() < EOCD_LEN as usize {
        return None;
    }
    // Rank every consistent end record: one that ends exactly at EOF beats one
    // followed by trailing bytes, one that declares entries beats an empty one
    // (a comment can embed a fake empty record), and among equals the record
    // closest to the end wins. Only the winner's central directory is walked.
    let mut best: Option<((bool, bool), ZipArchive)> = None;
    let mut seen = 0usize;
    let mut p = tail.len() - EOCD_LEN as usize;
    loop {
        if slice(tail, p, 4) == Some(EOCD_SIG)
            && let Some(arch) = candidate(view, tail, p, ts + p as u64, size)
        {
            let key = (arch.end == size, arch.declared_entries > 0);
            if best.as_ref().is_none_or(|(k, _)| key > *k) {
                best = Some((key, arch));
            }
            seen += 1;
        }
        if p == 0
            || seen >= MAX_CANDIDATES
            || best.as_ref().is_some_and(|(k, _)| *k == (true, true))
        {
            break;
        }
        p -= 1;
    }
    let (_, mut arch) = best?;
    arch.entries = walk_central(
        view,
        arch.cd_offset,
        arch.cd_size,
        arch.declared_entries,
        arch.shift,
    );
    Some(arch)
}

/// Validate the EOCD candidate at `p` in `tail` (absolute offset `abs`).
fn candidate(
    view: &dyn FileView,
    tail: &[u8],
    p: usize,
    abs: u64,
    size: u64,
) -> Option<ZipArchive> {
    let comment_len = u16_le(tail, p + 20)? as u64;
    let end = abs.checked_add(EOCD_LEN)?.checked_add(comment_len)?;
    if end > size {
        return None;
    }
    let disk = u16_le(tail, p + 4)?;
    let cd_disk = u16_le(tail, p + 6)?;
    let on_disk = u16_le(tail, p + 8)? as u64;
    let mut total = u16_le(tail, p + 10)? as u64;
    let mut cd_size = u32_le(tail, p + 12)? as u64;
    let mut cd_off = u32_le(tail, p + 16)? as u64;
    if disk != cd_disk && disk != 0xFFFF && cd_disk != 0xFFFF {
        return None;
    }
    if on_disk > total {
        return None;
    }

    let mut zip64 = false;
    let mut cd_end = abs;
    if total == 0xFFFF || cd_size == 0xFFFF_FFFF || cd_off == 0xFFFF_FFFF {
        let (rec_abs, t, s, o) = zip64_record(view, abs)?;
        zip64 = true;
        cd_end = rec_abs;
        total = t;
        cd_size = s;
        cd_off = o;
    }

    if cd_size > cd_end {
        return None;
    }
    // The central directory normally sits at its declared offset. When a stub
    // was prepended (self-extractors), it sits immediately before the end
    // records instead; accept that shifted position too.
    let shifted = cd_end - cd_size;
    let cd_abs = if total == 0 {
        if cd_off.checked_add(cd_size)? > cd_end {
            return None;
        }
        cd_off
    } else if cd_off.checked_add(cd_size)? <= cd_end && has_sig(view, cd_off, CENTRAL_SIG) {
        cd_off
    } else if has_sig(view, shifted, CENTRAL_SIG) {
        shifted
    } else {
        return None;
    };
    Some(ZipArchive {
        comment_offset: abs + EOCD_LEN,
        comment_len,
        end,
        cd_offset: cd_abs,
        cd_size,
        declared_entries: total,
        entries: Vec::new(),
        zip64,
        shift: cd_abs.saturating_sub(cd_off),
    })
}

/// Resolve the ZIP64 end record through the locator just before the classic
/// end record at `eocd_abs`. Returns (record offset, entries, cd size, cd offset).
fn zip64_record(view: &dyn FileView, eocd_abs: u64) -> Option<(u64, u64, u64, u64)> {
    let loc_abs = eocd_abs.checked_sub(20)?;
    let loc = fetch(view, loc_abs, 20)?;
    if slice(&loc, 0, 4)? != ZIP64_LOCATOR_SIG {
        return None;
    }
    let declared = u64_le(&loc, 8)?;
    let fallback = loc_abs.checked_sub(56);
    for rec_abs in [Some(declared), fallback].into_iter().flatten() {
        let Some(rec) = fetch(view, rec_abs, 56) else {
            continue;
        };
        if slice(&rec, 0, 4) != Some(ZIP64_EOCD_SIG) || rec_abs >= loc_abs {
            continue;
        }
        let total = u64_le(&rec, 32)?;
        let cd_size = u64_le(&rec, 40)?;
        let cd_off = u64_le(&rec, 48)?;
        return Some((rec_abs, total, cd_size, cd_off));
    }
    None
}

fn has_sig(view: &dyn FileView, off: u64, sig: &[u8]) -> bool {
    fetch(view, off, sig.len()).is_some_and(|b| b == sig)
}

/// Walk the central directory, stopping at the first inconsistent entry.
fn walk_central(
    view: &dyn FileView,
    cd_abs: u64,
    cd_size: u64,
    total: u64,
    shift: u64,
) -> Vec<ZipEntry> {
    let want = (cd_size.min(MAX_CD_BYTES as u64)) as usize;
    let Ok(buf) = view.read_at(cd_abs, want) else {
        return Vec::new();
    };
    let limit = (total.min(MAX_ENTRIES as u64)) as usize;
    let mut entries = Vec::new();
    let mut pos = 0usize;
    while entries.len() < limit {
        let Some(entry) = central_entry(&buf, pos, cd_abs, shift) else {
            break;
        };
        pos = entry.1;
        entries.push(entry.0);
    }
    entries
}

/// Parse one central header at `pos`, returning it and the next position.
fn central_entry(buf: &[u8], pos: usize, cd_abs: u64, shift: u64) -> Option<(ZipEntry, usize)> {
    let fixed = slice(buf, pos, CENTRAL_LEN)?;
    if &fixed[..4] != CENTRAL_SIG {
        return None;
    }
    let flags = u16_le(fixed, 8)?;
    let method = u16_le(fixed, 10)?;
    let mut compressed = u32_le(fixed, 20)? as u64;
    let mut uncompressed = u32_le(fixed, 24)? as u64;
    let name_len = u16_le(fixed, 28)? as usize;
    let extra_len = u16_le(fixed, 30)? as usize;
    let comment_len = u16_le(fixed, 32)? as usize;
    let mut local = u32_le(fixed, 42)? as u64;
    let name = slice(buf, pos + CENTRAL_LEN, name_len)?;
    let extra = slice(buf, pos + CENTRAL_LEN + name_len, extra_len)?;
    let next = pos + CENTRAL_LEN + name_len + extra_len + comment_len;
    if next > buf.len() {
        return None;
    }

    // ZIP64 extended information: present fields appear in a fixed order,
    // only for the classic fields that are saturated.
    if uncompressed == 0xFFFF_FFFF || compressed == 0xFFFF_FFFF || local == 0xFFFF_FFFF {
        let mut i = 0usize;
        while let (Some(id), Some(len)) = (u16_le(extra, i), u16_le(extra, i + 2)) {
            let body = slice(extra, i + 4, len as usize)?;
            if id == 0x0001 {
                let mut k = 0usize;
                if uncompressed == 0xFFFF_FFFF {
                    uncompressed = u64_le(body, k)?;
                    k += 8;
                }
                if compressed == 0xFFFF_FFFF {
                    compressed = u64_le(body, k)?;
                    k += 8;
                }
                if local == 0xFFFF_FFFF {
                    local = u64_le(body, k)?;
                }
                break;
            }
            i += 4 + len as usize;
        }
    }

    Some((
        ZipEntry {
            name: name[..name.len().min(MAX_NAME)].to_vec(),
            flags,
            method,
            compressed,
            uncompressed,
            local_offset: local.saturating_add(shift),
            central_offset: cd_abs + pos as u64,
        },
        next,
    ))
}

/// Absolute offset and length of an entry's stored data, read from its local
/// header. `None` when the local header does not check out.
pub(crate) fn entry_data_span(view: &dyn FileView, entry: &ZipEntry) -> Option<(u64, u64)> {
    let lh = fetch(view, entry.local_offset, 30)?;
    if slice(&lh, 0, 4)? != LOCAL_SIG {
        return None;
    }
    let n = u16_le(&lh, 26)? as u64;
    let m = u16_le(&lh, 28)? as u64;
    let start = entry.local_offset.checked_add(30 + n + m)?;
    let end = start.checked_add(entry.compressed)?;
    (end <= view.size()).then_some((start, entry.compressed))
}

struct ZipProbe;

impl Probe for ZipProbe {
    fn id(&self) -> &'static str {
        "zip"
    }

    fn formats(&self) -> &'static [&'static str] {
        &["zip", "jar", "apk", "ooxml"]
    }

    fn run(&self, ctx: &ProbeCtx, out: &mut Vec<crate::model::Finding>) {
        let view = ctx.view;
        let Some(z) = parse(view) else {
            return;
        };
        comment_finding(view, ctx.format, &z, out);
        trailing_finding(view, &z, out);
        let encrypted: Vec<&ZipEntry> = z.entries.iter().filter(|e| e.encrypted()).collect();
        if let (Some(first), Some(name)) = (encrypted.first(), pw_in_name(view)) {
            out.push(finding(
                "zip.encrypted",
                Category::Deception(DeceptionKind::PwInFilename),
                Confidence::Strong,
                Severity::Warn,
                "Encrypted ZIP with a password in its file name",
                Evidence::at(first.central_offset)
                    .with_bytes(excerpt(&first.name))
                    .with_note(format!(
                        "{} of {} entries are encrypted and the file name \"{}\" appears to \
                         carry the password, which keeps scanners out of the contents",
                        encrypted.len(),
                        z.entries.len(),
                        quote(name.as_bytes(), NOTE_CHARS)
                    )),
                None,
            ));
        }
        info_finding(&z, encrypted.len(), out);
    }
}

fn comment_finding(
    view: &dyn FileView,
    format: Option<&str>,
    z: &ZipArchive,
    out: &mut Vec<crate::model::Finding>,
) {
    if z.comment_len == 0 {
        return;
    }
    let Some(comment) = fetch(view, z.comment_offset, z.comment_len as usize) else {
        return;
    };
    if is_blank(&comment) {
        return;
    }
    let region = Region::new(z.comment_offset, z.comment_len);
    let marker = if z.end == view.size() {
        Marker {
            region,
            removal: RemovalStrategy::StructuralRemove,
            container: ContainerKind::ZipComment,
            reversible: true,
        }
    } else {
        Marker {
            region,
            removal: RemovalStrategy::RawBlank { fill: b' ' },
            container: ContainerKind::ZipComment,
            reversible: true,
        }
    };
    let mut note = format!(
        "{} comment: \"{}\"",
        human_size(z.comment_len),
        quote(&comment, NOTE_CHARS)
    );
    if format == Some("apk") || apk_signing_block(view, z) {
        note.push_str("; an APK v2+ signature covers this record, so removal invalidates it");
    }
    out.push(finding(
        "zip.comment",
        Category::Junk(JunkKind::ArchiveComment),
        Confidence::Strong,
        Severity::Notice,
        format!("ZIP comment \"{}\"", quote(&comment, TITLE_CHARS)),
        Evidence::at(z.comment_offset)
            .with_bytes(excerpt(&comment))
            .with_note(note),
        Some(marker),
    ));
}

/// Whether an APK signing block sits right before the central directory.
fn apk_signing_block(view: &dyn FileView, z: &ZipArchive) -> bool {
    z.cd_offset >= 16 && has_sig(view, z.cd_offset - 16, b"APK Sig Block 42")
}

fn trailing_finding(view: &dyn FileView, z: &ZipArchive, out: &mut Vec<crate::model::Finding>) {
    let size = view.size();
    if z.end >= size {
        return;
    }
    let extra = size - z.end;
    let head = view.read_at(z.end, 64).unwrap_or_default();
    out.push(finding(
        "zip.trailing_data",
        Category::Tamper(TamperKind::AppendedData),
        Confidence::Strong,
        Severity::Notice,
        format!("{} appended after the ZIP end record", human_size(extra)),
        Evidence::at(z.end)
            .with_bytes(excerpt(&head))
            .with_note(format!(
                "the archive ends at offset {} but the file runs {} bytes further",
                z.end, extra
            )),
        Some(Marker::truncate_at(z.end, ContainerKind::Generic)),
    ));
}

fn info_finding(z: &ZipArchive, encrypted: usize, out: &mut Vec<crate::model::Finding>) {
    let mut seen: Vec<&str> = Vec::new();
    for e in z.entries.iter().take(MARKER_SCAN) {
        for m in MARKER_NAMES {
            if e.name == m.as_bytes() && !seen.contains(m) {
                seen.push(m);
            }
        }
    }
    let mut note = format!("{} entries", z.declared_entries);
    if (z.entries.len() as u64) < z.declared_entries {
        note.push_str(&format!(" ({} walked)", z.entries.len()));
    }
    if encrypted > 0 {
        note.push_str(&format!(", {encrypted} encrypted"));
    }
    if z.zip64 {
        note.push_str(", ZIP64");
    }
    if !seen.is_empty() {
        note.push_str(&format!("; contains {}", seen.join(", ")));
    }
    out.push(finding(
        "zip.info",
        Category::Brand(crate::model::BrandKind::Toolchain),
        Confidence::Moderate,
        Severity::Info,
        format!("ZIP container with {} entries", z.declared_entries),
        Evidence::at(z.cd_offset).with_note(note),
        None,
    ));
}

/// Probes contributed by this module.
pub fn probes() -> Vec<Box<dyn Probe>> {
    vec![Box::new(ZipProbe)]
}

/// Structural removal of a ZIP archive comment ([`ContainerKind::ZipComment`]).
///
/// `region` must be exactly the comment bytes: it starts right after a 22-byte
/// end-of-central-directory record whose comment-length field equals
/// `region.len`, and so it ends where that comment ends (normally EOF). The
/// result has the comment-length field set to 0 and the comment bytes dropped;
/// any bytes after the comment are kept. Nothing before the end record moves,
/// so every central-directory offset stays valid. Returns `None` when the
/// layout differs.
pub fn structural_remove(data: &[u8], region: Region) -> Option<Vec<u8>> {
    let off = usize::try_from(region.offset).ok()?;
    let len = usize::try_from(region.len).ok()?;
    if len == 0 || len > 0xFFFF {
        return None;
    }
    let eocd = off.checked_sub(EOCD_LEN as usize)?;
    if slice(data, eocd, 4)? != EOCD_SIG {
        return None;
    }
    if u16_le(data, eocd + 20)? as usize != len {
        return None;
    }
    let end = off.checked_add(len)?;
    if end > data.len() {
        return None;
    }
    let cd_size = u32_le(data, eocd + 12)?;
    let cd_off = u32_le(data, eocd + 16)?;
    if cd_size != u32::MAX && cd_off != u32::MAX && cd_off as u64 + cd_size as u64 > eocd as u64 {
        return None;
    }
    let mut out = Vec::with_capacity(data.len() - len);
    out.extend_from_slice(&data[..eocd + 20]);
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&data[end..]);
    Some(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::model::{DeceptionKind, Finding};
    use crate::parsers::image::shared::crc32;
    use crate::parsers::image::shared::testkit::{apply, garbage, run, with_id};
    use crate::scan::MemView;

    /// One entry for [`build_zip`]: name, stored data, general-purpose flags.
    pub struct Ent<'a> {
        pub name: &'a str,
        pub data: &'a [u8],
        pub flags: u16,
    }

    /// Build a stored (method 0) ZIP with an optional comment and trailer.
    pub fn build_zip(entries: &[Ent], comment: &[u8], trailing: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for e in entries {
            let off = out.len() as u32;
            let crc = crc32(e.data);
            let n = e.name.len() as u16;
            let len = e.data.len() as u32;
            out.extend_from_slice(LOCAL_SIG);
            out.extend_from_slice(&20u16.to_le_bytes());
            out.extend_from_slice(&e.flags.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&[0, 0, 0x21, 0]);
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&n.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(e.name.as_bytes());
            out.extend_from_slice(e.data);

            central.extend_from_slice(CENTRAL_SIG);
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&e.flags.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&[0, 0, 0x21, 0]);
            central.extend_from_slice(&crc.to_le_bytes());
            central.extend_from_slice(&len.to_le_bytes());
            central.extend_from_slice(&len.to_le_bytes());
            central.extend_from_slice(&n.to_le_bytes());
            central.extend_from_slice(&[0; 12]);
            central.extend_from_slice(&off.to_le_bytes());
            central.extend_from_slice(e.name.as_bytes());
        }
        let cd_off = out.len() as u32;
        out.extend_from_slice(&central);
        out.extend_from_slice(EOCD_SIG);
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(central.len() as u32).to_le_bytes());
        out.extend_from_slice(&cd_off.to_le_bytes());
        out.extend_from_slice(&(comment.len() as u16).to_le_bytes());
        out.extend_from_slice(comment);
        out.extend_from_slice(trailing);
        out
    }

    fn scan(name: &str, data: &[u8]) -> Vec<Finding> {
        run(probes(), name, data, "zip")
    }

    fn sample() -> Vec<Ent<'static>> {
        vec![
            Ent {
                name: "mimetype",
                data: b"application/epub+zip",
                flags: 0,
            },
            Ent {
                name: "a.txt",
                data: b"hello",
                flags: 0,
            },
        ]
    }

    #[test]
    fn comment_is_found_and_structurally_removed() {
        let data = build_zip(&sample(), b"Downloaded from example.test", b"");
        let fs = scan("a.zip", &data);
        let c = with_id(&fs, "zip.comment");
        assert_eq!(c.len(), 1);
        let c = c[0];
        assert_eq!(c.confidence, Confidence::Strong);
        assert_eq!(c.severity, Severity::Notice);
        let m = c.marker.as_ref().unwrap();
        assert_eq!(m.removal, RemovalStrategy::StructuralRemove);
        assert_eq!(m.container, ContainerKind::ZipComment);
        assert_eq!(m.region.end(), data.len() as u64);
        assert!(c.evidence.note.as_deref().unwrap().contains("example.test"));
        assert!(with_id(&fs, "zip.trailing_data").is_empty());

        let cleaned = apply(&data, c);
        assert_eq!(cleaned.len(), data.len() - 28);
        let z = parse(&MemView::new("a.zip", cleaned.clone())).unwrap();
        assert_eq!(z.comment_len, 0);
        assert_eq!(z.entries.len(), 2);
        assert_eq!(z.end, cleaned.len() as u64);
        let again = scan("a.zip", &cleaned);
        assert!(with_id(&again, "zip.comment").is_empty());
        assert_eq!(with_id(&again, "zip.info").len(), 1);
    }

    #[test]
    fn trailing_data_truncates_and_comment_blanks() {
        let data = build_zip(&sample(), b"hi there", b"APPENDED-PAYLOAD");
        let fs = scan("a.zip", &data);
        let t = with_id(&fs, "zip.trailing_data");
        assert_eq!(t.len(), 1);
        let t = t[0];
        assert_eq!(t.category, Category::Tamper(TamperKind::AppendedData));
        let end = (data.len() - 16) as u64;
        assert_eq!(t.evidence.offset, end);
        assert_eq!(
            t.marker,
            Some(Marker::truncate_at(end, ContainerKind::Generic))
        );

        // The comment is not at EOF, so it gets a length-preserving blank.
        let c = with_id(&fs, "zip.comment")[0];
        assert_eq!(
            c.marker.as_ref().unwrap().removal,
            RemovalStrategy::RawBlank { fill: b' ' }
        );

        let blanked = apply(&data, c);
        let again = scan("a.zip", &blanked);
        assert!(with_id(&again, "zip.comment").is_empty());
        assert_eq!(with_id(&again, "zip.trailing_data").len(), 1);

        let cut = apply(&data, t);
        let again = scan("a.zip", &cut);
        assert!(with_id(&again, "zip.trailing_data").is_empty());
        let z = parse(&MemView::new("a.zip", cut)).unwrap();
        assert_eq!(z.entries.len(), 2);
    }

    #[test]
    fn info_names_markers_and_counts() {
        let ents = vec![
            Ent {
                name: "META-INF/MANIFEST.MF",
                data: b"Manifest-Version: 1.0\r\n",
                flags: 0,
            },
            Ent {
                name: "classes.dex",
                data: b"dex\n035\0",
                flags: 0,
            },
        ];
        let data = build_zip(&ents, b"", b"");
        let fs = scan("app.zip", &data);
        assert_eq!(fs.len(), 1);
        let i = &fs[0];
        assert_eq!(i.signature_id, "zip.info");
        let note = i.evidence.note.as_deref().unwrap();
        assert!(note.starts_with("2 entries"));
        assert!(note.contains("META-INF/MANIFEST.MF") && note.contains("classes.dex"));
        assert!(i.marker.is_none());
    }

    #[test]
    fn encrypted_archive_password_in_name() {
        let ents = vec![Ent {
            name: "setup.exe",
            data: b"\x01\x02\x03\x04encrypted",
            flags: 1,
        }];
        let data = build_zip(&ents, b"", b"");
        let fs = scan("invoice_PW_1234.zip", &data);
        let d = with_id(&fs, "zip.encrypted");
        assert_eq!(d.len(), 1);
        assert_eq!(
            d[0].category,
            Category::Deception(DeceptionKind::PwInFilename)
        );
        assert_eq!(d[0].severity, Severity::Warn);
        assert_eq!(d[0].confidence, Confidence::Strong);

        let fs = scan("invoice.zip", &data);
        assert!(with_id(&fs, "zip.encrypted").is_empty());
        let note = with_id(&fs, "zip.info")[0].evidence.note.clone().unwrap();
        assert!(note.contains("1 encrypted"));
    }

    #[test]
    fn zip64_end_record_is_followed() {
        let base = build_zip(&sample(), b"", b"");
        // Rebuild the end records as ZIP64: saturated classic fields, a ZIP64
        // end record and its locator.
        let eocd = base.len() - 22;
        let cd_size = u32::from_le_bytes(base[eocd + 12..eocd + 16].try_into().unwrap()) as u64;
        let cd_off = u32::from_le_bytes(base[eocd + 16..eocd + 20].try_into().unwrap()) as u64;
        let mut data = base[..eocd].to_vec();
        let rec = data.len() as u64;
        data.extend_from_slice(ZIP64_EOCD_SIG);
        data.extend_from_slice(&44u64.to_le_bytes());
        data.extend_from_slice(&[45, 0, 45, 0]);
        data.extend_from_slice(&[0; 8]);
        data.extend_from_slice(&2u64.to_le_bytes());
        data.extend_from_slice(&2u64.to_le_bytes());
        data.extend_from_slice(&cd_size.to_le_bytes());
        data.extend_from_slice(&cd_off.to_le_bytes());
        data.extend_from_slice(ZIP64_LOCATOR_SIG);
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&rec.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(EOCD_SIG);
        data.extend_from_slice(&[0xFF; 4]);
        data.extend_from_slice(&[0xFF; 4]);
        data.extend_from_slice(&[0xFF; 8]);
        data.extend_from_slice(&3u16.to_le_bytes());
        data.extend_from_slice(b"z64");
        let z = parse(&MemView::new("a.zip", data.clone())).unwrap();
        assert!(z.zip64);
        assert_eq!(z.entries.len(), 2);
        assert_eq!(z.cd_offset, cd_off);
        let fs = scan("a.zip", &data);
        let c = with_id(&fs, "zip.comment")[0];
        let cleaned = apply(&data, c);
        let z = parse(&MemView::new("a.zip", cleaned)).unwrap();
        assert!(z.zip64 && z.comment_len == 0 && z.entries.len() == 2);
    }

    #[test]
    fn remover_refuses_wrong_regions() {
        let data = build_zip(&sample(), b"comment", b"");
        let n = data.len() as u64;
        assert!(structural_remove(&data, Region::new(n - 7, 7)).is_some());
        assert!(structural_remove(&data, Region::new(n - 6, 6)).is_none());
        assert!(structural_remove(&data, Region::new(n - 7, 6)).is_none());
        assert!(structural_remove(&data, Region::new(0, 7)).is_none());
        assert!(structural_remove(&data, Region::new(n, 0)).is_none());
        assert!(structural_remove(b"PK", Region::new(1, 1)).is_none());
    }

    #[test]
    fn comment_holding_a_fake_end_record_is_not_misread() {
        let mut fake = EOCD_SIG.to_vec();
        fake.extend_from_slice(&[0; 18]);
        let data = build_zip(&sample(), &fake, b"");
        let z = parse(&MemView::new("a.zip", data.clone())).unwrap();
        assert_eq!(z.entries.len(), 2);
        assert_eq!(z.comment_len, 22);
    }

    #[test]
    fn garbage_and_truncation_are_quiet() {
        let data = build_zip(&sample(), b"a comment", b"");
        for cut in 0..data.len() {
            let fs = scan("a.zip", &data[..cut]);
            assert!(fs.is_empty(), "prefix {cut} produced {fs:?}");
        }
        for seed in 0..32 {
            let g = garbage(seed, 4096);
            assert!(scan("g.zip", &g).is_empty());
        }
        let mut g = garbage(7, 300);
        g.extend_from_slice(EOCD_SIG);
        g.extend_from_slice(&[0xFF; 18]);
        assert!(scan("g.zip", &g).is_empty());
    }
}
