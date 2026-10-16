//! ISO base media (MP4, MOV, M4A, HEIC, AVIF): the `ftyp` brands, the
//! iTunes-style `udta/meta/ilst` tags (encoder and text atoms), XMP `uuid`
//! boxes, and C2PA content credentials (the ContentProvenanceBox `uuid` box
//! and `jumb`/`c2pa` boxes). A top-level `meta` box is handed to [`heif`] for
//! the EXIF and XMP items of HEIC and AVIF images.
//!
//! Top-level boxes are walked with positioned reads, so a `moov` at the end
//! of a large file is still found; at most 8 MiB of `moov` is read.
//!
//! Dropping a box or item never moves a byte: the box is renamed `free` and
//! zero-filled, an item is retyped `free` and its data zero-filled, so every
//! `stco`, `co64` and `iloc` offset stays valid (see [`remove`]).

use super::{Draft, evidence, fourcc, heif, is_blank, push, read, show, text_marker};
use crate::model::{
    BrandKind, Category, Confidence, ContainerKind, Finding, JunkKind, Marker, Region,
    RemovalStrategy, Severity,
};
use crate::parsers::provenance::{XMP_BMFF_UUID, is_c2pa_box_name, is_c2pa_uuid_payload};
use crate::scan::FileView;
use crate::util::bytes::{slice, u32_be, u64_be};

const MAX_BOXES: usize = 4096;
const MAX_DEPTH: usize = 6;
const MAX_MOOV: usize = 8 * 1024 * 1024;

/// The XMP box usertype, BE7ACFCB-97A9-42E8-9C71-999491E3AFAC.
const XMP_UUID: [u8; 16] = XMP_BMFF_UUID;

/// iTunes text atoms reported as metadata, with a readable name.
const TEXT_ATOMS: &[(&[u8; 4], &str)] = &[
    (b"\xa9nam", "title"),
    (b"\xa9ART", "artist"),
    (b"\xa9alb", "album"),
    (b"\xa9day", "date"),
    (b"\xa9cmt", "comment"),
    (b"\xa9gen", "genre"),
    (b"\xa9wrt", "composer"),
    (b"aART", "album artist"),
    (b"desc", "description"),
];

/// A parsed box header. Offsets are absolute.
#[derive(Debug, Clone, Copy)]
pub(super) struct BoxHdr {
    pub kind: [u8; 4],
    pub start: u64,
    pub header: u64,
    pub size: u64,
    pub uuid: Option<[u8; 16]>,
}

impl BoxHdr {
    pub fn payload(&self) -> u64 {
        self.start + self.header
    }

    pub fn end(&self) -> u64 {
        self.start + self.size
    }

    /// The box as a removable region.
    pub fn region(&self) -> Region {
        Region::new(self.start, self.size)
    }
}

/// Parse a box header from `bytes`, which begin at absolute `start`; `avail`
/// is how many bytes the enclosing container has left from `start`. A box
/// that claims more than `avail` is clamped to it.
pub(super) fn parse_header(bytes: &[u8], start: u64, avail: u64) -> Option<BoxHdr> {
    let size32 = u32_be(bytes, 0)?;
    let kind: [u8; 4] = slice(bytes, 4, 4)?.try_into().ok()?;
    let (size, mut header) = match size32 {
        0 => (avail, 8),
        1 => (u64_be(bytes, 8)?, 16),
        n => (u64::from(n), 8),
    };
    let mut uuid = None;
    if &kind == b"uuid" {
        uuid = Some(slice(bytes, header as usize, 16)?.try_into().ok()?);
        header += 16;
    }
    if size < header || avail < header {
        return None;
    }
    Some(BoxHdr {
        kind,
        start,
        header,
        size: size.min(avail),
        uuid,
    })
}

pub(super) fn run(view: &dyn FileView, out: &mut Vec<Finding>) {
    let size = view.size();
    let mut off = 0u64;
    let mut count = 0usize;
    while off.saturating_add(8) <= size && count < MAX_BOXES {
        count += 1;
        let Some(bytes) = read(view, off, 40) else {
            return;
        };
        let Some(b) = parse_header(&bytes, off, size - off) else {
            return;
        };
        match &b.kind {
            b"ftyp" => brand(view, &b, out),
            b"moov" => moov(view, &b, &mut count, out),
            b"meta" => heif::meta(view, &b, out),
            b"uuid" if b.uuid == Some(XMP_UUID) => {
                let len = (b.size - b.header).min(64) as usize;
                let prefix = read(view, b.payload(), len).unwrap_or_default();
                xmp(&b, &prefix, out);
            }
            kind if is_c2pa_box(kind, bytes.get(b.header as usize - uuid_len(&b)..)) => {
                let len = (b.size - b.header).min(64) as usize;
                let prefix = read(view, b.payload(), len).unwrap_or_default();
                c2pa(&b, &prefix, out);
            }
            _ => {}
        }
        off = b.end();
    }
}

/// Structural removal for [`ContainerKind::IsoBox`]: the file stays the same
/// size.
///
/// * `region` is one whole box that is a C2PA container (`jumb`, `c2pa`, or a
///   `uuid` box with the ContentProvenanceBox user type) or an XMP `uuid`
///   box: the box is renamed `free` and everything after its header is
///   zero-filled. A box of any other kind is refused.
/// * `region` is the data of one EXIF or XMP item of a `meta` box (HEIC,
///   AVIF): see [`heif::remove_item`].
///
/// `None` when the region matches neither, or the file has no `ftyp` box.
pub(super) fn remove(data: &[u8], region: Region) -> Option<Vec<u8>> {
    if data.get(4..8)? != b"ftyp" {
        return None;
    }
    remove_box(data, region).or_else(|| heif::remove_item(data, region))
}

fn remove_box(data: &[u8], region: Region) -> Option<Vec<u8>> {
    let start = usize::try_from(region.offset).ok()?;
    let end = start.checked_add(usize::try_from(region.len).ok()?)?;
    let rest = data.get(start..)?;
    let b = parse_header(rest, start as u64, rest.len() as u64)?;
    if b.size != region.len || end > data.len() {
        return None;
    }
    let pre = b.header as usize - uuid_len(&b);
    let known = b.uuid == Some(XMP_UUID) || is_c2pa_box(&b.kind, rest.get(pre..));
    if !known {
        return None;
    }
    let mut out = data.to_vec();
    out.get_mut(start + 4..start + 8)?.copy_from_slice(b"free");
    out.get_mut(start + pre..end)?.fill(0);
    Some(out)
}

fn brand(view: &dyn FileView, b: &BoxHdr, out: &mut Vec<Finding>) {
    let len = (b.size - b.header).min(256) as usize;
    let Some(p) = read(view, b.payload(), len) else {
        return;
    };
    let Some(major) = slice(&p, 0, 4) else {
        return;
    };
    let minor = u32_be(&p, 4).unwrap_or(0);
    let compat: Vec<String> = p
        .get(8..)
        .unwrap_or_default()
        .as_chunks::<4>()
        .0
        .iter()
        .take(16)
        .map(|c| fourcc(c))
        .collect();
    let major_s = fourcc(major);
    let mut note = format!("major brand {major_s} (minor version {minor})");
    if !compat.is_empty() {
        note.push_str(&format!(", compatible: {}", compat.join(" ")));
    }
    push(
        out,
        Draft {
            category: Category::Brand(BrandKind::MediaEncoder),
            confidence: Confidence::Moderate,
            severity: Severity::Info,
            id: "mp4.brand",
            title: format!("MP4 brand {}", major_s.trim_end()),
            evidence: evidence(b.payload(), major, note),
            marker: None,
        },
    );
}

/// The bytes of a `uuid` box's user type, which `parse_header` counts in the
/// header; zero for every other box.
pub(super) fn uuid_len(b: &BoxHdr) -> usize {
    if b.uuid.is_some() { 16 } else { 0 }
}

/// Whether the box of `kind`, whose bytes after the fourcc are `after`, is a
/// C2PA container: a `jumb` or `c2pa` box by name, or a `uuid` box with the
/// ContentProvenanceBox user type (directly or after a version and flags
/// prefix).
pub(super) fn is_c2pa_box(kind: &[u8; 4], after: Option<&[u8]>) -> bool {
    is_c2pa_box_name(kind) || (kind == b"uuid" && after.is_some_and(is_c2pa_uuid_payload))
}

/// A marker that turns the whole box into free space of the same size.
pub(super) fn box_marker(b: &BoxHdr) -> Marker {
    Marker {
        region: b.region(),
        removal: RemovalStrategy::StructuralRemove,
        container: ContainerKind::IsoBox,
        reversible: true,
    }
}

pub(super) fn xmp(b: &BoxHdr, prefix: &[u8], out: &mut Vec<Finding>) {
    let len = b.size - b.header;
    if len == 0 || is_blank(prefix) {
        return;
    }
    push(
        out,
        Draft {
            category: Category::Junk(JunkKind::Xmp),
            confidence: Confidence::Strong,
            severity: Severity::Notice,
            id: "mp4.xmp",
            title: format!("XMP metadata box ({len} bytes)"),
            evidence: evidence(
                b.payload(),
                prefix,
                "uuid box BE7ACFCB-97A9-42E8-9C71-999491E3AFAC holds an XMP packet; scrubbing turns the box into free space of the same size",
            ),
            marker: Some(box_marker(b)),
        },
    );
}

pub(super) fn c2pa(b: &BoxHdr, prefix: &[u8], out: &mut Vec<Finding>) {
    let name = fourcc(&b.kind);
    push(
        out,
        Draft {
            category: Category::Junk(JunkKind::Provenance),
            confidence: Confidence::Strong,
            severity: Severity::Notice,
            id: "mp4.c2pa",
            title: format!("C2PA content credentials ({name} box, {} bytes)", b.size),
            evidence: evidence(
                b.payload(),
                prefix,
                format!(
                    "{name} box holding a C2PA manifest; scrubbing turns the box into free space of the same size"
                ),
            ),
            marker: Some(box_marker(b)),
        },
    );
}

fn moov(view: &dyn FileView, b: &BoxHdr, count: &mut usize, out: &mut Vec<Finding>) {
    let want = usize::try_from(b.size).unwrap_or(usize::MAX).min(MAX_MOOV);
    let Some(buf) = read(view, b.start, want) else {
        return;
    };
    let mut seen: Vec<[u8; 4]> = Vec::new();
    let header = b.header as usize;
    walk(&buf, b.start, header, buf.len(), 1, count, &mut seen, out);
}

/// Walk the child boxes of `buf[start..end]` (absolute base `base`).
#[allow(clippy::too_many_arguments)]
fn walk(
    buf: &[u8],
    base: u64,
    start: usize,
    end: usize,
    depth: usize,
    count: &mut usize,
    seen: &mut Vec<[u8; 4]>,
    out: &mut Vec<Finding>,
) {
    let mut off = start;
    while off + 8 <= end && *count < MAX_BOXES {
        *count += 1;
        let Some(bytes) = buf.get(off..end) else {
            return;
        };
        let Some(b) = parse_header(bytes, base + off as u64, (end - off) as u64) else {
            return;
        };
        let pay = off + b.header as usize;
        let bend = off + b.size as usize;
        match &b.kind {
            b"moov" | b"trak" | b"udta" | b"mdia" | b"minf" if depth < MAX_DEPTH => {
                walk(buf, base, pay, bend, depth + 1, count, seen, out);
            }
            b"meta" if depth < MAX_DEPTH => {
                // ISO meta is a full box (4 bytes of version and flags);
                // QuickTime meta is not, and starts straight with hdlr.
                let first = if slice(buf, pay + 4, 4) == Some(b"hdlr") {
                    pay
                } else {
                    pay + 4
                };
                walk(buf, base, first, bend, depth + 1, count, seen, out);
            }
            b"ilst" => ilst(buf, base, pay, bend, count, seen, out),
            b"uuid" if b.uuid == Some(XMP_UUID) => {
                let prefix = buf.get(pay..bend.min(pay + 64)).unwrap_or_default();
                xmp(&b, prefix, out);
            }
            _ => {}
        }
        if bend <= off {
            return;
        }
        off = bend;
    }
}

/// The `ilst` item list: each child is an atom whose first `data` box holds
/// the value after an 8-byte type and locale prefix.
fn ilst(
    buf: &[u8],
    base: u64,
    start: usize,
    end: usize,
    count: &mut usize,
    seen: &mut Vec<[u8; 4]>,
    out: &mut Vec<Finding>,
) {
    let mut off = start;
    while off + 8 <= end && *count < MAX_BOXES {
        *count += 1;
        let Some(item) = buf
            .get(off..end)
            .and_then(|b| parse_header(b, 0, (end - off) as u64))
        else {
            return;
        };
        let item_end = off + item.size as usize;
        let dstart = off + item.header as usize;
        if let Some(data) = buf
            .get(dstart..item_end)
            .and_then(|b| parse_header(b, 0, (item_end - dstart) as u64))
            && &data.kind == b"data"
        {
            let vstart = dstart + data.header as usize + 8;
            let vend = dstart + data.size as usize;
            let well_known = u32_be(buf, dstart + data.header as usize).unwrap_or(0) & 0x00ff_ffff;
            if vend > vstart
                && well_known == 1
                && let Some(value) = buf.get(vstart..vend)
            {
                text_atom(&item.kind, base + vstart as u64, value, seen, out);
            }
        }
        if item_end <= off {
            return;
        }
        off = item_end;
    }
}

fn text_atom(
    kind: &[u8; 4],
    offset: u64,
    value: &[u8],
    seen: &mut Vec<[u8; 4]>,
    out: &mut Vec<Finding>,
) {
    if is_blank(value) || seen.contains(kind) {
        return;
    }
    let len = value.len() as u64;
    let atom = fourcc(kind);
    if kind == b"\xa9too" {
        seen.push(*kind);
        let v = show(value, 60);
        push(
            out,
            Draft {
                category: Category::Brand(BrandKind::MediaEncoder),
                confidence: Confidence::Strong,
                severity: Severity::Info,
                id: "mp4.encoder",
                title: format!("MP4 encoder {v}"),
                evidence: evidence(offset, value, format!("udta/meta/ilst {atom} = \"{v}\"")),
                marker: text_marker(offset, len, ContainerKind::IsoBox),
            },
        );
        return;
    }
    let Some((_, name)) = TEXT_ATOMS.iter().find(|(k, _)| *k == kind) else {
        return;
    };
    seen.push(*kind);
    let v = show(value, 40);
    push(
        out,
        Draft {
            category: Category::Junk(JunkKind::Comment),
            confidence: Confidence::Moderate,
            severity: Severity::Notice,
            id: "mp4.metadata",
            title: format!("MP4 {name} tag"),
            evidence: evidence(offset, value, format!("ilst {atom} ({name}) = \"{v}\"")),
            marker: text_marker(offset, len, ContainerKind::IsoBox),
        },
    );
}

#[cfg(test)]
pub(crate) mod tests_support {
    /// A box of `kind` around `payload`.
    pub fn bx(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut b = ((payload.len() + 8) as u32).to_be_bytes().to_vec();
        b.extend_from_slice(kind);
        b.extend_from_slice(payload);
        b
    }

    /// An ilst item holding one UTF-8 `data` box.
    pub fn item(kind: &[u8; 4], value: &[u8]) -> Vec<u8> {
        let mut data = vec![0, 0, 0, 1, 0, 0, 0, 0];
        data.extend_from_slice(value);
        bx(kind, &bx(b"data", &data))
    }

    pub fn ftyp() -> Vec<u8> {
        bx(b"ftyp", b"isom\0\0\x02\0isomiso2avc1mp41")
    }

    /// moov/udta/meta(full box)/ilst with the given items.
    pub fn moov(items: &[Vec<u8>]) -> Vec<u8> {
        let ilst = bx(b"ilst", &items.concat());
        let mut meta = vec![0, 0, 0, 0];
        meta.extend(bx(b"hdlr", &[0u8; 25]));
        meta.extend(ilst);
        let udta = bx(b"udta", &bx(b"meta", &meta));
        bx(b"moov", &[bx(b"mvhd", &[0u8; 100]), udta].concat())
    }

    pub fn xmp_box(packet: &[u8]) -> Vec<u8> {
        let mut p = super::XMP_UUID.to_vec();
        p.extend_from_slice(packet);
        bx(b"uuid", &p)
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::{apply, find, format_of, fuzz, ids, run};
    use super::tests_support::{bx, ftyp, item, moov, xmp_box};
    use super::*;
    use crate::model::RemovalStrategy;

    fn movie() -> Vec<u8> {
        [
            ftyp(),
            xmp_box(b"<?xpacket begin=\"\"?><x:xmpmeta/>"),
            bx(b"mdat", &[7u8; 2000]),
            moov(&[
                item(b"\xa9too", b"Lavf60.16.100"),
                item(b"\xa9nam", b"Holiday"),
                item(b"\xa9ART", b"Someone"),
                item(b"\xa9nam", b"Second title"),
                item(b"\xa9day", b"2024"),
                item(b"\xa9cmt", b"note"),
                item(b"covr", &[1, 2, 3]),
            ]),
        ]
        .concat()
    }

    #[test]
    fn brand_encoder_metadata_xmp() {
        let data = movie();
        let f = run("a.mp4", "mp4", &data);
        assert_eq!(
            ids(&f),
            [
                "mp4.brand",
                "mp4.xmp",
                "mp4.encoder",
                "mp4.metadata",
                "mp4.metadata",
                "mp4.metadata",
                "mp4.metadata"
            ]
        );
        let b = find(&f, "mp4.brand");
        assert_eq!(b.confidence, Confidence::Moderate);
        assert_eq!(b.severity, Severity::Info);
        assert!(b.marker.is_none());
        assert_eq!(b.evidence.offset, 8);
        assert!(
            b.evidence
                .note
                .as_deref()
                .unwrap()
                .contains("compatible: isom iso2 avc1 mp41")
        );

        let e = find(&f, "mp4.encoder");
        assert_eq!(e.confidence, Confidence::Strong);
        assert_eq!(e.category, Category::Brand(BrandKind::MediaEncoder));
        let m = e.marker.as_ref().unwrap();
        assert_eq!(m.removal, RemovalStrategy::RawBlank { fill: 0x20 });
        assert_eq!(m.container, ContainerKind::IsoBox);
        let at = m.region.offset as usize;
        assert_eq!(&data[at..at + m.region.len as usize], b"Lavf60.16.100");

        let x = find(&f, "mp4.xmp");
        assert_eq!(x.category, Category::Junk(JunkKind::Xmp));
        assert_eq!(x.confidence, Confidence::Strong);
        let xm = x.marker.as_ref().unwrap();
        assert_eq!(xm.removal, RemovalStrategy::StructuralRemove);
        assert_eq!(xm.container, ContainerKind::IsoBox);
        let at = xm.region.offset as usize;
        assert_eq!(&data[at + 4..at + 8], b"uuid");
        assert_eq!(xm.region.len, 56);

        let titles: Vec<&str> = f
            .iter()
            .filter(|f| f.signature_id == "mp4.metadata")
            .map(|f| f.title.as_str())
            .collect();
        assert_eq!(
            titles,
            [
                "MP4 title tag",
                "MP4 artist tag",
                "MP4 date tag",
                "MP4 comment tag"
            ]
        );
    }

    #[test]
    fn every_marker_scrubs_and_the_file_still_parses() {
        let mut data = movie();
        let first = run("a.mp4", "mp4", &data);
        let markers: Vec<_> = first.iter().filter_map(|f| f.marker.clone()).collect();
        assert_eq!(markers.len(), 6);
        for m in &markers {
            apply(&mut data, m);
        }
        let after = run("a.mp4", "mp4", &data);
        // The second title atom surfaces once the first is blank; scrub it too.
        assert_eq!(ids(&after), ["mp4.brand", "mp4.metadata"]);
        apply(&mut data, after[1].marker.as_ref().unwrap());
        let after = run("a.mp4", "mp4", &data);
        assert_eq!(ids(&after), ["mp4.brand"]);
        assert_eq!(format_of("a.mp4", &data), Some("mp4"));
        assert_eq!(data.len(), movie().len());
    }

    fn c2pa_box(extra: &[u8]) -> Vec<u8> {
        let mut p = C2PA_BMFF_UUID_TEST.to_vec();
        p.extend_from_slice(extra);
        bx(b"uuid", &p)
    }

    const C2PA_BMFF_UUID_TEST: [u8; 16] = crate::parsers::provenance::C2PA_BMFF_UUID;

    #[test]
    fn c2pa_boxes_become_free_space() {
        let data = [
            ftyp(),
            c2pa_box(b"manifest-bytes"),
            bx(b"jumb", b"more-manifest"),
            bx(b"mdat", &[7u8; 64]),
            xmp_box(b"<?xpacket begin=\"\"?><x:xmpmeta/>"),
        ]
        .concat();
        let f = run("a.mp4", "mp4", &data);
        assert_eq!(ids(&f), ["mp4.brand", "mp4.c2pa", "mp4.c2pa", "mp4.xmp"]);
        let c = find(&f, "mp4.c2pa");
        assert_eq!(c.category, Category::Junk(JunkKind::Provenance));
        assert_eq!(c.confidence, Confidence::Strong);
        assert_eq!(c.title, "C2PA content credentials (uuid box, 38 bytes)");
        let m = c.marker.as_ref().unwrap();
        assert_eq!(m.removal, RemovalStrategy::StructuralRemove);
        assert_eq!(m.container, ContainerKind::IsoBox);

        let mut cur = data.clone();
        for finding in f.iter().filter(|f| f.marker.is_some()) {
            apply(&mut cur, finding.marker.as_ref().unwrap());
        }
        // Same size, same box boundaries, three boxes now free and zeroed.
        assert_eq!(cur.len(), data.len());
        assert_eq!(format_of("a.mp4", &cur), Some("mp4"));
        let mut off = 0usize;
        let mut kinds = Vec::new();
        while off < cur.len() {
            let size = u32::from_be_bytes(cur[off..off + 4].try_into().unwrap()) as usize;
            kinds.push(cur[off + 4..off + 8].to_vec());
            off += size;
        }
        assert_eq!(off, cur.len());
        assert_eq!(
            kinds,
            [
                b"ftyp".to_vec(),
                b"free".to_vec(),
                b"free".to_vec(),
                b"mdat".to_vec(),
                b"free".to_vec()
            ]
        );
        assert!(
            cur[m.region.offset as usize + 8..m.region.end() as usize]
                .iter()
                .all(|&b| b == 0)
        );
        assert_eq!(ids(&run("a.mp4", "mp4", &cur)), ["mp4.brand"]);
    }

    #[test]
    fn box_remover_is_strict() {
        let data = [ftyp(), c2pa_box(b"m"), bx(b"mdat", &[1; 8])].concat();
        let c = find(&run("a.mp4", "mp4", &data), "mp4.c2pa").clone();
        let r = c.marker.unwrap().region;
        assert!(remove(&data, r).is_some());
        assert!(remove(&data, Region::new(r.offset, r.len - 1)).is_none());
        assert!(remove(&data, Region::new(r.offset + 1, r.len)).is_none());
        let mdat = data.len() as u64 - 16;
        assert!(remove(&data, Region::new(mdat, 16)).is_none());
        assert!(remove(b"not iso at all", Region::new(1, 1)).is_none());
    }

    #[test]
    fn moov_at_the_end_of_a_large_file() {
        let mut data = ftyp();
        let mut mdat = 0u32.to_be_bytes().to_vec();
        mdat.extend_from_slice(b"mdat");
        data.extend(bx(b"free", &vec![0u8; 200_000]));
        data.extend(moov(&[item(b"\xa9too", b"HandBrake 1.8.0")]));
        let f = run("a.mp4", "mp4", &data);
        let e = find(&f, "mp4.encoder");
        assert!(e.evidence.offset > 200_000);
        // A size-0 box runs to EOF and ends the walk.
        let mut tail = ftyp();
        tail.extend(&mdat);
        tail.extend(moov(&[item(b"\xa9too", b"x")]));
        assert_eq!(ids(&run("a.mp4", "mp4", &tail)), ["mp4.brand"]);
    }

    #[test]
    fn largesize_and_quicktime_meta() {
        let mut data = ftyp();
        let mut big = 1u32.to_be_bytes().to_vec();
        big.extend_from_slice(b"free");
        big.extend_from_slice(&(16u64 + 40).to_be_bytes());
        big.extend_from_slice(&[0u8; 40]);
        data.extend(big);
        // QuickTime-style meta: no version and flags before hdlr.
        let mut meta = bx(b"hdlr", &[0u8; 25]);
        meta.extend(bx(b"ilst", &item(b"\xa9too", b"Lavf61.1.100")));
        let moov_box = bx(b"moov", &bx(b"udta", &bx(b"meta", &meta)));
        data.extend(moov_box);
        let f = run("a.mov", "mp4", &data);
        assert_eq!(find(&f, "mp4.encoder").title, "MP4 encoder Lavf61.1.100");
    }

    #[test]
    fn non_text_and_blank_values_are_quiet() {
        let mut bin = vec![0, 0, 0, 13, 0, 0, 0, 0];
        bin.extend_from_slice(b"Lavf");
        let data = [
            ftyp(),
            moov(&[bx(b"\xa9too", &bx(b"data", &bin)), item(b"\xa9nam", b"   ")]),
        ]
        .concat();
        assert_eq!(ids(&run("a.mp4", "mp4", &data)), ["mp4.brand"]);
    }

    #[test]
    fn deep_nesting_and_box_storms_are_bounded() {
        let mut inner = bx(b"ilst", &item(b"\xa9too", b"deep"));
        for _ in 0..20 {
            inner = bx(b"udta", &inner);
        }
        let data = [ftyp(), bx(b"moov", &inner)].concat();
        assert_eq!(ids(&run("a.mp4", "mp4", &data)), ["mp4.brand"]);
        let storm: Vec<u8> = std::iter::repeat_n(bx(b"free", &[]), 10_000)
            .flatten()
            .collect();
        let data = [ftyp(), storm, moov(&[item(b"\xa9too", b"late")])].concat();
        assert_eq!(ids(&run("a.mp4", "mp4", &data)), ["mp4.brand"]);
    }

    #[test]
    fn truncated_and_corrupt_inputs() {
        fuzz("a.mp4", "mp4", &movie());
    }
}
