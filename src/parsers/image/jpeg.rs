//! JPEG: walk marker segments from SOI to the first SOS (capped at 256) and
//! report metadata segments, the encoder hints they carry, and bytes appended
//! after the final EOI.

use crate::model::{
    BrandKind, Category, Confidence, ContainerKind, Evidence, Finding, JunkKind, Marker, Region,
    RemovalStrategy, Severity, TamperKind,
};
use crate::scan::{FileView, MemView};
use crate::util::bytes::{find, rfind, slice, u16_be, u32_be};
use crate::util::fmt::human_size;

use super::exif::{self, ExifSummary};
use super::shared::{NOTE_CHARS, TITLE_CHARS, clip, excerpt, fetch, finding, is_blank, quote};

const SOI: [u8; 2] = [0xFF, 0xD8];
const MAX_SEGMENTS: usize = 256;
const EXIF_SIG: &[u8] = b"Exif\0\0";
const XMP_SIG: &[u8] = b"http://ns.adobe.com/xap/1.0/\0";
const XMP_EXT_SIG: &[u8] = b"http://ns.adobe.com/xmp/extension/\0";
/// Extended XMP header: namespace, 32-byte GUID, full length, chunk offset.
const XMP_EXT_HEADER: usize = 35 + 32 + 4 + 4;
const PHOTOSHOP_SIG: &[u8] = b"Photoshop 3.0\0";
const ADOBE_SIG: &[u8] = b"Adobe";

const APP1: u8 = 0xE1;
const APP2: u8 = 0xE2;
const APP11: u8 = 0xEB;
const APP13: u8 = 0xED;
const APP14: u8 = 0xEE;
const COM: u8 = 0xFE;
const SOS: u8 = 0xDA;

/// One marker segment.
#[derive(Debug, Clone, Copy)]
struct Segment {
    /// Absolute offset of the `FF xx` marker.
    off: u64,
    marker: u8,
    /// Total length including the marker and the length field.
    len: u64,
}

impl Segment {
    fn payload_off(&self) -> u64 {
        self.off + 4
    }

    fn payload_len(&self) -> usize {
        (self.len - 4) as usize
    }
}

#[derive(Debug, Default)]
struct Walk {
    segments: Vec<Segment>,
    /// One past the SOS segment header, where entropy-coded data begins.
    sos_end: Option<u64>,
    /// An EOI met before any SOS (a header-only file).
    early_eoi: Option<u64>,
}

fn walk(view: &dyn FileView) -> Option<Walk> {
    if fetch(view, 0, 2)? != SOI {
        return None;
    }
    let size = view.size();
    let mut w = Walk::default();
    let mut pos = 2u64;
    for _ in 0..MAX_SEGMENTS {
        let Some(h) = fetch(view, pos, 2) else {
            break;
        };
        if h[0] != 0xFF {
            break;
        }
        let m = h[1];
        match m {
            0xFF => {
                pos += 1;
                continue;
            }
            0x00 | 0xD8 => break,
            0x01 | 0xD0..=0xD7 => {
                pos += 2;
                continue;
            }
            0xD9 => {
                w.early_eoi = Some(pos);
                break;
            }
            _ => {}
        }
        let Some(len) = fetch(view, pos + 2, 2).and_then(|b| u16_be(&b, 0)) else {
            break;
        };
        if len < 2 {
            break;
        }
        let end = pos + 2 + len as u64;
        if end > size {
            break;
        }
        w.segments.push(Segment {
            off: pos,
            marker: m,
            len: 2 + len as u64,
        });
        if m == SOS {
            w.sos_end = Some(end);
            break;
        }
        pos = end;
    }
    (!w.segments.is_empty() || w.early_eoi.is_some()).then_some(w)
}

/// The EOI position in a fully buffered file, scanning entropy-coded data from
/// `start` and stepping over any marker segments between progressive scans.
fn find_eoi(buf: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    while i + 1 < buf.len() {
        if buf[i] != 0xFF {
            i += 1;
            continue;
        }
        match buf[i + 1] {
            0x00 => i += 2,
            0xFF => i += 1,
            0xD0..=0xD7 => i += 2,
            0xD9 => return Some(i),
            _ => {
                let len = u16_be(buf, i + 2)? as usize;
                if len < 2 {
                    return None;
                }
                i += 2 + len;
            }
        }
    }
    None
}

pub(super) fn run(view: &dyn FileView, out: &mut Vec<Finding>) {
    let Some(w) = walk(view) else {
        return;
    };
    let mut software: Option<(String, u64)> = None;
    let mut mpf = false;
    for seg in &w.segments {
        if !matches!(seg.marker, APP1 | APP2 | APP13 | APP14 | COM) {
            continue;
        }
        let Some(payload) = fetch(view, seg.payload_off(), seg.payload_len()) else {
            continue;
        };
        match seg.marker {
            APP1 => app1(seg, &payload, out, &mut software),
            APP2 => mpf |= payload.starts_with(b"MPF\0"),
            APP13 => app13(seg, &payload, out),
            APP14 => app14(seg, &payload, out),
            _ => comment(seg, &payload, out),
        }
    }
    c2pa(view, &w, out);
    if let Some((sw, at)) = software {
        out.push(finding(
            "jpeg.software",
            Category::Brand(BrandKind::MediaEncoder),
            Confidence::Moderate,
            Severity::Info,
            format!("Software: {}", clip(&sw, TITLE_CHARS)),
            Evidence::at(at)
                .with_bytes(excerpt(sw.as_bytes()))
                .with_note(format!(
                    "EXIF IFD0 Software tag: \"{}\"",
                    clip(&sw, NOTE_CHARS)
                )),
            None,
        ));
    }
    trailing(view, &w, mpf, out);
}

fn app1(seg: &Segment, payload: &[u8], out: &mut Vec<Finding>, sw: &mut Option<(String, u64)>) {
    if let Some(tiff) = payload.strip_prefix(EXIF_SIG) {
        if is_blank(tiff) {
            return;
        }
        let summary = exif::parse_tiff(tiff);
        let tiff_abs = seg.payload_off() + EXIF_SIG.len() as u64;
        if let Some(ExifSummary {
            software: Some((s, at)),
            ..
        }) = &summary
        {
            *sw = Some((s.clone(), tiff_abs + *at as u64));
        }
        let title = match summary.as_ref().and_then(ExifSummary::camera) {
            Some(cam) => format!("EXIF metadata ({})", clip(&cam, TITLE_CHARS)),
            None => "EXIF metadata".to_string(),
        };
        let mut note = format!("{} EXIF block", human_size(tiff.len() as u64));
        if let Some(d) = summary.as_ref().and_then(ExifSummary::describe) {
            note.push_str(&format!(": {d}"));
        }
        out.push(finding(
            "jpeg.exif",
            Category::Junk(JunkKind::Exif),
            Confidence::Strong,
            Severity::Notice,
            title,
            Evidence::at(seg.payload_off())
                .with_bytes(excerpt(payload))
                .with_note(note),
            Some(Marker {
                region: Region::new(seg.off, seg.len),
                removal: RemovalStrategy::StructuralRemove,
                container: ContainerKind::JpegApp1,
                reversible: true,
            }),
        ));
        return;
    }
    let (skip, extended) = if payload.starts_with(XMP_SIG) {
        (XMP_SIG.len(), false)
    } else if payload.starts_with(XMP_EXT_SIG) {
        (XMP_EXT_HEADER, true)
    } else {
        return;
    };
    let Some(xml) = payload.get(skip..) else {
        return;
    };
    if is_blank(xml) {
        return;
    }
    let mut note = format!("{} XMP packet", human_size(xml.len() as u64));
    if let Some(tool) = xmp_creator_tool(xml) {
        note.push_str(&format!(", CreatorTool \"{tool}\""));
    }
    out.push(finding(
        "jpeg.xmp",
        Category::Junk(JunkKind::Xmp),
        Confidence::Strong,
        Severity::Notice,
        if extended {
            "XMP metadata (extended)"
        } else {
            "XMP metadata"
        },
        Evidence::at(seg.payload_off() + skip as u64)
            .with_bytes(excerpt(xml))
            .with_note(note),
        Some(Marker {
            region: Region::new(seg.off, seg.len),
            removal: RemovalStrategy::StructuralRemove,
            container: ContainerKind::JpegApp1,
            reversible: true,
        }),
    ));
}

/// C2PA content credentials: the APP11 segments, which carry the JUMBF boxes
/// of a manifest (a large manifest spans several consecutive segments, all
/// reported and removed as one run).
fn c2pa(view: &dyn FileView, w: &Walk, out: &mut Vec<Finding>) {
    let mut i = 0usize;
    while i < w.segments.len() {
        let first = w.segments[i];
        if first.marker != APP11 {
            i += 1;
            continue;
        }
        let mut end = first.off + first.len;
        let mut count = 1usize;
        while let Some(next) = w.segments.get(i + count)
            && next.marker == APP11
            && next.off == end
        {
            end += next.len;
            count += 1;
        }
        i += count;
        let head =
            fetch(view, first.payload_off(), first.payload_len().min(256)).unwrap_or_default();
        let jumbf = find(&head, b"jumb").is_some() || find(&head, b"c2pa").is_some();
        let mut note = format!(
            "{} APP11 segment{} holding {} of JUMBF boxes",
            count,
            if count == 1 { "" } else { "s" },
            human_size(end - first.off)
        );
        if jumbf {
            note.push_str("; the boxes name a C2PA manifest");
        }
        out.push(finding(
            "jpeg.c2pa",
            Category::Junk(JunkKind::Provenance),
            if jumbf {
                Confidence::Strong
            } else {
                Confidence::Moderate
            },
            Severity::Notice,
            if jumbf {
                "C2PA content credentials (JUMBF)"
            } else {
                "JPEG APP11 segment (JUMBF, C2PA)"
            },
            Evidence::at(first.payload_off())
                .with_bytes(excerpt(&head))
                .with_note(note),
            Some(Marker {
                region: Region::new(first.off, end - first.off),
                removal: RemovalStrategy::StructuralRemove,
                container: ContainerKind::JpegSegment,
                reversible: true,
            }),
        ));
    }
}

/// The `xmp:CreatorTool` value from an XMP packet, attribute or element form.
pub(super) fn xmp_creator_tool(xml: &[u8]) -> Option<String> {
    let at = find(xml, b"CreatorTool")?;
    let rest = xml.get(at + b"CreatorTool".len()..)?;
    let rest = &rest[..rest.len().min(512)];
    let (open, close): (usize, u8) = match rest.first()? {
        b'=' => (2, *rest.get(1)?),
        b'>' => (1, b'<'),
        _ => return None,
    };
    let body = rest.get(open..)?;
    let end = body.iter().position(|&b| b == close)?;
    let value = quote(&body[..end], NOTE_CHARS);
    (!value.is_empty()).then_some(value)
}

fn app13(seg: &Segment, payload: &[u8], out: &mut Vec<Finding>) {
    let Some(rest) = payload.strip_prefix(PHOTOSHOP_SIG) else {
        return;
    };
    if is_blank(rest) {
        return;
    }
    let ids = photoshop_resources(rest);
    let mut kinds = Vec::new();
    for (id, label) in [
        (0x0404u16, "IPTC-NAA record"),
        (0x040C, "thumbnail"),
        (0x0422, "EXIF"),
        (0x0424, "XMP"),
    ] {
        if ids.contains(&id) {
            kinds.push(label);
        }
    }
    let mut note = format!("{} Photoshop resource block", human_size(rest.len() as u64));
    if !kinds.is_empty() {
        note.push_str(&format!(" with {}", kinds.join(", ")));
    }
    out.push(finding(
        "jpeg.iptc",
        Category::Junk(JunkKind::Iptc),
        Confidence::Strong,
        Severity::Notice,
        if ids.contains(&0x0404) {
            "IPTC metadata (Photoshop APP13)"
        } else {
            "Photoshop metadata (APP13)"
        },
        Evidence::at(seg.payload_off())
            .with_bytes(excerpt(payload))
            .with_note(note),
        Some(Marker::blank(
            Region::new(
                seg.payload_off() + PHOTOSHOP_SIG.len() as u64,
                rest.len() as u64,
            ),
            ContainerKind::JpegSegment,
        )),
    ));
}

/// Resource ids in a Photoshop image resource block (`8BIM` records).
fn photoshop_resources(buf: &[u8]) -> Vec<u16> {
    let mut ids = Vec::new();
    let mut i = 0usize;
    while ids.len() < 256 && slice(buf, i, 4) == Some(b"8BIM") {
        let Some(id) = u16_be(buf, i + 4) else {
            break;
        };
        ids.push(id);
        let Some(name_len) = buf.get(i + 6).map(|&n| n as usize) else {
            break;
        };
        let name_total = (1 + name_len + 1) & !1;
        let size_at = i + 6 + name_total;
        let Some(size) = u32_be(buf, size_at) else {
            break;
        };
        let Some(next) = (size as usize)
            .checked_add(1)
            .map(|s| s & !1)
            .and_then(|s| (size_at + 4).checked_add(s))
        else {
            break;
        };
        i = next;
    }
    ids
}

fn app14(seg: &Segment, payload: &[u8], out: &mut Vec<Finding>) {
    if !payload.starts_with(ADOBE_SIG) {
        return;
    }
    let mut note = "Adobe APP14 segment".to_string();
    if let (Some(v), Some(t)) = (u16_be(payload, 5), payload.get(11)) {
        let transform = match t {
            0 => "none (RGB or CMYK)",
            1 => "YCbCr",
            2 => "YCCK",
            _ => "unknown",
        };
        note = format!("DCTEncodeVersion {v}, color transform {transform}");
    }
    out.push(finding(
        "jpeg.adobe",
        Category::Brand(BrandKind::MediaEncoder),
        Confidence::Moderate,
        Severity::Info,
        "Adobe JPEG encoder (APP14)",
        Evidence::at(seg.payload_off())
            .with_bytes(excerpt(payload))
            .with_note(note),
        None,
    ));
}

fn comment(seg: &Segment, payload: &[u8], out: &mut Vec<Finding>) {
    if is_blank(payload) {
        return;
    }
    out.push(finding(
        "jpeg.comment",
        Category::Junk(JunkKind::Comment),
        Confidence::Strong,
        Severity::Notice,
        format!("JPEG comment \"{}\"", quote(payload, TITLE_CHARS)),
        Evidence::at(seg.payload_off())
            .with_bytes(excerpt(payload))
            .with_note(format!("COM segment: \"{}\"", quote(payload, NOTE_CHARS))),
        Some(Marker {
            region: Region::new(seg.payload_off(), payload.len() as u64),
            removal: RemovalStrategy::RawBlank { fill: b' ' },
            container: ContainerKind::JpegSegment,
            reversible: true,
        }),
    ));
}

fn trailing(view: &dyn FileView, w: &Walk, mpf: bool, out: &mut Vec<Finding>) {
    let size = view.size();
    let header = view.header();
    let eoi = if size <= header.len() as u64 {
        match (w.early_eoi, w.sos_end) {
            (Some(e), _) => Some(e),
            (None, Some(start)) => find_eoi(header, start as usize).map(|p| p as u64),
            (None, None) => None,
        }
    } else {
        rfind(view.tail(), &[0xFF, 0xD9])
            .map(|p| view.tail_start() + p as u64)
            .filter(|&e| w.sos_end.is_none_or(|s| e >= s))
    };
    let Some(eoi) = eoi else {
        return;
    };
    let end = eoi + 2;
    if end >= size {
        return;
    }
    let extra = size - end;
    let head = view.read_at(end, 64).unwrap_or_default();
    let mut note =
        format!("the image ends at offset {end} but the file runs {extra} bytes further");
    if head.starts_with(&[0xFF, 0xD8, 0xFF]) {
        note.push_str("; it starts with another JPEG image");
        if mpf {
            note.push_str(" (likely an MPF secondary image)");
        }
    } else if head.starts_with(b"PK\x03\x04") {
        note.push_str("; it starts with a ZIP archive (a JPEG/ZIP polyglot)");
    } else if find(&head[..head.len().min(16)], b"ftyp").is_some() {
        note.push_str("; it holds an MP4 video (a motion photo)");
    }
    out.push(finding(
        "jpeg.trailing_data",
        Category::Tamper(TamperKind::AppendedData),
        Confidence::Strong,
        Severity::Notice,
        format!("{} appended after the JPEG end marker", human_size(extra)),
        Evidence::at(end).with_bytes(excerpt(&head)).with_note(note),
        Some(Marker::truncate_at(end, ContainerKind::Generic)),
    ));
}

/// Structural removal of JPEG marker segments ([`ContainerKind::JpegApp1`]
/// and [`ContainerKind::JpegSegment`]).
///
/// `region` must be one whole segment found by walking from SOI to SOS: it
/// starts at the segment's `FF xx` marker and spans the marker, the length
/// field and the payload. Only metadata segments are accepted (APP1, APP11,
/// APP13 and COM); segments a decoder needs are refused. A region may also
/// span a run of consecutive APP11 segments, the way a long C2PA manifest is
/// stored. The result is the file with those bytes dropped.
pub(super) fn remove_segment(data: &[u8], region: Region) -> Option<Vec<u8>> {
    let view = MemView::new("", data.to_vec());
    let w = walk(&view)?;
    let at = w.segments.iter().position(|s| s.off == region.offset)?;
    let seg = w.segments[at];
    if !matches!(seg.marker, APP1 | APP11 | APP13 | COM) {
        return None;
    }
    let mut total = seg.len;
    let mut next = at + 1;
    while total < region.len && seg.marker == APP11 {
        let more = w.segments.get(next)?;
        if more.marker != APP11 || more.off != region.offset + total {
            return None;
        }
        total += more.len;
        next += 1;
    }
    if total != region.len {
        return None;
    }
    let s = usize::try_from(region.offset).ok()?;
    let e = usize::try_from(region.end()).ok()?;
    let mut out = Vec::with_capacity(data.len() - (e - s));
    out.extend_from_slice(data.get(..s)?);
    out.extend_from_slice(data.get(e..)?);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::image::exif::build_tiff;
    use crate::parsers::image::probes;
    use crate::parsers::image::shared::testkit::{apply, garbage, run, with_id};

    fn seg(marker: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0xFF, marker];
        v.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    /// A baseline JPEG skeleton with the given metadata segments, `scan`
    /// entropy bytes, EOI, and `trailing`.
    fn build(meta: &[Vec<u8>], scan: &[u8], trailing: &[u8]) -> Vec<u8> {
        let mut v = SOI.to_vec();
        v.extend(seg(0xE0, b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0"));
        for m in meta {
            v.extend_from_slice(m);
        }
        v.extend(seg(0xDB, &[0u8; 65]));
        v.extend(seg(0xC0, &[8, 0, 1, 0, 1, 1, 1, 0x11, 0]));
        v.extend(seg(0xC4, &[0u8; 20]));
        v.extend(seg(0xDA, &[1, 1, 0, 0, 63, 0]));
        v.extend_from_slice(scan);
        v.extend_from_slice(&[0xFF, 0xD9]);
        v.extend_from_slice(trailing);
        v
    }

    fn exif_seg() -> Vec<u8> {
        let mut p = EXIF_SIG.to_vec();
        p.extend(build_tiff(
            &[
                (0x010F, "Canon"),
                (0x0110, "EOS R5"),
                (0x0131, "Adobe Photoshop 25.0"),
            ],
            true,
        ));
        seg(APP1, &p)
    }

    fn xmp_seg() -> Vec<u8> {
        let mut p = XMP_SIG.to_vec();
        p.extend_from_slice(
            b"<x:xmpmeta><rdf:Description xmp:CreatorTool=\"Lightroom Classic\"/></x:xmpmeta>",
        );
        seg(APP1, &p)
    }

    fn iptc_seg() -> Vec<u8> {
        let mut p = PHOTOSHOP_SIG.to_vec();
        p.extend_from_slice(b"8BIM\x04\x04\0\0\0\0\0\x08\x1c\x02\x50\0\x03Bob\0");
        seg(APP13, &p)
    }

    fn scan(data: &[u8]) -> Vec<Finding> {
        run(probes(), "photo.jpg", data, "jpeg")
    }

    fn rich() -> Vec<u8> {
        build(
            &[
                exif_seg(),
                xmp_seg(),
                iptc_seg(),
                seg(COM, b"shot by a test"),
                seg(APP14, b"Adobe\0\x64\0\0\0\0\x01"),
            ],
            &[0x12, 0xFF, 0x00, 0x34, 0xFF, 0xD0, 0x56],
            b"TRAILER-BYTES",
        )
    }

    #[test]
    fn finds_every_segment_kind() {
        let data = rich();
        let fs = scan(&data);
        let exif = with_id(&fs, "jpeg.exif");
        assert_eq!(exif.len(), 1);
        assert_eq!(exif[0].title, "EXIF metadata (Canon EOS R5)");
        let note = exif[0].evidence.note.clone().unwrap();
        assert!(note.contains("Adobe Photoshop 25.0") && note.contains("GPS"));
        let m = exif[0].marker.as_ref().unwrap();
        assert_eq!(m.removal, RemovalStrategy::StructuralRemove);
        assert_eq!(m.container, ContainerKind::JpegApp1);
        assert_eq!(&data[m.region.offset as usize..][..2], &[0xFF, 0xE1]);

        let sw = with_id(&fs, "jpeg.software");
        assert_eq!(sw.len(), 1);
        assert_eq!(sw[0].title, "Software: Adobe Photoshop 25.0");
        let at = sw[0].evidence.offset as usize;
        assert_eq!(&data[at..at + 20], b"Adobe Photoshop 25.0");

        let xmp = with_id(&fs, "jpeg.xmp");
        assert_eq!(xmp.len(), 1);
        assert!(
            xmp[0]
                .evidence
                .note
                .as_deref()
                .unwrap()
                .contains("Lightroom Classic")
        );
        let iptc = with_id(&fs, "jpeg.iptc");
        assert_eq!(iptc[0].title, "IPTC metadata (Photoshop APP13)");
        let com = with_id(&fs, "jpeg.comment");
        assert_eq!(com[0].title, "JPEG comment \"shot by a test\"");
        assert_eq!(with_id(&fs, "jpeg.adobe").len(), 1);
        let t = with_id(&fs, "jpeg.trailing_data");
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].evidence.offset, (data.len() - 13) as u64);
    }

    #[test]
    fn every_marker_cleans_and_reparses() {
        let data = rich();
        let fs = scan(&data);
        for id in [
            "jpeg.exif",
            "jpeg.xmp",
            "jpeg.iptc",
            "jpeg.comment",
            "jpeg.trailing_data",
        ] {
            let f = with_id(&fs, id)[0];
            let cleaned = apply(&data, f);
            let again = scan(&cleaned);
            assert!(
                with_id(&again, id).is_empty(),
                "{id} survived its own marker"
            );
            // The rest of the file still walks to SOS and keeps its findings.
            let w = walk(&MemView::new("", cleaned.clone())).unwrap();
            assert!(w.sos_end.is_some());
            assert_eq!(again.len() + 1 + usize::from(id == "jpeg.exif"), fs.len());
        }
    }

    fn jumbf(extra: &[u8]) -> Vec<u8> {
        let mut p = b"JP        jumb   jumdc2pa".to_vec();
        p.extend_from_slice(extra);
        p
    }

    #[test]
    fn xmp_is_dropped_with_its_segment() {
        let data = rich();
        let fs = scan(&data);
        let xmp = with_id(&fs, "jpeg.xmp")[0];
        let m = xmp.marker.as_ref().unwrap();
        assert_eq!(m.removal, RemovalStrategy::StructuralRemove);
        assert_eq!(m.container, ContainerKind::JpegApp1);
        assert_eq!(&data[m.region.offset as usize..][..2], &[0xFF, 0xE1]);
        let cleaned = apply(&data, xmp);
        assert_eq!(cleaned.len(), data.len() - m.region.len as usize);
        assert!(!cleaned.windows(5).any(|w| w == b"xmpme"));
        assert!(with_id(&scan(&cleaned), "jpeg.xmp").is_empty());
        let w = walk(&MemView::new("", cleaned)).unwrap();
        assert!(w.sos_end.is_some());
    }

    #[test]
    fn c2pa_segments_are_one_run() {
        let data = build(
            &[
                exif_seg(),
                seg(APP11, &jumbf(&[1; 40])),
                seg(APP11, &jumbf(&[2; 10])),
                seg(COM, b"between"),
                seg(APP11, b"JP tail"),
            ],
            &[0x12, 0x34],
            b"",
        );
        let fs = scan(&data);
        let c = with_id(&fs, "jpeg.c2pa");
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].title, "C2PA content credentials (JUMBF)");
        assert_eq!(c[0].category, Category::Junk(JunkKind::Provenance));
        assert_eq!(c[0].confidence, Confidence::Strong);
        assert!(
            c[0].evidence
                .note
                .as_deref()
                .unwrap()
                .starts_with("2 APP11 segments")
        );
        assert_eq!(c[1].title, "JPEG APP11 segment (JUMBF, C2PA)");
        assert_eq!(c[1].confidence, Confidence::Moderate);
        let m = c[0].marker.as_ref().unwrap();
        assert_eq!(m.removal, RemovalStrategy::StructuralRemove);
        assert_eq!(m.container, ContainerKind::JpegSegment);

        let once = apply(&data, c[0]);
        assert_eq!(once.len(), data.len() - m.region.len as usize);
        let again = scan(&once);
        assert_eq!(with_id(&again, "jpeg.c2pa").len(), 1);
        let both = apply(&once, with_id(&again, "jpeg.c2pa")[0]);
        assert!(with_id(&scan(&both), "jpeg.c2pa").is_empty());
        let w = walk(&MemView::new("", both.clone())).unwrap();
        assert!(w.sos_end.is_some());
        assert_eq!(both.len(), data.len() - m.region.len as usize - 4 - 8);
        // A run is only removed whole: the second segment alone, or a region
        // that stops short or runs over, is refused.
        let w = walk(&MemView::new("", data.clone())).unwrap();
        let first = w.segments.iter().find(|s| s.marker == APP11).unwrap();
        assert!(remove_segment(&data, Region::new(first.off, first.len + 1)).is_none());
        assert!(remove_segment(&data, Region::new(first.off, first.len)).is_some());
        let over = m.region.len + 4 + 7;
        assert!(remove_segment(&data, Region::new(first.off, over)).is_none());
    }

    #[test]
    fn large_file_uses_the_tail_for_eoi() {
        let body = vec![0x11u8; 80 * 1024];
        let data = build(&[seg(COM, b"c")], &body, b"tail-junk");
        let fs = scan(&data);
        let t = with_id(&fs, "jpeg.trailing_data");
        assert_eq!(t.len(), 1);
        let cut = apply(&data, t[0]);
        assert!(cut.ends_with(&[0xFF, 0xD9]));
        assert!(with_id(&scan(&cut), "jpeg.trailing_data").is_empty());
        let clean = build(&[], &body, b"");
        assert!(scan(&clean).is_empty());
    }

    #[test]
    fn appended_zip_is_described() {
        let data = build(&[], &[1, 2, 3], b"PK\x03\x04rest");
        let fs = scan(&data);
        let note = with_id(&fs, "jpeg.trailing_data")[0]
            .evidence
            .note
            .clone()
            .unwrap();
        assert!(note.contains("polyglot"));
    }

    #[test]
    fn remover_refuses_non_metadata_segments() {
        let data = rich();
        let w = walk(&MemView::new("", data.clone())).unwrap();
        for s in &w.segments {
            let r = remove_segment(&data, Region::new(s.off, s.len));
            assert_eq!(
                r.is_some(),
                matches!(s.marker, APP1 | APP11 | APP13 | COM),
                "{:x}",
                s.marker
            );
        }
        let first = w.segments[1];
        assert!(remove_segment(&data, Region::new(first.off, first.len - 1)).is_none());
        assert!(remove_segment(&data, Region::new(first.off + 1, first.len)).is_none());
    }

    #[test]
    fn garbage_and_truncation_are_safe() {
        let data = rich();
        for cut in 0..data.len() {
            let _ = scan(&data[..cut]);
        }
        for seed in 0..32 {
            assert!(scan(&garbage(seed, 2048)).is_empty());
        }
        let mut g = SOI.to_vec();
        g.extend(garbage(3, 1024));
        let _ = scan(&g);
        assert!(scan(&[0xFF, 0xD8, 0xFF, 0xFF, 0xFF]).is_empty());
    }
}
