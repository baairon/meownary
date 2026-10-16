//! PNG: walk chunks from offset 8 (capped at 4,096), CRC-check the metadata
//! chunks we report, and look for bytes after IEND.

use crate::model::{
    Category, Confidence, ContainerKind, Evidence, Finding, JunkKind, Marker, Region,
    RemovalStrategy, Severity, TamperKind,
};
use crate::parsers::provenance;
use crate::scan::{FileView, MemView};
use crate::util::bytes::{cstr, rfind, u16_be, u32_be};
use crate::util::fmt::human_size;

use super::exif::{self, ExifSummary};
use super::shared::{NOTE_CHARS, TITLE_CHARS, clip, crc32, excerpt, fetch, finding, latin1, quote};
use crate::scan::reader::MAX_READ;

pub(super) const SIG: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
const MAX_CHUNKS: usize = 4096;
const IEND_CHUNK: [u8; 12] = [0, 0, 0, 0, b'I', b'E', b'N', b'D', 0xAE, 0x42, 0x60, 0x82];

#[derive(Debug, Clone, Copy)]
struct Chunk {
    /// Absolute offset of the chunk's length field.
    off: u64,
    len: u32,
    ty: [u8; 4],
}

impl Chunk {
    fn total(&self) -> u64 {
        12 + self.len as u64
    }

    fn data_off(&self) -> u64 {
        self.off + 8
    }
}

#[derive(Debug, Default)]
struct Walk {
    chunks: Vec<Chunk>,
    /// One past the IEND chunk, when the walk reached it.
    iend_end: Option<u64>,
}

fn walk(view: &dyn FileView) -> Option<Walk> {
    if fetch(view, 0, 8)? != SIG {
        return None;
    }
    let size = view.size();
    let mut w = Walk::default();
    let mut pos = 8u64;
    for _ in 0..MAX_CHUNKS {
        let Some(h) = fetch(view, pos, 8) else {
            break;
        };
        let Some(len) = u32_be(&h, 0) else {
            break;
        };
        let ty = [h[4], h[5], h[6], h[7]];
        if len > 0x7FFF_FFFF || !ty.iter().all(u8::is_ascii_alphabetic) {
            break;
        }
        let chunk = Chunk { off: pos, len, ty };
        let end = pos + chunk.total();
        if end > size {
            break;
        }
        if w.chunks.is_empty() && &ty != b"IHDR" {
            return None;
        }
        w.chunks.push(chunk);
        if &ty == b"IEND" {
            w.iend_end = Some(end);
            break;
        }
        pos = end;
    }
    (!w.chunks.is_empty()).then_some(w)
}

/// The chunk's data and whether its CRC checks out, or `None` when too large
/// to read in one go.
fn read_chunk(view: &dyn FileView, c: &Chunk) -> Option<(Vec<u8>, bool)> {
    let total = usize::try_from(c.total()).ok()?;
    if total > MAX_READ {
        return None;
    }
    let raw = fetch(view, c.off, total)?;
    let body = raw.get(4..total - 4)?;
    let stored = u32_be(&raw, total - 4)?;
    let ok = crc32(body) == stored;
    Some((body[4..].to_vec(), ok))
}

fn chunk_marker(c: &Chunk) -> Marker {
    Marker {
        region: Region::new(c.off, c.total()),
        removal: RemovalStrategy::StructuralRemove,
        container: ContainerKind::PngChunk,
        reversible: true,
    }
}

pub(super) fn run(view: &dyn FileView, out: &mut Vec<Finding>) {
    let Some(w) = walk(view) else {
        return;
    };
    for c in &w.chunks {
        if provenance::is_c2pa_png_chunk(&c.ty) {
            c2pa(view, c, out);
            continue;
        }
        if !matches!(&c.ty, b"tEXt" | b"zTXt" | b"iTXt" | b"eXIf" | b"tIME") {
            continue;
        }
        let Some((data, crc_ok)) = read_chunk(view, c) else {
            continue;
        };
        let confidence = if crc_ok {
            Confidence::Strong
        } else {
            Confidence::Moderate
        };
        let ty = latin1(&c.ty);
        let (sig, category, title, mut note) = match &c.ty {
            b"eXIf" => {
                let summary = exif::parse_tiff(&data);
                let title = match summary.as_ref().and_then(ExifSummary::camera) {
                    Some(cam) => format!("PNG eXIf chunk ({})", clip(&cam, TITLE_CHARS)),
                    None => "PNG eXIf chunk".to_string(),
                };
                let mut note = format!("{} EXIF block", human_size(data.len() as u64));
                if let Some(d) = summary.as_ref().and_then(ExifSummary::describe) {
                    note.push_str(&format!(": {d}"));
                }
                ("png.exif", Category::Junk(JunkKind::Exif), title, note)
            }
            b"tIME" => {
                let note = match (u16_be(&data, 0), data.get(1..7)) {
                    (Some(y), Some(t)) if data.len() == 7 => format!(
                        "last modified {y:04}-{:02}-{:02} {:02}:{:02}:{:02}",
                        t[1], t[2], t[3], t[4], t[5]
                    ),
                    _ => "malformed tIME chunk".to_string(),
                };
                (
                    "png.time",
                    Category::Junk(JunkKind::DocInfo),
                    "PNG modification time (tIME)".to_string(),
                    note,
                )
            }
            _ => {
                let (keyword, note) = text_note(&c.ty, &data);
                (
                    "png.text",
                    Category::Junk(JunkKind::TextChunk),
                    format!("PNG {ty} chunk \"{}\"", clip(&keyword, TITLE_CHARS)),
                    note,
                )
            }
        };
        if !crc_ok {
            note.push_str("; the chunk CRC does not match");
        }
        out.push(finding(
            sig,
            category,
            confidence,
            Severity::Notice,
            title,
            Evidence::at(c.data_off())
                .with_bytes(excerpt(&data))
                .with_note(note),
            Some(chunk_marker(c)),
        ));
    }
    trailing(view, &w, out);
}

/// A C2PA manifest chunk (`caBX`, the JUMBF types, or the `c2` family).
fn c2pa(view: &dyn FileView, c: &Chunk, out: &mut Vec<Finding>) {
    let ty = latin1(&c.ty);
    let head = fetch(view, c.data_off(), (c.len as usize).min(64)).unwrap_or_default();
    out.push(finding(
        "png.c2pa",
        Category::Junk(JunkKind::Provenance),
        Confidence::Strong,
        Severity::Notice,
        format!("C2PA content credentials (PNG {ty} chunk)"),
        Evidence::at(c.data_off())
            .with_bytes(excerpt(&head))
            .with_note(format!(
                "{} {ty} chunk holding a C2PA manifest (JUMBF)",
                human_size(c.len as u64)
            )),
        Some(chunk_marker(c)),
    ));
}

/// The keyword and a note for a tEXt, zTXt or iTXt chunk.
fn text_note(ty: &[u8; 4], data: &[u8]) -> (String, String) {
    let kw = cstr(data, 0, 79).unwrap_or_default();
    let keyword = latin1(kw);
    let rest = data.get(kw.len() + 1..).unwrap_or_default();
    let value = match ty {
        b"tEXt" => Some(latin1(rest)),
        b"iTXt" => itxt_text(rest),
        _ => None,
    };
    let note = match value {
        Some(v) => format!(
            "{} = \"{}\"",
            clip(&keyword, NOTE_CHARS),
            clip(&v, NOTE_CHARS)
        ),
        None => format!(
            "keyword \"{}\", {} of compressed text",
            clip(&keyword, NOTE_CHARS),
            human_size(rest.len() as u64)
        ),
    };
    (keyword, note)
}

/// Uncompressed iTXt text after the keyword: flag, method, language, and the
/// translated keyword come first.
fn itxt_text(rest: &[u8]) -> Option<String> {
    if *rest.first()? != 0 {
        return None;
    }
    let lang = cstr(rest, 2, rest.len())?;
    let tk_at = 2 + lang.len() + 1;
    let tk = cstr(rest, tk_at, rest.len())?;
    let text = rest.get(tk_at + tk.len() + 1..)?;
    Some(quote(text, NOTE_CHARS))
}

fn trailing(view: &dyn FileView, w: &Walk, out: &mut Vec<Finding>) {
    let size = view.size();
    let end = w
        .iend_end
        .or_else(|| rfind(view.tail(), &IEND_CHUNK).map(|p| view.tail_start() + p as u64 + 12));
    let Some(end) = end else {
        return;
    };
    if end >= size {
        return;
    }
    let extra = size - end;
    let head = view.read_at(end, 64).unwrap_or_default();
    out.push(finding(
        "png.trailing_data",
        Category::Tamper(TamperKind::AppendedData),
        Confidence::Strong,
        Severity::Notice,
        format!("{} appended after the PNG IEND chunk", human_size(extra)),
        Evidence::at(end)
            .with_bytes(excerpt(&head))
            .with_note(format!(
                "the image ends at offset {end} but the file runs {extra} bytes further"
            )),
        Some(Marker::truncate_at(end, ContainerKind::Generic)),
    ));
}

/// Structural removal of one PNG chunk ([`ContainerKind::PngChunk`]).
///
/// `region` must be one whole chunk (length, type, data and CRC) found by
/// walking from offset 8: it must sit after the leading IHDR chunk and before
/// IEND, and its type must be ancillary (lowercase first letter). The result
/// is the file with that chunk dropped; PNG has no other length or offset to
/// fix up.
pub(super) fn remove_chunk(data: &[u8], region: Region) -> Option<Vec<u8>> {
    let view = MemView::new("", data.to_vec());
    let w = walk(&view)?;
    let (idx, c) = w
        .chunks
        .iter()
        .enumerate()
        .find(|(_, c)| c.off == region.offset)?;
    if idx == 0 || c.total() != region.len || c.ty[0].is_ascii_uppercase() {
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
pub(super) mod tests {
    use super::*;
    use crate::parsers::image::exif::build_tiff;
    use crate::parsers::image::probes;
    use crate::parsers::image::shared::testkit::{apply, garbage, run, with_id};

    pub fn chunk(ty: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let mut v = (data.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(ty);
        v.extend_from_slice(data);
        let mut body = ty.to_vec();
        body.extend_from_slice(data);
        v.extend_from_slice(&crc32(&body).to_be_bytes());
        v
    }

    pub fn build(meta: &[Vec<u8>], trailing: &[u8]) -> Vec<u8> {
        let mut v = SIG.to_vec();
        v.extend(chunk(b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0]));
        for m in meta {
            v.extend_from_slice(m);
        }
        v.extend(chunk(b"IDAT", &[0x78, 0x9C, 0x63, 0x60, 0, 0, 0, 2, 0, 1]));
        v.extend(chunk(b"IEND", &[]));
        v.extend_from_slice(trailing);
        v
    }

    fn scan(data: &[u8]) -> Vec<Finding> {
        run(probes(), "img.png", data, "png")
    }

    fn rich() -> Vec<u8> {
        build(
            &[
                chunk(b"tEXt", b"Software\0GIMP 2.10.36"),
                chunk(b"iTXt", b"Comment\0\0\0en\0\0made in a test"),
                chunk(
                    b"eXIf",
                    &build_tiff(&[(0x010F, "Apple"), (0x0110, "iPhone 15")], true),
                ),
                chunk(b"tIME", &[0x07, 0xE8, 1, 2, 3, 4, 5]),
            ],
            b"hidden-tail",
        )
    }

    #[test]
    fn finds_text_exif_time_and_trailer() {
        let data = rich();
        let fs = scan(&data);
        let text = with_id(&fs, "png.text");
        assert_eq!(text.len(), 2);
        assert_eq!(text[0].title, "PNG tEXt chunk \"Software\"");
        assert!(
            text[0]
                .evidence
                .note
                .as_deref()
                .unwrap()
                .contains("GIMP 2.10.36")
        );
        assert!(
            text[1]
                .evidence
                .note
                .as_deref()
                .unwrap()
                .contains("made in a test")
        );
        assert!(text.iter().all(|f| f.confidence == Confidence::Strong));
        let ex = with_id(&fs, "png.exif");
        assert_eq!(ex[0].title, "PNG eXIf chunk (Apple iPhone 15)");
        let t = with_id(&fs, "png.time");
        assert!(
            t[0].evidence
                .note
                .as_deref()
                .unwrap()
                .contains("2024-01-02 03:04:05")
        );
        let tr = with_id(&fs, "png.trailing_data");
        assert_eq!(tr.len(), 1);
        assert_eq!(tr[0].evidence.offset, (data.len() - 11) as u64);
        for f in &fs[..4] {
            let m = f.marker.as_ref().unwrap();
            assert_eq!(m.removal, RemovalStrategy::StructuralRemove);
            assert_eq!(m.container, ContainerKind::PngChunk);
        }
    }

    #[test]
    fn every_marker_cleans_and_reparses() {
        let data = rich();
        let fs = scan(&data);
        for f in &fs {
            let cleaned = apply(&data, f);
            let again = scan(&cleaned);
            assert_eq!(
                again.len(),
                fs.len() - 1,
                "{} not removed alone",
                f.signature_id
            );
            assert!(!again.contains(f));
            let w = walk(&MemView::new("", cleaned.clone())).unwrap();
            assert_eq!(&w.chunks[0].ty, b"IHDR");
            assert!(w.iend_end.is_some());
        }
        // Remove everything in sequence: the image ends up bare and valid.
        let mut cur = data;
        loop {
            let fs = scan(&cur);
            let Some(f) = fs.first() else { break };
            cur = apply(&cur, f);
        }
        assert_eq!(cur, build(&[], b""));
    }

    #[test]
    fn c2pa_chunks_are_found_and_dropped() {
        let manifest = b"   jumb   jumdc2pa    manifest-bytes";
        let data = build(
            &[
                chunk(b"caBX", manifest),
                chunk(b"tEXt", b"Comment hi"),
                chunk(b"juMB", b"other"),
            ],
            b"",
        );
        let fs = scan(&data);
        let c2 = with_id(&fs, "png.c2pa");
        assert_eq!(c2.len(), 2);
        assert_eq!(c2[0].title, "C2PA content credentials (PNG caBX chunk)");
        assert_eq!(c2[0].category, Category::Junk(JunkKind::Provenance));
        assert_eq!(c2[0].confidence, Confidence::Strong);
        let m = c2[0].marker.as_ref().unwrap();
        assert_eq!(m.removal, RemovalStrategy::StructuralRemove);
        assert_eq!(m.container, ContainerKind::PngChunk);
        assert_eq!(m.region.len, 12 + manifest.len() as u64);

        let mut cur = data.clone();
        while let Some(f) = scan(&cur)
            .into_iter()
            .find(|f| f.signature_id == "png.c2pa")
        {
            cur = apply(&cur, &f);
            // Every CRC and length still checks out.
            let w = walk(&MemView::new("", cur.clone())).unwrap();
            assert!(w.iend_end.is_some());
        }
        assert!(!cur.windows(4).any(|w| w == b"caBX" || w == b"juMB"));
        let rest = scan(&cur);
        assert_eq!(rest.len(), 1);
        assert_eq!(rest[0].signature_id, "png.text");
        assert!(rest[0].evidence.note.as_deref().unwrap().contains("hi"));
        assert_eq!(
            cur.len(),
            build(&[chunk(b"tEXt", b"Comment hi")], b"").len()
        );
    }

    #[test]
    fn bad_crc_is_moderate() {
        let mut c = chunk(b"tEXt", b"Author\0me");
        let n = c.len();
        c[n - 1] ^= 0xFF;
        let fs = scan(&build(&[c], b""));
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].confidence, Confidence::Moderate);
    }

    #[test]
    fn remover_refuses_critical_and_misaligned_chunks() {
        let data = rich();
        let w = walk(&MemView::new("", data.clone())).unwrap();
        for c in &w.chunks {
            let r = remove_chunk(&data, Region::new(c.off, c.total()));
            assert_eq!(r.is_some(), c.ty[0].is_ascii_lowercase(), "{:?}", c.ty);
        }
        let t = w.chunks[1];
        assert!(remove_chunk(&data, Region::new(t.off, t.total() - 1)).is_none());
        assert!(remove_chunk(&data, Region::new(t.off + 4, t.total())).is_none());
        assert!(remove_chunk(b"not a png", Region::new(1, 1)).is_none());
    }

    #[test]
    fn trailer_found_from_tail_when_walk_stops_early() {
        // A chunk claiming a bogus type stops the walk; the tail still has IEND.
        let mut data = build(&[], b"");
        let iend = data.len() - 12;
        let mut bad = data[..iend].to_vec();
        bad.extend_from_slice(&[0, 0, 0, 1, b'1', b'2', b'3', b'4', 0, 0, 0, 0, 0]);
        bad.extend_from_slice(&data[iend..]);
        bad.extend_from_slice(b"junk");
        data = bad;
        let fs = scan(&data);
        assert_eq!(with_id(&fs, "png.trailing_data").len(), 1);
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
        let mut g = SIG.to_vec();
        g.extend(garbage(9, 1024));
        assert!(scan(&g).is_empty());
    }
}
