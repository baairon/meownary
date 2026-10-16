//! WebP: walk the RIFF chunks after the `WEBP` form type and report the EXIF
//! and XMP metadata chunks. Also hosts the RIFF chunk remover.

use crate::model::{
    Category, Confidence, ContainerKind, Evidence, Finding, JunkKind, Marker, Region,
    RemovalStrategy, Severity,
};
use crate::parsers::provenance;
use crate::scan::{FileView, MemView};
use crate::util::bytes::{slice, u32_le};
use crate::util::fmt::human_size;

use super::exif::{self, ExifSummary};
use super::jpeg::xmp_creator_tool;
use super::shared::{TITLE_CHARS, clip, excerpt, fetch, finding, is_blank};
use crate::scan::reader::MAX_READ;

const MAX_CHUNKS: usize = 1024;
/// VP8X feature flags.
const FLAG_EXIF: u8 = 0x08;
const FLAG_XMP: u8 = 0x04;

#[derive(Debug, Clone, Copy)]
struct Chunk {
    /// Absolute offset of the FourCC.
    off: u64,
    fourcc: [u8; 4],
    size: u32,
}

impl Chunk {
    fn data_off(&self) -> u64 {
        self.off + 8
    }

    /// Header, data, and the pad byte that keeps the next chunk even.
    fn padded_len(&self) -> u64 {
        8 + self.size as u64 + (self.size as u64 & 1)
    }
}

/// The form type and top-level chunks of a RIFF file.
fn walk(view: &dyn FileView) -> Option<([u8; 4], Vec<Chunk>)> {
    let hdr = fetch(view, 0, 12)?;
    if &hdr[..4] != b"RIFF" {
        return None;
    }
    let form = [hdr[8], hdr[9], hdr[10], hdr[11]];
    let riff_end = (8 + u32_le(&hdr, 4)? as u64).min(view.size());
    let mut chunks = Vec::new();
    let mut pos = 12u64;
    while chunks.len() < MAX_CHUNKS && pos + 8 <= riff_end {
        let Some(h) = fetch(view, pos, 8) else {
            break;
        };
        let size = u32_le(&h, 4)?;
        let c = Chunk {
            off: pos,
            fourcc: [h[0], h[1], h[2], h[3]],
            size,
        };
        if c.data_off() + size as u64 > riff_end {
            break;
        }
        chunks.push(c);
        pos += c.padded_len();
    }
    Some((form, chunks))
}

pub(super) fn run(view: &dyn FileView, out: &mut Vec<Finding>) {
    let Some((form, chunks)) = walk(view) else {
        return;
    };
    if &form != b"WEBP" {
        return;
    }
    let size = view.size();
    for c in &chunks {
        if provenance::is_c2pa_riff_chunk(&c.fourcc) {
            let head = fetch(view, c.data_off(), (c.size as usize).min(64)).unwrap_or_default();
            let len = c.padded_len().min(size - c.off);
            out.push(finding(
                "webp.c2pa",
                Category::Junk(JunkKind::Provenance),
                Confidence::Strong,
                Severity::Notice,
                "C2PA content credentials (WebP C2PA chunk)",
                Evidence::at(c.data_off())
                    .with_bytes(excerpt(&head))
                    .with_note(format!(
                        "{} C2PA chunk holding a content credentials manifest",
                        human_size(c.size as u64)
                    )),
                Some(Marker {
                    region: Region::new(c.off, len),
                    removal: RemovalStrategy::StructuralRemove,
                    container: ContainerKind::RiffChunk,
                    reversible: true,
                }),
            ));
            continue;
        }
        let (sig, kind) = match &c.fourcc {
            b"EXIF" => ("webp.exif", JunkKind::Exif),
            b"XMP " => ("webp.xmp", JunkKind::Xmp),
            _ => continue,
        };
        let len = (c.size as usize).min(MAX_READ);
        let Some(data) = fetch(view, c.data_off(), len) else {
            continue;
        };
        if is_blank(&data) {
            continue;
        }
        let (title, note) = if kind == JunkKind::Exif {
            let tiff = data.strip_prefix(b"Exif\0\0").unwrap_or(&data);
            let summary = exif::parse_tiff(tiff);
            let title = match summary.as_ref().and_then(ExifSummary::camera) {
                Some(cam) => format!("WebP EXIF chunk ({})", clip(&cam, TITLE_CHARS)),
                None => "WebP EXIF chunk".to_string(),
            };
            let mut note = format!("{} EXIF block", human_size(c.size as u64));
            if let Some(d) = summary.as_ref().and_then(ExifSummary::describe) {
                note.push_str(&format!(": {d}"));
            }
            (title, note)
        } else {
            let mut note = format!("{} XMP packet", human_size(c.size as u64));
            if let Some(tool) = xmp_creator_tool(&data) {
                note.push_str(&format!(", CreatorTool \"{tool}\""));
            }
            ("WebP XMP chunk".to_string(), note)
        };
        // The pad byte belongs to the chunk only when it is present.
        let len = c.padded_len().min(size - c.off);
        out.push(finding(
            sig,
            Category::Junk(kind),
            Confidence::Strong,
            Severity::Notice,
            title,
            Evidence::at(c.data_off())
                .with_bytes(excerpt(&data))
                .with_note(note),
            Some(Marker {
                region: Region::new(c.off, len),
                removal: RemovalStrategy::StructuralRemove,
                container: ContainerKind::RiffChunk,
                reversible: true,
            }),
        ));
    }
}

/// Structural removal of one top-level RIFF chunk ([`ContainerKind::RiffChunk`]).
///
/// `region` must be one whole chunk found by walking the RIFF file from offset
/// 12: the FourCC, the size field, the data and the pad byte that keeps the
/// next chunk on an even offset (the pad byte may be missing only at EOF).
/// Only metadata chunks are accepted, in WebP (`EXIF`, `XMP `, `C2PA`) and WAVE
/// (`LIST` of type `INFO`, `id3 `, `ID3 `, `_PMX`) files. The RIFF size field
/// shrinks by the removed length, and in WebP the matching VP8X feature flag
/// is cleared so the header no longer promises the chunk.
pub(super) fn remove_chunk(data: &[u8], region: Region) -> Option<Vec<u8>> {
    let view = MemView::new("", data.to_vec());
    let (form, chunks) = walk(&view)?;
    let c = chunks.iter().find(|c| c.off == region.offset)?;
    let full = c.padded_len();
    let at_eof_unpadded = c.data_off() + c.size as u64 == data.len() as u64;
    if region.len != full && !(at_eof_unpadded && region.len == full - 1) {
        return None;
    }
    let allowed = match (&form, &c.fourcc) {
        (b"WEBP", b"EXIF" | b"XMP ") => true,
        (b"WEBP", f) if provenance::is_c2pa_riff_chunk(f) => true,
        (b"WAVE", b"id3 " | b"ID3 " | b"_PMX") => true,
        (b"WAVE", b"LIST") => slice(data, c.data_off() as usize, 4).is_some_and(|t| t == b"INFO"),
        _ => false,
    };
    if !allowed {
        return None;
    }
    let s = usize::try_from(region.offset).ok()?;
    let e = usize::try_from(region.end()).ok()?;
    let mut out = Vec::with_capacity(data.len() - (e - s));
    out.extend_from_slice(data.get(..s)?);
    out.extend_from_slice(data.get(e..)?);
    let riff = u32_le(&out, 4)?.checked_sub(region.len as u32)?;
    out[4..8].copy_from_slice(&riff.to_le_bytes());
    if &form == b"WEBP" {
        let flag = match &c.fourcc {
            b"EXIF" => FLAG_EXIF,
            b"XMP " => FLAG_XMP,
            _ => 0,
        };
        if let Some(vp8x) = chunks.iter().find(|c| &c.fourcc == b"VP8X") {
            let at = vp8x.data_off() as usize;
            if at < s
                && let Some(b) = out.get_mut(at)
            {
                *b &= !flag;
            }
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::image::exif::build_tiff;
    use crate::parsers::image::probes;
    use crate::parsers::image::shared::testkit::{apply, garbage, run};

    fn chunk(fourcc: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let mut v = fourcc.to_vec();
        v.extend_from_slice(&(data.len() as u32).to_le_bytes());
        v.extend_from_slice(data);
        if data.len() % 2 == 1 {
            v.push(0);
        }
        v
    }

    fn riff(form: &[u8; 4], chunks: &[Vec<u8>]) -> Vec<u8> {
        let body: Vec<u8> = chunks.concat();
        let mut v = b"RIFF".to_vec();
        v.extend_from_slice(&((body.len() + 4) as u32).to_le_bytes());
        v.extend_from_slice(form);
        v.extend(body);
        v
    }

    fn webp(meta: &[Vec<u8>], flags: u8) -> Vec<u8> {
        let mut all = vec![chunk(b"VP8X", &[flags, 0, 0, 0, 0, 0, 0, 0, 0, 0])];
        all.push(chunk(
            b"VP8 ",
            &[0x30, 0x01, 0x00, 0x9D, 0x01, 0x2A, 1, 0, 1, 0],
        ));
        all.extend_from_slice(meta);
        riff(b"WEBP", &all)
    }

    fn scan(data: &[u8]) -> Vec<Finding> {
        run(probes(), "pic.webp", data, "webp")
    }

    #[test]
    fn exif_and_xmp_chunks_are_found_and_removed() {
        let exif = chunk(
            b"EXIF",
            &build_tiff(&[(0x010F, "Google"), (0x0110, "Pixel 8")], false),
        );
        let xmp = chunk(b"XMP ", b"<x xmp:CreatorTool=\"cwebp\"/>!");
        let data = webp(&[exif, xmp], FLAG_EXIF | FLAG_XMP);
        let fs = scan(&data);
        assert_eq!(fs.len(), 2);
        assert_eq!(fs[0].signature_id, "webp.exif");
        assert_eq!(fs[0].title, "WebP EXIF chunk (Google Pixel 8)");
        assert_eq!(fs[1].signature_id, "webp.xmp");
        assert!(fs[1].evidence.note.as_deref().unwrap().contains("cwebp"));
        for f in &fs {
            let m = f.marker.as_ref().unwrap();
            assert_eq!(m.region.len % 2, 0);
            let cleaned = apply(&data, f);
            let again = scan(&cleaned);
            assert_eq!(again.len(), 1);
            assert_ne!(again[0].signature_id, f.signature_id);
            let riff = u32::from_le_bytes(cleaned[4..8].try_into().unwrap()) as usize;
            assert_eq!(riff + 8, cleaned.len());
            let flags = cleaned[20];
            let gone = if f.signature_id == "webp.exif" {
                FLAG_EXIF
            } else {
                FLAG_XMP
            };
            assert_eq!(flags & gone, 0);
            assert_ne!(flags, 0);
        }
        let mut cur = data;
        while let Some(f) = scan(&cur).first().cloned() {
            cur = apply(&cur, &f);
        }
        assert_eq!(cur, webp(&[], 0));
    }

    #[test]
    fn c2pa_chunk_is_found_and_dropped() {
        let manifest = chunk(b"C2PA", b"   jumbc2pa-odd");
        let lower = chunk(b"c2pa", b"x");
        let exif = chunk(b"EXIF", &build_tiff(&[(0x0131, "x")], false));
        let data = webp(&[manifest, exif, lower], FLAG_EXIF);
        let fs = scan(&data);
        let c2 = fs
            .iter()
            .filter(|f| f.signature_id == "webp.c2pa")
            .collect::<Vec<_>>();
        assert_eq!(c2.len(), 2);
        assert_eq!(c2[0].title, "C2PA content credentials (WebP C2PA chunk)");
        assert_eq!(c2[0].category, Category::Junk(JunkKind::Provenance));
        let m = c2[0].marker.as_ref().unwrap();
        assert_eq!(m.container, ContainerKind::RiffChunk);
        assert_eq!(m.region.len % 2, 0);

        let mut cur = data.clone();
        while let Some(f) = scan(&cur)
            .into_iter()
            .find(|f| f.signature_id == "webp.c2pa")
        {
            cur = apply(&cur, &f);
            let riff = u32::from_le_bytes(cur[4..8].try_into().unwrap()) as usize;
            assert_eq!(riff + 8, cur.len());
            let (form, chunks) = walk(&MemView::new("", cur.clone())).unwrap();
            assert_eq!(&form, b"WEBP");
            assert_eq!(
                chunks.iter().map(|c| c.padded_len()).sum::<u64>() + 12,
                cur.len() as u64
            );
        }
        // The EXIF flag is untouched: only the manifest went.
        assert_eq!(cur[20], FLAG_EXIF);
        let rest = scan(&cur);
        assert_eq!(rest.len(), 1);
        assert_eq!(rest[0].signature_id, "webp.exif");
    }

    #[test]
    fn remover_scope() {
        let data = webp(&[chunk(b"EXIF", b"II*\0")], FLAG_EXIF);
        let (_, chunks) = walk(&MemView::new("", data.clone())).unwrap();
        for c in &chunks {
            let ok = remove_chunk(&data, Region::new(c.off, c.padded_len())).is_some();
            assert_eq!(ok, &c.fourcc == b"EXIF");
        }
        let wav = riff(
            b"WAVE",
            &[
                chunk(
                    b"fmt ",
                    &[1, 0, 1, 0, 0x44, 0xAC, 0, 0, 0x88, 0x58, 1, 0, 2, 0, 16, 0],
                ),
                chunk(b"LIST", b"INFOISFT\x05\0\0\0Lavf\0\0"),
                chunk(b"data", &[0, 0, 0, 0]),
            ],
        );
        let (_, chunks) = walk(&MemView::new("", wav.clone())).unwrap();
        let list = chunks[1];
        let out = remove_chunk(&wav, Region::new(list.off, list.padded_len())).unwrap();
        let (_, left) = walk(&MemView::new("", out.clone())).unwrap();
        assert_eq!(left.len(), 2);
        assert_eq!(
            u32::from_le_bytes(out[4..8].try_into().unwrap()) as usize + 8,
            out.len()
        );
        assert!(remove_chunk(&wav, Region::new(chunks[2].off, chunks[2].padded_len())).is_none());
        assert!(remove_chunk(&wav, Region::new(list.off, list.padded_len() - 2)).is_none());
    }

    #[test]
    fn garbage_and_truncation_are_safe() {
        let exif = chunk(b"EXIF", &build_tiff(&[(0x0131, "x")], false));
        let data = webp(&[exif], FLAG_EXIF);
        for cut in 0..data.len() {
            let _ = scan(&data[..cut]);
        }
        for seed in 0..32 {
            assert!(scan(&garbage(seed, 1024)).is_empty());
        }
        let mut g = b"RIFF\xff\xff\xff\xffWEBP".to_vec();
        g.extend(garbage(1, 256));
        let _ = scan(&g);
    }
}
