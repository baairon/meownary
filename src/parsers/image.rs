//! Image probes (`jpeg`, `png`, `gif`, `webp`, `bmp`): metadata segments and
//! chunks (EXIF, XMP, IPTC, comments, text chunks), the encoder hints they
//! carry, and bytes appended after the image's declared end. BMP has nothing
//! worth reporting and is accepted only so the gate stays uniform.
//!
//! Structural removers live here for JPEG segments, PNG chunks and RIFF
//! chunks; [`structural_remove`] picks one from the file's magic bytes.

pub(crate) mod exif;
mod gif;
mod jpeg;
mod png;
pub(crate) mod shared;
mod webp;

use crate::model::{Finding, Region};
use crate::scan::{Probe, ProbeCtx};

struct ImageProbe;

impl Probe for ImageProbe {
    fn id(&self) -> &'static str {
        "image"
    }

    fn formats(&self) -> &'static [&'static str] {
        &["jpeg", "png", "gif", "webp", "bmp"]
    }

    fn run(&self, ctx: &ProbeCtx, out: &mut Vec<Finding>) {
        match ctx.format {
            Some("jpeg") => jpeg::run(ctx.view, out),
            Some("png") => png::run(ctx.view, out),
            Some("gif") => gif::run(ctx.view, out),
            Some("webp") => webp::run(ctx.view, out),
            _ => {}
        }
    }
}

/// Probes contributed by this module.
pub fn probes() -> Vec<Box<dyn Probe>> {
    vec![Box::new(ImageProbe)]
}

/// Structure-aware removal for the image containers, chosen by magic bytes:
///
/// * PNG ([`crate::model::ContainerKind::PngChunk`]): `region` is one whole
///   ancillary chunk after IHDR; the chunk is dropped.
/// * JPEG ([`crate::model::ContainerKind::JpegApp1`] and
///   [`crate::model::ContainerKind::JpegSegment`]): `region` is one whole APP1,
///   APP13 or COM segment before SOS, from its `FF xx` marker on; the segment
///   is dropped.
/// * RIFF ([`crate::model::ContainerKind::RiffChunk`]): `region` is one whole
///   top-level metadata chunk including its pad byte, in a WebP or WAVE file;
///   the chunk is dropped, the RIFF size is reduced, and WebP's VP8X flag for
///   that chunk is cleared.
///
/// Returns `None` (changing nothing) when the region does not match exactly.
pub fn structural_remove(data: &[u8], region: Region) -> Option<Vec<u8>> {
    if region.offset == 0 || region.len == 0 {
        return None;
    }
    if data.starts_with(&png::SIG) {
        png::remove_chunk(data, region)
    } else if data.starts_with(&[0xFF, 0xD8]) {
        jpeg::remove_segment(data, region)
    } else if data.starts_with(b"RIFF") {
        webp::remove_chunk(data, region)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::image::shared::testkit::run;

    #[test]
    fn bmp_and_unknown_inputs_are_quiet() {
        let bmp = b"BM\x3a\0\0\0\0\0\0\0\x36\0\0\0\x28\0\0\0".to_vec();
        assert!(run(probes(), "a.bmp", &bmp, "bmp").is_empty());
        assert!(structural_remove(b"BMxxxx", Region::new(1, 1)).is_none());
        assert!(structural_remove(b"", Region::new(1, 1)).is_none());
    }
}
