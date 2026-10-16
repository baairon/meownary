//! Archive and compression probes (`rar`, `7z`, `gzip`, `xz`, `zstd`, `bzip2`,
//! `tar`): header strings that leak names and comments (gzip FNAME and
//! FCOMMENT, RAR comments, tar owners), encryption combined with a password in
//! the file name, and plain format facts. Nothing is decompressed.
//!
//! The only structural remover here is the tar owner scrub; gzip and RAR
//! markers are length-preserving blanks.

mod gzip;
mod rar;
mod sevenz;
mod stream;
mod tar;

use crate::model::{Finding, Region};
use crate::scan::{Probe, ProbeCtx};

struct ArchiveProbe;

impl Probe for ArchiveProbe {
    fn id(&self) -> &'static str {
        "archive"
    }

    fn formats(&self) -> &'static [&'static str] {
        &["rar", "7z", "gzip", "xz", "zstd", "bzip2", "tar"]
    }

    fn run(&self, ctx: &ProbeCtx, out: &mut Vec<Finding>) {
        match ctx.format {
            Some("gzip") => gzip::run(ctx.view, out),
            Some("rar") => rar::run(ctx.view, out),
            Some("7z") => sevenz::run(ctx.view, out),
            Some("tar") => tar::run(ctx.view, out),
            Some("xz") => stream::xz(ctx.view, out),
            Some("zstd") => stream::zstd(ctx.view, out),
            Some("bzip2") => stream::bzip2(ctx.view, out),
            _ => {}
        }
    }
}

/// Probes contributed by this module.
pub fn probes() -> Vec<Box<dyn Probe>> {
    vec![Box::new(ArchiveProbe)]
}

/// Structure-aware removal for the archive containers.
///
/// * [`crate::model::ContainerKind::TarHeader`]: `region` is the 64 bytes of
///   `uname` and `gname` in one ustar header (header offset + 265). Both names
///   become NUL and that header's checksum is recomputed; the file keeps its
///   length.
/// * [`crate::model::ContainerKind::GzipHeader`] and
///   [`crate::model::ContainerKind::RarBlock`]: no structural remover; their
///   markers are in-place blanks, so this returns `None`.
pub fn structural_remove(data: &[u8], region: Region) -> Option<Vec<u8>> {
    if data.get(257..262) == Some(b"ustar") {
        return tar::remove_owner(data, region);
    }
    None
}
