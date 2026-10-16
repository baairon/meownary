//! Document probes (`pdf`, `ooxml`, `cfb`, `msi`): the tool and author names a
//! document carries in its metadata, incremental updates, and encryption.
//!
//! * PDF: the trailer's `/Info` dictionary and any `/Producer` or `/Creator`
//!   string, found in the header and tail windows (the whole file when it is
//!   at most 4 MiB), plus the Info object itself when a classic xref table
//!   points outside those windows. Nothing is decompressed.
//! * OOXML: `docProps/app.xml` and `docProps/core.xml`, read only when they
//!   are stored uncompressed, else the package kind from its entry names.
//! * CFB (legacy Office and MSI): the class named by the directory, and the
//!   `\x05SummaryInformation` property set when it lives in regular sectors.
//!
//! Every marker here is a length-preserving in-place blank, so this module
//! ships no structural remover.

mod cfb;
mod ooxml;
mod pdf;

use crate::model::{Finding, Region};
use crate::scan::{Probe, ProbeCtx};

struct DocProbe;

impl Probe for DocProbe {
    fn id(&self) -> &'static str {
        "doc"
    }

    fn formats(&self) -> &'static [&'static str] {
        &["pdf", "ooxml", "cfb", "msi"]
    }

    fn run(&self, ctx: &ProbeCtx, out: &mut Vec<Finding>) {
        match ctx.format {
            Some("pdf") => pdf::run(ctx.view, out),
            Some("ooxml") => ooxml::run(ctx.view, out),
            Some("cfb" | "msi") => cfb::run(ctx.view, out),
            _ => {}
        }
    }
}

/// Probes contributed by this module.
pub fn probes() -> Vec<Box<dyn Probe>> {
    vec![Box::new(DocProbe)]
}

/// Structure-aware removal for [`crate::model::ContainerKind::PdfObject`] and
/// [`crate::model::ContainerKind::CfbStream`].
///
/// Neither has a structural remover: PDF string values and CFB property
/// strings are blanked in place (`RawBlank`), which keeps every xref offset,
/// sector chain and length field valid. This always returns `None`, so the
/// engine reports a structural edit of these containers as unsupported and
/// changes nothing.
pub fn structural_remove(_data: &[u8], _region: Region) -> Option<Vec<u8>> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::image::shared::testkit::{garbage, run};

    #[test]
    fn unknown_formats_and_garbage_are_quiet() {
        for fmt in ["pdf", "ooxml", "cfb", "msi"] {
            for seed in 0..16 {
                assert!(run(probes(), "g.bin", &garbage(seed, 4096), fmt).is_empty());
            }
            assert!(run(probes(), "e.bin", b"", fmt).is_empty());
        }
        assert!(structural_remove(b"%PDF-1.7", Region::new(1, 1)).is_none());
    }
}
