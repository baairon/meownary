//! The probe collection. `identify` names a file's true format; `registry`
//! returns every format-specific and cross-cutting probe the scan runs.
//!
//! Each probe module is owned by one stream and exposes `probes()`. The scan
//! gates each probe by `Probe::formats`, so a probe that only understands PE
//! never touches a JPEG.

pub mod identity;

pub mod archive;
pub mod catalog_probe;
pub mod deception;
pub mod doc;
pub mod elf;
pub mod image;
pub mod macho;
pub mod media;
pub mod pe;
pub mod provenance;
pub mod text;
pub mod zip;

use crate::model::Finding;
use crate::scan::{FileView, Registry};

/// Identify a file's true format and any identity-level findings.
pub fn identify(view: &dyn FileView) -> (Option<&'static str>, Vec<Finding>) {
    identity::identify(view)
}

/// Build the probe registry by collecting every module's probes.
pub fn registry() -> Registry {
    let mut probes: Registry = Vec::new();
    probes.extend(pe::probes());
    probes.extend(elf::probes());
    probes.extend(macho::probes());
    probes.extend(zip::probes());
    probes.extend(archive::probes());
    probes.extend(media::probes());
    probes.extend(image::probes());
    probes.extend(doc::probes());
    probes.extend(text::probes());
    probes.extend(deception::probes());
    probes.extend(catalog_probe::probes());
    probes
}
