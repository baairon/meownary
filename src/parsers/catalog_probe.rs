//! Probes for the catalog_probe stream. Implemented by a dedicated agent; the module is
//! pre-declared and wired into the registry so it compiles while empty.

use crate::scan::Probe;

/// Probes contributed by this module. Empty until implemented.
pub fn probes() -> Vec<Box<dyn Probe>> {
    Vec::new()
}
