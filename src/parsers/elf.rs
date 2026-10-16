//! Probes for the elf stream. Implemented by a dedicated agent; the module is
//! pre-declared and wired into the registry so it compiles while empty.

use crate::model::Region;
use crate::scan::Probe;

/// Probes contributed by this module. Empty until implemented.
pub fn probes() -> Vec<Box<dyn Probe>> {
    Vec::new()
}

/// Structure-aware removal for the containers this module owns. Returns a
/// rewritten copy of `data` with `region` dropped and the container kept
/// valid, or `None` when no remover exists yet (the engine then changes
/// nothing).
pub fn structural_remove(_data: &[u8], _region: Region) -> Option<Vec<u8>> {
    None
}
