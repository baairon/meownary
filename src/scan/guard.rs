//! The per-file guard. A single malformed, truncated, or hostile file must
//! never take down the scan, so each file's probes run inside `catch_unwind`.
//! Because every read is bounded (see `reader`), a probe cannot hang on size
//! alone; a panic is converted into a partial result.

use std::panic::{AssertUnwindSafe, catch_unwind};

/// Run `f`, catching any panic. `Ok` on success, `Err` when the closure
/// panicked (the caller marks the file's report partial and moves on).
pub fn guarded<T>(f: impl FnOnce() -> T) -> Result<T, ()> {
    catch_unwind(AssertUnwindSafe(f)).map_err(|_| ())
}
