//! The per-file guard. A single malformed, truncated, or hostile file must
//! never take down the scan, so each file's probes run inside `catch_unwind`.
//! Because every read is bounded (see `reader`), a probe cannot hang on size
//! alone; a panic is converted into a partial result.
//!
//! While a guarded closure runs, [`in_guard`] reports `true` on that thread, so
//! the binary's panic hook can stay quiet about panics the guard is about to
//! catch and report as a partial file.

use std::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind};

thread_local! {
    /// Nesting depth of guarded regions on this thread.
    static DEPTH: Cell<u32> = const { Cell::new(0) };
}

/// Restores the depth counter even if the closure unwinds.
struct Depth;

impl Depth {
    fn enter() -> Self {
        DEPTH.with(|d| d.set(d.get().saturating_add(1)));
        Depth
    }
}

impl Drop for Depth {
    fn drop(&mut self) {
        DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
    }
}

/// Run `f`, catching any panic. `Ok` on success, `Err` when the closure
/// panicked (the caller marks the file's report partial and moves on).
#[allow(clippy::result_unit_err)] // public signature kept stable; the error carries nothing
pub fn guarded<T>(f: impl FnOnce() -> T) -> Result<T, ()> {
    let depth = Depth::enter();
    let result = catch_unwind(AssertUnwindSafe(f)).map_err(|_| ());
    drop(depth);
    result
}

/// Whether the current thread is inside [`guarded`]. A panic hook uses this to
/// skip printing for panics the guard will catch.
pub fn in_guard() -> bool {
    DEPTH.with(|d| d.get() > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ok_passes_through() {
        assert_eq!(guarded(|| 7), Ok(7));
        assert!(!in_guard());
    }

    #[test]
    fn panic_becomes_err_and_depth_resets() {
        // libtest captures the default hook's message for this test thread.
        let seen = guarded(|| {
            assert!(in_guard());
            let v: Vec<u8> = Vec::new();
            v.get(3)
                .copied()
                .map(u32::from)
                .unwrap_or_else(|| panic!("boom"))
        });
        assert_eq!(seen, Err(()));
        assert!(!in_guard());
    }

    #[test]
    fn nested_guards_track_depth() {
        let inner = guarded(|| guarded(in_guard));
        assert_eq!(inner, Ok(Ok(true)));
        assert!(!in_guard());
    }
}
