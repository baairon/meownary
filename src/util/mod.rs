//! Cross-cutting helpers with no domain logic.

pub mod atomic;
// The backbone readers are frozen for this release and use `chunks_exact`,
// which this lint (active from the 1.88 MSRV) would rewrite to `as_chunks`.
#[allow(clippy::chunks_exact_to_as_chunks)]
pub mod bytes;
pub mod fmt;
pub mod hash;
pub mod paths;
