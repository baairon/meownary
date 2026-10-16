//! meownary engine + CLI as a library, so the whole thing is unit-testable
//! without a terminal. The binary in `src/main.rs` is a thin dispatcher.

pub mod catalog;
pub mod cli;
pub mod edit;
pub mod model;
pub mod parsers;
pub mod scan;
pub mod util;

#[cfg(feature = "tui")]
pub mod tui;
