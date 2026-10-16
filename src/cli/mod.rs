//! Command-line surface: argument parsing, the no-TUI runners, and the small
//! styling helper they share.

pub mod args;
pub mod headless;
pub mod style;

pub use args::{Command, HELP_TEXT, exit, parse};
