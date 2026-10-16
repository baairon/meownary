//! Command-line surface: argument parsing and the no-TUI runners.

pub mod args;
pub mod headless;

pub use args::{Command, HELP_TEXT, exit, parse};
