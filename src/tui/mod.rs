//! The interactive terminal view and the theme/keymap it is built on.

#![cfg(feature = "tui")]

pub mod app;
pub mod keymap;
pub mod logo;
pub mod theme;

pub use app::run;
