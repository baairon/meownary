//! Small drawing pieces the views share. Like the rest of `ui`, each one
//! paints straight into a ratatui `Buffer` and takes every style from the
//! [`Look`](super::theme::Look), so the live terminal and the README
//! previews draw them the same way.

#![cfg(feature = "tui")]

pub mod gauge;

pub use gauge::Gauge;
