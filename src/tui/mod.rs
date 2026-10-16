//! The interactive terminal view and the theme/keymap it is built on.
//!
//! `app` is the state machine (no terminal), `ui` draws it, `runtime` owns the
//! terminal, the frame clock and the edit engine, and `preview` renders the
//! same drawing code to animated SVG for the README.

#![cfg(feature = "tui")]

pub mod app;
pub mod keymap;
pub mod logo;
pub mod picker;
pub mod preview;
pub mod runtime;
pub mod theme;
pub mod ui;

pub use app::run;
