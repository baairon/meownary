//! The interactive terminal view and the theme/keymap it is built on.
//!
//! `app` is the state machine (no terminal), `ui` draws it, `runtime` owns the
//! terminal, the frame clock and the edit engine, and `preview` renders the
//! same drawing code to animated SVG for the README.
//!
//! `picker` is the first-run file browser. `listing` reads one folder from
//! its directory listing alone, for the views that browse folders, and `bg`
//! runs work that must not block the input thread. `tree` adds a scan's
//! reports up per folder, and `explorer` lays out the folder the files list
//! shows.

#![cfg(feature = "tui")]

pub mod app;
pub mod bg;
pub mod explorer;
pub mod keymap;
pub mod listing;
pub mod logo;
pub mod picker;
pub mod preview;
pub mod runtime;
pub mod theme;
pub mod tree;
pub mod ui;

pub use app::run;
