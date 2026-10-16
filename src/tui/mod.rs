//! The interactive terminal view and the theme/keymap it is built on.
//!
//! `app` is the state machine (no terminal), `ui` draws it, `widgets` holds
//! the small drawing pieces the views share (the thin progress bar),
//! `runtime` owns the terminal, the frame clock and the edit engine, and
//! `preview` renders the same drawing code to animated SVG for the README
//! through `svg`.
//!
//! `picker` is the first-run file browser. `listing` reads one folder from
//! its directory listing alone, for the views that browse folders, and `bg`
//! runs work that must not block the input thread. `views` holds the parts
//! of the drawing split out of `ui`, one owner each, `progress` carries
//! live progress from the workers to the activity row, `tree` adds a scan's
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
pub mod progress;
pub mod runtime;
pub mod svg;
pub mod theme;
pub mod tree;
pub mod ui;
pub mod views;
pub mod widgets;

pub use app::run;
