//! Screens split out of `ui`, one file per part of the view, so each has a
//! single owner: the picker, the main screen's files and findings panes, and
//! the status row.

#![cfg(feature = "tui")]

pub mod files;
pub mod picker;
pub mod status;
