//! The edit subsystem: trash-backed, reversible removal of marker bytes, whole
//! files, and external-editor changes. Nothing here is destructive without a
//! snapshot and a journal entry, so every action has a one-key undo.

pub mod engine;
pub mod external;
pub mod journal;
pub mod safety;
pub mod structural;
pub mod trash;

pub use engine::{Applied, EditEngine, EditError};
pub use external::{editor_command, spawn_editor};
pub use journal::{Journal, UndoAction, UndoRecord};
pub use safety::{Risk, assess};
pub use trash::Trash;
