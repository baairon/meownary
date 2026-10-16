//! The edit subsystem: trash-backed, reversible removal of marker bytes, whole
//! files, and external-editor changes. Nothing here is destructive without a
//! snapshot and a journal entry written first, so every action has a one-key
//! undo. See `engine` for the record-before-mutate protocol and `lock` for how
//! two meownary processes are kept from interleaving. Deattribution is the one
//! exception to the trash: it never writes the original, only a copy beside it
//! (see `deattribute`), so it needs neither the store nor an undo.

pub mod deattribute;
pub mod engine;
pub mod external;
mod fsio;
pub mod journal;
pub mod lock;
pub mod safety;
pub mod structural;
pub mod trash;

#[cfg(test)]
mod tests;

pub use engine::{Applied, EditEngine, EditError, UndoReport};
pub use external::{editor_command, editor_command_from, spawn_editor, split_command};
pub use journal::{Fingerprint, Journal, JournalLine, UndoAction, UndoRecord};
pub use safety::{Risk, assess};
pub use trash::Trash;

/// Canonical absolute form of an existing path, without the Windows verbatim
/// prefix on plain drive paths: the form the journal records.
#[cfg(feature = "tui")]
pub(crate) use fsio::canonical as canonical_path;
