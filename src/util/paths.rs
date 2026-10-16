//! Where meownary keeps its state (the trash store and the undo journal).
//! Overridable with `MEOWNARY_STATE_DIR` so tests never touch real user data.

use std::path::PathBuf;

/// The base state directory. Honors `MEOWNARY_STATE_DIR`, else the per-OS data
/// dir, else a temp fallback.
pub fn state_dir() -> PathBuf {
    if let Ok(p) = std::env::var("MEOWNARY_STATE_DIR") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    directories::ProjectDirs::from("dev", "bairon", "meownary")
        .map(|d| d.data_dir().to_path_buf())
        .unwrap_or_else(|| std::env::temp_dir().join("meownary"))
}

/// The trash store root (original bytes are snapshotted here before edits).
pub fn trash_dir() -> PathBuf {
    state_dir().join("trash")
}

/// The append-only undo journal file.
pub fn journal_path() -> PathBuf {
    state_dir().join("undo-journal.jsonl")
}
