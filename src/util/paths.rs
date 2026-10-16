//! Where meownary keeps its state (the trash store and the undo journal).
//! Overridable with `MEOWNARY_STATE_DIR` so tests never touch real user data.

use std::ffi::OsString;
use std::path::PathBuf;

/// The base state directory. Honors `MEOWNARY_STATE_DIR` when set and
/// non-empty, else the per-OS data dir, else `meownary` under the temp dir.
pub fn state_dir() -> PathBuf {
    let data = directories::ProjectDirs::from("dev", "bairon", "meownary")
        .map(|d| d.data_dir().to_path_buf());
    resolve(std::env::var_os("MEOWNARY_STATE_DIR"), data)
}

/// The choice behind [`state_dir`], kept pure for tests.
fn resolve(env: Option<OsString>, data_dir: Option<PathBuf>) -> PathBuf {
    if let Some(p) = env
        && !p.is_empty()
    {
        return PathBuf::from(p);
    }
    data_dir.unwrap_or_else(|| std::env::temp_dir().join("meownary"))
}

/// The trash store root (original bytes are snapshotted here before edits).
pub fn trash_dir() -> PathBuf {
    state_dir().join("trash")
}

/// The append-only undo journal file.
pub fn journal_path() -> PathBuf {
    state_dir().join("undo-journal.jsonl")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_override_wins_when_non_empty() {
        let data = Some(PathBuf::from("data"));
        assert_eq!(
            resolve(Some(OsString::from("custom")), data.clone()),
            PathBuf::from("custom")
        );
        assert_eq!(
            resolve(Some(OsString::new()), data.clone()),
            PathBuf::from("data")
        );
        assert_eq!(resolve(None, data), PathBuf::from("data"));
    }

    #[test]
    fn temp_fallback_without_a_data_dir() {
        assert_eq!(resolve(None, None), std::env::temp_dir().join("meownary"));
    }

    #[test]
    fn trash_and_journal_live_under_the_state_dir() {
        assert!(trash_dir().starts_with(state_dir()));
        assert!(journal_path().starts_with(state_dir()));
    }
}
