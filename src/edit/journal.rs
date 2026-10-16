//! The append-only undo journal. Each applied edit writes one JSON line
//! recording how to invert it. The key efficiency move: a blank or truncate
//! stores only the *original affected bytes* (inline or in trash), so undo is
//! O(marker) even on a huge file; only whole-file operations snapshot the file.

use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::util::paths::journal_path;

/// How to reverse one edit.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum UndoAction {
    /// Write `bytes_hex` back at `offset` (inverse of a length-preserving blank).
    RestoreBytes { offset: u64, bytes_hex: String },
    /// Re-append the bytes saved at `tail_path`, restoring length (inverse of truncate).
    RestoreTail { from: u64, tail_path: PathBuf },
    /// Move the file back from `trash_path` (inverse of whole-file delete).
    RestoreFile { trash_path: PathBuf },
    /// Overwrite the file with the snapshot at `trash_path` (inverse of a
    /// structural rewrite or an external-editor change).
    RestoreSnapshot { trash_path: PathBuf },
}

/// One journal entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UndoRecord {
    pub id: u64,
    /// Bulk operations share a group id so one undo reverts the whole batch.
    pub group: u64,
    pub ts: u64,
    pub path: PathBuf,
    /// The signature/marker this came from, for display.
    pub label: String,
    pub action: UndoAction,
}

/// The journal file (append-only, rewritten only to drop undone records).
pub struct Journal {
    path: PathBuf,
}

impl Journal {
    pub fn open() -> io::Result<Self> {
        let path = journal_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(Self { path })
    }

    /// All records, oldest first. Missing file = empty.
    pub fn records(&self) -> io::Result<Vec<UndoRecord>> {
        let file = match fs::File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut out = Vec::new();
        for line in BufReader::new(file).lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(rec) = serde_json::from_str::<UndoRecord>(&line) {
                out.push(rec);
            }
        }
        Ok(out)
    }

    /// Next free record id (max existing + 1).
    pub fn next_id(&self) -> io::Result<u64> {
        Ok(self
            .records()?
            .iter()
            .map(|r| r.id)
            .max()
            .map(|m| m + 1)
            .unwrap_or(1))
    }

    /// Append one record.
    pub fn append(&self, rec: &UndoRecord) -> io::Result<()> {
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let line = serde_json::to_string(rec).map_err(io::Error::other)?;
        writeln!(f, "{line}")?;
        f.sync_all()?;
        Ok(())
    }

    /// Rewrite the journal with exactly `records` (used after an undo drops the
    /// records it reverted).
    pub fn rewrite(&self, records: &[UndoRecord]) -> io::Result<()> {
        let mut buf = String::new();
        for rec in records {
            buf.push_str(&serde_json::to_string(rec).map_err(io::Error::other)?);
            buf.push('\n');
        }
        crate::util::atomic::write_atomic(&self.path, buf.as_bytes())
    }
}
