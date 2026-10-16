//! The undo journal: one JSON line per applied edit, recording how to invert
//! it. A blank or truncate stores only the original affected bytes (inline for
//! small regions, in trash otherwise), so undo is O(marker) even on a huge
//! file; only whole-file operations snapshot the file.
//!
//! The file is append-only between compactions. Three kinds of line exist:
//!
//! * a record (`UndoRecord`), written *before* the file it describes changes;
//! * a tombstone (`{"undone": <id>}`), appended after an inverse succeeds, or
//!   when an edit fails after its record was written, so the record is dead;
//! * anything else, which is kept byte for byte on every rewrite and reported,
//!   never silently dropped.
//!
//! [`Journal::compact`] rewrites the file atomically without dead records and
//! tombstones. Lines written by older builds (no fingerprints) still parse,
//! since every newer field has a serde default.

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::util::paths::journal_path;

/// How to reverse one edit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum UndoAction {
    /// Write `bytes_hex` back at `offset` (inverse of a small length-preserving blank).
    RestoreBytes { offset: u64, bytes_hex: String },
    /// Re-append the bytes saved at `tail_path`, restoring length (inverse of truncate).
    RestoreTail { from: u64, tail_path: PathBuf },
    /// Move the file back from `trash_path` (inverse of whole-file delete).
    RestoreFile { trash_path: PathBuf },
    /// Overwrite the file with the snapshot at `trash_path` (inverse of a
    /// structural rewrite or an external-editor change).
    RestoreSnapshot { trash_path: PathBuf },
    /// Write the `len` bytes saved at `trash_path` back at `offset` (inverse of
    /// a large length-preserving blank, too big to keep inline).
    RestoreRange {
        offset: u64,
        len: u64,
        trash_path: PathBuf,
    },
}

impl UndoAction {
    /// The trash file this action restores from, if any.
    pub fn trash_path(&self) -> Option<&Path> {
        match self {
            UndoAction::RestoreBytes { .. } => None,
            UndoAction::RestoreTail { tail_path, .. } => Some(tail_path),
            UndoAction::RestoreFile { trash_path }
            | UndoAction::RestoreSnapshot { trash_path }
            | UndoAction::RestoreRange { trash_path, .. } => Some(trash_path),
        }
    }
}

/// A cheap identity check for one state of a file: its size plus, optionally,
/// the blake3 of a span. The span is chosen per action: the blanked region, the
/// last bytes before a truncation point, or the whole file for snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fingerprint {
    /// File size in bytes.
    pub size: u64,
    /// Lowercase hex blake3 of `offset..offset + len`, when the span is checked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(default)]
    pub offset: u64,
    #[serde(default)]
    pub len: u64,
}

impl Fingerprint {
    /// A size-only fingerprint.
    pub fn size_only(size: u64) -> Self {
        Self {
            size,
            hash: None,
            offset: 0,
            len: 0,
        }
    }

    /// A fingerprint with a hashed span.
    pub fn span(size: u64, offset: u64, len: u64, hash: String) -> Self {
        Self {
            size,
            hash: Some(hash),
            offset,
            len,
        }
    }
}

/// One journal entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UndoRecord {
    pub id: u64,
    /// Bulk operations share a group id so one undo reverts the whole batch.
    pub group: u64,
    pub ts: u64,
    /// The absolute, canonical path of the edited file.
    pub path: PathBuf,
    /// The signature/marker this came from, for display.
    pub label: String,
    pub action: UndoAction,
    /// The file as it was before the edit. Lets undo recognise an edit that
    /// never landed (a crash between journaling and mutating).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<Fingerprint>,
    /// The file as the edit left it. Undo refuses with `Changed` when the
    /// current file no longer matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<Fingerprint>,
}

/// A tombstone line: the record with this id is dead (undone or never applied).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct Tombstone {
    undone: u64,
}

/// One line of the journal as read from disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalLine {
    Record(UndoRecord),
    /// The record with this id is dead.
    Undone(u64),
    /// A line that could not be parsed, kept verbatim (without its newline).
    Raw(Vec<u8>),
}

/// The parsed journal: live records plus the lines it could not read.
#[derive(Debug, Clone, Default)]
pub struct JournalState {
    /// Records not yet undone, oldest first.
    pub live: Vec<UndoRecord>,
    /// Unparseable lines, kept verbatim.
    pub raw: Vec<Vec<u8>>,
    /// Whether the file holds tombstones or dead records a compaction would drop.
    pub has_dead: bool,
}

/// The journal file.
pub struct Journal {
    path: PathBuf,
}

impl Journal {
    /// Open the journal at the default location (`util::paths::journal_path`).
    pub fn open() -> io::Result<Self> {
        Self::open_at(journal_path())
    }

    /// Open the journal at an explicit path, creating its parent directory.
    pub fn open_at(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        Ok(Self { path })
    }

    /// Where the journal lives.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Every line, in file order. A missing file is empty.
    pub fn load(&self) -> io::Result<Vec<JournalLine>> {
        let bytes = match fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut out = Vec::new();
        for line in bytes.split(|&b| b == b'\n') {
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            out.push(parse_line(line));
        }
        Ok(out)
    }

    /// Live records, unparseable lines, and whether compaction would help.
    pub fn state(&self) -> io::Result<JournalState> {
        Ok(fold(&self.load()?))
    }

    /// All live records, oldest first. Missing file = empty.
    pub fn records(&self) -> io::Result<Vec<UndoRecord>> {
        Ok(self.state()?.live)
    }

    /// The lines that could not be parsed, verbatim.
    pub fn unparsed(&self) -> io::Result<Vec<Vec<u8>>> {
        Ok(self.state()?.raw)
    }

    /// Next free record id (max id ever written + 1).
    pub fn next_id(&self) -> io::Result<u64> {
        let max = self
            .load()?
            .iter()
            .filter_map(|l| match l {
                JournalLine::Record(r) => Some(r.id),
                JournalLine::Undone(id) => Some(*id),
                JournalLine::Raw(_) => None,
            })
            .max();
        Ok(max.map(|m| m + 1).unwrap_or(1))
    }

    /// Append one record and fsync.
    pub fn append(&self, rec: &UndoRecord) -> io::Result<()> {
        let line = serde_json::to_string(rec).map_err(io::Error::other)?;
        self.append_line(&line)
    }

    /// Append a tombstone for `id` and fsync.
    pub fn mark_undone(&self, id: u64) -> io::Result<()> {
        let line = serde_json::to_string(&Tombstone { undone: id }).map_err(io::Error::other)?;
        self.append_line(&line)
    }

    fn append_line(&self, line: &str) -> io::Result<()> {
        let mut f = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&self.path)?;
        // A crash mid-append can leave a line without its newline; never glue
        // a new record onto it.
        let len = f.metadata()?.len();
        let mut buf = String::with_capacity(line.len() + 2);
        if len > 0 {
            let mut last = [0u8; 1];
            f.seek(SeekFrom::Start(len - 1))?;
            f.read_exact(&mut last)?;
            if last[0] != b'\n' {
                buf.push('\n');
            }
        }
        buf.push_str(line);
        buf.push('\n');
        f.write_all(buf.as_bytes())?;
        f.sync_all()
    }

    /// Rewrite the journal with exactly `records` as its live set. Unparseable
    /// lines already in the file are kept verbatim, ahead of the records.
    pub fn rewrite(&self, records: &[UndoRecord]) -> io::Result<()> {
        let raw = self.state()?.raw;
        let mut lines: Vec<JournalLine> = raw.into_iter().map(JournalLine::Raw).collect();
        lines.extend(records.iter().cloned().map(JournalLine::Record));
        self.write_lines(&lines)
    }

    /// Drop dead records and tombstones, keeping live records and unparseable
    /// lines in their original order. Returns the number of unparseable lines.
    pub fn compact(&self) -> io::Result<usize> {
        let lines = self.load()?;
        let state = fold(&lines);
        if !state.has_dead {
            return Ok(state.raw.len());
        }
        let live_ids: Vec<u64> = state.live.iter().map(|r| r.id).collect();
        let kept: Vec<JournalLine> = lines
            .into_iter()
            .filter(|l| match l {
                JournalLine::Record(r) => live_ids.contains(&r.id),
                JournalLine::Undone(_) => false,
                JournalLine::Raw(_) => true,
            })
            .collect();
        self.write_lines(&kept)?;
        Ok(state.raw.len())
    }

    fn write_lines(&self, lines: &[JournalLine]) -> io::Result<()> {
        let mut buf: Vec<u8> = Vec::new();
        for line in lines {
            match line {
                JournalLine::Record(r) => {
                    buf.extend_from_slice(
                        serde_json::to_string(r)
                            .map_err(io::Error::other)?
                            .as_bytes(),
                    );
                }
                JournalLine::Undone(id) => {
                    buf.extend_from_slice(
                        serde_json::to_string(&Tombstone { undone: *id })
                            .map_err(io::Error::other)?
                            .as_bytes(),
                    );
                }
                JournalLine::Raw(bytes) => buf.extend_from_slice(bytes),
            }
            buf.push(b'\n');
        }
        if buf.is_empty() && !self.path.exists() {
            return Ok(());
        }
        super::fsio::replace_atomic(&self.path, &buf)
    }
}

fn parse_line(line: &[u8]) -> JournalLine {
    if let Ok(rec) = serde_json::from_slice::<UndoRecord>(line) {
        return JournalLine::Record(rec);
    }
    if let Ok(t) = serde_json::from_slice::<Tombstone>(line) {
        return JournalLine::Undone(t.undone);
    }
    JournalLine::Raw(line.to_vec())
}

fn fold(lines: &[JournalLine]) -> JournalState {
    let dead: Vec<u64> = lines
        .iter()
        .filter_map(|l| match l {
            JournalLine::Undone(id) => Some(*id),
            _ => None,
        })
        .collect();
    let mut state = JournalState {
        has_dead: !dead.is_empty(),
        ..JournalState::default()
    };
    for line in lines {
        match line {
            JournalLine::Record(r) if !dead.contains(&r.id) => state.live.push(r.clone()),
            JournalLine::Record(_) | JournalLine::Undone(_) => {}
            JournalLine::Raw(b) => state.raw.push(b.clone()),
        }
    }
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: u64, group: u64) -> UndoRecord {
        UndoRecord {
            id,
            group,
            ts: 1,
            path: PathBuf::from("/x/file.bin"),
            label: "t".into(),
            action: UndoAction::RestoreBytes {
                offset: 4,
                bytes_hex: "00ff".into(),
            },
            before: None,
            after: Some(Fingerprint::size_only(10)),
        }
    }

    #[test]
    fn old_lines_without_fingerprints_still_parse() {
        let line = br#"{"id":3,"group":2,"ts":9,"path":"/a/b","label":"zip.comment","action":{"action":"restore_bytes","offset":5,"bytes_hex":"6869"}}"#;
        match parse_line(line) {
            JournalLine::Record(r) => {
                assert_eq!(r.id, 3);
                assert!(r.before.is_none() && r.after.is_none());
            }
            other => panic!("expected a record, got {other:?}"),
        }
    }

    #[test]
    fn tombstones_kill_records_and_compaction_keeps_raw_lines() {
        let dir = tempfile::tempdir().unwrap();
        let j = Journal::open_at(dir.path().join("j.jsonl")).unwrap();
        j.append(&rec(1, 1)).unwrap();
        // A torn line with no newline, as a crash mid-append would leave.
        let mut f = OpenOptions::new().append(true).open(j.path()).unwrap();
        f.write_all(b"{\"id\":2,\"gro").unwrap();
        drop(f);
        j.append(&rec(3, 2)).unwrap();
        j.mark_undone(1).unwrap();

        let st = j.state().unwrap();
        assert_eq!(st.live.iter().map(|r| r.id).collect::<Vec<_>>(), vec![3]);
        assert_eq!(st.raw, vec![b"{\"id\":2,\"gro".to_vec()]);
        assert!(st.has_dead);
        assert_eq!(j.next_id().unwrap(), 4);

        assert_eq!(j.compact().unwrap(), 1);
        let text = fs::read_to_string(j.path()).unwrap();
        assert!(text.contains("{\"id\":2,\"gro\n"), "raw line kept verbatim");
        assert!(!text.contains("undone"));
        assert_eq!(j.records().unwrap().len(), 1);

        j.rewrite(&[]).unwrap();
        assert!(j.records().unwrap().is_empty());
        assert_eq!(j.unparsed().unwrap().len(), 1);
    }
}
