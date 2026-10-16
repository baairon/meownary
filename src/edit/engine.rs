//! Apply and reverse edits. The engine owns the trash store and the undo
//! journal; `apply` snapshots exactly what it needs, performs the edit, and
//! records how to invert it, and `undo` replays those inverses newest-first.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::model::{Marker, RemovalStrategy};

use super::journal::{Journal, UndoAction, UndoRecord};
use super::safety::{self, Risk};
use super::trash::Trash;

#[derive(Debug)]
pub enum EditError {
    /// The edit was refused as corrupting; never applied.
    Refused(String),
    /// A `Warn`-level edit attempted without `force`.
    NeedsForce(String),
    /// The bytes changed since the scan (TOCTOU); re-scan and retry.
    Changed,
    /// This strategy/container is not implemented yet (safe no-op).
    Unsupported(String),
    Io(io::Error),
}

impl fmt::Display for EditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EditError::Refused(r) => write!(f, "refused: {r}"),
            EditError::NeedsForce(r) => write!(f, "needs force: {r}"),
            EditError::Changed => write!(f, "file changed since scan"),
            EditError::Unsupported(r) => write!(f, "unsupported: {r}"),
            EditError::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for EditError {}

impl From<io::Error> for EditError {
    fn from(e: io::Error) -> Self {
        EditError::Io(e)
    }
}

/// The outcome of one successful `apply`.
#[derive(Debug, Clone)]
pub struct Applied {
    pub undo_id: u64,
    pub group: u64,
    pub path: PathBuf,
    pub label: String,
}

/// Owns the trash store and journal and performs every mutating operation.
pub struct EditEngine {
    trash: Trash,
    journal: Journal,
    next_id: u64,
    next_group: u64,
    cur_group: u64,
}

impl EditEngine {
    pub fn new() -> io::Result<Self> {
        let journal = Journal::open()?;
        let records = journal.records()?;
        let next_id = records
            .iter()
            .map(|r| r.id)
            .max()
            .map(|m| m + 1)
            .unwrap_or(1);
        let next_group = records
            .iter()
            .map(|r| r.group)
            .max()
            .map(|m| m + 1)
            .unwrap_or(1);
        Ok(Self {
            trash: Trash::new()?,
            journal,
            next_id,
            next_group,
            cur_group: 0,
        })
    }

    /// Start a new bulk group; every `apply` until the next `begin_group`
    /// shares this id, so one `undo_last` reverts the whole batch.
    pub fn begin_group(&mut self) -> u64 {
        self.cur_group = self.next_group;
        self.next_group += 1;
        self.cur_group
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Apply the removal described by `marker` to `path`.
    ///
    /// * `format` and `size` feed the risk assessment.
    /// * `expected_region_hash` (if given) must match the current bytes, else
    ///   the edit is refused with [`EditError::Changed`].
    /// * `force` permits `Warn`-level edits (the TUI passes it after a confirm).
    pub fn apply(
        &mut self,
        path: &Path,
        marker: &Marker,
        format: Option<&str>,
        size: u64,
        expected_region_hash: Option<&str>,
        force: bool,
        label: &str,
    ) -> Result<Applied, EditError> {
        match safety::assess(format, size, marker) {
            Risk::Refuse(r) => return Err(EditError::Refused(r)),
            Risk::Warn(r) if !force => return Err(EditError::NeedsForce(r)),
            _ => {}
        }

        if self.cur_group == 0 {
            self.begin_group();
        }

        let action = match &marker.removal {
            RemovalStrategy::RawBlank { fill } => self.do_blank(
                path,
                marker.region.offset,
                marker.region.len,
                *fill,
                expected_region_hash,
            )?,
            RemovalStrategy::Truncate { from } => self.do_truncate(path, *from)?,
            RemovalStrategy::DeleteFile => self.do_delete(path)?,
            RemovalStrategy::StructuralRemove => self.do_structural(path, marker)?,
        };

        let id = self.alloc_id();
        let rec = UndoRecord {
            id,
            group: self.cur_group,
            ts: now_secs(),
            path: path.to_path_buf(),
            label: label.to_string(),
            action,
        };
        self.journal.append(&rec)?;
        Ok(Applied {
            undo_id: id,
            group: self.cur_group,
            path: path.to_path_buf(),
            label: label.to_string(),
        })
    }

    fn do_blank(
        &mut self,
        path: &Path,
        offset: u64,
        len: u64,
        fill: u8,
        expected: Option<&str>,
    ) -> Result<UndoAction, EditError> {
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        let len = len as usize;
        let mut orig = vec![0u8; len];
        read_exact_at(&mut file, offset, &mut orig)?;

        if let Some(want) = expected {
            if crate::util::hash::hash_hex(&orig) != want {
                return Err(EditError::Changed);
            }
        }

        write_at(&file, offset, &vec![fill; len])?;
        file.sync_all()?;
        Ok(UndoAction::RestoreBytes {
            offset,
            bytes_hex: to_hex(&orig),
        })
    }

    fn do_truncate(&mut self, path: &Path, from: u64) -> Result<UndoAction, EditError> {
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        let size = file.metadata()?.len();
        if from >= size {
            // Nothing to drop; still record a no-op tail so undo stays uniform.
            let tail_path = self.trash.stash_bytes(&[], "tail")?;
            return Ok(UndoAction::RestoreTail { from, tail_path });
        }
        // Stream the dropped tail into trash before cutting.
        file.seek(SeekFrom::Start(from))?;
        let mut tail = Vec::new();
        file.read_to_end(&mut tail)?;
        let tail_path = self.trash.stash_bytes(&tail, "tail")?;
        file.set_len(from)?;
        file.sync_all()?;
        Ok(UndoAction::RestoreTail { from, tail_path })
    }

    fn do_delete(&mut self, path: &Path) -> Result<UndoAction, EditError> {
        let trash_path = self.trash.stash_file(path)?;
        Ok(UndoAction::RestoreFile { trash_path })
    }

    /// Structure-aware removal: snapshot the whole file, ask the container
    /// rewriter for a valid file with the region dropped, and write it back
    /// atomically. Undo restores the snapshot. If no rewriter exists for the
    /// container, nothing is changed.
    fn do_structural(&mut self, path: &Path, marker: &Marker) -> Result<UndoAction, EditError> {
        let data = std::fs::read(path)?;
        let Some(new_data) =
            crate::edit::structural::remove(marker.container, &data, marker.region)
        else {
            return Err(EditError::Unsupported(
                "no structural remover for this container yet".into(),
            ));
        };
        let snap = self.trash.stash_bytes(&data, "structural-snapshot")?;
        crate::util::atomic::write_atomic(path, &new_data)?;
        Ok(UndoAction::RestoreSnapshot { trash_path: snap })
    }

    /// Open `path` in the user's external editor, blocking until it exits. The
    /// file is snapshotted to trash first; if the bytes changed on return the
    /// change is recorded as an undoable snapshot restore, otherwise the
    /// snapshot is discarded and `None` is returned.
    pub fn open_in_editor(&mut self, path: &Path) -> Result<Option<Applied>, EditError> {
        let before = std::fs::read(path)?;
        let before_hash = crate::util::hash::hash_hex(&before);
        let snap = self.trash.stash_bytes(&before, "editor-snapshot")?;

        super::external::spawn_editor(path)?;

        let after = std::fs::read(path)?;
        if crate::util::hash::hash_hex(&after) == before_hash {
            let _ = std::fs::remove_file(&snap);
            return Ok(None);
        }

        if self.cur_group == 0 {
            self.begin_group();
        }
        let id = self.alloc_id();
        let rec = UndoRecord {
            id,
            group: self.cur_group,
            ts: now_secs(),
            path: path.to_path_buf(),
            label: "external edit".to_string(),
            action: UndoAction::RestoreSnapshot { trash_path: snap },
        };
        self.journal.append(&rec)?;
        Ok(Some(Applied {
            undo_id: id,
            group: self.cur_group,
            path: path.to_path_buf(),
            label: "external edit".to_string(),
        }))
    }

    /// Undo the most recent group. Returns how many edits were reverted.
    pub fn undo_last(&mut self) -> Result<usize, EditError> {
        let records = self.journal.records()?;
        let Some(group) = records.iter().map(|r| r.group).max() else {
            return Ok(0);
        };
        let (revert, keep): (Vec<_>, Vec<_>) = records.into_iter().partition(|r| r.group == group);
        let mut n = 0;
        for rec in revert.iter().rev() {
            invert(&rec.action, &rec.path)?;
            n += 1;
        }
        self.journal.rewrite(&keep)?;
        Ok(n)
    }

    /// Undo everything in the journal, newest first.
    pub fn undo_all(&mut self) -> Result<usize, EditError> {
        let records = self.journal.records()?;
        let mut n = 0;
        for rec in records.iter().rev() {
            invert(&rec.action, &rec.path)?;
            n += 1;
        }
        self.journal.rewrite(&[])?;
        Ok(n)
    }
}

/// Reverse a single recorded action.
fn invert(action: &UndoAction, path: &Path) -> Result<(), EditError> {
    match action {
        UndoAction::RestoreBytes { offset, bytes_hex } => {
            let bytes = from_hex(bytes_hex).ok_or(EditError::Changed)?;
            let file = OpenOptions::new().read(true).write(true).open(path)?;
            write_at(&file, *offset, &bytes)?;
            file.sync_all()?;
        }
        UndoAction::RestoreTail { from, tail_path } => {
            let tail = std::fs::read(tail_path)?;
            let file = OpenOptions::new().read(true).write(true).open(path)?;
            write_at(&file, *from, &tail)?;
            file.set_len(*from + tail.len() as u64)?;
            file.sync_all()?;
        }
        UndoAction::RestoreFile { trash_path } => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            if std::fs::rename(trash_path, path).is_err() {
                std::fs::copy(trash_path, path)?;
                let _ = std::fs::remove_file(trash_path);
            }
        }
        UndoAction::RestoreSnapshot { trash_path } => {
            let data = std::fs::read(trash_path)?;
            crate::util::atomic::write_atomic(path, &data)?;
        }
    }
    Ok(())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Positioned write of the whole buffer at `offset`.
fn write_at(file: &File, offset: u64, buf: &[u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.write_all_at(buf, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let mut written = 0usize;
        while written < buf.len() {
            let n = file.seek_write(&buf[written..], offset + written as u64)?;
            if n == 0 {
                return Err(io::Error::other("short write"));
            }
            written += n;
        }
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        use std::io::Write;
        let mut f = file.try_clone()?;
        f.seek(SeekFrom::Start(offset))?;
        f.write_all(buf)
    }
}

fn read_exact_at(file: &mut File, offset: u64, buf: &mut [u8]) -> io::Result<()> {
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(buf)
}
