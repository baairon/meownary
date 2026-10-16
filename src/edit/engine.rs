//! Apply and reverse edits. The engine owns the trash store, the undo journal
//! and the state-dir lock.
//!
//! # Record before mutate
//!
//! Every edit follows the same order, so a crash or a failing disk can never
//! leave a change the journal does not know about:
//!
//! 1. validate: risk assessment, no symlinks, canonical absolute path, the
//!    scan-time size (and region hash, when given) still match;
//! 2. take the lock, then save what the inverse needs (inline bytes for a
//!    small blank, a trash copy otherwise);
//! 3. append the journal record, fsynced, carrying two fingerprints: the file
//!    as it is now (`before`) and as the edit will leave it (`after`);
//! 4. change the file;
//! 5. if the change fails, put back anything partially written and append a
//!    tombstone so the record is dead.
//!
//! The fingerprints make a crash between steps 3 and 4 harmless: undo finds
//! the file still matching `before`, drops the record and its trash copy, and
//! never touches the file. A file matching neither fingerprint has changed
//! since the edit, so undo refuses with [`EditError::Changed`] rather than
//! overwrite someone else's bytes.
//!
//! # Undo
//!
//! Undo validates the records first (absolute paths, trash copies inside the
//! trash store), then inverts newest first. Each successful inverse appends a
//! tombstone right away, so a failure partway leaves a journal that holds
//! exactly the edits still in effect. The journal is compacted once at the end.
//! Unparseable journal lines are kept verbatim and counted in [`UndoReport`].

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use crate::model::{Marker, Region, RemovalStrategy};
use crate::util::paths::{journal_path, state_dir, trash_dir};

use super::fsio;
use super::journal::{Fingerprint, Journal, UndoAction, UndoRecord};
use super::lock::{LockError, LockFile};
use super::safety::{self, BIG_SNAPSHOT, Risk};
use super::trash::{self, Trash};

/// Blanks up to this many bytes keep their original bytes inline in the
/// journal; larger regions are copied to trash.
pub const INLINE_MAX: u64 = 4096;

/// How many bytes before a truncation point the `after` fingerprint covers.
pub const TRUNCATE_EDGE: u64 = 64 * 1024;

/// Largest file a structural rewrite will load (it needs the whole file).
pub const STRUCTURAL_MAX: u64 = BIG_SNAPSHOT;

/// Journal file name inside a state dir.
pub const JOURNAL_NAME: &str = "undo-journal.jsonl";

/// Trash folder name inside a state dir.
pub const TRASH_NAME: &str = "trash";

#[derive(Debug)]
pub enum EditError {
    /// The edit was refused as corrupting; never applied.
    Refused(String),
    /// A `Warn`-level edit attempted without `force`.
    NeedsForce(String),
    /// The bytes changed since the scan (or since the edit, for undo); re-scan
    /// and retry.
    Changed,
    /// This strategy/container is not implemented yet (safe no-op).
    Unsupported(String),
    Io(io::Error),
    /// Another meownary process holds the state-dir lock; carries who.
    Locked(String),
    /// The target is a symbolic link; edits never follow links.
    Symlink(PathBuf),
}

impl fmt::Display for EditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EditError::Refused(r) => write!(f, "refused: {r}"),
            EditError::NeedsForce(r) => write!(f, "needs force: {r}"),
            EditError::Changed => write!(f, "file changed since it was scanned or edited"),
            EditError::Unsupported(r) => write!(f, "unsupported: {r}"),
            EditError::Io(e) => write!(f, "io error: {e}"),
            EditError::Locked(who) => {
                write!(f, "another meownary process holds the edit lock ({who})")
            }
            EditError::Symlink(p) => {
                write!(f, "refusing to edit through a symlink: {}", p.display())
            }
        }
    }
}

impl std::error::Error for EditError {}

impl From<io::Error> for EditError {
    fn from(e: io::Error) -> Self {
        EditError::Io(e)
    }
}

/// A short read means the file shrank since the scan.
pub(super) fn eof_is_changed(e: io::Error) -> EditError {
    if e.kind() == io::ErrorKind::UnexpectedEof {
        EditError::Changed
    } else {
        EditError::Io(e)
    }
}

/// The outcome of one successful `apply`.
#[derive(Debug, Clone)]
pub struct Applied {
    pub undo_id: u64,
    pub group: u64,
    /// The canonical absolute path that was edited.
    pub path: PathBuf,
    pub label: String,
}

/// What an undo run did.
#[derive(Debug, Default)]
pub struct UndoReport {
    /// Edits whose inverse was applied.
    pub reverted: usize,
    /// Records whose edit never reached the file (a crash between journaling
    /// and mutating); dropped without touching the file.
    pub never_landed: usize,
    /// Files restored, in undo order, without duplicates.
    pub paths: Vec<PathBuf>,
    /// Journal lines that could not be parsed; kept verbatim.
    pub unparsed_lines: usize,
    /// The record that stopped the run, if any. Everything undone before it
    /// stays undone and is gone from the journal.
    pub failure: Option<EditError>,
}

enum Outcome {
    Reverted,
    NeverLanded,
}

enum FileState {
    /// Matches what the edit left (or the record predates fingerprints).
    After,
    /// Still matches the pre-edit file: the edit never landed.
    Before,
    /// Matches neither.
    Other,
}

/// Owns the trash store and journal and performs every mutating operation.
pub struct EditEngine {
    state_dir: PathBuf,
    trash: Trash,
    journal: Journal,
    lock: Option<LockFile>,
    next_id: u64,
    next_group: u64,
    cur_group: u64,
    group_used: bool,
}

impl EditEngine {
    /// An engine over the default state dir (`util::paths`, which honors
    /// `MEOWNARY_STATE_DIR`).
    pub fn new() -> io::Result<Self> {
        Self::with_layout(state_dir(), trash_dir(), journal_path())
    }

    /// An engine whose trash, journal and lock live under `state_dir`. Lets
    /// tests and callers pick a location without touching the environment.
    pub fn open_in(state_dir: &Path) -> io::Result<Self> {
        Self::with_layout(
            state_dir.to_path_buf(),
            state_dir.join(TRASH_NAME),
            state_dir.join(JOURNAL_NAME),
        )
    }

    fn with_layout(state: PathBuf, trash_root: PathBuf, journal: PathBuf) -> io::Result<Self> {
        fs::create_dir_all(&state)?;
        let state = fsio::canonical(&state)?;
        fs::create_dir_all(&trash_root)?;
        let trash_root = fsio::canonical(&trash_root)?;
        let journal = Journal::open_at(journal)?;
        let mut engine = Self {
            state_dir: state,
            trash: Trash::in_dir(trash_root),
            journal,
            lock: None,
            next_id: 1,
            next_group: 1,
            cur_group: 0,
            group_used: false,
        };
        engine.refresh_counters()?;
        Ok(engine)
    }

    /// The state dir holding the journal, trash and lock.
    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    /// The trash root every stash lives under.
    pub fn trash_root(&self) -> &Path {
        self.trash.root()
    }

    /// The undo journal.
    pub fn journal(&self) -> &Journal {
        &self.journal
    }

    /// Whether this engine currently holds the state-dir lock.
    pub fn holds_lock(&self) -> bool {
        self.lock.is_some()
    }

    /// Take (or refresh) the state-dir lock now. Every mutating call does this
    /// on its own; callers use it to learn early that another run is busy.
    pub fn acquire_lock(&mut self) -> Result<(), EditError> {
        if let Some(l) = &self.lock {
            if l.refresh() {
                return Ok(());
            }
            self.lock = None;
        }
        match LockFile::acquire(&self.state_dir) {
            Ok(l) => {
                self.lock = Some(l);
                let _ = self.journal.compact();
                self.refresh_counters()?;
                Ok(())
            }
            Err(LockError::Held(h)) => Err(EditError::Locked(h.describe())),
            Err(LockError::Io(e)) => Err(EditError::Io(e)),
        }
    }

    /// Release the lock early (it is also released on drop).
    pub fn release_lock(&mut self) {
        self.lock = None;
    }

    fn refresh_counters(&mut self) -> io::Result<()> {
        let next_id = self.journal.next_id()?;
        let max_group = self
            .journal
            .records()?
            .iter()
            .map(|r| r.group)
            .max()
            .unwrap_or(0);
        self.next_id = self.next_id.max(next_id);
        if self.cur_group != 0 && !self.group_used && self.cur_group <= max_group {
            self.cur_group = max_group + 1;
        }
        self.next_group = self
            .next_group
            .max(max_group + 1)
            .max(self.cur_group.saturating_add(1));
        Ok(())
    }

    /// Start a new bulk group; every `apply` until the next `begin_group`
    /// shares this id, so one `undo_last` reverts the whole batch.
    pub fn begin_group(&mut self) -> u64 {
        self.cur_group = self.next_group;
        self.next_group += 1;
        self.group_used = false;
        self.cur_group
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn record(
        &self,
        id: u64,
        path: &Path,
        label: &str,
        action: UndoAction,
        before: Option<Fingerprint>,
        after: Option<Fingerprint>,
    ) -> UndoRecord {
        UndoRecord {
            id,
            group: self.cur_group,
            ts: fsio::now_secs(),
            path: path.to_path_buf(),
            label: label.to_string(),
            action,
            before,
            after,
        }
    }

    /// Append `rec`; if that fails, discard its trash copy and report.
    fn journal_first(&mut self, rec: &UndoRecord) -> Result<(), EditError> {
        if let Err(e) = self.journal.append(rec) {
            if let Some(p) = rec.action.trash_path() {
                self.trash.discard(p);
            }
            return Err(EditError::Io(e));
        }
        Ok(())
    }

    /// Retire a record whose edit did not happen: tombstone it and drop its
    /// trash copy. If the tombstone cannot be written the record stays, and
    /// undo later recognises it as never landed.
    fn void(&mut self, rec: &UndoRecord) {
        if self.journal.mark_undone(rec.id).is_ok()
            && let Some(p) = rec.action.trash_path()
        {
            self.trash.discard(p);
        }
    }

    /// Apply the removal described by `marker` to `path`.
    ///
    /// * `format` and `size` feed the risk assessment; `size` must also equal
    ///   the file's current size, else [`EditError::Changed`].
    /// * `expected_region_hash` (if given) must match the blake3 of the bytes
    ///   the edit acts on: the marker region when it is non-empty, else the
    ///   dropped tail for a truncate and the whole file for a delete.
    /// * `force` permits `Warn`-level edits (the TUI passes it after a confirm).
    ///
    /// Symlinks are refused; the journal records the canonical absolute path,
    /// which is also what [`Applied::path`] reports.
    #[allow(clippy::too_many_arguments)]
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
        let (target, meta) = resolve_target(path)?;
        if meta.len() != size {
            return Err(EditError::Changed);
        }
        if let Some(want) = expected_region_hash {
            let (off, len) = check_span(marker, size);
            let file = File::open(&target)?;
            let got = fsio::hash_range(&file, off, len).map_err(eof_is_changed)?;
            if !got.eq_ignore_ascii_case(want.trim()) {
                return Err(EditError::Changed);
            }
        }

        self.acquire_lock()?;
        if self.cur_group == 0 {
            self.begin_group();
        }
        let id = self.alloc_id();
        match &marker.removal {
            RemovalStrategy::RawBlank { fill } => {
                self.do_blank(id, &target, label, marker.region, *fill, size)?
            }
            RemovalStrategy::Truncate { from } => {
                self.do_truncate(id, &target, label, *from, size)?
            }
            RemovalStrategy::DeleteFile => self.do_delete(id, &target, label, size)?,
            RemovalStrategy::StructuralRemove => {
                self.do_structural(id, &target, label, marker, size)?
            }
        }
        self.group_used = true;
        Ok(Applied {
            undo_id: id,
            group: self.cur_group,
            path: target,
            label: label.to_string(),
        })
    }

    fn do_blank(
        &mut self,
        id: u64,
        target: &Path,
        label: &str,
        region: Region,
        fill: u8,
        size: u64,
    ) -> Result<(), EditError> {
        let (offset, len) = (region.offset, region.len);
        if offset.checked_add(len).is_none_or(|end| end > size) {
            return Err(EditError::Refused(
                "the marker region runs past the end of the file".into(),
            ));
        }
        let file = OpenOptions::new().read(true).write(true).open(target)?;
        let (action, before_hash, inline) = if len <= INLINE_MAX {
            let mut orig = vec![0u8; len as usize];
            fsio::read_exact_at(&file, offset, &mut orig).map_err(eof_is_changed)?;
            let h = crate::util::hash::hash_hex(&orig);
            let action = UndoAction::RestoreBytes {
                offset,
                bytes_hex: fsio::to_hex(&orig),
            };
            (action, h, Some(orig))
        } else {
            let (p, h) = self
                .trash
                .stash_range(&file, offset, len, "region")
                .map_err(eof_is_changed)?;
            let action = UndoAction::RestoreRange {
                offset,
                len,
                trash_path: p,
            };
            (action, h, None)
        };
        let after_hash = fsio::hash_fill(fill, len);
        let rec = self.record(
            id,
            target,
            label,
            action,
            Some(Fingerprint::span(size, offset, len, before_hash)),
            Some(Fingerprint::span(size, offset, len, after_hash)),
        );
        self.journal_first(&rec)?;

        if let Err(e) = fsio::write_fill(&file, offset, len, fill).and_then(|_| file.sync_all()) {
            let restored = match (&inline, rec.action.trash_path()) {
                (Some(orig), _) => fsio::write_at(&file, offset, orig),
                (None, Some(p)) => fsio::copy_file_into(p, &file, offset).map(|_| ()),
                (None, None) => Err(io::Error::other("nothing to restore from")),
            }
            .and_then(|_| file.sync_all());
            if restored.is_ok() {
                self.void(&rec);
            }
            return Err(EditError::Io(e));
        }
        Ok(())
    }

    fn do_truncate(
        &mut self,
        id: u64,
        target: &Path,
        label: &str,
        from: u64,
        size: u64,
    ) -> Result<(), EditError> {
        if from >= size {
            return Err(EditError::Refused(
                "nothing lies past the truncation point".into(),
            ));
        }
        let file = OpenOptions::new().read(true).write(true).open(target)?;
        let tail_len = size - from;
        let (tail_path, tail_hash) = self
            .trash
            .stash_range(&file, from, tail_len, "tail")
            .map_err(eof_is_changed)?;
        let edge_off = from.saturating_sub(TRUNCATE_EDGE);
        let edge_len = from - edge_off;
        let edge_hash = match fsio::hash_range(&file, edge_off, edge_len) {
            Ok(h) => h,
            Err(e) => {
                self.trash.discard(&tail_path);
                return Err(eof_is_changed(e));
            }
        };
        let rec = self.record(
            id,
            target,
            label,
            UndoAction::RestoreTail { from, tail_path },
            Some(Fingerprint::span(size, from, tail_len, tail_hash)),
            Some(Fingerprint::span(from, edge_off, edge_len, edge_hash)),
        );
        self.journal_first(&rec)?;

        if let Err(e) = file.set_len(from).and_then(|_| file.sync_all()) {
            if file.metadata().map(|m| m.len()).ok() == Some(size) {
                self.void(&rec);
            }
            return Err(EditError::Io(e));
        }
        Ok(())
    }

    fn do_delete(
        &mut self,
        id: u64,
        target: &Path,
        label: &str,
        size: u64,
    ) -> Result<(), EditError> {
        let base = target
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "file".to_string());
        let trash_path = self.trash.reserve(&base)?;
        let rec = self.record(
            id,
            target,
            label,
            UndoAction::RestoreFile {
                trash_path: trash_path.clone(),
            },
            Some(Fingerprint::size_only(size)),
            None,
        );
        self.journal_first(&rec)?;

        if let Err(e) = trash::move_file(target, &trash_path) {
            if target.exists() {
                self.void(&rec);
            }
            return Err(EditError::Io(e));
        }
        Ok(())
    }

    /// Structure-aware removal: snapshot the whole file, ask the container
    /// rewriter for a valid file with the region dropped, and write it back
    /// atomically. Undo restores the snapshot. If no rewriter exists for the
    /// container, nothing is changed and nothing is recorded.
    fn do_structural(
        &mut self,
        id: u64,
        target: &Path,
        label: &str,
        marker: &Marker,
        size: u64,
    ) -> Result<(), EditError> {
        if size > STRUCTURAL_MAX {
            return Err(EditError::Unsupported(
                "file too large for a structural rewrite".into(),
            ));
        }
        let data = fs::read(target)?;
        if data.len() as u64 != size {
            return Err(EditError::Changed);
        }
        let Some(new_data) =
            crate::edit::structural::remove(marker.container, &data, marker.region)
        else {
            return Err(EditError::Unsupported(
                "no structural remover for this container yet".into(),
            ));
        };
        if new_data == data {
            return Err(EditError::Unsupported(
                "the structural remover found nothing to change".into(),
            ));
        }
        let snap = self.trash.stash_bytes(&data, "snapshot")?;
        let new_len = new_data.len() as u64;
        let rec = self.record(
            id,
            target,
            label,
            UndoAction::RestoreSnapshot { trash_path: snap },
            Some(Fingerprint::span(
                size,
                0,
                size,
                crate::util::hash::hash_hex(&data),
            )),
            Some(Fingerprint::span(
                new_len,
                0,
                new_len,
                crate::util::hash::hash_hex(&new_data),
            )),
        );
        self.journal_first(&rec)?;

        if let Err(e) = fsio::replace_atomic(target, &new_data) {
            self.void(&rec);
            return Err(EditError::Io(e));
        }
        Ok(())
    }

    /// Open `path` in the user's external editor, blocking until it exits. The
    /// file is snapshotted to trash and journaled first; if the bytes changed
    /// on return the change is recorded as an undoable snapshot restore,
    /// otherwise the snapshot is discarded and `None` is returned.
    pub fn open_in_editor(&mut self, path: &Path) -> Result<Option<Applied>, EditError> {
        self.open_with(path, |p| super::external::spawn_editor(p).map(|_| ()))
    }

    /// [`EditEngine::open_in_editor`] with the editor replaced by `edit`, which
    /// receives the canonical path. Used by tests and by callers that change
    /// a file through some other tool.
    pub fn open_with(
        &mut self,
        path: &Path,
        edit: impl FnOnce(&Path) -> io::Result<()>,
    ) -> Result<Option<Applied>, EditError> {
        let (target, _) = resolve_target(path)?;
        self.acquire_lock()?;
        let (size, before_hash) = fsio::hash_file(&target)?;
        let snap = self.trash.stash_copy(&target, "editor-snapshot")?;
        if self.cur_group == 0 {
            self.begin_group();
        }
        let label = "external edit";
        let before = Fingerprint::span(size, 0, size, before_hash.clone());
        let pending_id = self.alloc_id();
        let pending = self.record(
            pending_id,
            &target,
            label,
            UndoAction::RestoreSnapshot {
                trash_path: snap.clone(),
            },
            Some(before.clone()),
            None,
        );
        self.journal_first(&pending)?;

        if let Err(e) = edit(&target) {
            self.void(&pending);
            return Err(EditError::Io(e));
        }

        let after = match fs::symlink_metadata(&target) {
            Ok(m) if m.is_file() => Some(fsio::hash_file(&target)?),
            _ => None,
        };
        if after.as_ref() == Some(&(size, before_hash)) {
            self.void(&pending);
            return Ok(None);
        }

        // Record the final state under a fresh id, then retire the pending
        // record. Until the tombstone lands, the pending record alone still
        // covers the change.
        let id = self.alloc_id();
        let fin = self.record(
            id,
            &target,
            label,
            UndoAction::RestoreSnapshot { trash_path: snap },
            Some(before),
            after.map(|(s, h)| Fingerprint::span(s, 0, s, h)),
        );
        self.journal.append(&fin)?;
        let _ = self.journal.mark_undone(pending_id);
        self.group_used = true;
        Ok(Some(Applied {
            undo_id: id,
            group: self.cur_group,
            path: target,
            label: label.to_string(),
        }))
    }

    /// Undo the most recent group. Returns how many edits were reverted.
    pub fn undo_last(&mut self) -> Result<usize, EditError> {
        finish(self.undo_last_report()?)
    }

    /// Undo everything in the journal, newest first.
    pub fn undo_all(&mut self) -> Result<usize, EditError> {
        finish(self.undo_all_report()?)
    }

    /// Undo the most recent group, reporting what happened in detail. `Err`
    /// means nothing was attempted (lock, unreadable journal, invalid record).
    pub fn undo_last_report(&mut self) -> Result<UndoReport, EditError> {
        self.acquire_lock()?;
        let state = self.journal.state()?;
        let unparsed = state.raw.len();
        let Some(group) = state.live.iter().map(|r| r.group).max() else {
            return Ok(UndoReport {
                unparsed_lines: unparsed,
                ..UndoReport::default()
            });
        };
        let batch: Vec<UndoRecord> = state
            .live
            .into_iter()
            .filter(|r| r.group == group)
            .collect();
        self.undo_records(&batch, unparsed)
    }

    /// Undo every live record, newest first, reporting in detail.
    pub fn undo_all_report(&mut self) -> Result<UndoReport, EditError> {
        self.acquire_lock()?;
        let state = self.journal.state()?;
        let unparsed = state.raw.len();
        self.undo_records(&state.live, unparsed)
    }

    /// How many journal lines could not be parsed (kept verbatim).
    pub fn unparsed_journal_lines(&self) -> io::Result<usize> {
        Ok(self.journal.state()?.raw.len())
    }

    fn undo_records(
        &mut self,
        records: &[UndoRecord],
        unparsed: usize,
    ) -> Result<UndoReport, EditError> {
        for rec in records {
            self.validate(rec)?;
        }
        let mut report = UndoReport {
            unparsed_lines: unparsed,
            ..UndoReport::default()
        };
        for rec in records.iter().rev() {
            match self.undo_one(rec) {
                Ok(outcome) => {
                    if let Err(e) = self.journal.mark_undone(rec.id) {
                        report.failure = Some(EditError::Io(e));
                        break;
                    }
                    if let Some(p) = rec.action.trash_path() {
                        let _ = fs::remove_file(p);
                        if let Some(dir) = p.parent() {
                            trash::prune_session(self.trash.root(), dir);
                        }
                    }
                    match outcome {
                        Outcome::Reverted => {
                            report.reverted += 1;
                            if !report.paths.contains(&rec.path) {
                                report.paths.push(rec.path.clone());
                            }
                        }
                        Outcome::NeverLanded => report.never_landed += 1,
                    }
                }
                Err(e) => {
                    report.failure = Some(e);
                    break;
                }
            }
        }
        let _ = self.journal.compact();
        Ok(report)
    }

    /// Refuse records that point somewhere they should not.
    fn validate(&self, rec: &UndoRecord) -> Result<(), EditError> {
        if !fsio::is_plain_absolute(&rec.path) {
            return Err(EditError::Refused(format!(
                "journal record {} has a path that is not absolute",
                rec.id
            )));
        }
        if let Some(p) = rec.action.trash_path()
            && (!fsio::is_plain_absolute(p) || !p.starts_with(self.trash.root()))
        {
            return Err(EditError::Refused(format!(
                "journal record {} points outside the trash store",
                rec.id
            )));
        }
        Ok(())
    }

    fn undo_one(&mut self, rec: &UndoRecord) -> Result<Outcome, EditError> {
        let path = &rec.path;
        if let Ok(m) = fs::symlink_metadata(path)
            && m.file_type().is_symlink()
        {
            return Err(EditError::Symlink(path.clone()));
        }
        let damaged = || {
            EditError::Refused(format!(
                "trash copy for journal record {} is damaged",
                rec.id
            ))
        };
        match &rec.action {
            UndoAction::RestoreBytes { offset, bytes_hex } => {
                let bytes = fsio::from_hex(bytes_hex).ok_or_else(damaged)?;
                match classify(rec)? {
                    FileState::After => {}
                    FileState::Before => return Ok(Outcome::NeverLanded),
                    FileState::Other => return Err(EditError::Changed),
                }
                let file = OpenOptions::new().read(true).write(true).open(path)?;
                let len = file.metadata()?.len();
                if offset
                    .checked_add(bytes.len() as u64)
                    .is_none_or(|end| end > len)
                {
                    return Err(EditError::Changed);
                }
                fsio::write_at(&file, *offset, &bytes)?;
                file.sync_all()?;
            }
            UndoAction::RestoreRange {
                offset,
                len,
                trash_path,
            } => {
                if fs::metadata(trash_path).map(|m| m.len()).ok() != Some(*len) {
                    return Err(damaged());
                }
                match classify(rec)? {
                    FileState::After => {}
                    FileState::Before => return Ok(Outcome::NeverLanded),
                    FileState::Other => return Err(EditError::Changed),
                }
                let file = OpenOptions::new().read(true).write(true).open(path)?;
                let size = file.metadata()?.len();
                if offset.checked_add(*len).is_none_or(|end| end > size) {
                    return Err(EditError::Changed);
                }
                fsio::copy_file_into(trash_path, &file, *offset)?;
                file.sync_all()?;
            }
            UndoAction::RestoreTail { from, tail_path } => {
                let tail_len = fs::metadata(tail_path).map_err(|_| damaged())?.len();
                if let Some(b) = &rec.before
                    && from.checked_add(tail_len) != Some(b.size)
                {
                    return Err(damaged());
                }
                match classify(rec)? {
                    FileState::After => {}
                    FileState::Before => return Ok(Outcome::NeverLanded),
                    FileState::Other => return Err(EditError::Changed),
                }
                let file = OpenOptions::new().read(true).write(true).open(path)?;
                // Never grow a file that is not exactly where the edit left it.
                if file.metadata()?.len() != *from {
                    return Err(EditError::Changed);
                }
                let wrote = fsio::copy_file_into(tail_path, &file, *from)?;
                file.set_len(from + wrote.min(tail_len))?;
                file.sync_all()?;
            }
            UndoAction::RestoreFile { trash_path } => {
                if fs::symlink_metadata(path).is_ok() {
                    let same_size = rec
                        .before
                        .as_ref()
                        .is_some_and(|b| fs::metadata(path).map(|m| m.len()).ok() == Some(b.size));
                    if same_size && !trash_path.exists() {
                        return Ok(Outcome::NeverLanded);
                    }
                    return Err(EditError::Changed);
                }
                let meta = fs::metadata(trash_path).map_err(|_| damaged())?;
                if let Some(b) = &rec.before
                    && meta.len() != b.size
                {
                    return Err(damaged());
                }
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                trash::move_file(trash_path, path)?;
            }
            UndoAction::RestoreSnapshot { trash_path } => {
                if !trash_path.is_file() {
                    return Err(damaged());
                }
                match classify(rec)? {
                    FileState::After => {}
                    FileState::Before => return Ok(Outcome::NeverLanded),
                    FileState::Other => return Err(EditError::Changed),
                }
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fsio::replace_atomic_from(path, trash_path)?;
            }
        }
        Ok(Outcome::Reverted)
    }
}

/// Turn a report into the plain count API: a stopped run is an error.
fn finish(report: UndoReport) -> Result<usize, EditError> {
    match report.failure {
        Some(e) => Err(e),
        None => Ok(report.reverted),
    }
}

/// Compare the file at `rec.path` with the record's fingerprints.
fn classify(rec: &UndoRecord) -> Result<FileState, EditError> {
    if let Some(a) = &rec.after
        && matches_fingerprint(&rec.path, a)?
    {
        return Ok(FileState::After);
    }
    if let Some(b) = &rec.before
        && matches_fingerprint(&rec.path, b)?
    {
        return Ok(FileState::Before);
    }
    let snapshot = matches!(rec.action, UndoAction::RestoreSnapshot { .. });
    match (&rec.before, &rec.after) {
        // A record from before fingerprints existed: trust it as before.
        (None, None) => Ok(FileState::After),
        // An external edit that left no final state (still open when the run
        // ended, or the file was removed): anything but the original is
        // treated as the edit's result.
        (Some(_), None) if snapshot => Ok(FileState::After),
        _ => Ok(FileState::Other),
    }
}

fn matches_fingerprint(path: &Path, fp: &Fingerprint) -> Result<bool, EditError> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(EditError::Io(e)),
    };
    if file.metadata()?.len() != fp.size {
        return Ok(false);
    }
    match &fp.hash {
        None => Ok(true),
        Some(want) => match fsio::hash_range(&file, fp.offset, fp.len) {
            Ok(got) => Ok(got.eq_ignore_ascii_case(want)),
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
            Err(e) => Err(EditError::Io(e)),
        },
    }
}

/// Refuse symlinks and non-files; return the canonical path and metadata.
fn resolve_target(path: &Path) -> Result<(PathBuf, fs::Metadata), EditError> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Err(EditError::Symlink(path.to_path_buf()));
    }
    if !meta.is_file() {
        return Err(EditError::Refused("not a regular file".into()));
    }
    let canon = fsio::canonical(path)?;
    Ok((canon, meta))
}

/// The span `expected_region_hash` covers for `marker` in a `size`-byte file.
fn check_span(marker: &Marker, size: u64) -> (u64, u64) {
    if marker.region.len > 0 {
        return (marker.region.offset, marker.region.len);
    }
    match marker.removal {
        RemovalStrategy::Truncate { from } => (from.min(size), size.saturating_sub(from)),
        RemovalStrategy::DeleteFile => (0, size),
        _ => (marker.region.offset, 0),
    }
}
