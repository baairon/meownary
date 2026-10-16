//! The interactive view's state machine, kept free of the terminal so it can be
//! tested directly. [`App::on_key`] turns a key into state changes plus an
//! [`Effect`] the runtime carries out (an edit batch, the editor, an undo, a
//! hex read); the runtime then reports back through methods such as
//! [`App::replace_report`] and [`App::set_status`]. Rendering reads the same
//! state through the query methods here, so what is drawn and what is tested
//! are one model.
//!
//! A bare `meownary` starts in picker mode ([`App::picking`]): no scan runs
//! until the picker hands back a file or folder, and then [`App::on_key`]
//! turns the app into a fresh main view for it and returns [`Effect::Scan`].
//! `o` reopens the picker over a running view ([`App::open_picker`]); the
//! old view and its scan carry on until a new path is actually chosen, and
//! backing out of the picker returns to them unchanged.

#![cfg(feature = "tui")]

use std::collections::{BTreeSet, HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::edit::deattribute;
use crate::edit::{self, Risk};
use crate::model::{
    Bucket, BucketBy, Confidence, ContainerKind, FileReport, Finding, Marker, Region,
    RemovalStrategy, bucketize,
};
use crate::scan::walk::CountDelta;
use crate::scan::{Scanned, WindowedFile};

use super::explorer::{self, Explorer, FolderState, Row, find_report};
use super::keymap::Key;
use super::listing::Listing;
use super::picker::{PickOutcome, Picker};
use super::progress::{Activity, Progress, Silent};
use super::theme::Tone;
use super::tree::{Tree, subtree};

/// Run the interactive view. With a path it scans that folder right away;
/// without one it opens on the folder picker. Sets up and tears down the
/// terminal.
pub fn run(path: Option<&Path>) -> io::Result<()> {
    super::runtime::run(path)
}

/// Copy for the common outcomes. Warm in tone, exact in content.
pub const MSG_NOTHING: &str = "Nothing to remove.";
pub const MSG_MAGIC: &str = "Refused: this edit would overwrite the file's magic bytes.";
pub const MSG_LOCKED: &str = "Another meownary process is editing. Try again when it finishes.";
pub const MSG_QUIT_ARMED: &str = "Press Esc again to quit, or press q.";
pub const MSG_NEVER_MIND: &str = "Cancelled. Nothing changed.";
pub const MSG_UNDO_RUNS: &str = "Undo cannot be stopped. It finishes on its own.";
pub const MSG_QUIT_AFTER_UNDO: &str = "Quitting when the undo finishes.";

/// Which list has focus on the main screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pane {
    Files,
    Findings,
}

/// The full-body screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Main,
    Detail,
    Buckets,
}

/// What narrows the file list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filter {
    None,
    /// Case-insensitive substring of path, format, signature id or title.
    Text(String),
    /// Exactly the findings of one bucket.
    Bucket {
        by: BucketBy,
        key: String,
        label: String,
    },
}

impl Filter {
    pub fn is_active(&self) -> bool {
        match self {
            Filter::None => false,
            Filter::Text(t) => !t.is_empty(),
            Filter::Bucket { .. } => true,
        }
    }

    /// Footer text for an active filter.
    pub fn describe(&self) -> Option<String> {
        match self {
            Filter::None => None,
            Filter::Text(t) if t.is_empty() => None,
            Filter::Text(t) => Some(t.clone()),
            Filter::Bucket { by, key, .. } => Some(format!("{}={key}", bucket_by_name(*by))),
        }
    }
}

/// A modal over the current screen.
#[derive(Debug, Clone)]
pub enum Overlay {
    Help,
    /// The filter prompt; typing edits `App::filter` live.
    Filter,
    Confirm(Plan),
}

/// The message line under the scan status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub text: String,
    pub tone: Tone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanKind {
    Scrub,
    Deattribute,
    DeepDeattribute,
    Delete,
}

/// One edit a confirm modal lists.
#[derive(Debug, Clone)]
pub struct PlanItem {
    pub path: PathBuf,
    pub format: Option<String>,
    pub size: u64,
    /// The journal label: a signature id, or "delete file".
    pub label: String,
    pub title: String,
    pub marker: Marker,
    pub risk: Risk,
    pub expected_hash: Option<String>,
    pub replacement: Option<Vec<u8>>,
    /// Which credit a deattribute item blanks or rewrites.
    pub credit: Option<deattribute::Kind>,
    /// Set when the item means "the files inside this archive": a deattributed
    /// copy is rebuilt around them instead of blanking one region.
    pub archive: Option<ArchivePlan>,
}

/// An archive a deattribute plan rebuilds, with what its dry run found, so
/// the confirm and the write both work from the one dry run.
#[derive(Debug, Clone)]
pub struct ArchivePlan {
    pub kind: deattribute::ArchiveKind,
    pub dry_run: deattribute::ArchiveOutcome,
}

/// A batch awaiting confirmation.
#[derive(Debug, Clone)]
pub struct Plan {
    pub kind: PlanKind,
    pub items: Vec<PlanItem>,
    /// Weak-confidence findings left out of a bulk action.
    pub weak_left_out: usize,
    pub private_skips: Vec<String>,
    /// What the copies lose besides the credits, one line per kind of loss.
    pub caveats: Vec<String>,
    /// Copies already on disk that this plan would replace.
    pub replaces: Vec<PathBuf>,
    pub scroll: usize,
}

impl Plan {
    /// Items that will actually run (everything not refused).
    pub fn runnable(&self) -> usize {
        self.items
            .iter()
            .filter(|i| !matches!(i.risk, Risk::Refuse(_)))
            .count()
    }

    /// The deattribute mode a deattribute plan runs in.
    pub fn mode(&self) -> deattribute::Mode {
        if self.kind == PlanKind::DeepDeattribute {
            deattribute::Mode::Deep
        } else {
            deattribute::Mode::Basic
        }
    }

    pub fn title(&self) -> String {
        let n = self.runnable();
        match self.kind {
            PlanKind::Scrub => format!("Scrub {n} {}?", plural(n, "marker", "markers")),
            PlanKind::DeepDeattribute => {
                format!("Deep deattribute {n} {}?", plural(n, "edit", "edits"))
            }
            PlanKind::Deattribute => {
                let archives = self.items.iter().filter(|i| i.archive.is_some()).count();
                let markers = n.saturating_sub(archives);
                let a = plural(archives, "archive", "archives");
                match (markers, archives) {
                    (_, 0) => format!("Deattribute {n} {}?", plural(n, "marker", "markers")),
                    (0, _) => format!("Deattribute {archives} {a}?"),
                    _ => format!(
                        "Deattribute {markers} {} and {archives} {a}?",
                        plural(markers, "marker", "markers")
                    ),
                }
            }
            PlanKind::Delete => {
                format!("Delete {n} {}?", plural(n, "file", "files"))
            }
        }
    }
}

/// Something the runtime must do after a key.
#[derive(Debug)]
pub enum Effect {
    None,
    Quit,
    /// Read the hex window for the detail view.
    LoadHex {
        path: PathBuf,
        offset: u64,
    },
    /// Apply a confirmed plan as one undo group (a deattribute plan writes
    /// its copies off the input thread instead).
    Apply(Plan),
    /// Build a deattribute plan off the input thread and hand it back
    /// through [`App::plan_ready`].
    PlanDeattribute(DeattributeRequest),
    /// The picker chose a file or folder: start scanning it.
    Scan(PathBuf),
    /// Open the picker again over the current view.
    Pick,
    /// Suspend and open this file in the external editor.
    Edit(PathBuf),
    Undo,
    /// Ask the work running off the input thread to stop: a plan is dropped
    /// at once, copies and edits end after the file they are on.
    Stop,
}

/// Bytes around a finding, read for the detail view.
#[derive(Debug, Clone)]
pub struct HexView {
    pub path: PathBuf,
    pub base: u64,
    pub bytes: Vec<u8>,
    pub error: Option<String>,
}

/// How many bytes the detail view dumps around the evidence offset.
pub const HEX_WINDOW: u64 = 256;

/// Where the hex window starts for an evidence `offset`: 16-aligned, with the
/// evidence near the middle.
pub fn hex_base(offset: u64) -> u64 {
    offset.saturating_sub(HEX_WINDOW / 2) & !0xf
}

/// How a saved file was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SavedKind {
    /// Markers were scrubbed from the file in place.
    Scrubbed,
    /// A deattributed copy was written beside the file.
    Deattributed,
}

impl SavedKind {
    /// The word the files list and the detail view show.
    pub fn word(self) -> &'static str {
        match self {
            SavedKind::Scrubbed => "scrubbed",
            SavedKind::Deattributed => "deattributed",
        }
    }
}

/// A file this session saved an edit for. The mark is kept by path, apart
/// from the report, so it survives the rescan that follows the edit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Saved {
    pub kind: SavedKind,
    /// Where the result is: the file itself for a scrub, the copy for a
    /// deattribute.
    pub output: PathBuf,
    /// Edits saved into `output` this session.
    pub edits: usize,
}

/// One file an action saved, for [`App::record_saved`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedItem {
    /// The file the action ran on, as the view knows it.
    pub path: PathBuf,
    /// Where the result was written (the same path for a scrub).
    pub output: PathBuf,
    /// Edits this action saved.
    pub edits: usize,
}

/// Work the view is waiting on. Edit keys are ignored until it finishes, so
/// a key typed meanwhile never acts on a plan nobody has seen yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Busy {
    /// Building a deattribute plan.
    Planning,
    /// Writing a confirmed plan's deattributed copies.
    Writing,
    /// Scrubbing confirmed markers.
    Scrubbing,
    /// Moving confirmed files to the trash.
    Deleting,
    /// Undoing the last batch.
    Undoing,
}

impl Busy {
    /// The status line while this work runs.
    pub fn status(self) -> &'static str {
        match self {
            Busy::Planning => "Planning...",
            Busy::Writing => "Writing copies...",
            Busy::Scrubbing => "Scrubbing...",
            Busy::Deleting => "Deleting...",
            Busy::Undoing => "Undoing...",
        }
    }

    /// Whether Esc can stop this work. An undo always runs to the end.
    pub fn stoppable(self) -> bool {
        self != Busy::Undoing
    }
}

/// A copy of the picks, taken when a job starts, so only those are cleared
/// when it ends.
#[derive(Debug, Clone, Default)]
struct Picks {
    files: BTreeSet<PathBuf>,
    findings: BTreeSet<(PathBuf, usize)>,
    dirs: BTreeSet<PathBuf>,
}

/// Everything a deattribute plan is built from, so it can be built on a
/// worker thread while the view keeps drawing.
#[derive(Debug, Clone)]
pub struct DeattributeRequest {
    pub root: PathBuf,
    pub mode: deattribute::Mode,
    /// The selected files' reports, in path order.
    pub reports: Vec<FileReport>,
}

/// What writing a deattribute plan's copies did.
#[derive(Debug, Default)]
pub struct CopiesOutcome {
    pub saved: Vec<SavedItem>,
    /// Files whose copy was not written, each reason led by the file's
    /// display path.
    pub failed: Vec<String>,
    /// Display paths of written copies that did not pass verification.
    pub unverified: Vec<String>,
    /// Fresh reports for copies under the scanned root, each with the
    /// original it was made from.
    pub copies: Vec<(PathBuf, FileReport)>,
    /// Writing stopped early at the user's request.
    pub stopped: bool,
    /// Files whose copies a stop left unwritten.
    pub not_written: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    pub flagged: usize,
    pub removable: usize,
    pub alerts: usize,
}

/// The most common signatures under a folder, as last worked out.
#[derive(Debug, Clone)]
struct Signatures {
    path: PathBuf,
    stamp: u64,
    at: u64,
    top: Vec<(String, usize)>,
}

/// How often the buckets regroup while the scan streams in.
const BUCKETS_EVERY_MS: u64 = 500;
/// How often a folder's signatures are counted again while the scan streams
/// in.
const SIGNATURES_EVERY_MS: u64 = 300;

/// The whole interactive state.
pub struct App {
    pub root: PathBuf,
    reports: Vec<FileReport>,
    pub scanning: bool,
    /// Total files the walk found, once known.
    pub total: Option<usize>,
    pub screen: Screen,
    pub pane: Pane,
    pub overlay: Option<Overlay>,
    pub filter: Filter,
    pub file_cursor: usize,
    pub file_offset: usize,
    pub finding_cursor: usize,
    pub finding_offset: usize,
    pub picked_files: BTreeSet<PathBuf>,
    pub picked_findings: BTreeSet<(PathBuf, usize)>,
    /// Folders picked in the files list: an action covers every file under
    /// them.
    pub picked_dirs: BTreeSet<PathBuf>,
    /// Every folder holding scanned files, with what is under it added up.
    tree: Tree,
    /// The folder the files list shows, and its rows.
    explorer: Explorer,
    /// The most common signatures under the highlighted folder, kept until
    /// that folder changes.
    signatures: Option<Signatures>,
    /// When the buckets were last regrouped, on the animation clock.
    buckets_at: Option<u64>,
    pub bucket_by: BucketBy,
    buckets: Vec<Bucket>,
    pub bucket_cursor: usize,
    pub bucket_offset: usize,
    pub detail_scroll: usize,
    /// Set by the renderer: how many lines the detail view has.
    pub detail_lines: usize,
    pub hex: Option<HexView>,
    pub status: Option<Status>,
    quit_armed: bool,
    pub should_quit: bool,
    /// Set by the renderer: below 60 columns only one pane shows.
    pub narrow: bool,
    /// Set by the renderer: rows in the active list, for paging.
    pub page: usize,
    /// Animation clock in milliseconds, set by the runtime before drawing.
    pub anim_ms: u64,
    /// Set by the renderer: every rainbow wordmark cell it drew, as
    /// `(column, row, letter index)`, so the SVG preview can animate them.
    pub rainbow_cells: Vec<(u16, u16, usize)>,
    /// The picker, while it is up: at startup without a path, or over the
    /// view after `o`.
    pub picker: Option<Picker>,
    /// Set by the renderer: the first picker row in view.
    pub picker_offset: usize,
    /// Files this session saved an edit for, by the view's path.
    saved: HashMap<PathBuf, Saved>,
    /// Output copies listed in the view, mapped to their originals.
    copies: HashMap<PathBuf, PathBuf>,
    /// Work running off the input thread, if any.
    pub busy: Option<Busy>,
    /// Set by the renderer once the open confirm has been drawn; `y` does
    /// nothing before that, so a key queued ahead of the modal cannot
    /// confirm it.
    pub confirm_drawn: bool,
    /// What the running job last reported, for the activity row.
    pub activity: Option<Activity>,
    /// When the running job started, on the animation clock.
    pub busy_since: u64,
    /// The running job was asked to stop after its current item.
    pub stopping: bool,
    /// Quit once the running job has ended.
    pub quit_after: bool,
    /// Why Esc did not stop the running job, for the activity row.
    pub busy_note: Option<&'static str>,
    /// The picks the running job (or the plan awaiting its confirm) was
    /// built from.
    job_picks: Option<Picks>,
    /// Caveats for the deattribute plan being built: folders that were
    /// still being scanned when it was asked for.
    pub plan_caveats: Vec<String>,
}

impl App {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            root: root.clone(),
            reports: Vec::new(),
            scanning: true,
            total: None,
            screen: Screen::Main,
            pane: Pane::Files,
            overlay: None,
            filter: Filter::None,
            file_cursor: 0,
            file_offset: 0,
            finding_cursor: 0,
            finding_offset: 0,
            picked_files: BTreeSet::new(),
            picked_findings: BTreeSet::new(),
            picked_dirs: BTreeSet::new(),
            tree: Tree::new(&root),
            explorer: Explorer::new(&root),
            signatures: None,
            buckets_at: None,
            bucket_by: BucketBy::Category,
            buckets: Vec::new(),
            bucket_cursor: 0,
            bucket_offset: 0,
            detail_scroll: 0,
            detail_lines: 0,
            hex: None,
            status: None,
            quit_armed: false,
            should_quit: false,
            narrow: false,
            page: 10,
            anim_ms: 0,
            rainbow_cells: Vec::new(),
            picker: None,
            picker_offset: 0,
            saved: HashMap::new(),
            copies: HashMap::new(),
            busy: None,
            confirm_drawn: false,
            activity: None,
            busy_since: 0,
            stopping: false,
            quit_after: false,
            busy_note: None,
            job_picks: None,
            plan_caveats: Vec::new(),
        }
    }

    /// The app in picker mode: nothing is scanned until something is chosen.
    pub fn picking(picker: Picker) -> Self {
        let mut app = Self::new(PathBuf::new());
        app.scanning = false;
        app.picker = Some(picker);
        app
    }

    /// Show `picker` over the current view, which keeps its state (and its
    /// scan keeps streaming) until a new path is chosen.
    pub fn open_picker(&mut self, picker: Picker) {
        self.overlay = None;
        self.quit_armed = false;
        self.picker = Some(picker);
        self.picker_offset = 0;
    }

    /// True while the picker is up.
    pub fn is_picking(&self) -> bool {
        self.picker.is_some()
    }

    /// Text the picker takes in one piece: a bracketed paste, or (with
    /// `burst`) keys that came too fast to be typed by hand, which become
    /// prompt text instead of commands. A key sheet over the picker closes.
    pub fn picker_text(&mut self, text: &str, burst: bool) {
        let Some(picker) = self.picker.as_mut() else {
            return;
        };
        self.overlay = None;
        if burst {
            picker.on_burst(text);
        } else {
            picker.on_paste(text);
        }
    }

    /// Leave the picker for a fresh main view over `root`: picks, filter and
    /// old reports are dropped. Only the animation clock carries over.
    fn begin(&mut self, root: PathBuf) {
        let anim = self.anim_ms;
        *self = Self::new(root);
        self.anim_ms = anim;
    }

    // ---- data in -------------------------------------------------------

    /// Add freshly scanned reports (one drained batch), as
    /// [`App::push_scanned`] does without reasons.
    pub fn push_reports(&mut self, batch: Vec<FileReport>) {
        let batch = batch
            .into_iter()
            .map(|report| Scanned {
                report,
                error: None,
            })
            .collect();
        self.push_scanned(batch);
    }

    /// Add one drained batch of scanned entries. Every entry moves the
    /// scan's progress and frontier, repeats included (the walk counted
    /// them), and a folder that could not be listed goes to its folder row,
    /// never the files. The list stays sorted by path while the scan
    /// streams in, so nothing reshuffles at the end. A path already listed
    /// keeps its report: a copy written and rescanned while the scan streams
    /// would otherwise show up twice.
    pub fn push_scanned(&mut self, batch: Vec<Scanned>) {
        if batch.is_empty() {
            return;
        }
        let keep = self.cursor_path();
        let mut created = Vec::new();
        for s in &batch {
            self.tree.entry(&s.report.path, &mut created);
        }
        let mut files = Vec::with_capacity(batch.len());
        for s in batch {
            match s.error.as_deref() {
                Some(why) if s.report.partial && is_folder_reason(why) => {
                    self.tree.add_unreadable(&s.report.path, why, &mut created)
                }
                _ => files.push(s),
            }
        }
        files.sort_by(|a, b| a.report.path.cmp(&b.report.path));
        files.dedup_by(|a, b| a.report.path == b.report.path);
        files.retain(|s| find_report(&self.reports, &s.report.path).is_none());
        for s in &files {
            self.tree.add(&s.report, s.error.as_deref(), &mut created);
        }
        let paths: Vec<PathBuf> = files.iter().map(|s| s.report.path.clone()).collect();
        // The walk hands files over in path order, so a batch nearly always
        // sorts after everything listed; otherwise the stable sort merges the
        // two sorted runs in linear time.
        let appends = match (self.reports.last(), paths.first()) {
            (Some(last), Some(first)) => *first > last.path,
            _ => true,
        };
        self.reports.extend(files.into_iter().map(|s| s.report));
        if !appends {
            self.reports.sort_by(|a, b| a.path.cmp(&b.path));
        }
        let added: Vec<&FileReport> = paths
            .iter()
            .filter_map(|p| find_report(&self.reports, p))
            .collect();
        self.explorer
            .absorb(&self.tree, &created, &added, &self.filter);
        self.refresh(keep);
    }

    /// Fold in one of the walk's count deltas.
    pub fn counted(&mut self, delta: &CountDelta) {
        self.tree.counted(delta);
    }

    /// The scan finished: every folder is complete.
    pub fn scan_done(&mut self) {
        let keep = self.cursor_path();
        self.scanning = false;
        self.reports.sort_by(|a, b| a.path.cmp(&b.path));
        self.buckets_at = None;
        self.refresh(keep);
    }

    /// Replace the report for `new.path` in place (or add it). Not a scanned
    /// entry, so the scan's progress stays where it is.
    pub fn replace_report(&mut self, new: FileReport) {
        let keep = self.cursor_path();
        self.picked_findings.retain(|(p, _)| *p != new.path);
        match self.reports.binary_search_by(|r| r.path.cmp(&new.path)) {
            Ok(at) => {
                self.tree.replace(&self.reports[at], &new);
                self.reports[at] = new;
                self.explorer.recheck(&self.reports[at], &self.filter);
            }
            Err(at) => {
                let mut created = Vec::new();
                self.tree.add(&new, None, &mut created);
                self.reports.insert(at, new);
                let added = [&self.reports[at]];
                self.explorer
                    .absorb(&self.tree, &created, &added, &self.filter);
            }
        }
        self.hex = None;
        self.refresh(keep);
    }

    /// Drop the report for `path` (its file went to the trash).
    pub fn remove_report(&mut self, path: &Path) {
        let keep = self.cursor_path();
        self.saved.remove(path);
        self.copies.remove(path);
        if let Ok(at) = self
            .reports
            .binary_search_by(|r| r.path.as_path().cmp(path))
        {
            let gone = self.reports.remove(at);
            self.tree.remove(&gone);
        }
        self.explorer.forget(&self.tree, path);
        self.picked_files.remove(path);
        self.picked_findings.retain(|(p, _)| p != path);
        self.hex = None;
        self.refresh(keep);
    }

    /// The folder whose listing the files list still lacks, for the runtime
    /// to read off the input thread.
    pub fn listing_request(&self) -> Option<PathBuf> {
        if self.is_picking() {
            return None;
        }
        self.explorer.listing_request().map(Path::to_path_buf)
    }

    /// A folder listing the runtime read.
    pub fn listing_ready(&mut self, listing: Listing) {
        if self.explorer.listing_ready(listing) {
            let keep = self.cursor_path();
            self.rebuild_rows();
            self.refresh(keep);
        }
    }

    /// The listing of `at` could not be read at all.
    pub fn listing_failed(&mut self, at: &Path) {
        self.explorer.listing_failed(at);
    }

    pub fn reports(&self) -> &[FileReport] {
        &self.reports
    }

    pub fn has_report(&self, path: &Path) -> bool {
        self.reports
            .binary_search_by(|r| r.path.as_path().cmp(path))
            .is_ok()
    }

    pub fn clear_picks(&mut self) {
        self.picked_files.clear();
        self.picked_findings.clear();
        self.picked_dirs.clear();
    }

    pub fn set_status(&mut self, text: impl Into<String>, tone: Tone) {
        self.status = Some(Status {
            text: text.into(),
            tone,
        });
    }

    // ---- saved marks ---------------------------------------------------

    /// Mark `path` as saved. Another scrub of the same file adds its edits to
    /// the count; a new deattributed copy replaces the old one, so its count
    /// replaces the old count.
    pub fn mark_saved(&mut self, path: &Path, kind: SavedKind, output: PathBuf, edits: usize) {
        match self.saved.get_mut(path) {
            Some(s) if kind == SavedKind::Scrubbed && s.kind == kind && s.output == output => {
                s.edits += edits
            }
            _ => {
                self.saved.insert(
                    path.to_path_buf(),
                    Saved {
                        kind,
                        output,
                        edits,
                    },
                );
            }
        }
    }

    /// The saved mark on `path`, if any.
    pub fn saved(&self, path: &Path) -> Option<&Saved> {
        self.saved.get(path)
    }

    /// Clear a scrub mark (its edits were undone). A deattribute mark stays:
    /// its copy is a separate file that undo does not touch.
    pub fn clear_scrubbed(&mut self, path: &Path) {
        if self
            .saved
            .get(path)
            .is_some_and(|s| s.kind == SavedKind::Scrubbed)
        {
            self.saved.remove(path);
        }
    }

    /// The original an output copy in the view was made from.
    pub fn copy_of(&self, path: &Path) -> Option<&Path> {
        self.copies.get(path).map(PathBuf::as_path)
    }

    /// Whether `path` is under the scanned root (a single-file scan has
    /// nothing under it).
    pub fn in_root(&self, path: &Path) -> bool {
        under_root(&self.root, path)
    }

    /// A deattributed copy was written and scanned as `report`. When it lands
    /// under the scanned root it joins the list and points back to
    /// `original`. True when it was added.
    pub fn add_output_copy(&mut self, original: &Path, report: FileReport) -> bool {
        if !self.in_root(&report.path) {
            return false;
        }
        self.copies
            .insert(report.path.clone(), original.to_path_buf());
        self.replace_report(report);
        true
    }

    /// Whether `path` is a deattributed copy: one written this session, or
    /// any file named like one.
    pub fn is_copy(&self, path: &Path) -> bool {
        self.copies.contains_key(path) || deattribute::is_deattributed(path)
    }

    /// Start waiting on `work`: edit keys are ignored until it finishes. The
    /// picks a plan or batch is built from are noted, so only those are
    /// cleared when it ends and picks made meanwhile survive.
    pub fn begin_busy(&mut self, work: Busy) {
        if work != Busy::Undoing && self.job_picks.is_none() {
            self.job_picks = Some(Picks {
                files: self.picked_files.clone(),
                findings: self.picked_findings.clone(),
                dirs: self.picked_dirs.clone(),
            });
        }
        self.busy = Some(work);
        self.activity = None;
        self.stopping = false;
        self.busy_note = None;
        self.busy_since = self.anim_ms;
        self.set_status(work.status(), Tone::Info);
    }

    /// The work running off the input thread ended, whatever its outcome:
    /// the edit keys work again. A quit asked for while it ran happens now.
    pub fn end_busy(&mut self) {
        self.busy = None;
        self.activity = None;
        self.stopping = false;
        self.busy_note = None;
        if self.quit_after {
            self.should_quit = true;
        }
    }

    /// Clear the picks the ended job was built from; picks made while it ran
    /// stay.
    pub fn clear_job_picks(&mut self) {
        if let Some(p) = self.job_picks.take() {
            self.picked_files.retain(|f| !p.files.contains(f));
            self.picked_findings.retain(|f| !p.findings.contains(f));
            self.picked_dirs.retain(|d| !p.dirs.contains(d));
        }
    }

    /// Whether Esc stops the running work now: it can stop, has not been
    /// asked to yet, and is not rescanning what it changed.
    pub fn can_stop(&self) -> bool {
        self.busy.is_some_and(Busy::stoppable)
            && !self.stopping
            && !self.activity.as_ref().is_some_and(|a| a.rescanning)
    }

    /// The work could not run (the trash store would not open, or another
    /// meownary process holds the lock): say why. Nothing changed, so the
    /// picks stay.
    pub fn job_refused(&mut self, text: impl Into<String>, tone: Tone) {
        self.job_picks = None;
        self.end_busy();
        self.set_status(text, tone);
    }

    /// The work ended without a result: it stopped on an internal error.
    pub fn job_failed(&mut self) {
        let Some(work) = self.busy else {
            return;
        };
        self.job_picks = None;
        self.end_busy();
        let text = match work {
            Busy::Planning => "Planning stopped on an internal error. Nothing changed.",
            Busy::Writing => {
                "Writing copies stopped on an internal error. The originals are unchanged."
            }
            Busy::Scrubbing | Busy::Deleting => {
                "That action stopped on an internal error. Press u to undo any part that landed."
            }
            Busy::Undoing => "Undo stopped on an internal error.",
        };
        self.set_status(text, Tone::Bad);
    }

    /// A deattribute plan finished building: offer it, or say why not.
    pub fn plan_ready(&mut self, plan: Result<Plan, String>) {
        self.end_busy();
        self.status = None;
        if plan.is_err() {
            self.job_picks = None;
        }
        let caveats = std::mem::take(&mut self.plan_caveats);
        let plan = plan.map(|mut plan| {
            plan.caveats.splice(0..0, caveats);
            plan
        });
        self.offer(plan);
    }

    /// The copies of a confirmed deattribute plan were written (or not), or
    /// writing stopped early. Write failures are listed before the plan's
    /// own skips.
    pub fn copies_written(&mut self, plan_skips: &[String], out: CopiesOutcome) {
        self.end_busy();
        self.clear_job_picks();
        let mut skipped = out.failed;
        skipped.extend(plan_skips.iter().cloned());
        self.record_saved(SavedKind::Deattributed, &out.saved, &skipped, &[]);
        if out.stopped {
            self.status = Some(stopped_status(
                PlanKind::Deattribute,
                out.saved.len(),
                out.not_written,
                &skipped,
                &[],
            ));
        }
        if let (Some(first), Some(status)) = (out.unverified.first(), self.status.as_mut()) {
            if status.text.ends_with('.') {
                status.text.pop();
            }
            status
                .text
                .push_str(&format!("; verification incomplete for {first}"));
            if out.unverified.len() > 1 {
                status
                    .text
                    .push_str(&format!(" +{} more", thousands(out.unverified.len() - 1)));
            }
            status.text.push('.');
            status.tone = Tone::Warn;
        }
        for (original, report) in out.copies {
            self.add_output_copy(&original, report);
        }
    }

    /// Mark every saved file and say what was saved in the status line, with
    /// the first file named and a "+N more" for the rest. `skipped` and
    /// `refused` carry reasons, as in [`batch_status`].
    pub fn record_saved(
        &mut self,
        kind: SavedKind,
        items: &[SavedItem],
        skipped: &[String],
        refused: &[String],
    ) {
        for item in items {
            self.mark_saved(&item.path, kind, item.output.clone(), item.edits);
        }
        self.status = Some(self.saved_status(kind, items, skipped, refused));
    }

    /// The status after an action saved `items`.
    pub fn saved_status(
        &self,
        kind: SavedKind,
        items: &[SavedItem],
        skipped: &[String],
        refused: &[String],
    ) -> Status {
        let Some(first) = items.first() else {
            if kind == SavedKind::Deattributed && !skipped.is_empty() {
                return Status {
                    text: format!(
                        "Saved nothing; skipped {}: {}.",
                        thousands(skipped.len()),
                        skipped[0]
                    ),
                    tone: Tone::Bad,
                };
            }
            let plan = match kind {
                SavedKind::Scrubbed => PlanKind::Scrub,
                SavedKind::Deattributed => PlanKind::Deattribute,
            };
            return batch_status(plan, 0, skipped, refused);
        };
        let name = self.display_path(&first.path);
        let mut text = match kind {
            SavedKind::Scrubbed => format!(
                "Saved {name} ({} {})",
                thousands(first.edits),
                plural(first.edits, "edit", "edits")
            ),
            SavedKind::Deattributed => {
                let out = first
                    .output
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| first.output.display().to_string());
                let beside = first
                    .path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or(name);
                format!("Saved {out} beside {beside}")
            }
        };
        if items.len() > 1 {
            text.push_str(&format!(" +{} more", thousands(items.len() - 1)));
        }
        if !skipped.is_empty() {
            text.push_str(&format!(
                "; skipped {}: {}",
                thousands(skipped.len()),
                skipped[0]
            ));
        }
        if !refused.is_empty() {
            text.push_str(&format!("; refused {}", thousands(refused.len())));
        }
        text.push('.');
        if kind == SavedKind::Scrubbed {
            text.push_str(" Press u to undo.");
        }
        let tone = if skipped.is_empty() && refused.is_empty() {
            Tone::Good
        } else {
            Tone::Warn
        };
        Status { text, tone }
    }

    /// The highlighted row's path. A change to the rows captures it first,
    /// while the cursor still points where it did, and hands it to
    /// [`App::refresh`], so an insert or removal above never moves the
    /// highlight.
    fn cursor_path(&self) -> Option<PathBuf> {
        self.rows().get(self.file_cursor).map(|r| r.path.clone())
    }

    fn refresh(&mut self, keep: Option<PathBuf>) {
        // A row asked for on entering a folder wins once it shows up.
        let wanted = self
            .explorer
            .want
            .clone()
            .filter(|w| self.rows().iter().any(|r| r.path == *w));
        if wanted.is_some() {
            self.explorer.want = None;
        }
        if let Some(p) = wanted.or(keep)
            && let Some(pos) = self.rows().iter().position(|r| r.path == p)
        {
            self.file_cursor = pos;
        }
        self.file_cursor = clamp(self.file_cursor, self.rows().len());
        let n = self.current_findings().len();
        self.finding_cursor = clamp(self.finding_cursor, n);
        // Buckets are only kept current while their screen is up, and at
        // most twice a second while the scan streams in.
        if self.screen == Screen::Buckets && self.buckets_due() {
            self.regroup();
        }
        self.bucket_cursor = clamp(self.bucket_cursor, self.buckets.len());
        if self.screen == Screen::Detail && self.current_finding().is_none() {
            self.screen = Screen::Main;
        }
    }

    fn buckets_due(&self) -> bool {
        !self.scanning
            || self
                .buckets_at
                .is_none_or(|at| self.anim_ms >= at.saturating_add(BUCKETS_EVERY_MS))
    }

    /// Group the findings under the cwd into buckets again.
    fn regroup(&mut self) {
        let range = self.range_of(self.explorer.cwd());
        self.buckets = bucketize(&self.reports[range], self.bucket_by);
        self.buckets_at = Some(self.anim_ms);
    }

    /// Lay the files list out again for the cwd and the filter.
    fn rebuild_rows(&mut self) {
        self.explorer
            .rebuild(&self.tree, &self.reports, &self.filter);
    }

    // ---- queries -------------------------------------------------------

    /// Counts for the whole scan, from the tree's root.
    pub fn stats(&self) -> Stats {
        let a = self.tree.root_agg();
        Stats {
            flagged: a.flagged,
            removable: a.removable,
            alerts: a.alerts(),
        }
    }

    /// The rows of the files list: the cwd's folders and files, or with a
    /// filter on, the matching files under it.
    pub fn rows(&self) -> &[Row] {
        self.explorer.rows()
    }

    pub fn current_row(&self) -> Option<&Row> {
        self.rows().get(self.file_cursor)
    }

    /// The highlighted folder, when a folder row is highlighted.
    pub fn current_folder(&self) -> Option<&Path> {
        self.current_row()
            .filter(|r| r.dir)
            .map(|r| r.path.as_path())
    }

    /// The report at `path`.
    pub fn report(&self, path: &Path) -> Option<&FileReport> {
        find_report(&self.reports, path)
    }

    pub fn current_file(&self) -> Option<&FileReport> {
        let row = self.current_row().filter(|r| !r.dir)?;
        self.report(&row.path)
    }

    /// The folder the files list shows.
    pub fn cwd(&self) -> &Path {
        self.explorer.cwd()
    }

    pub fn at_root(&self) -> bool {
        self.explorer.at_root()
    }

    pub fn tree(&self) -> &Tree {
        &self.tree
    }

    /// The reports under `dir`: a contiguous run, or every report at the
    /// root.
    fn range_of(&self, dir: &Path) -> std::ops::Range<usize> {
        if dir == self.root {
            0..self.reports.len()
        } else {
            subtree(&self.reports, dir)
        }
    }

    /// Files under the cwd, at any depth.
    pub fn cwd_files(&self) -> usize {
        if self.at_root() {
            return self.tree.root_agg().files;
        }
        self.tree
            .find(self.cwd())
            .map_or(0, |i| self.tree.node(i).agg.files)
    }

    /// The state a folder row shows.
    pub fn folder_state(&self, row: &Row) -> FolderState {
        explorer::folder_state(&self.tree, &row.path, row.listed, self.scanning)
    }

    /// Whether the scan is done with `path`, so a listed entry it never
    /// delivered was left out.
    pub fn is_final(&self, path: &Path) -> bool {
        explorer::is_final(&self.tree, path, self.scanning)
    }

    /// Whether the scan has yet to finish `dir`.
    pub fn still_scanning(&self, dir: &Path) -> bool {
        !self.is_final(dir)
    }

    /// Why the cwd could not be listed, when it could not.
    pub fn cwd_unreadable(&self) -> Option<&str> {
        let i = self.tree.find(self.cwd())?;
        self.tree.node(i).unreadable.as_deref()
    }

    /// Whether the root has subfolders, so the idle hint can point at Enter.
    pub fn has_subfolders(&self) -> bool {
        !self.tree.node(0).children.is_empty() || self.explorer.lists_folders(&self.root)
    }

    /// The path from the root down to the cwd, as the files pane titles it.
    pub fn breadcrumb(&self) -> String {
        let base = explorer::name_of(&self.root);
        match self.cwd().strip_prefix(&self.root) {
            Ok(rel) if !rel.as_os_str().is_empty() => {
                format!("{base}{}{}", std::path::MAIN_SEPARATOR, rel.display())
            }
            _ => base,
        }
    }

    /// The cwd's own name.
    pub fn cwd_name(&self) -> String {
        explorer::name_of(self.cwd())
    }

    /// The scan's progress: entries delivered, out of how many, and whether
    /// that count is final. `None` until the walk has counted anything.
    pub fn scan_progress(&self) -> Option<(usize, usize, bool)> {
        let done = self.tree.scanned();
        if let Some(t) = self.total {
            return Some((done, t.max(done), true));
        }
        let counted = self.tree.counts().total() as usize;
        (counted > 0).then_some((done, counted.max(done), false))
    }

    /// The folder the scan is in, as shown.
    pub fn scanning_folder(&self) -> Option<String> {
        let f = self.tree.frontier()?;
        let dir = if f == self.root {
            f
        } else {
            f.parent().unwrap_or(f)
        };
        Some(self.display_path(dir))
    }

    /// The five most common signatures under `dir`, each with its count.
    /// Kept per folder until something under it changes, and while the scan
    /// streams in, worked out again at most every 300 ms.
    pub fn folder_signatures(&mut self, dir: &Path) -> Vec<(String, usize)> {
        let stamp = self.tree.find(dir).map_or(0, |i| self.tree.node(i).stamp());
        if let Some(c) = &self.signatures
            && c.path == dir
            && (c.stamp == stamp
                || (self.scanning && self.anim_ms < c.at.saturating_add(SIGNATURES_EVERY_MS)))
        {
            return c.top.clone();
        }
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for r in &self.reports[self.range_of(dir)] {
            for f in &r.findings {
                *counts.entry(f.signature_id.as_str()).or_default() += 1;
            }
        }
        let mut top: Vec<(String, usize)> = counts
            .into_iter()
            .map(|(s, n)| (s.to_string(), n))
            .collect();
        top.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        top.truncate(5);
        self.signatures = Some(Signatures {
            path: dir.to_path_buf(),
            stamp,
            at: self.anim_ms,
            top: top.clone(),
        });
        top
    }

    /// Indices into the current file's findings that the filter lets
    /// through, loudest first.
    pub fn current_findings(&self) -> Vec<usize> {
        self.current_file()
            .map(|r| finding_indices(&self.filter, r))
            .unwrap_or_default()
    }

    /// The highlighted finding: its file, its index, the finding.
    pub fn current_finding(&self) -> Option<(&FileReport, usize, &Finding)> {
        let r = self.current_file()?;
        let idx = *finding_indices(&self.filter, r).get(self.finding_cursor)?;
        Some((r, idx, r.findings.get(idx)?))
    }

    pub fn buckets(&self) -> &[Bucket] {
        &self.buckets
    }

    /// The hex window the detail view needs and does not have yet, as the
    /// file and the evidence offset. The runtime reads it before drawing.
    pub fn hex_request(&self) -> Option<(PathBuf, u64)> {
        if self.screen != Screen::Detail {
            return None;
        }
        let (r, _, f) = self.current_finding()?;
        let base = hex_base(f.evidence.offset);
        match &self.hex {
            Some(h) if h.path == r.path && h.base == base => None,
            _ => Some((r.path.clone(), f.evidence.offset)),
        }
    }

    pub fn picked(&self) -> usize {
        self.picked_files.len() + self.picked_findings.len() + self.picked_dirs.len()
    }

    pub fn is_file_picked(&self, p: &Path) -> bool {
        self.picked_files.contains(p)
    }

    pub fn is_dir_picked(&self, p: &Path) -> bool {
        self.picked_dirs.contains(p)
    }

    pub fn is_finding_picked(&self, p: &Path, idx: usize) -> bool {
        self.picked_findings.contains(&(p.to_path_buf(), idx))
    }

    /// A path as shown: relative to the scan root, or the file name.
    pub fn display_path(&self, p: &Path) -> String {
        display_under(&self.root, p)
    }

    /// The scan line: progress while scanning, a summary after.
    pub fn scan_line(&self) -> String {
        let n = self.tree.scanned();
        let shown = thousands(n);
        if self.scanning {
            return match self.scan_progress() {
                Some((_, of, true)) => format!("Scanning {shown} of {} files", thousands(of)),
                Some((_, of, false)) => format!("Scanning {shown} of {}+ files", thousands(of)),
                None => format!("Scanning {shown} {}...", plural(n, "file", "files")),
            };
        }
        if n == 0 {
            return "No files to scan.".to_string();
        }
        let s = self.stats();
        if s.flagged == 0 {
            return format!(
                "Scanned {shown} {}. No findings.",
                plural(n, "file", "files")
            );
        }
        format!(
            "Scanned {shown} {}: {} with findings, {} removable {}.",
            plural(n, "file", "files"),
            thousands(s.flagged),
            thousands(s.removable),
            plural(s.removable, "marker", "markers")
        )
    }

    /// The footer context name for `keymap::footer_hints`.
    pub fn context(&self) -> &'static str {
        if self.is_picking() {
            return "picker";
        }
        match &self.overlay {
            Some(Overlay::Help) => return "help",
            Some(Overlay::Filter) => return "filter",
            Some(Overlay::Confirm(_)) => return "confirm",
            None => {}
        }
        match (self.screen, self.pane) {
            (Screen::Detail, _) => "detail",
            (Screen::Buckets, _) => "buckets",
            (Screen::Main, Pane::Findings) => "findings",
            (Screen::Main, Pane::Files) => "files",
        }
    }

    // ---- keys ----------------------------------------------------------

    /// Handle one key event.
    pub fn on_key(&mut self, ev: KeyEvent) -> Effect {
        if let Some(picker) = self.picker.as_mut() {
            if ev.kind == KeyEventKind::Release {
                return Effect::None;
            }
            if matches!(self.overlay, Some(Overlay::Help)) {
                // Any key closes the picker's key sheet; ctrl+c still quits.
                let ctrl = ev.modifiers.contains(KeyModifiers::CONTROL);
                if ctrl && ev.code == KeyCode::Char('c') {
                    return self.quit();
                }
                self.overlay = None;
                return Effect::None;
            }
            return match picker.on_key(ev) {
                PickOutcome::Stay => Effect::None,
                PickOutcome::Help => {
                    self.overlay = Some(Overlay::Help);
                    Effect::None
                }
                PickOutcome::Quit => self.quit(),
                PickOutcome::Back => {
                    // Reopened over a view: that view, and any scan still
                    // streaming into it, carry on unchanged.
                    self.picker = None;
                    Effect::None
                }
                PickOutcome::Scan(path) => {
                    self.begin(path.clone());
                    Effect::Scan(path)
                }
            };
        }
        if matches!(self.overlay, Some(Overlay::Filter)) {
            return self.on_filter_key(ev);
        }
        match Key::from_event(&ev) {
            Some(k) => self.on_action(k),
            None => {
                self.quit_armed = false;
                Effect::None
            }
        }
    }

    fn on_filter_key(&mut self, ev: KeyEvent) -> Effect {
        let ctrl = ev.modifiers.contains(KeyModifiers::CONTROL);
        let mut text = match &self.filter {
            Filter::Text(t) => t.clone(),
            _ => String::new(),
        };
        match ev.code {
            KeyCode::Char('c') if ctrl => return self.stop_or_quit(),
            KeyCode::Enter => {
                self.overlay = None;
                return Effect::None;
            }
            KeyCode::Esc => {
                self.overlay = None;
                self.set_filter(Filter::None);
                return Effect::None;
            }
            KeyCode::Backspace => {
                text.pop();
            }
            KeyCode::Char(c) if !ctrl && !c.is_control() => text.push(c),
            _ => return Effect::None,
        }
        self.set_filter(Filter::Text(text));
        Effect::None
    }

    /// Handle a mapped key. Every [`Key`] has an arm here.
    pub fn on_action(&mut self, key: Key) -> Effect {
        if self.is_picking() {
            // The picker reads raw events through `on_key`; only an
            // interrupt means anything here.
            return if key == Key::Interrupt {
                self.quit()
            } else {
                Effect::None
            };
        }
        if key != Key::Esc {
            self.quit_armed = false;
        }
        if key == Key::Interrupt {
            return self.stop_or_quit();
        }
        if let Some(work) = self.busy
            && matches!(
                key,
                Key::Scrub
                    | Key::Deattribute
                    | Key::DeepDeattribute
                    | Key::Delete
                    | Key::Yes
                    | Key::Undo
                    | Key::Editor
                    | Key::Open
            )
        {
            self.set_status(work.status(), Tone::Info);
            return Effect::None;
        }
        match &mut self.overlay {
            Some(Overlay::Help) => {
                self.overlay = None;
                return Effect::None;
            }
            Some(Overlay::Confirm(plan)) => {
                let len = plan.items.len();
                match key {
                    // Only once the modal has been seen.
                    Key::Yes if !self.confirm_drawn => {}
                    Key::Yes => {
                        if let Some(Overlay::Confirm(plan)) = self.overlay.take() {
                            return Effect::Apply(plan);
                        }
                    }
                    Key::No | Key::Esc | Key::Quit => {
                        self.overlay = None;
                        self.job_picks = None;
                        self.set_status(MSG_NEVER_MIND, Tone::Info);
                    }
                    Key::Up | Key::Down | Key::PageUp | Key::PageDown | Key::Home | Key::End => {
                        plan.scroll = step(plan.scroll, len, key, self.page.max(1));
                    }
                    _ => {}
                }
                return Effect::None;
            }
            Some(Overlay::Filter) | None => {}
        }

        match key {
            Key::Up | Key::Down | Key::PageUp | Key::PageDown | Key::Home | Key::End => {
                self.navigate(key);
                Effect::None
            }
            Key::Tab => {
                if self.screen == Screen::Main {
                    self.pane = match self.pane {
                        Pane::Files => Pane::Findings,
                        Pane::Findings => Pane::Files,
                    };
                }
                Effect::None
            }
            Key::Left | Key::Backspace => {
                self.left();
                Effect::None
            }
            Key::Right | Key::Enter => self.enter(),
            Key::Esc => self.back(),
            Key::Space => {
                self.toggle_pick();
                Effect::None
            }
            Key::Scrub => {
                let plan = if self.screen == Screen::Buckets {
                    self.bucket_plan()
                } else {
                    self.scrub_plan()
                };
                self.offer(plan)
            }
            Key::Deattribute => self.request_plan(deattribute::Mode::Basic),
            Key::DeepDeattribute => self.request_plan(deattribute::Mode::Deep),
            Key::Delete => {
                let plan = self.delete_plan();
                self.offer(plan)
            }
            Key::Editor => match (self.screen, self.current_file()) {
                (Screen::Buckets, _) | (_, None) => {
                    self.set_status("Select a file first.", Tone::Info);
                    Effect::None
                }
                (_, Some(r)) => Effect::Edit(r.path.clone()),
            },
            Key::Buckets => {
                self.cycle_buckets();
                Effect::None
            }
            Key::Filter => {
                if !matches!(self.filter, Filter::Text(_)) {
                    self.set_filter(Filter::Text(String::new()));
                }
                self.overlay = Some(Overlay::Filter);
                Effect::None
            }
            Key::Undo => Effect::Undo,
            Key::Open => Effect::Pick,
            Key::Help => {
                self.overlay = Some(Overlay::Help);
                Effect::None
            }
            Key::Quit | Key::Interrupt => self.stop_or_quit(),
            Key::Yes | Key::No => Effect::None,
        }
    }

    fn quit(&mut self) -> Effect {
        self.should_quit = true;
        Effect::Quit
    }

    /// Ask the work running off the input thread to stop; with `quit`, the
    /// view ends once it has. `Some` carries what the runtime must do, and the
    /// key then does nothing else; `None` means nothing was running.
    ///
    /// A plan is dropped at once: nothing is written while planning. Copies
    /// and edits end after the file they are on, so none is left half done.
    /// An undo always runs to the end, and says so. A second quit request
    /// while waiting leaves at once, without waiting for the work.
    pub fn stop_request(&mut self, quit: bool) -> Option<Effect> {
        let work = self.busy?;
        if quit && self.quit_after {
            return Some(self.quit());
        }
        self.quit_after |= quit;
        match work {
            Busy::Planning => {
                self.job_picks = None;
                self.end_busy();
                self.set_status(MSG_NEVER_MIND, Tone::Info);
                Some(Effect::Stop)
            }
            Busy::Undoing => {
                self.busy_note = Some(if self.quit_after {
                    MSG_QUIT_AFTER_UNDO
                } else {
                    MSG_UNDO_RUNS
                });
                Some(Effect::None)
            }
            Busy::Writing | Busy::Scrubbing | Busy::Deleting => {
                self.stopping = true;
                Some(Effect::Stop)
            }
        }
    }

    /// Stop what is running and quit afterwards, or quit now.
    fn stop_or_quit(&mut self) -> Effect {
        match self.stop_request(true) {
            Some(effect) => effect,
            None => self.quit(),
        }
    }

    /// Where `o` opens the picker: the folder the view is showing.
    pub fn reopen_target(&self) -> &Path {
        self.explorer.cwd()
    }

    fn navigate(&mut self, key: Key) {
        let page = self.page.max(1);
        match self.screen {
            Screen::Detail => {
                let max = self.detail_lines.saturating_sub(page);
                self.detail_scroll = step(self.detail_scroll, max + 1, key, page);
            }
            Screen::Buckets => {
                self.bucket_cursor = step(self.bucket_cursor, self.buckets.len(), key, page);
            }
            Screen::Main => match self.pane {
                Pane::Files => {
                    let before = self.file_cursor;
                    self.file_cursor = step(self.file_cursor, self.rows().len(), key, page);
                    self.explorer.want = None;
                    if self.file_cursor != before {
                        self.finding_cursor = 0;
                        self.finding_offset = 0;
                        self.hex = None;
                    }
                }
                Pane::Findings => {
                    let n = self.current_findings().len();
                    self.finding_cursor = step(self.finding_cursor, n, key, page);
                }
            },
        }
    }

    /// Enter, Right and `l`: open the highlighted folder, focus a file's
    /// findings, open a finding's detail, or show a bucket.
    fn enter(&mut self) -> Effect {
        match self.screen {
            Screen::Main => {
                if let Some(dir) = self.current_folder().map(Path::to_path_buf) {
                    self.open_folder(&dir);
                    self.pane = Pane::Files;
                    return Effect::None;
                }
                match self.pane {
                    Pane::Files => {
                        if !self.current_findings().is_empty() {
                            self.pane = Pane::Findings;
                        } else if self.current_file().is_some() {
                            self.set_status("This file has no findings.", Tone::Good);
                        } else if self.current_row().is_some() {
                            self.set_status("This file has not been scanned.", Tone::Info);
                        }
                        Effect::None
                    }
                    Pane::Findings => self.open_detail(),
                }
            }
            Screen::Buckets => {
                if let Some(b) = self.buckets.get(self.bucket_cursor).cloned() {
                    self.screen = Screen::Main;
                    self.pane = Pane::Files;
                    self.set_filter(Filter::Bucket {
                        by: b.by,
                        key: b.key,
                        label: b.label,
                    });
                }
                Effect::None
            }
            Screen::Detail => Effect::None,
        }
    }

    /// Left, `h` and Backspace: back out of the detail or the buckets, back
    /// to the files from the findings, or up a folder in the files.
    fn left(&mut self) {
        match self.screen {
            Screen::Detail | Screen::Buckets => self.screen = Screen::Main,
            Screen::Main if self.pane == Pane::Findings => self.pane = Pane::Files,
            Screen::Main => self.go_up(),
        }
    }

    /// Show `dir` in the files list, highlighting the row it last had.
    pub fn open_folder(&mut self, dir: &Path) {
        if let Some(here) = self.cursor_path() {
            let cwd = self.explorer.cwd().to_path_buf();
            self.explorer.remember(&cwd, &here);
        }
        let back = self.explorer.remembered(dir).map(Path::to_path_buf);
        self.explorer.set_cwd(dir);
        self.rebuild_rows();
        self.file_cursor = 0;
        self.file_offset = 0;
        self.finding_cursor = 0;
        self.finding_offset = 0;
        self.hex = None;
        if let Some(p) = back {
            match self.rows().iter().position(|r| r.path == p) {
                Some(pos) => self.file_cursor = pos,
                None => self.explorer.want = Some(p),
            }
        }
        self.refresh(None);
    }

    /// Go up a folder, highlighting the one just left. Nothing happens at
    /// the root, or in a single-file scan.
    pub fn go_up(&mut self) {
        let from = self.explorer.cwd().to_path_buf();
        if from == self.root || !from.starts_with(&self.root) {
            return;
        }
        let Some(parent) = from.parent().map(Path::to_path_buf) else {
            return;
        };
        self.explorer.remember(&parent, &from);
        self.open_folder(&parent);
    }

    /// Show the file at `path` in its own folder, highlighted, with every
    /// folder on the way remembering the step down.
    fn reveal(&mut self, path: &Path) {
        let Some(dir) = path.parent().filter(|d| d.starts_with(&self.root)) else {
            return;
        };
        let mut at = path;
        while let Some(up) = at.parent() {
            self.explorer.remember(up, at);
            if up == self.root || !up.starts_with(&self.root) {
                break;
            }
            at = up;
        }
        self.explorer.set_cwd(dir);
        self.rebuild_rows();
        self.file_offset = 0;
        self.file_cursor = self.rows().iter().position(|r| r.path == path).unwrap_or(0);
    }

    fn open_detail(&mut self) -> Effect {
        let Some((r, _, f)) = self.current_finding() else {
            return Effect::None;
        };
        let (path, offset) = (r.path.clone(), f.evidence.offset);
        self.screen = Screen::Detail;
        self.detail_scroll = 0;
        Effect::LoadHex { path, offset }
    }

    fn back(&mut self) -> Effect {
        match self.screen {
            Screen::Detail | Screen::Buckets => {
                self.screen = Screen::Main;
                return Effect::None;
            }
            Screen::Main => {}
        }
        if self.filter.is_active() {
            self.set_filter(Filter::None);
            self.set_status("Filter cleared.", Tone::Info);
            return Effect::None;
        }
        if self.pane == Pane::Findings {
            self.pane = Pane::Files;
            return Effect::None;
        }
        if let Some(effect) = self.stop_request(false) {
            return effect;
        }
        if self.quit_armed {
            return self.quit();
        }
        self.quit_armed = true;
        self.set_status(MSG_QUIT_ARMED, Tone::Info);
        Effect::None
    }

    fn toggle_pick(&mut self) {
        if self.screen == Screen::Main
            && let Some(dir) = self.current_folder().map(Path::to_path_buf)
        {
            if !self.picked_dirs.remove(&dir) {
                self.picked_dirs.insert(dir);
            }
            return;
        }
        let on_file = self.screen == Screen::Main && self.pane == Pane::Files;
        if on_file {
            if let Some(p) = self.current_file().map(|r| r.path.clone())
                && !self.picked_files.remove(&p)
            {
                self.picked_files.insert(p);
            }
        } else if self.screen != Screen::Buckets
            && let Some(key) = self.current_finding().map(|(r, i, _)| (r.path.clone(), i))
            && !self.picked_findings.remove(&key)
        {
            self.picked_findings.insert(key);
        }
    }

    fn cycle_buckets(&mut self) {
        let next = match (self.screen, self.bucket_by) {
            (Screen::Buckets, BucketBy::Category) => Some(BucketBy::Signature),
            (Screen::Buckets, BucketBy::Signature) => Some(BucketBy::Container),
            (Screen::Buckets, BucketBy::Container) => None,
            _ => Some(BucketBy::Category),
        };
        match next {
            Some(by) => {
                self.screen = Screen::Buckets;
                self.bucket_by = by;
                self.bucket_cursor = 0;
                self.bucket_offset = 0;
                self.regroup();
            }
            None => {
                self.screen = Screen::Main;
                self.bucket_by = BucketBy::Category;
            }
        }
    }

    /// Replace the filter and lay the files list out again. Clearing a
    /// filter shows the highlighted match in its own folder.
    pub fn set_filter(&mut self, f: Filter) {
        let keep = self.cursor_path();
        let reveal = self.filter.is_active() && !f.is_active();
        self.filter = f;
        self.rebuild_rows();
        if reveal && let Some(p) = &keep {
            self.reveal(p);
        }
        self.refresh(keep);
    }

    fn offer(&mut self, plan: Result<Plan, String>) -> Effect {
        match plan {
            Ok(plan) => {
                self.overlay = Some(Overlay::Confirm(plan));
                self.confirm_drawn = false;
            }
            Err(why) => self.set_status(why, Tone::Info),
        }
        Effect::None
    }

    /// Hand the selected files to the runtime to plan off the input thread.
    fn request_plan(&mut self, mode: deattribute::Mode) -> Effect {
        match self.deattribute_request(mode) {
            Ok(req) => {
                // Folders still being scanned are named on the confirm, as
                // they stood when the plan was asked for.
                self.plan_caveats = self.scan_caveats(&self.selected_folders());
                self.begin_busy(Busy::Planning);
                Effect::PlanDeattribute(req)
            }
            Err(why) => {
                self.set_status(why, Tone::Info);
                Effect::None
            }
        }
    }

    // ---- plans ---------------------------------------------------------

    /// The scrub batch for the current picks, or the highlighted item. A
    /// folder covers every removable, non-weak finding under it.
    pub fn scrub_plan(&self) -> Result<Plan, String> {
        let index: HashMap<&Path, usize> = self
            .reports
            .iter()
            .enumerate()
            .map(|(i, r)| (r.path.as_path(), i))
            .collect();
        let mut picks: Vec<(usize, usize)> = Vec::new();
        let mut weak = 0usize;
        let mut dirs: Vec<&Path> = Vec::new();
        let mut push = |ri: usize, fi: usize, allow_weak: bool, picks: &mut Vec<(usize, usize)>| {
            let Some(f) = self.reports.get(ri).and_then(|r| r.findings.get(fi)) else {
                return;
            };
            if !f.is_removable() {
                return;
            }
            if f.confidence == Confidence::Weak && !allow_weak {
                weak += 1;
                return;
            }
            picks.push((ri, fi));
        };

        if self.picked() > 0 {
            for (p, fi) in &self.picked_findings {
                if let Some(&ri) = index.get(p.as_path()) {
                    push(ri, *fi, false, &mut picks);
                }
            }
            for p in &self.picked_files {
                if let Some(&ri) = index.get(p.as_path()) {
                    for fi in finding_indices(&self.filter, &self.reports[ri]) {
                        push(ri, fi, false, &mut picks);
                    }
                }
            }
            dirs.extend(self.picked_dirs.iter().map(PathBuf::as_path));
        } else if self.screen == Screen::Main
            && let Some(dir) = self.current_folder()
        {
            dirs.push(dir);
        } else if self.screen == Screen::Detail || self.pane == Pane::Findings {
            let Some((r, fi, f)) = self.current_finding() else {
                return Err(MSG_NOTHING.to_string());
            };
            if !f.is_removable() {
                return Err("Nothing to remove: this finding has no removable marker.".to_string());
            }
            if let Some(&ri) = index.get(r.path.as_path()) {
                push(ri, fi, true, &mut picks);
            }
        } else if let Some(r) = self.current_file()
            && let Some(&ri) = index.get(r.path.as_path())
        {
            for fi in finding_indices(&self.filter, r) {
                push(ri, fi, false, &mut picks);
            }
        }
        for dir in &dirs {
            for ri in self.range_of(dir) {
                for fi in finding_indices(&self.filter, &self.reports[ri]) {
                    push(ri, fi, false, &mut picks);
                }
            }
        }
        let mut plan = self.build_scrub(picks, weak)?;
        plan.caveats = self.scan_caveats(&dirs);
        Ok(plan)
    }

    /// A line for each of `dirs` the scan has yet to finish: files it finds
    /// there later are not part of an action started now.
    pub fn scan_caveats(&self, dirs: &[&Path]) -> Vec<String> {
        dirs.iter()
            .filter(|d| self.still_scanning(d))
            .map(|d| {
                format!(
                    "{} is still being scanned; files found later are not included.",
                    self.display_path(d)
                )
            })
            .collect()
    }

    /// The folders a deattribute would cover: the picked ones, or the
    /// highlighted one. W2's planner can hand [`App::scan_caveats`] of
    /// these to the confirm.
    pub fn selected_folders(&self) -> Vec<&Path> {
        if !self.picked_dirs.is_empty() {
            return self.picked_dirs.iter().map(PathBuf::as_path).collect();
        }
        if self.picked() == 0 && self.screen == Screen::Main {
            return self.current_folder().into_iter().collect();
        }
        Vec::new()
    }

    /// Every removable, non-weak member of the highlighted bucket, under the
    /// cwd.
    pub fn bucket_plan(&self) -> Result<Plan, String> {
        let Some(b) = self.buckets.get(self.bucket_cursor) else {
            return Err(MSG_NOTHING.to_string());
        };
        let mut picks = Vec::new();
        let mut weak = 0;
        for ri in self.range_of(self.cwd()) {
            for (fi, f) in self.reports[ri].findings.iter().enumerate() {
                if !f.is_removable() || bucket_key(b.by, f).as_deref() != Some(b.key.as_str()) {
                    continue;
                }
                if f.confidence == Confidence::Weak {
                    weak += 1;
                } else {
                    picks.push((ri, fi));
                }
            }
        }
        self.build_scrub(picks, weak)
    }

    fn build_scrub(&self, picks: Vec<(usize, usize)>, weak: usize) -> Result<Plan, String> {
        // Per file: drop duplicate markers, keep only the earliest truncate
        // (it covers the later ones), and run length-preserving edits first so
        // their offsets stay valid.
        let mut per_file: Vec<(usize, Vec<usize>)> = Vec::new();
        let mut slot: HashMap<usize, usize> = HashMap::new();
        let mut seen: HashSet<(usize, usize)> = HashSet::new();
        for (ri, fi) in picks {
            if !seen.insert((ri, fi)) {
                continue;
            }
            match slot.get(&ri) {
                Some(&k) => per_file[k].1.push(fi),
                None => {
                    slot.insert(ri, per_file.len());
                    per_file.push((ri, vec![fi]));
                }
            }
        }
        let mut items = Vec::new();
        for (ri, fis) in per_file {
            let r = &self.reports[ri];
            let mut markers: Vec<(&Finding, &Marker)> = Vec::new();
            for fi in fis {
                let f = &r.findings[fi];
                if let Some(m) = &f.marker
                    && !markers.iter().any(|(_, seen)| *seen == m)
                {
                    markers.push((f, m));
                }
            }
            let first_cut = markers
                .iter()
                .filter_map(|(_, m)| match m.removal {
                    RemovalStrategy::Truncate { from } => Some(from),
                    _ => None,
                })
                .min();
            markers.retain(|(_, m)| match m.removal {
                RemovalStrategy::Truncate { from } => Some(from) == first_cut,
                _ => true,
            });
            markers.sort_by_key(|(_, m)| match m.removal {
                RemovalStrategy::RawBlank { .. } => 0,
                RemovalStrategy::StructuralRemove => 1,
                RemovalStrategy::Truncate { .. } => 2,
                RemovalStrategy::DeleteFile => 3,
            });
            for (f, m) in markers {
                items.push(PlanItem {
                    path: r.path.clone(),
                    format: r.format.clone(),
                    size: r.size,
                    label: f.signature_id.clone(),
                    title: f.title.clone(),
                    marker: m.clone(),
                    risk: edit::assess(r.format.as_deref(), r.size, m),
                    expected_hash: None,
                    replacement: None,
                    credit: None,
                    archive: None,
                });
            }
        }
        if items.is_empty() {
            return Err(if weak > 0 {
                format!(
                    "Nothing to remove. {weak} weak {} left out of bulk scrubs.",
                    plural(weak, "finding is", "findings are")
                )
            } else {
                MSG_NOTHING.to_string()
            });
        }
        Ok(Plan {
            kind: PlanKind::Scrub,
            items,
            weak_left_out: weak,
            private_skips: Vec::new(),
            caveats: Vec::new(),
            replaces: Vec::new(),
            scroll: 0,
        })
    }

    /// Deattribute every selected file through the same planner as headless
    /// clean, right here. The view builds its plans on a worker through
    /// [`App::deattribute_request`] and [`plan_deattribute`] instead.
    pub fn deattribute_plan(&self) -> Result<Plan, String> {
        self.deattribute_plan_mode(deattribute::Mode::Basic)
    }

    /// [`App::deattribute_plan`] in `mode`.
    pub fn deattribute_plan_mode(&self, mode: deattribute::Mode) -> Result<Plan, String> {
        plan_deattribute(&self.deattribute_request(mode)?)
    }

    /// The files a deattribute in `mode` would cover: the picks (a folder
    /// covers every file under it, since a deattribute finds credits even
    /// in files with no findings), the highlighted bucket's files under the
    /// cwd, or the highlighted folder or file. Only the reports are gathered
    /// here; reading the files is left to [`plan_deattribute`].
    pub fn deattribute_request(
        &self,
        mode: deattribute::Mode,
    ) -> Result<DeattributeRequest, String> {
        let mut picked: BTreeSet<usize> = BTreeSet::new();
        let at = |p: &Path| {
            self.reports
                .binary_search_by(|r| r.path.as_path().cmp(p))
                .ok()
        };
        picked.extend(self.picked_files.iter().filter_map(|p| at(p)));
        picked.extend(self.picked_findings.iter().filter_map(|(p, _)| at(p)));
        let dirs = self.selected_folders();
        if picked.is_empty() && dirs.is_empty() {
            if self.screen == Screen::Buckets {
                if let Some(bucket) = self.buckets.get(self.bucket_cursor) {
                    for ri in self.range_of(self.cwd()) {
                        if self.reports[ri].findings.iter().any(|finding| {
                            bucket_key(bucket.by, finding).as_deref() == Some(bucket.key.as_str())
                        }) {
                            picked.insert(ri);
                        }
                    }
                }
            } else if let Some(report) = self.current_file() {
                picked.extend(at(&report.path));
            }
        }
        for dir in &dirs {
            picked.extend(self.range_of(dir));
        }
        if picked.is_empty() {
            return Err(MSG_NOTHING.to_string());
        }
        Ok(DeattributeRequest {
            root: self.root.clone(),
            mode,
            reports: picked
                .into_iter()
                .map(|i| self.reports[i].clone())
                .collect(),
        })
    }

    /// Delete the picked files, or the highlighted one. Folders are never
    /// deleted whole.
    pub fn delete_plan(&self) -> Result<Plan, String> {
        if self.screen == Screen::Buckets {
            return Err("Select files in the file list to delete them.".to_string());
        }
        let on_folder = self.picked_files.is_empty() && self.current_folder().is_some();
        if !self.picked_dirs.is_empty() || on_folder {
            return Err("Delete works on files only. Open the folder to pick files.".to_string());
        }
        let targets: Vec<&FileReport> = if self.picked_files.is_empty() {
            self.current_file().into_iter().collect()
        } else {
            self.reports
                .iter()
                .filter(|r| self.picked_files.contains(&r.path))
                .collect()
        };
        if targets.is_empty() {
            return Err(MSG_NOTHING.to_string());
        }
        let items = targets
            .into_iter()
            .map(|r| {
                let marker = delete_marker();
                PlanItem {
                    path: r.path.clone(),
                    format: r.format.clone(),
                    size: r.size,
                    label: "delete file".to_string(),
                    title: self.display_path(&r.path),
                    risk: edit::assess(r.format.as_deref(), r.size, &marker),
                    marker,
                    expected_hash: None,
                    replacement: None,
                    credit: None,
                    archive: None,
                }
            })
            .collect();
        Ok(Plan {
            kind: PlanKind::Delete,
            items,
            weak_left_out: 0,
            private_skips: Vec::new(),
            caveats: Vec::new(),
            replaces: Vec::new(),
            scroll: 0,
        })
    }
}

/// Whether a partial entry's reason says it is a folder that could not be
/// listed (see `scan::walk`).
fn is_folder_reason(why: &str) -> bool {
    why.starts_with("cannot list directory")
}

/// An archive entry's name made safe to show: control characters become `?`.
fn plain(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// Why a deattributed copy was not written, in a few generic words. A
/// refusal's own text names the rule, never the file's content.
pub fn edit_error_reason(e: &edit::EditError) -> String {
    match e {
        edit::EditError::Changed => "changed since scan".to_string(),
        edit::EditError::Io(_) => "io error".to_string(),
        edit::EditError::Symlink(_) => "a symlink, which is never followed".to_string(),
        edit::EditError::Refused(r) | edit::EditError::Unsupported(r) => plain(r),
        edit::EditError::Locked(_) => "another meownary process is editing".to_string(),
        edit::EditError::NeedsForce(_) => "unsafe edit".to_string(),
    }
}

/// A path as shown under `root`: relative to it, or the file name.
pub fn display_under(root: &Path, p: &Path) -> String {
    match p.strip_prefix(root) {
        Ok(rel) if !rel.as_os_str().is_empty() => rel.to_string_lossy().into_owned(),
        _ => p
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| p.to_string_lossy().into_owned()),
    }
}

/// Whether `path` is under the scanned `root` (a single-file scan has
/// nothing under it).
pub fn under_root(root: &Path, path: &Path) -> bool {
    path != root && path.starts_with(root) && root.is_dir()
}

/// The private skip for a file that is itself a deattributed copy.
pub const ALREADY_A_COPY: &str = "already a deattributed copy";

/// Build the deattribute plan for `req`. This reads every file (a deep sweep
/// reads up to 256 MiB of one, and an archive is dry-run through its writer),
/// so the view runs it on a worker. A panic while planning one file skips
/// that file as an unsafe edit. A plan with nothing to blank is an error
/// that names the first skip, never an empty confirm.
pub fn plan_deattribute(req: &DeattributeRequest) -> Result<Plan, String> {
    plan_deattribute_with(req, &mut Silent)
}

/// How much of a plain file a basic plan reads at most, for its weight on
/// the activity bar; a deep sweep reads up to [`DEEP_READ`].
const BASIC_READ: u64 = 16 << 20;
const DEEP_READ: u64 = 256 << 20;

/// What planning `report` weighs on the activity bar: an archive is dry-run
/// whole, a plain file read up to what its mode reads, and a copy is skipped.
fn plan_weight(report: &FileReport, mode: deattribute::Mode) -> u64 {
    if deattribute::is_deattributed(&report.path) {
        return 0;
    }
    if matches!(report.format.as_deref(), Some("zip" | "tar" | "gzip")) {
        return report.size;
    }
    let cap = if mode == deattribute::Mode::Deep {
        DEEP_READ
    } else {
        BASIC_READ
    };
    report.size.min(cap)
}

/// [`plan_deattribute`], reporting each file to `progress` as it is read. A
/// stop request abandons the plan between files: the view has already
/// dropped it, so the result says only that nothing changed.
pub fn plan_deattribute_with(
    req: &DeattributeRequest,
    progress: &mut dyn Progress,
) -> Result<Plan, String> {
    let mode = req.mode;
    let mut items = Vec::new();
    let mut private_skips = Vec::new();
    let mut caveats: Vec<String> = Vec::new();
    let mut replaces = Vec::new();
    let weights: Vec<u64> = req.reports.iter().map(|r| plan_weight(r, mode)).collect();
    let total = weights.iter().fold(0u64, |a, &w| a.saturating_add(w));
    progress.begin(req.reports.len(), total);
    for (report, &weight) in req.reports.iter().zip(&weights) {
        if progress.stop_requested() {
            return Err(MSG_NEVER_MIND.to_string());
        }
        progress.item(&report.path, weight);
        let shown = display_under(&req.root, &report.path);
        if deattribute::is_deattributed(&report.path) {
            private_skips.push(format!("{shown}: {ALREADY_A_COPY}"));
            continue;
        }
        if let Some(kind) = deattribute::archive_kind(&report.path, report.format.as_deref()) {
            if let Some(item) = archive_plan_item(&shown, report, kind, mode, &mut private_skips) {
                if let Some(a) = &item.archive
                    && exists(&a.dry_run.output)
                {
                    replaces.push(a.dry_run.output.clone());
                }
                items.push(item);
            }
            continue;
        }
        let Ok(view) = WindowedFile::open(&report.path) else {
            private_skips.push(format!("{shown}: io error"));
            continue;
        };
        let Ok(file_plan) =
            crate::scan::guard::guarded(|| deattribute::plan_mode(report, &view, mode))
        else {
            private_skips.push(format!("{shown}: unsafe edit"));
            continue;
        };
        for skipped in file_plan.skipped {
            private_skips.push(format!(
                "{shown}: {} ({})",
                skipped.kind.slug(),
                skipped.reason.slug()
            ));
        }
        if file_plan.targets.is_empty() {
            continue;
        }
        for caveat in file_plan.caveats {
            let line = sentence(caveat.slug());
            if !caveats.contains(&line) {
                caveats.push(line);
            }
        }
        let output = deattribute::deattributed_name(&report.path);
        if exists(&output) {
            replaces.push(output);
        }
        for target in file_plan.targets {
            items.push(PlanItem {
                path: report.path.clone(),
                format: report.format.clone(),
                size: report.size,
                label: target.kind.slug().to_string(),
                title: target.kind.slug().to_string(),
                marker: target.marker,
                risk: Risk::Safe,
                expected_hash: Some(target.expected_hash),
                replacement: target.replacement,
                credit: Some(target.kind),
                archive: None,
            });
        }
    }
    progress.end();
    if items.is_empty() {
        return Err(match private_skips.first() {
            None => MSG_NOTHING.to_string(),
            Some(first) => format!(
                "Nothing to blank; {} skipped: {first}.",
                thousands(private_skips.len())
            ),
        });
    }
    Ok(Plan {
        kind: if mode == deattribute::Mode::Deep {
            PlanKind::DeepDeattribute
        } else {
            PlanKind::Deattribute
        },
        items,
        weak_left_out: 0,
        private_skips,
        caveats,
        replaces,
        scroll: 0,
    })
}

/// Plan one archive as a single item meaning "the files inside": a dry run
/// through the same writer counts the files that have something to blank,
/// and the item keeps that dry run for the confirm and the write.
fn archive_plan_item(
    shown: &str,
    report: &FileReport,
    kind: deattribute::ArchiveKind,
    mode: deattribute::Mode,
    private_skips: &mut Vec<String>,
) -> Option<PlanItem> {
    let dry = crate::scan::guard::guarded(|| {
        deattribute::deattribute_archive_mode(&report.path, kind, true, mode)
    });
    let outcome = match dry {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(e)) => {
            private_skips.push(format!("{shown}: {}", edit_error_reason(&e)));
            return None;
        }
        Err(()) => {
            private_skips.push(format!("{shown}: unsafe edit"));
            return None;
        }
    };
    for (entry, reason) in &outcome.skipped {
        private_skips.push(format!("{shown}:{}: {}", plain(entry), reason.slug()));
    }
    let n = outcome.entries_cleaned;
    if n == 0 {
        private_skips.push(format!("{shown}: {}", deattribute::NOTHING_INSIDE));
        return None;
    }
    let label = format!("{} {} inside", thousands(n), plural(n, "file", "files"));
    Some(PlanItem {
        path: report.path.clone(),
        format: report.format.clone(),
        size: report.size,
        title: label.clone(),
        label,
        marker: Marker::blank(Region::new(0, 0), ContainerKind::Raw),
        risk: Risk::Safe,
        expected_hash: None,
        replacement: None,
        credit: None,
        archive: Some(ArchivePlan {
            kind,
            dry_run: outcome,
        }),
    })
}

/// Whether anything is at `path`, without following a link.
fn exists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// `s` as a sentence: a capital first letter and a closing period.
fn sentence(s: &str) -> String {
    let mut chars = s.chars();
    let mut out: String = chars
        .next()
        .map(|c| c.to_uppercase().collect())
        .unwrap_or_default();
    out.push_str(chars.as_str());
    if !out.ends_with('.') {
        out.push('.');
    }
    out
}

/// The marker a whole-file delete uses.
pub fn delete_marker() -> Marker {
    Marker {
        region: Region::new(0, 0),
        removal: RemovalStrategy::DeleteFile,
        container: ContainerKind::Generic,
        reversible: true,
    }
}

/// Move `cur` within `0..len` for a navigation key, clamping at both ends.
pub fn step(cur: usize, len: usize, key: Key, page: usize) -> usize {
    if len == 0 {
        return 0;
    }
    let last = len - 1;
    let cur = cur.min(last);
    match key {
        Key::Up => cur.saturating_sub(1),
        Key::Down => (cur + 1).min(last),
        Key::PageUp => cur.saturating_sub(page),
        Key::PageDown => cur.saturating_add(page).min(last),
        Key::Home => 0,
        Key::End => last,
        _ => cur,
    }
}

fn clamp(cur: usize, len: usize) -> usize {
    if len == 0 { 0 } else { cur.min(len - 1) }
}

pub fn plural<'a>(n: usize, one: &'a str, many: &'a str) -> &'a str {
    if n == 1 { one } else { many }
}

/// `n` with comma thousands separators: 1101278 reads "1,101,278".
pub fn thousands(n: usize) -> String {
    let digits = n.to_string();
    let len = digits.len();
    let mut out = String::with_capacity(len + len / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (len - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// How a file relates to the filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Match {
    None,
    /// The file itself matches: show every finding.
    All,
    /// Only some findings match: show those.
    Some,
}

/// Whether `r` passes `filter`, and how.
pub fn file_match(filter: &Filter, r: &FileReport) -> Match {
    match filter {
        Filter::None => Match::All,
        Filter::Text(q) if q.is_empty() => Match::All,
        Filter::Text(q) => {
            let q = q.to_lowercase();
            let hit = |s: &str| s.to_lowercase().contains(&q);
            if hit(&r.path.to_string_lossy()) || r.format.as_deref().is_some_and(hit) {
                return Match::All;
            }
            if r.findings
                .iter()
                .any(|f| hit(&f.signature_id) || hit(&f.title))
            {
                Match::Some
            } else {
                Match::None
            }
        }
        Filter::Bucket { by, key, .. } => {
            if r.findings
                .iter()
                .any(|f| bucket_key(*by, f).as_deref() == Some(key.as_str()))
            {
                Match::Some
            } else {
                Match::None
            }
        }
    }
}

/// Indices of `r`'s findings that pass `filter`, loudest first (severity, then
/// confidence, then scan order).
pub fn finding_indices(filter: &Filter, r: &FileReport) -> Vec<usize> {
    let all = file_match(filter, r) == Match::All;
    let mut out: Vec<usize> = (0..r.findings.len())
        .filter(|&i| all || finding_matches(filter, &r.findings[i]))
        .collect();
    out.sort_by(|&a, &b| {
        let (fa, fb) = (&r.findings[a], &r.findings[b]);
        fb.severity
            .cmp(&fa.severity)
            .then(fb.confidence.cmp(&fa.confidence))
            .then(a.cmp(&b))
    });
    out
}

fn finding_matches(filter: &Filter, f: &Finding) -> bool {
    match filter {
        Filter::None => true,
        Filter::Text(q) => {
            let q = q.to_lowercase();
            f.signature_id.to_lowercase().contains(&q) || f.title.to_lowercase().contains(&q)
        }
        Filter::Bucket { by, key, .. } => bucket_key(*by, f).as_deref() == Some(key.as_str()),
    }
}

/// The bucket key `model::bucketize` gives `f` under `by` (None when `f`
/// does not appear in that grouping).
pub fn bucket_key(by: BucketBy, f: &Finding) -> Option<String> {
    match by {
        BucketBy::Category => Some(f.category.slug().to_string()),
        BucketBy::Signature => Some(f.signature_id.clone()),
        BucketBy::Container => f
            .marker
            .as_ref()
            .map(|m| container_slug(m.container).to_string()),
    }
}

pub fn bucket_by_name(by: BucketBy) -> &'static str {
    match by {
        BucketBy::Category => "category",
        BucketBy::Signature => "signature",
        BucketBy::Container => "container",
    }
}

/// Mirrors the container slugs `model::bucketize` uses (checked by a test).
pub fn container_slug(c: ContainerKind) -> &'static str {
    match c {
        ContainerKind::Raw => "raw",
        ContainerKind::PeOverlay => "pe-overlay",
        ContainerKind::PeResource => "pe-resource",
        ContainerKind::JpegApp1 => "jpeg-app1",
        ContainerKind::ZipComment => "zip-comment",
        ContainerKind::Id3v1 => "id3v1",
        ContainerKind::Id3v2 => "id3v2",
        ContainerKind::ElfSection => "elf-section",
        ContainerKind::MachoLoadCmd => "macho-loadcmd",
        ContainerKind::PngChunk => "png-chunk",
        ContainerKind::RiffChunk => "riff-chunk",
        ContainerKind::IsoBox => "iso-box",
        ContainerKind::EbmlElement => "ebml-element",
        ContainerKind::PdfObject => "pdf-object",
        ContainerKind::GzipHeader => "gzip-header",
        ContainerKind::JpegSegment => "jpeg-segment",
        ContainerKind::CfbStream => "cfb-stream",
        ContainerKind::TarHeader => "tar-header",
        ContainerKind::RarBlock => "rar-block",
        ContainerKind::Generic => "generic",
    }
}

/// The status after a job stopped early: `done` items landed and `left`
/// were never tried. `skipped` and `refused` carry reasons, as in
/// [`batch_status`]; `done` counts copies for a deattribute.
pub fn stopped_status(
    kind: PlanKind,
    done: usize,
    left: usize,
    skipped: &[String],
    refused: &[String],
) -> Status {
    let copies = matches!(kind, PlanKind::Deattribute | PlanKind::DeepDeattribute);
    if done == 0 {
        let text = if copies {
            "Stopped. No copies were written."
        } else {
            "Stopped. Nothing changed."
        };
        return Status {
            text: text.to_string(),
            tone: Tone::Info,
        };
    }
    let (n, left) = (thousands(done), thousands(left));
    let mut text = match kind {
        PlanKind::Scrub => format!(
            "Stopped: scrubbed {n} {}; {left} left in place",
            plural(done, "marker", "markers")
        ),
        PlanKind::Deattribute | PlanKind::DeepDeattribute => format!(
            "Stopped: saved {n} {}; {left} not written",
            plural(done, "copy", "copies")
        ),
        PlanKind::Delete => format!(
            "Stopped: moved {n} {} to the trash; {left} left in place",
            plural(done, "file", "files")
        ),
    };
    if !skipped.is_empty() {
        text.push_str(&format!(
            "; skipped {}: {}",
            thousands(skipped.len()),
            skipped[0]
        ));
    }
    if !refused.is_empty() {
        text.push_str(&format!("; refused {}", thousands(refused.len())));
    }
    text.push('.');
    match kind {
        PlanKind::Scrub => text.push_str(" Press u to undo."),
        PlanKind::Delete => text.push_str(&format!(
            " Press u to restore {}.",
            plural(done, "it", "them")
        )),
        PlanKind::Deattribute | PlanKind::DeepDeattribute => {}
    }
    Status {
        text,
        tone: Tone::Warn,
    }
}

/// The status after an edit batch. `skipped` and `refused` carry reasons.
pub fn batch_status(kind: PlanKind, ok: usize, skipped: &[String], refused: &[String]) -> Status {
    let mut text = match (kind, ok) {
        (_, 0) if !refused.is_empty() && skipped.is_empty() => {
            let s = if refused.iter().any(|r| r == edit::safety::MAGIC_REASON) {
                MSG_MAGIC.to_string()
            } else {
                format!(
                    "Nothing scrubbed: {} refused ({}).",
                    refused.len(),
                    refused[0]
                )
            };
            return Status {
                text: s,
                tone: Tone::Bad,
            };
        }
        (_, 0) if skipped.is_empty() => {
            return Status {
                text: MSG_NOTHING.to_string(),
                tone: Tone::Info,
            };
        }
        (PlanKind::Scrub, n) => format!("Scrubbed {n} {}", plural(n, "marker", "markers")),
        (PlanKind::Deattribute | PlanKind::DeepDeattribute, n) => {
            format!("Cleaned {n} {}", plural(n, "marker", "markers"))
        }
        (PlanKind::Delete, n) => {
            format!("Moved {n} {} to the trash", plural(n, "file", "files"))
        }
    };
    if !skipped.is_empty() {
        text.push_str(&format!("; skipped {}: {}", skipped.len(), skipped[0]));
    }
    if !refused.is_empty() {
        text.push_str(&format!("; refused {}", refused.len()));
    }
    text.push('.');
    if kind == PlanKind::Delete && ok > 0 {
        text.push_str(&format!(
            " Press u to restore {}.",
            plural(ok, "it", "them")
        ));
    }
    let tone = if skipped.is_empty() && refused.is_empty() {
        Tone::Good
    } else {
        Tone::Warn
    };
    Status { text, tone }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Category, Evidence, JunkKind, Severity, TamperKind};

    #[test]
    fn deattribute_key_offers_quiet_shared_plan() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invented.exe");
        let mut bytes = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00".to_vec();
        bytes.resize(256, 0);
        bytes.extend_from_slice(b"patched by Invented\0");
        std::fs::write(&path, bytes).unwrap();
        let report = crate::scan::scan_file(&path, &crate::parsers::registry());
        let mut app = App::new(dir.path());
        app.push_reports(vec![report]);
        app.scan_done();
        let Effect::PlanDeattribute(req) = app.on_action(Key::Deattribute) else {
            panic!("the plan is built off the input thread");
        };
        app.plan_ready(plan_deattribute(&req));
        let Some(Overlay::Confirm(plan)) = &app.overlay else {
            panic!("confirm plan");
        };
        assert_eq!(plan.kind, PlanKind::Deattribute);
        assert!(plan.items.iter().any(|item| item.label == "patch"));
        assert!(plan.items.iter().all(|item| item.expected_hash.is_some()));
        assert!(
            plan.items
                .iter()
                .all(|item| !item.label.contains("Invented") && !item.title.contains("Invented"))
        );
    }

    /// A small PE with an invented patch credit, scanned into a fresh view.
    fn patched_view(dir: &Path, name: &str) -> App {
        let path = dir.join(name);
        let mut bytes = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00".to_vec();
        bytes.resize(256, 0);
        bytes.extend_from_slice(b"patched by Invented\0");
        std::fs::write(&path, bytes).unwrap();
        let report = crate::scan::scan_file(&path, &crate::parsers::registry());
        let mut app = App::new(dir);
        app.push_reports(vec![report]);
        app.scan_done();
        app
    }

    /// Render one frame, as the runtime does before reading more keys.
    fn draw(app: &mut App) {
        use ratatui::buffer::Buffer;
        use ratatui::layout::Rect;
        let area = Rect::new(0, 0, 100, 30);
        let mut buf = Buffer::empty(area);
        crate::tui::ui::draw_into(&mut buf, area, app, &crate::tui::theme::Look::vivid());
    }

    #[test]
    fn deep_key_plans_a_deep_deattribute_and_holds_edit_keys_meanwhile() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = patched_view(dir.path(), "invented.exe");
        let Effect::PlanDeattribute(req) = app.on_action(Key::DeepDeattribute) else {
            panic!("A plans off the input thread");
        };
        assert_eq!(req.mode, deattribute::Mode::Deep);
        assert_eq!(app.busy, Some(Busy::Planning));
        assert_eq!(app.status.as_ref().unwrap().text, "Planning...");
        for k in [Key::Deattribute, Key::DeepDeattribute, Key::Scrub, Key::Yes] {
            assert!(matches!(app.on_action(k), Effect::None), "{k:?}");
        }
        assert!(app.overlay.is_none(), "nothing opens while planning");

        app.plan_ready(plan_deattribute(&req));
        assert_eq!(app.busy, None);
        let Some(Overlay::Confirm(plan)) = &app.overlay else {
            panic!("confirm plan");
        };
        assert_eq!(plan.kind, PlanKind::DeepDeattribute);
        assert!(
            plan.title().starts_with("Deep deattribute "),
            "{}",
            plan.title()
        );
        assert!(plan.title().ends_with(" edits?") || plan.title().ends_with(" edit?"));
    }

    #[test]
    fn yes_before_the_confirm_is_drawn_is_ignored() {
        let mut app = sample();
        press(&mut app, Key::End); // tool.exe
        press(&mut app, Key::Scrub);
        assert!(!app.confirm_drawn);
        assert!(matches!(press(&mut app, Key::Yes), Effect::None));
        assert!(
            matches!(app.overlay, Some(Overlay::Confirm(_))),
            "a queued y leaves the modal up"
        );
        draw(&mut app);
        assert!(app.confirm_drawn);
        assert!(matches!(press(&mut app, Key::Yes), Effect::Apply(_)));

        // A new confirm has to be drawn again.
        press(&mut app, Key::Scrub);
        assert!(!app.confirm_drawn);
        assert!(matches!(press(&mut app, Key::Yes), Effect::None));
    }

    #[test]
    fn copies_are_left_out_of_planning() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = patched_view(dir.path(), "invented.deattributed.exe");
        let copy = dir.path().join("invented.deattributed.exe");
        assert!(
            app.is_copy(&copy),
            "named like a copy, so it wears the chip"
        );
        let err = app.deattribute_plan().unwrap_err();
        assert_eq!(
            err,
            "Nothing to blank; 1 skipped: invented.deattributed.exe: already a deattributed copy."
        );
        let again = crate::scan::scan_file(&copy, &crate::parsers::registry());
        app.push_reports(vec![again]);
        assert_eq!(
            app.reports().len(),
            1,
            "a path already listed is not added twice"
        );
    }

    #[test]
    fn a_plan_with_nothing_to_blank_says_so_instead_of_opening_a_modal() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = patched_view(dir.path(), "invented.deattributed.exe");
        let Effect::PlanDeattribute(req) = app.on_action(Key::Deattribute) else {
            panic!("planned off the input thread");
        };
        let plan = plan_deattribute(&req);
        assert!(plan.is_err(), "zero items is an error, not an empty plan");
        app.plan_ready(plan);
        assert!(app.overlay.is_none(), "no \"Deattribute 0 markers?\" modal");
        assert!(app.busy.is_none());
        assert!(
            app.status
                .as_ref()
                .unwrap()
                .text
                .starts_with("Nothing to blank; 1 skipped: ")
        );
    }

    #[test]
    fn a_write_that_saved_nothing_says_so_in_the_bad_tone() {
        let mut app = sample();
        app.begin_busy(Busy::Writing);
        app.copies_written(
            &["photo.jpg: already a deattributed copy".to_string()],
            CopiesOutcome {
                failed: vec!["tool.exe: changed since scan".to_string()],
                ..CopiesOutcome::default()
            },
        );
        let s = app.status.as_ref().unwrap();
        assert_eq!(
            s.text,
            "Saved nothing; skipped 2: tool.exe: changed since scan."
        );
        assert_eq!(s.tone, Tone::Bad);
        assert!(app.busy.is_none());
    }

    #[test]
    fn deattribute_offers_the_files_inside_a_zip() {
        let dir = tempfile::tempdir().unwrap();
        let mut exe = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00".to_vec();
        exe.resize(256, 0);
        exe.extend_from_slice(b"patched by Invented\0");
        let path = dir.path().join("bundle.zip");
        std::fs::write(&path, {
            use crate::edit::deattribute::zip::tests::{build, item};
            build(&[item("a.exe", &exe, true)], b"")
        })
        .unwrap();
        let report = crate::scan::scan_file(&path, &crate::parsers::registry());
        let mut app = App::new(dir.path());
        app.push_reports(vec![report]);
        app.scan_done();
        let plan = app.deattribute_plan().unwrap();
        assert_eq!(plan.items.len(), 1);
        assert_eq!(plan.items[0].label, "1 file inside");
        assert_eq!(plan.items[0].title, "1 file inside");
        assert!(plan.items[0].archive.is_some());
        assert_eq!(plan.title(), "Deattribute 1 archive?");
        assert!(!dir.path().join("bundle.deattributed.zip").exists());
    }

    /// Every user-facing string in the interactive view reads as plain English:
    /// no texting-style "u" and none of the old cat-themed verbs.
    #[test]
    fn copy_is_plain_english() {
        const BANNED: [&str; 7] = [
            "sniff",
            "groom",
            "litter",
            "napping",
            "whisker",
            "this cat",
            "know what a file",
        ];
        let sources = [
            ("app.rs", include_str!("app.rs")),
            ("runtime.rs", include_str!("runtime.rs")),
            ("ui.rs", include_str!("ui.rs")),
            ("keymap.rs", include_str!("keymap.rs")),
            ("logo.rs", include_str!("logo.rs")),
            ("views/files.rs", include_str!("views/files.rs")),
            ("views/picker.rs", include_str!("views/picker.rs")),
            ("picker.rs", include_str!("picker.rs")),
            ("views/status.rs", include_str!("views/status.rs")),
            ("listing.rs", include_str!("listing.rs")),
            ("bg.rs", include_str!("bg.rs")),
            ("progress.rs", include_str!("progress.rs")),
            ("tree.rs", include_str!("tree.rs")),
            ("explorer.rs", include_str!("explorer.rs")),
        ];
        for (name, src) in sources {
            let code = src.split("#[cfg(test)]").next().unwrap_or(src);
            for lit in string_literals(code) {
                let lower = lit.to_lowercase();
                for word in BANNED {
                    assert!(!lower.contains(word), "{name}: {lit:?} uses {word:?}");
                }
                if lit == "u" {
                    continue;
                }
                let words: Vec<&str> = lower
                    .split(|c: char| !c.is_ascii_alphanumeric())
                    .filter(|w| !w.is_empty())
                    .collect();
                for (k, w) in words.iter().enumerate() {
                    if *w == "u" {
                        // The undo key, or the ctrl+u key: never "you".
                        let named = k > 0 && matches!(words[k - 1], "press" | "ctrl");
                        assert!(named, "{name}: {lit:?} uses \"u\" as a word");
                    }
                }
            }
        }
    }

    /// The contents of every double-quoted string literal in `code`.
    fn string_literals(code: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut chars = code.chars().peekable();
        let mut prev = ' ';
        while let Some(c) = chars.next() {
            if c == '"' && prev != '\\' && prev != '\'' {
                let mut lit = String::new();
                let mut escaped = false;
                for d in chars.by_ref() {
                    if escaped {
                        escaped = false;
                        lit.push(d);
                    } else if d == '\\' {
                        escaped = true;
                    } else if d == '"' {
                        break;
                    } else {
                        lit.push(d);
                    }
                }
                out.push(lit);
                prev = '"';
                continue;
            }
            prev = c;
        }
        out
    }
    fn finding(
        sig: &str,
        title: &str,
        conf: Confidence,
        sev: Severity,
        marker: Option<Marker>,
    ) -> Finding {
        Finding {
            category: if sig.starts_with("tamper") {
                Category::Tamper(TamperKind::AppendedData)
            } else {
                Category::Junk(JunkKind::Exif)
            },
            confidence: conf,
            severity: sev,
            signature_id: sig.to_string(),
            title: title.to_string(),
            evidence: Evidence::at(40),
            marker,
        }
    }

    fn blank(off: u64) -> Option<Marker> {
        Some(Marker::blank(Region::new(off, 8), ContainerKind::JpegApp1))
    }

    fn report(name: &str, fmt: &str, findings: Vec<Finding>) -> FileReport {
        let mut r = FileReport::new(PathBuf::from("root").join(name), 4096);
        r.format = Some(fmt.to_string());
        r.findings = findings;
        r
    }

    fn sample() -> App {
        let mut app = App::new("root");
        app.push_reports(vec![
            report(
                "photo.jpg",
                "jpeg",
                vec![
                    finding(
                        "jpeg.exif",
                        "EXIF block",
                        Confidence::Strong,
                        Severity::Notice,
                        blank(100),
                    ),
                    finding(
                        "jpeg.xmp",
                        "XMP packet",
                        Confidence::Weak,
                        Severity::Notice,
                        blank(300),
                    ),
                ],
            ),
            report("clean.png", "png", vec![]),
            report(
                "tool.exe",
                "pe",
                vec![
                    finding(
                        "tamper.overlay",
                        "Appended data",
                        Confidence::Moderate,
                        Severity::Warn,
                        Some(Marker::truncate_at(2048, ContainerKind::PeOverlay)),
                    ),
                    finding(
                        "pe.pdb_path",
                        "PDB path",
                        Confidence::Strong,
                        Severity::Notice,
                        blank(512),
                    ),
                    finding(
                        "pe.rich",
                        "Rich header",
                        Confidence::Strong,
                        Severity::Info,
                        None,
                    ),
                ],
            ),
        ]);
        app.scan_done();
        app
    }

    fn press(app: &mut App, key: Key) -> Effect {
        app.on_action(key)
    }

    fn type_text(app: &mut App, s: &str) {
        for c in s.chars() {
            app.on_key(KeyEvent::from(KeyCode::Char(c)));
        }
    }

    #[test]
    fn right_opens_like_enter_and_left_backs_out() {
        let mut app = sample();
        // clean.png has no findings: right says so, like enter.
        press(&mut app, Key::Right);
        assert_eq!(app.pane, Pane::Files);
        assert_eq!(
            app.status.as_ref().unwrap().text,
            "This file has no findings."
        );
        press(&mut app, Key::End);
        app.on_key(KeyEvent::from(KeyCode::Char('l')));
        assert_eq!(app.pane, Pane::Findings);
        assert!(matches!(
            press(&mut app, Key::Right),
            Effect::LoadHex { .. }
        ));
        assert_eq!(app.screen, Screen::Detail);
        app.on_key(KeyEvent::from(KeyCode::Char('h')));
        assert_eq!(app.screen, Screen::Main, "left closes the detail");
        app.on_key(KeyEvent::from(KeyCode::Backspace));
        assert_eq!(app.pane, Pane::Files, "then goes back to the files");
        app.on_key(KeyEvent::from(KeyCode::Left));
        assert_eq!(app.pane, Pane::Files, "the root has no folder above");
        assert_eq!(app.cwd(), Path::new("root"));
        press(&mut app, Key::Tab);
        assert_eq!(app.pane, Pane::Findings, "tab switches panes");

        // The filter still takes h and l as text.
        press(&mut app, Key::Filter);
        type_text(&mut app, "hl");
        app.on_key(KeyEvent::from(KeyCode::Enter));
        assert_eq!(app.filter.describe().as_deref(), Some("hl"));
    }

    #[test]
    fn navigation_is_bounded() {
        let mut app = sample();
        assert_eq!(app.rows().len(), 3);
        assert_eq!(
            app.current_file().unwrap().path,
            PathBuf::from("root/clean.png")
        );
        press(&mut app, Key::Up);
        assert_eq!(app.file_cursor, 0);
        for _ in 0..10 {
            press(&mut app, Key::Down);
        }
        assert_eq!(app.file_cursor, 2);
        press(&mut app, Key::Home);
        assert_eq!(app.file_cursor, 0);
        press(&mut app, Key::End);
        assert_eq!(app.file_cursor, 2);
        app.page = 2;
        press(&mut app, Key::PageUp);
        assert_eq!(app.file_cursor, 0);
        press(&mut app, Key::PageDown);
        assert_eq!(app.file_cursor, 2);

        // Findings pane: loudest first, bounded.
        press(&mut app, Key::Tab);
        assert_eq!(app.pane, Pane::Findings);
        let (_, _, f) = app.current_finding().unwrap();
        assert_eq!(f.signature_id, "tamper.overlay");
        press(&mut app, Key::End);
        press(&mut app, Key::Down);
        assert_eq!(app.finding_cursor, 2);

        assert_eq!(step(5, 0, Key::Down, 3), 0);
        assert_eq!(
            step(9, 4, Key::Up, 3),
            2,
            "an out-of-range cursor is pulled in first"
        );
    }

    #[test]
    fn enter_drills_down_and_esc_backs_out_then_quits() {
        let mut app = sample();
        press(&mut app, Key::End);
        assert!(matches!(press(&mut app, Key::Enter), Effect::None));
        assert_eq!(app.pane, Pane::Findings);
        match press(&mut app, Key::Enter) {
            Effect::LoadHex { path, offset } => {
                assert_eq!(path, PathBuf::from("root/tool.exe"));
                assert_eq!(offset, 40);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(app.screen, Screen::Detail);
        press(&mut app, Key::Esc);
        assert_eq!(app.screen, Screen::Main);
        press(&mut app, Key::Esc);
        assert_eq!(app.pane, Pane::Files);
        press(&mut app, Key::Esc);
        assert!(!app.should_quit);
        assert_eq!(app.status.as_ref().unwrap().text, MSG_QUIT_ARMED);
        assert!(matches!(press(&mut app, Key::Esc), Effect::Quit));
        assert!(app.should_quit);

        let mut app = sample();
        press(&mut app, Key::Esc);
        press(&mut app, Key::Down);
        press(&mut app, Key::Esc);
        assert!(!app.should_quit, "any other key disarms");
        assert!(matches!(press(&mut app, Key::Quit), Effect::Quit));
    }

    #[test]
    fn selection_toggles() {
        let mut app = sample();
        press(&mut app, Key::Space);
        assert!(app.is_file_picked(Path::new("root/clean.png")));
        press(&mut app, Key::Space);
        assert_eq!(app.picked(), 0);

        press(&mut app, Key::End);
        press(&mut app, Key::Tab);
        press(&mut app, Key::Space);
        press(&mut app, Key::Down);
        press(&mut app, Key::Space);
        assert_eq!(app.picked(), 2);
        press(&mut app, Key::Space);
        assert_eq!(app.picked(), 1);
        let (r, idx, _) = app.current_finding().unwrap();
        assert!(!app.is_finding_picked(&r.path, idx));
    }

    #[test]
    fn filter_matches_path_format_signature_and_title() {
        let mut app = sample();
        let n = |app: &App| app.rows().len();
        press(&mut app, Key::Filter);
        assert!(matches!(app.overlay, Some(Overlay::Filter)));
        type_text(&mut app, "PHOTO");
        assert_eq!(n(&app), 1, "path, case-insensitive");
        app.on_key(KeyEvent::from(KeyCode::Enter));
        assert!(app.overlay.is_none());
        assert_eq!(app.filter.describe().as_deref(), Some("PHOTO"));

        app.set_filter(Filter::Text("JPEG".into()));
        assert_eq!(n(&app), 1, "format (the path says jpg)");
        assert_eq!(
            app.current_findings().len(),
            2,
            "a file-level match shows every finding"
        );
        app.set_filter(Filter::Text("pdb_path".into()));
        assert_eq!(n(&app), 1, "signature id");
        assert_eq!(
            app.current_findings().len(),
            1,
            "only the matching finding shows"
        );
        app.set_filter(Filter::Text("xmp packet".into()));
        assert_eq!(n(&app), 1, "title");
        app.set_filter(Filter::Text("zzz".into()));
        assert_eq!(n(&app), 0);
        assert!(app.current_file().is_none());

        // esc in the prompt clears; esc on the main screen clears too.
        press(&mut app, Key::Filter);
        app.on_key(KeyEvent::from(KeyCode::Backspace));
        app.on_key(KeyEvent::from(KeyCode::Esc));
        assert_eq!(app.filter, Filter::None);
        assert_eq!(n(&app), 3);
        app.set_filter(Filter::Text("exe".into()));
        press(&mut app, Key::Esc);
        assert_eq!(app.filter, Filter::None);
    }

    #[test]
    fn bucket_view_cycles_and_filters() {
        let mut app = sample();
        press(&mut app, Key::Buckets);
        assert_eq!(
            (app.screen, app.bucket_by),
            (Screen::Buckets, BucketBy::Category)
        );
        press(&mut app, Key::Buckets);
        assert_eq!(app.bucket_by, BucketBy::Signature);
        assert_eq!(app.buckets().len(), 5);
        press(&mut app, Key::Buckets);
        assert_eq!(app.bucket_by, BucketBy::Container);
        press(&mut app, Key::Buckets);
        assert_eq!(app.screen, Screen::Main);
        press(&mut app, Key::Buckets);
        assert_eq!(app.bucket_by, BucketBy::Category);

        // The loudest bucket first: tamper (warn).
        assert_eq!(app.buckets()[0].key, "tamper");
        press(&mut app, Key::Enter);
        assert_eq!(app.screen, Screen::Main);
        assert_eq!(app.rows().len(), 1);
        assert_eq!(app.filter.describe().as_deref(), Some("category=tamper"));
    }

    #[test]
    fn container_slugs_match_bucketize() {
        use ContainerKind::*;
        let all = [
            Raw,
            PeOverlay,
            PeResource,
            JpegApp1,
            ZipComment,
            Id3v1,
            Id3v2,
            ElfSection,
            MachoLoadCmd,
            PngChunk,
            RiffChunk,
            IsoBox,
            EbmlElement,
            PdfObject,
            GzipHeader,
            JpegSegment,
            CfbStream,
            TarHeader,
            RarBlock,
            Generic,
        ];
        for c in all {
            let f = finding(
                "x.y",
                "t",
                Confidence::Strong,
                Severity::Info,
                Some(Marker::blank(Region::new(32, 1), c)),
            );
            let r = report("f", "zip", vec![f.clone()]);
            let b = bucketize(&[r], BucketBy::Container);
            assert_eq!(
                Some(b[0].key.clone()),
                bucket_key(BucketBy::Container, &f),
                "{c:?}"
            );
        }
    }

    #[test]
    fn scrub_plans_skip_weak_in_bulk_but_not_alone() {
        let mut app = sample();
        press(&mut app, Key::Down); // photo.jpg
        let plan = app.scrub_plan().unwrap();
        assert_eq!(plan.items.len(), 1);
        assert_eq!(plan.weak_left_out, 1);

        press(&mut app, Key::Tab);
        press(&mut app, Key::Down); // the weak XMP finding, highlighted alone
        let plan = app.scrub_plan().unwrap();
        assert_eq!(plan.items.len(), 1);
        assert_eq!(plan.items[0].label, "jpeg.xmp");

        press(&mut app, Key::Space); // picked: now a bulk action
        let err = app.scrub_plan().unwrap_err();
        assert!(err.starts_with(MSG_NOTHING), "{err}");
    }

    #[test]
    fn scrub_plan_orders_blanks_before_truncates_and_offers_a_confirm() {
        let mut app = sample();
        press(&mut app, Key::End); // tool.exe
        let plan = app.scrub_plan().unwrap();
        let labels: Vec<_> = plan.items.iter().map(|i| i.label.as_str()).collect();
        assert_eq!(labels, vec!["pe.pdb_path", "tamper.overlay"]);
        assert!(
            matches!(plan.items[1].risk, Risk::Warn(_)),
            "pe truncate warns"
        );

        press(&mut app, Key::Scrub);
        assert!(matches!(app.overlay, Some(Overlay::Confirm(_))));
        assert_eq!(app.context(), "confirm");
        press(&mut app, Key::No);
        assert!(app.overlay.is_none());
        press(&mut app, Key::Scrub);
        draw(&mut app);
        match press(&mut app, Key::Yes) {
            Effect::Apply(plan) => assert_eq!(plan.runnable(), 2),
            other => panic!("{other:?}"),
        }
        assert!(app.overlay.is_none());
    }

    #[test]
    fn refused_items_are_listed_but_not_runnable() {
        let mut app = App::new("root");
        app.push_reports(vec![report(
            "m.png",
            "png",
            vec![finding(
                "png.bad",
                "Bad marker",
                Confidence::Strong,
                Severity::Notice,
                blank(4),
            )],
        )]);
        app.scan_done();
        let plan = app.scrub_plan().unwrap();
        assert_eq!(plan.items.len(), 1);
        assert_eq!(plan.runnable(), 0);
        assert!(matches!(plan.items[0].risk, Risk::Refuse(_)));
        let s = batch_status(
            PlanKind::Scrub,
            0,
            &[],
            &[edit::safety::MAGIC_REASON.to_string()],
        );
        assert_eq!(s.text, MSG_MAGIC);
    }

    #[test]
    fn delete_plan_uses_picks_or_the_highlight() {
        let mut app = sample();
        let plan = app.delete_plan().unwrap();
        assert_eq!(plan.items.len(), 1);
        assert!(matches!(plan.items[0].risk, Risk::Warn(_)));
        press(&mut app, Key::Space);
        press(&mut app, Key::Down);
        press(&mut app, Key::Space);
        assert_eq!(app.delete_plan().unwrap().items.len(), 2);
        assert_eq!(app.delete_plan().unwrap().title(), "Delete 2 files?");
    }

    #[test]
    fn statuses_read_right() {
        let s = batch_status(PlanKind::Scrub, 3, &[], &[]);
        assert_eq!(s.text, "Scrubbed 3 markers.");
        let s = batch_status(PlanKind::Delete, 2, &[], &[]);
        assert_eq!(
            s.text,
            "Moved 2 files to the trash. Press u to restore them."
        );
        let s = batch_status(PlanKind::Scrub, 1, &["file changed".into()], &[]);
        assert_eq!(s.text, "Scrubbed 1 marker; skipped 1: file changed.");
        assert_eq!(batch_status(PlanKind::Scrub, 0, &[], &[]).text, MSG_NOTHING);
    }

    #[test]
    fn rescans_replace_in_place() {
        let mut app = sample();
        press(&mut app, Key::End);
        press(&mut app, Key::Tab);
        press(&mut app, Key::Space);
        let mut fresh = report("tool.exe", "pe", vec![]);
        fresh.size = 2048;
        app.replace_report(fresh);
        assert_eq!(app.rows().len(), 3);
        assert_eq!(
            app.current_file().unwrap().size,
            2048,
            "cursor stays on the file"
        );
        assert_eq!(app.picked(), 0, "stale finding picks dropped");
        app.remove_report(Path::new("root/tool.exe"));
        assert_eq!(app.rows().len(), 2);
        app.replace_report(report("tool.exe", "pe", vec![]));
        assert_eq!(
            app.reports()[2].path,
            PathBuf::from("root/tool.exe"),
            "sorted insert"
        );
    }

    #[test]
    fn the_highlight_stays_when_files_appear_or_go_above_it() {
        let mut app = sample();
        press(&mut app, Key::End);
        let here = || PathBuf::from("root/tool.exe");
        assert_eq!(app.current_file().unwrap().path, here());
        // A deattributed copy sorts right above its original.
        app.replace_report(report("tool.deattributed.exe", "pe", vec![]));
        assert_eq!(
            app.current_file().unwrap().path,
            here(),
            "copy inserted above"
        );
        app.push_reports(vec![report("aaa.bin", "pe", vec![])]);
        assert_eq!(
            app.current_file().unwrap().path,
            here(),
            "batch merged above"
        );
        app.remove_report(Path::new("root/clean.png"));
        assert_eq!(
            app.current_file().unwrap().path,
            here(),
            "file removed above"
        );
        app.set_filter(Filter::Text("tool".into()));
        assert_eq!(app.current_file().unwrap().path, here(), "filter narrowed");
    }

    #[test]
    fn scan_line_and_help_overlay() {
        let mut app = App::new("root");
        app.total = Some(400);
        app.push_reports(vec![report("x", "pe", vec![])]);
        assert_eq!(app.scan_line(), "Scanning 1 of 400 files");
        app.total = None;
        assert_eq!(app.scan_line(), "Scanning 1 file...");
        app.total = Some(400);
        app.scan_done();
        assert_eq!(app.scan_line(), "Scanned 1 file. No findings.");
        let app2 = sample();
        assert_eq!(
            app2.scan_line(),
            "Scanned 3 files: 2 with findings, 4 removable markers."
        );

        press(&mut app, Key::Help);
        assert_eq!(app.context(), "help");
        press(&mut app, Key::Down);
        assert!(app.overlay.is_none(), "any key closes help");
        assert!(matches!(press(&mut app, Key::Interrupt), Effect::Quit));
    }

    #[test]
    fn counts_carry_thousands_separators() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1_000), "1,000");
        assert_eq!(thousands(3_093), "3,093");
        assert_eq!(thousands(1_101_278), "1,101,278");

        let mut app = App::new("root");
        assert_eq!(app.scan_line(), "Scanning 0 files...");
        let batch: Vec<FileReport> = (0..1_234)
            .map(|i| report(&format!("f{i:05}"), "pe", vec![]))
            .collect();
        app.push_reports(batch);
        assert_eq!(app.scan_line(), "Scanning 1,234 files...");
        app.total = Some(1_101_278);
        assert_eq!(app.scan_line(), "Scanning 1,234 of 1,101,278 files");
        app.scan_done();
        assert_eq!(app.scan_line(), "Scanned 1,234 files. No findings.");
    }

    fn type_raw(app: &mut App, s: &str) -> Vec<Effect> {
        s.chars()
            .map(|c| app.on_key(KeyEvent::from(KeyCode::Char(c))))
            .collect()
    }

    /// Answer the picker's listings and lookups synchronously, the way the
    /// runtime's workers do.
    fn serve_picker(app: &mut App) {
        use crate::tui::listing::{Listing, MAX_READ};
        use crate::tui::picker::{Request, stat};
        for _ in 0..8 {
            let Some(p) = app.picker.as_mut() else {
                return;
            };
            for r in p.take_requests() {
                match r {
                    Request::List(dir) => p.on_listing(Listing::read(&dir, MAX_READ)),
                    Request::Stat(path) => {
                        let found = stat(&path);
                        p.on_stat(&path, found);
                    }
                    Request::Count(_) | Request::StopCount => {}
                }
            }
        }
    }

    /// A picker with no places, so nothing reads the user's own folders.
    fn quiet_picker() -> Picker {
        Picker::with_suggestions(Vec::new(), Vec::new()).with_home(None)
    }

    #[test]
    fn picker_mode_scans_nothing_until_a_folder_is_chosen() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = App::picking(quiet_picker());
        assert!(app.is_picking());
        assert!(!app.scanning, "no scan before a folder is chosen");
        assert_eq!(app.context(), "picker");
        // Mapped keys are inert here, and q never quits the picker.
        for k in Key::ALL {
            if k != Key::Interrupt {
                assert!(matches!(app.on_action(k), Effect::None), "{k:?}");
            }
        }
        let typed = type_raw(&mut app, "q");
        assert!(matches!(typed[..], [Effect::None]));
        assert!(!app.should_quit, "q is not a picker key");

        // A pasted folder opens; s scans it.
        app.picker_text(&dir.path().display().to_string(), false);
        serve_picker(&mut app);
        app.anim_ms = 777;
        let effect = app.on_key(KeyEvent::from(KeyCode::Char('s')));
        let Effect::Scan(chosen) = effect else {
            panic!("s on a small folder scans it: {effect:?}");
        };
        assert_eq!(
            chosen.file_name(),
            dir.path().file_name(),
            "the typed folder"
        );
        assert!(!app.is_picking());
        assert_eq!(app.root, chosen);
        assert!(app.scanning, "the main view opens scanning");
        assert_eq!(app.context(), "files");
        assert_eq!(app.anim_ms, 777, "the wordmark clock carries over");
        assert_eq!(app.scan_line(), "Scanning 0 files...");
    }

    #[test]
    fn o_reopens_the_picker_and_backing_out_keeps_the_view() {
        let mut app = sample();
        press(&mut app, Key::Space);
        press(&mut app, Key::End);
        assert!(matches!(press(&mut app, Key::Open), Effect::Pick));
        assert!(!app.is_picking(), "the runtime builds the picker");
        let root = app.root.clone();
        app.open_picker(quiet_picker().reopened_at(&root));
        assert!(app.is_picking());
        assert_eq!(app.context(), "picker");
        assert!(matches!(
            app.on_key(KeyEvent::from(KeyCode::Esc)),
            Effect::None
        ));
        assert!(!app.is_picking(), "one esc backs out of a reopened picker");
        assert!(!app.should_quit, "backing out never quits");
        assert_eq!(app.reports().len(), 3, "the old view is unchanged");
        assert_eq!(app.picked(), 1);
        assert_eq!(app.file_cursor, 2);
        assert_eq!(app.context(), "files");
    }

    #[test]
    fn a_new_pick_replaces_the_view() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = sample();
        press(&mut app, Key::Space);
        app.set_filter(Filter::Text("exe".into()));
        let root = app.root.clone();
        app.open_picker(quiet_picker().reopened_at(&root));
        app.picker_text(&dir.path().display().to_string(), false);
        serve_picker(&mut app);
        let Effect::Scan(chosen) = app.on_key(KeyEvent::from(KeyCode::Char('s'))) else {
            panic!("s scans the pasted folder");
        };
        assert_eq!(app.root, chosen);
        assert!(app.reports().is_empty(), "old reports dropped");
        assert_eq!(app.picked(), 0, "picks dropped");
        assert_eq!(app.filter, Filter::None, "filter dropped");
        assert!(app.scanning);
    }

    fn item(path: &str, output: &str, edits: usize) -> SavedItem {
        SavedItem {
            path: PathBuf::from(path),
            output: PathBuf::from(output),
            edits,
        }
    }

    #[test]
    fn saved_status_names_what_was_saved() {
        let app = sample();
        let one = [item("root/tool.exe", "root/tool.exe", 3)];
        let s = app.saved_status(SavedKind::Scrubbed, &one, &[], &[]);
        assert_eq!(s.text, "Saved tool.exe (3 edits). Press u to undo.");
        assert_eq!(s.tone, Tone::Good);

        let three = [
            item("root/tool.exe", "root/tool.exe", 1),
            item("root/photo.jpg", "root/photo.jpg", 2),
            item("root/clean.png", "root/clean.png", 1),
        ];
        let s = app.saved_status(SavedKind::Scrubbed, &three, &[], &["magic".into()]);
        assert_eq!(
            s.text,
            "Saved tool.exe (1 edit) +2 more; refused 1. Press u to undo."
        );
        assert_eq!(s.tone, Tone::Warn);

        let copy = [item(
            "root/setup-tool.exe",
            "root/setup-tool.deattributed.exe",
            4,
        )];
        let s = app.saved_status(SavedKind::Deattributed, &copy, &[], &[]);
        assert_eq!(
            s.text,
            "Saved setup-tool.deattributed.exe beside setup-tool.exe."
        );
        let s = app.saved_status(SavedKind::Deattributed, &[], &[], &[]);
        assert_eq!(s.text, MSG_NOTHING);
    }

    #[test]
    fn saved_marks_survive_rescans_and_undo_clears_scrubs() {
        let mut app = sample();
        let tool = PathBuf::from("root/tool.exe");
        let photo = PathBuf::from("root/photo.jpg");
        app.record_saved(
            SavedKind::Scrubbed,
            &[item("root/tool.exe", "root/tool.exe", 2)],
            &[],
            &[],
        );
        assert!(
            app.status
                .as_ref()
                .unwrap()
                .text
                .starts_with("Saved tool.exe")
        );
        app.mark_saved(&tool, SavedKind::Scrubbed, tool.clone(), 1);
        assert_eq!(app.saved(&tool).unwrap().edits, 3, "a second scrub adds up");
        app.mark_saved(
            &photo,
            SavedKind::Deattributed,
            PathBuf::from("root/photo.deattributed.jpg"),
            1,
        );

        // The rescan after an edit replaces the report; the mark stays.
        app.replace_report(report("tool.exe", "pe", vec![]));
        assert_eq!(app.saved(&tool).unwrap().kind, SavedKind::Scrubbed);

        app.clear_scrubbed(&tool);
        app.clear_scrubbed(&photo);
        assert!(app.saved(&tool).is_none(), "undo clears a scrub mark");
        assert!(app.saved(&photo).is_some(), "a copy is not undone");
        app.remove_report(&photo);
        assert!(app.saved(&photo).is_none(), "a trashed file loses its mark");
    }

    #[test]
    fn an_output_copy_inside_the_root_joins_the_list() {
        let dir = tempfile::tempdir().unwrap();
        let original = dir.path().join("setup-tool.exe");
        let copy = dir.path().join("setup-tool.deattributed.exe");
        std::fs::write(&original, b"MZ original").unwrap();
        std::fs::write(&copy, b"MZ copy").unwrap();
        let mut app = App::new(dir.path());
        app.push_reports(vec![FileReport::new(original.clone(), 11)]);
        app.scan_done();
        assert!(app.add_output_copy(&original, FileReport::new(copy.clone(), 7)));
        assert!(app.has_report(&copy));
        assert_eq!(app.copy_of(&copy), Some(original.as_path()));
        let outside = tempfile::tempdir().unwrap();
        let far = outside.path().join("x.deattributed.exe");
        assert!(
            !app.add_output_copy(&original, FileReport::new(far.clone(), 7)),
            "outside the root"
        );
        assert!(!app.has_report(&far));
    }

    #[test]
    fn a_replaced_copy_sets_its_edit_count() {
        let mut app = sample();
        let tool = PathBuf::from("root/tool.exe");
        let copy = PathBuf::from("root/tool.deattributed.exe");
        app.mark_saved(&tool, SavedKind::Deattributed, copy.clone(), 3);
        app.mark_saved(&tool, SavedKind::Deattributed, copy, 2);
        assert_eq!(app.saved(&tool).unwrap().edits, 2, "the copy was replaced");
    }

    #[test]
    fn esc_in_the_picker_quits() {
        let mut app = App::picking(quiet_picker());
        let last = app.on_key(KeyEvent::from(KeyCode::Esc));
        assert!(matches!(last, Effect::Quit), "one esc: {last:?}");
        assert!(app.should_quit);
        let mut app = App::picking(quiet_picker());
        assert!(matches!(app.on_action(Key::Interrupt), Effect::Quit));
    }

    #[test]
    fn planning_reports_each_file_and_stops_between_them() {
        use crate::tui::progress::testing::StopAfter;
        let dir = tempfile::tempdir().unwrap();
        let mut app = patched_view(dir.path(), "a.exe");
        let more = patched_view(dir.path(), "b.exe");
        app.push_reports(more.reports().to_vec());
        press(&mut app, Key::Space);
        press(&mut app, Key::Down);
        press(&mut app, Key::Space);
        let req = app.deattribute_request(deattribute::Mode::Basic).unwrap();
        let mut all = StopAfter::new(usize::MAX);
        assert!(plan_deattribute_with(&req, &mut all).is_ok());
        let size = req.reports[0].size;
        assert_eq!(all.began, Some((2, 2 * size)));
        assert_eq!((all.items.len(), all.ends), (2, 1));
        let mut one = StopAfter::new(1);
        let abandoned = plan_deattribute_with(&req, &mut one);
        assert_eq!(abandoned.unwrap_err(), MSG_NEVER_MIND);
        assert_eq!(one.items.len(), 1);
    }

    #[test]
    fn esc_while_busy_stops_in_the_files_pane_but_goes_back_from_detail() {
        let mut app = sample();
        press(&mut app, Key::End);
        press(&mut app, Key::Enter);
        press(&mut app, Key::Enter);
        assert_eq!(app.screen, Screen::Detail);
        app.begin_busy(Busy::Writing);
        assert!(matches!(press(&mut app, Key::Esc), Effect::None));
        assert_eq!(app.screen, Screen::Main);
        press(&mut app, Key::Esc);
        assert_eq!(app.pane, Pane::Files);
        assert!(!app.stopping);
        assert!(matches!(press(&mut app, Key::Esc), Effect::Stop));
        assert!(app.stopping && !app.can_stop());
        assert!(!app.should_quit, "esc never arms quit while busy");
    }

    #[test]
    fn a_plan_is_dropped_at_once() {
        let mut app = sample();
        app.begin_busy(Busy::Planning);
        assert!(matches!(press(&mut app, Key::Esc), Effect::Stop));
        assert!(app.busy.is_none());
        assert_eq!(app.status.as_ref().unwrap().text, MSG_NEVER_MIND);
        app.begin_busy(Busy::Planning);
        assert!(matches!(press(&mut app, Key::Interrupt), Effect::Stop));
        assert!(app.should_quit, "ctrl+c drops the plan and quits");
    }

    #[test]
    fn quit_while_busy_stops_first_and_a_second_quit_forces() {
        let mut app = sample();
        app.begin_busy(Busy::Writing);
        assert!(matches!(press(&mut app, Key::Quit), Effect::Stop));
        assert!(app.stopping && app.quit_after && !app.should_quit);
        assert!(matches!(press(&mut app, Key::Interrupt), Effect::Quit));
        assert!(app.should_quit);

        let mut app = sample();
        app.begin_busy(Busy::Writing);
        press(&mut app, Key::Quit);
        app.copies_written(
            &[],
            CopiesOutcome {
                stopped: true,
                not_written: 2,
                ..CopiesOutcome::default()
            },
        );
        assert!(app.should_quit, "quits once the job lands");

        // Ctrl+C in the filter prompt stops first too.
        let mut app = sample();
        app.begin_busy(Busy::Scrubbing);
        press(&mut app, Key::Filter);
        app.on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(app.stopping && !app.should_quit);
    }

    #[test]
    fn undo_cannot_stop_and_says_so() {
        let mut app = sample();
        app.begin_busy(Busy::Undoing);
        assert!(!app.can_stop());
        assert!(matches!(press(&mut app, Key::Esc), Effect::None));
        assert_eq!(app.busy_note, Some(MSG_UNDO_RUNS));
        assert!(!app.stopping);
        press(&mut app, Key::Quit);
        assert_eq!(app.busy_note, Some(MSG_QUIT_AFTER_UNDO));
        assert!(!app.should_quit);
        app.end_busy();
        assert!(app.should_quit, "quits when the undo finishes");
    }

    #[test]
    fn the_keys_that_need_the_engine_wait_while_busy() {
        let mut app = sample();
        press(&mut app, Key::End);
        app.begin_busy(Busy::Deleting);
        for k in [
            Key::Undo,
            Key::Editor,
            Key::Open,
            Key::Scrub,
            Key::Delete,
            Key::Deattribute,
        ] {
            assert!(matches!(press(&mut app, k), Effect::None), "{k:?}");
            assert_eq!(app.status.as_ref().unwrap().text, "Deleting...");
        }
        assert!(app.overlay.is_none());
    }

    #[test]
    fn picks_made_during_a_job_survive_it() {
        let mut app = sample();
        press(&mut app, Key::Down);
        press(&mut app, Key::Space); // photo.jpg
        app.begin_busy(Busy::Writing);
        press(&mut app, Key::Down);
        press(&mut app, Key::Space); // tool.exe, picked meanwhile
        app.copies_written(&[], CopiesOutcome::default());
        assert!(!app.is_file_picked(Path::new("root/photo.jpg")));
        assert!(app.is_file_picked(Path::new("root/tool.exe")));

        // A cancelled confirm forgets its snapshot.
        app.begin_busy(Busy::Planning);
        app.plan_ready(Err("Nothing to blank.".into()));
        app.begin_busy(Busy::Undoing);
        app.end_busy();
        app.clear_job_picks();
        assert!(
            app.is_file_picked(Path::new("root/tool.exe")),
            "undo takes no picks"
        );
    }

    #[test]
    fn stopped_statuses_read_right() {
        let s = stopped_status(PlanKind::Deattribute, 3, 4, &[], &[]);
        assert_eq!(s.text, "Stopped: saved 3 copies; 4 not written.");
        assert_eq!(s.tone, Tone::Warn);
        let s = stopped_status(PlanKind::Delete, 1, 2, &[], &[]);
        assert_eq!(
            s.text,
            "Stopped: moved 1 file to the trash; 2 left in place. Press u to restore it."
        );
        let s = stopped_status(PlanKind::Scrub, 0, 5, &[], &[]);
        assert_eq!(s.text, "Stopped. Nothing changed.");
        let s = stopped_status(PlanKind::DeepDeattribute, 0, 5, &[], &[]);
        assert_eq!(s.text, "Stopped. No copies were written.");
        let mut app = sample();
        app.begin_busy(Busy::Writing);
        app.copies_written(
            &[],
            CopiesOutcome {
                stopped: true,
                not_written: 4,
                ..CopiesOutcome::default()
            },
        );
        assert_eq!(
            app.status.as_ref().unwrap().text,
            "Stopped. No copies were written."
        );
    }

    #[test]
    fn question_mark_shows_the_pickers_keys_and_any_key_closes_them() {
        let mut app = App::picking(quiet_picker());
        app.on_key(KeyEvent::from(KeyCode::Char('?')));
        assert!(matches!(app.overlay, Some(Overlay::Help)));
        assert!(app.is_picking());
        // The key that closes the sheet does nothing else: esc does not quit.
        app.on_key(KeyEvent::from(KeyCode::Esc));
        assert!(app.overlay.is_none());
        assert!(!app.should_quit);
        app.on_key(KeyEvent::from(KeyCode::Char('?')));
        let effect = app.on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(matches!(effect, Effect::Quit), "ctrl+c still quits");
        // A paste closes the sheet too.
        let mut app = App::picking(quiet_picker());
        app.on_key(KeyEvent::from(KeyCode::Char('?')));
        app.picker_text("abc", true);
        assert!(app.overlay.is_none());
        assert_eq!(app.picker.as_ref().unwrap().prompt(), Some("abc"));
    }

    #[test]
    fn every_key_is_handled_without_panicking_anywhere() {
        for screen_keys in [
            vec![],
            vec![Key::End, Key::Tab, Key::Enter],
            vec![Key::Buckets],
        ] {
            for k in Key::ALL {
                let mut app = sample();
                for pre in &screen_keys {
                    app.on_action(*pre);
                }
                let _ = app.on_action(k);
                let _ = app.on_action(Key::Down);
            }
        }
        let mut empty = App::new("root");
        empty.scan_done();
        for k in Key::ALL {
            let _ = empty.on_action(k);
        }
    }

    // ---- the folder view ---------------------------------------------------

    /// `root` joined with a `/`-separated relative path.
    fn at(rel: &str) -> PathBuf {
        rel.split('/')
            .fold(PathBuf::from("root"), |p, part| p.join(part))
    }

    fn report_at(rel: &str, findings: Vec<Finding>) -> FileReport {
        let mut r = FileReport::new(at(rel), 4096);
        r.format = Some("pe".to_string());
        r.findings = findings;
        r
    }

    fn removable(sig: &str, conf: Confidence, sev: Severity) -> Finding {
        finding(sig, sig, conf, sev, blank(64))
    }

    /// root/
    ///   a.txt
    ///   b/x/deep.exe   (an alert)
    ///   b/y.bin        (a notice and a weak notice)
    ///   b-c/z.bin
    ///   b.txt          (a notice)
    fn nested_reports() -> Vec<FileReport> {
        vec![
            report_at("a.txt", vec![]),
            report_at(
                "b/x/deep.exe",
                vec![removable("pe.overlay", Confidence::Strong, Severity::Alert)],
            ),
            report_at(
                "b/y.bin",
                vec![
                    removable("jpeg.exif", Confidence::Strong, Severity::Notice),
                    removable("jpeg.xmp", Confidence::Weak, Severity::Notice),
                ],
            ),
            report_at("b-c/z.bin", vec![]),
            report_at(
                "b.txt",
                vec![removable("jpeg.exif", Confidence::Strong, Severity::Notice)],
            ),
        ]
    }

    fn nested() -> App {
        let mut app = App::new("root");
        app.push_reports(nested_reports());
        app.scan_done();
        app
    }

    fn row_names(app: &App) -> Vec<&str> {
        app.rows().iter().map(|r| r.name.as_str()).collect()
    }

    fn highlight(app: &mut App, name: &str) {
        let pos = app
            .rows()
            .iter()
            .position(|r| r.name == name)
            .unwrap_or_else(|| panic!("{name} in {:?}", row_names(app)));
        app.file_cursor = pos;
    }

    #[test]
    fn folders_come_first_and_open_with_a_remembered_highlight() {
        let mut app = nested();
        assert_eq!(row_names(&app), ["b", "b-c", "a.txt", "b.txt"]);
        assert!(app.has_subfolders());
        assert_eq!(app.current_folder(), Some(at("b").as_path()));
        press(&mut app, Key::Enter);
        assert_eq!(app.cwd(), at("b"));
        assert_eq!(row_names(&app), ["x", "y.bin"]);
        assert_eq!(
            app.breadcrumb(),
            format!("root{}b", std::path::MAIN_SEPARATOR)
        );
        assert_eq!(app.reopen_target(), at("b"), "o reopens the picker here");
        let mut hints = crate::tui::keymap::footer_hints("files").to_vec();
        crate::tui::views::files::explorer_hints(&app, "files", &mut hints);
        assert_eq!(hints[1].key, "left", "a subfolder offers the way up");

        press(&mut app, Key::Down); // y.bin
        app.on_key(KeyEvent::from(KeyCode::Char('h')));
        assert_eq!(app.cwd(), Path::new("root"));
        assert_eq!(
            app.current_folder(),
            Some(at("b").as_path()),
            "the folder left"
        );
        app.on_key(KeyEvent::from(KeyCode::Char('l')));
        assert_eq!(
            app.current_file().unwrap().path,
            at("b/y.bin"),
            "remembered"
        );

        // Esc never goes up: it backs out of panes, then arms quit.
        press(&mut app, Key::Esc);
        assert_eq!(app.cwd(), at("b"));
        assert_eq!(app.status.as_ref().unwrap().text, MSG_QUIT_ARMED);
        press(&mut app, Key::Backspace);
        assert_eq!(app.cwd(), Path::new("root"));
    }

    #[test]
    fn folder_picks_expand_into_plans_and_delete_refuses_them() {
        let mut app = nested();
        highlight(&mut app, "b");
        let plan = app.scrub_plan().unwrap();
        let labels: Vec<&str> = plan.items.iter().map(|i| i.label.as_str()).collect();
        assert_eq!(labels, ["pe.overlay", "jpeg.exif"]);
        assert_eq!(
            plan.weak_left_out, 1,
            "weak findings stay out of bulk scrubs"
        );
        assert!(plan.caveats.is_empty(), "the scan is done");

        let req = app.deattribute_request(deattribute::Mode::Basic).unwrap();
        let paths: Vec<PathBuf> = req.reports.iter().map(|r| r.path.clone()).collect();
        assert_eq!(
            paths,
            [at("b/x/deep.exe"), at("b/y.bin")],
            "every file under it"
        );

        assert_eq!(
            app.delete_plan().unwrap_err(),
            "Delete works on files only. Open the folder to pick files."
        );
        assert!(matches!(press(&mut app, Key::Editor), Effect::None));
        assert_eq!(app.status.as_ref().unwrap().text, "Select a file first.");

        press(&mut app, Key::Space);
        assert!(app.is_dir_picked(&at("b")));
        highlight(&mut app, "b.txt");
        press(&mut app, Key::Space);
        assert_eq!(app.picked(), 2);
        let req = app.deattribute_request(deattribute::Mode::Basic).unwrap();
        assert_eq!(
            req.reports.len(),
            3,
            "the folder's files and the picked file"
        );
        assert!(
            app.delete_plan().is_err(),
            "a picked folder is never deleted"
        );
    }

    #[test]
    fn a_folder_still_being_scanned_adds_a_caveat() {
        let mut app = App::new("root");
        let mut reports = nested_reports();
        reports.sort_by(|a, b| a.path.cmp(&b.path));
        // Walk order: a.txt, b/x/deep.exe, b/y.bin, ...; stop inside b.
        app.push_reports(reports[..2].to_vec());
        highlight(&mut app, "b");
        assert!(matches!(
            app.folder_state(app.current_row().unwrap()),
            explorer::FolderState::Scanning { scanned: 1, .. }
        ));
        let plan = app.scrub_plan().unwrap();
        assert_eq!(
            plan.caveats,
            ["b is still being scanned; files found later are not included."]
        );
        assert_eq!(app.scan_caveats(&app.selected_folders()), plan.caveats);
    }

    #[test]
    fn a_filter_lists_matches_under_the_folder_and_clearing_it_reveals() {
        let mut app = nested();
        app.set_filter(Filter::Text("deep".into()));
        let sep = std::path::MAIN_SEPARATOR;
        assert_eq!(row_names(&app), [format!("b{sep}x{sep}deep.exe")]);
        press(&mut app, Key::Esc);
        assert_eq!(app.filter, Filter::None);
        assert_eq!(app.cwd(), at("b/x"), "the match, shown in its folder");
        assert_eq!(app.current_file().unwrap().path, at("b/x/deep.exe"));
        press(&mut app, Key::Left);
        assert_eq!(app.current_folder(), Some(at("b/x").as_path()));

        // Scoped to the cwd: b holds y.bin, but b.txt at the root is out.
        app.set_filter(Filter::Text("exif".into()));
        assert_eq!(row_names(&app), ["y.bin"]);
        press(&mut app, Key::Buckets);
        let total: usize = app.buckets().iter().map(|b| b.members).sum();
        assert_eq!(total, 3, "buckets count only the findings under b");
    }

    fn brute_stats(app: &App) -> Stats {
        let mut s = Stats::default();
        for r in app.reports() {
            s.flagged += usize::from(!r.findings.is_empty());
            s.removable += r.findings.iter().filter(|f| f.is_removable()).count();
            s.alerts += r
                .findings
                .iter()
                .filter(|f| f.severity == Severity::Alert)
                .count();
        }
        s
    }

    #[test]
    fn header_stats_match_a_brute_force_count() {
        let mut app = nested();
        assert_eq!(app.stats(), brute_stats(&app));
        app.replace_report(report_at("b/x/deep.exe", vec![]));
        assert_eq!(app.stats(), brute_stats(&app));
        app.replace_report(report_at(
            "b/new.exe",
            vec![removable("x.y", Confidence::Strong, Severity::Alert)],
        ));
        assert_eq!(app.stats(), brute_stats(&app));
        app.remove_report(&at("b.txt"));
        assert_eq!(app.stats(), brute_stats(&app));
        assert_eq!(app.stats().alerts, 1);
    }

    #[test]
    fn rows_never_reorder_while_a_scan_streams_in() {
        let mut reports = nested_reports();
        reports.push(report_at("aa/q.bin", vec![]));
        reports.push(report_at("zz.bin", vec![]));
        reports.sort_by(|a, b| a.path.cmp(&b.path));
        let mut app = App::new("root");
        let mut before: Vec<PathBuf> = Vec::new();
        for r in reports {
            app.push_reports(vec![r]);
            let now: Vec<PathBuf> = app.rows().iter().map(|r| r.path.clone()).collect();
            let kept: Vec<&PathBuf> = now.iter().filter(|p| before.contains(p)).collect();
            assert_eq!(
                kept,
                before.iter().collect::<Vec<_>>(),
                "rows kept their order"
            );
            let mut fresh = app.explorer.clone();
            fresh.rebuild(&app.tree, &app.reports, &app.filter);
            assert_eq!(fresh.rows(), app.rows(), "merging matches a full rebuild");
            before = now;
        }
        assert_eq!(app.tree().scanned(), 7);
        assert_eq!(app.tree().frontier(), Some(at("zz.bin").as_path()));
    }

    fn listed(rel: &str, dir: bool, link: bool) -> crate::tui::listing::Item {
        crate::tui::listing::Item {
            name: rel.to_string(),
            path: at(rel),
            dir,
            cloud: false,
            link,
            hidden: false,
            size: None,
        }
    }

    #[test]
    fn a_listing_adds_rows_the_scan_never_delivers() {
        let mut app = App::new("root");
        app.listing_ready(Listing {
            location: PathBuf::from("root"),
            items: vec![
                listed("a.txt", false, false),
                listed("b", true, false),
                listed("empty", true, false),
                listed("late.txt", false, false),
                listed("link", true, true),
                listed("locked", true, false),
                listed("zz.txt", false, false),
            ],
            error: None,
            truncated: false,
        });
        assert_eq!(app.listing_request(), None, "the root is listed");
        assert_eq!(
            row_names(&app),
            [
                "b", "empty", "link", "locked", "a.txt", "late.txt", "zz.txt"
            ]
        );
        let mut locked =
            Scanned::unreadable(&at("locked"), "cannot list directory: permission denied");
        locked.report.partial = true;
        app.push_scanned(vec![
            Scanned {
                report: report_at("a.txt", vec![]),
                error: None,
            },
            Scanned {
                report: report_at("b/y.bin", vec![]),
                error: None,
            },
            locked,
        ]);
        let state = |app: &App, name: &str| {
            let row = app.rows().iter().find(|r| r.name == name).unwrap();
            app.folder_state(row)
        };
        use explorer::FolderState::*;
        assert_eq!(state(&app, "b"), Done);
        assert_eq!(state(&app, "empty"), Empty);
        assert_eq!(state(&app, "link"), NotScanned);
        assert_eq!(
            state(&app, "locked"),
            Unreadable("cannot list directory: permission denied".into())
        );
        assert!(!app.has_report(&at("locked")), "never a file");
        assert_eq!(
            app.rows().len(),
            7,
            "no extra row for the unreadable folder"
        );
        assert!(app.is_final(&at("late.txt")), "passed, so never scanned");
        assert!(!app.is_final(&at("zz.txt")), "not reached yet");
        assert_eq!(
            app.tree().scanned(),
            3,
            "every entry counts toward progress"
        );
    }

    #[test]
    fn folder_states_follow_the_frontier() {
        use explorer::FolderState::*;
        let mut app = App::new("root");
        app.counted(&{
            let mut t = crate::scan::walk::Tally::new(Path::new("root"));
            for rel in ["b/x/1.bin", "b/x/2.bin", "b-c/z.bin", "b.txt"] {
                t.add(&at(rel));
            }
            t.finish(false)
        });
        let state =
            |app: &App, rel: &str| explorer::folder_state(&app.tree, &at(rel), None, app.scanning);
        assert_eq!(
            state(&app, "b"),
            Pending {
                expected: Some(2),
                exact: true
            }
        );
        app.push_reports(vec![report_at("b/x/1.bin", vec![])]);
        assert!(matches!(
            state(&app, "b"),
            Scanning {
                scanned: 1,
                expected: Some(2),
                ..
            }
        ));
        assert!(
            matches!(state(&app, "b-c"), Pending { .. }),
            "b/x sorts before b-c"
        );
        app.push_reports(vec![
            report_at("b/x/2.bin", vec![]),
            report_at("b-c/z.bin", vec![]),
        ]);
        assert_eq!(state(&app, "b"), Done);
        assert_eq!(state(&app, "b/x"), Done);
        assert!(matches!(state(&app, "b-c"), Scanning { .. }));
        assert!(!app.is_final(&at("b.txt")));
        app.scan_done();
        assert_eq!(state(&app, "b-c"), Done);
        assert_eq!(state(&app, "never"), Empty, "the end completes everything");
    }

    #[test]
    fn a_single_file_scan_keeps_one_row() {
        let mut app = App::new("dir/only.bin");
        let mut r = FileReport::new(PathBuf::from("dir/only.bin"), 9);
        r.findings = vec![removable("x.y", Confidence::Strong, Severity::Notice)];
        app.push_reports(vec![r]);
        app.scan_done();
        assert_eq!(row_names(&app), ["only.bin"]);
        press(&mut app, Key::Left);
        assert_eq!(app.cwd(), Path::new("dir/only.bin"), "left does nothing");
        assert!(!app.has_subfolders());
        assert_eq!(
            app.scan_line(),
            "Scanned 1 file: 1 with findings, 1 removable marker."
        );
    }

    #[test]
    fn a_drive_root_holds_its_folders() {
        let root = if cfg!(windows) { r"C:\" } else { "/" };
        let mut app = App::new(root);
        let file = Path::new(root).join("Users").join("x.bin");
        app.push_reports(vec![FileReport::new(file, 1)]);
        assert_eq!(row_names(&app), ["Users"]);
        assert!(matches!(
            app.folder_state(&app.rows()[0]),
            explorer::FolderState::Scanning { .. }
        ));
        press(&mut app, Key::Enter);
        assert_eq!(row_names(&app), ["x.bin"]);
        press(&mut app, Key::Left);
        assert_eq!(app.cwd(), Path::new(root));
    }
}
