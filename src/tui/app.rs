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

use std::collections::{BTreeSet, HashMap};
use std::io;
use std::path::{Path, PathBuf};

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::edit::deattribute;
use crate::edit::{self, Risk};
use crate::model::{
    Bucket, BucketBy, Confidence, ContainerKind, FileReport, Finding, Marker, Region,
    RemovalStrategy, Severity, bucketize,
};
use crate::scan::WindowedFile;

use super::keymap::Key;
use super::picker::{PickOutcome, Picker};
use super::theme::Tone;

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
    Planning,
    Writing,
}

impl Busy {
    /// The status line while this work runs.
    pub fn status(self) -> &'static str {
        match self {
            Busy::Planning => "Planning...",
            Busy::Writing => "Writing copies...",
        }
    }
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
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    pub flagged: usize,
    pub removable: usize,
    pub alerts: usize,
}

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
    visible: Vec<usize>,
    stats: Stats,
    pub file_cursor: usize,
    pub file_offset: usize,
    pub finding_cursor: usize,
    pub finding_offset: usize,
    pub picked_files: BTreeSet<PathBuf>,
    pub picked_findings: BTreeSet<(PathBuf, usize)>,
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
}

impl App {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            reports: Vec::new(),
            scanning: true,
            total: None,
            screen: Screen::Main,
            pane: Pane::Files,
            overlay: None,
            filter: Filter::None,
            visible: Vec::new(),
            stats: Stats::default(),
            file_cursor: 0,
            file_offset: 0,
            finding_cursor: 0,
            finding_offset: 0,
            picked_files: BTreeSet::new(),
            picked_findings: BTreeSet::new(),
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

    /// Leave the picker for a fresh main view over `root`: picks, filter and
    /// old reports are dropped. Only the animation clock carries over.
    fn begin(&mut self, root: PathBuf) {
        let anim = self.anim_ms;
        *self = Self::new(root);
        self.anim_ms = anim;
    }

    // ---- data in -------------------------------------------------------

    /// Add freshly scanned reports (one drained batch). The list stays sorted
    /// by path while the scan streams in, so nothing reshuffles at the end.
    /// A path already listed keeps its report: a copy written and rescanned
    /// while the scan streams would otherwise show up twice.
    pub fn push_reports(&mut self, mut batch: Vec<FileReport>) {
        batch.sort_by(|a, b| a.path.cmp(&b.path));
        batch.dedup_by(|a, b| a.path == b.path);
        batch.retain(|r| {
            self.reports
                .binary_search_by(|have| have.path.cmp(&r.path))
                .is_err()
        });
        if batch.is_empty() {
            return;
        }
        self.reports.extend(batch);
        // Two sorted runs: the stable sort merges them in linear time.
        self.reports.sort_by(|a, b| a.path.cmp(&b.path));
        self.refresh();
    }

    /// The scan finished: sort by path, keeping the cursor on its file.
    pub fn scan_done(&mut self) {
        self.scanning = false;
        self.reports.sort_by(|a, b| a.path.cmp(&b.path));
        self.refresh();
    }

    /// Replace the report for `new.path` in place (or add it).
    pub fn replace_report(&mut self, new: FileReport) {
        self.picked_findings.retain(|(p, _)| *p != new.path);
        match self.reports.iter_mut().find(|r| r.path == new.path) {
            Some(slot) => *slot = new,
            None => {
                let at = self
                    .reports
                    .binary_search_by(|r| r.path.cmp(&new.path))
                    .unwrap_or_else(|i| i);
                self.reports.insert(at.min(self.reports.len()), new);
            }
        }
        self.hex = None;
        self.refresh();
    }

    /// Drop the report for `path` (its file went to the trash).
    pub fn remove_report(&mut self, path: &Path) {
        self.saved.remove(path);
        self.copies.remove(path);
        self.reports.retain(|r| r.path != path);
        self.picked_files.remove(path);
        self.picked_findings.retain(|(p, _)| p != path);
        self.hex = None;
        self.refresh();
    }

    pub fn reports(&self) -> &[FileReport] {
        &self.reports
    }

    pub fn has_report(&self, path: &Path) -> bool {
        self.reports.iter().any(|r| r.path == path)
    }

    pub fn clear_picks(&mut self) {
        self.picked_files.clear();
        self.picked_findings.clear();
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

    /// Start waiting on `work`: edit keys are ignored until it finishes.
    pub fn begin_busy(&mut self, work: Busy) {
        self.busy = Some(work);
        self.set_status(work.status(), Tone::Info);
    }

    /// A deattribute plan finished building: offer it, or say why not.
    pub fn plan_ready(&mut self, plan: Result<Plan, String>) {
        self.busy = None;
        self.status = None;
        self.offer(plan);
    }

    /// The copies of a confirmed deattribute plan were written (or not).
    /// Write failures are listed before the plan's own skips.
    pub fn copies_written(&mut self, plan_skips: &[String], out: CopiesOutcome) {
        self.busy = None;
        self.clear_picks();
        let mut skipped = out.failed;
        skipped.extend(plan_skips.iter().cloned());
        self.record_saved(SavedKind::Deattributed, &out.saved, &skipped, &[]);
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

    fn refresh(&mut self) {
        let keep = self.current_file().map(|r| r.path.clone());
        self.visible = (0..self.reports.len())
            .filter(|&i| file_match(&self.filter, &self.reports[i]) != Match::None)
            .collect();
        if let Some(p) = keep
            && let Some(pos) = self.visible.iter().position(|&i| self.reports[i].path == p)
        {
            self.file_cursor = pos;
        }
        self.file_cursor = clamp(self.file_cursor, self.visible.len());
        let n = self.current_findings().len();
        self.finding_cursor = clamp(self.finding_cursor, n);
        self.stats = Stats::default();
        for r in &self.reports {
            if !r.findings.is_empty() {
                self.stats.flagged += 1;
            }
            self.stats.removable += r.findings.iter().filter(|f| f.is_removable()).count();
            self.stats.alerts += r
                .findings
                .iter()
                .filter(|f| f.severity == Severity::Alert)
                .count();
        }
        // Buckets are only kept current while their screen is up.
        if self.screen == Screen::Buckets {
            self.buckets = bucketize(&self.reports, self.bucket_by);
        }
        self.bucket_cursor = clamp(self.bucket_cursor, self.buckets.len());
        if self.screen == Screen::Detail && self.current_finding().is_none() {
            self.screen = Screen::Main;
        }
    }

    // ---- queries -------------------------------------------------------

    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// Indices into `reports()` of the files the filter lets through.
    pub fn visible(&self) -> &[usize] {
        &self.visible
    }

    pub fn current_file(&self) -> Option<&FileReport> {
        self.visible
            .get(self.file_cursor)
            .and_then(|&i| self.reports.get(i))
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
        self.picked_files.len() + self.picked_findings.len()
    }

    pub fn is_file_picked(&self, p: &Path) -> bool {
        self.picked_files.contains(p)
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
        let n = self.reports.len();
        let shown = thousands(n);
        if self.scanning {
            return match self.total {
                Some(t) => format!("Scanning {shown} of {} files...", thousands(t)),
                None => format!("Scanning {shown} {}...", plural(n, "file", "files")),
            };
        }
        if n == 0 {
            return "No files to scan.".to_string();
        }
        let s = self.stats;
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
            return match picker.on_key(ev) {
                PickOutcome::Stay => Effect::None,
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
            KeyCode::Char('c') if ctrl => return self.quit(),
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
            return self.quit();
        }
        if let Some(work) = self.busy
            && matches!(
                key,
                Key::Scrub | Key::Deattribute | Key::DeepDeattribute | Key::Delete | Key::Yes
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
            Key::Left | Key::Right => {
                if self.screen == Screen::Main {
                    self.pane = if key == Key::Left {
                        Pane::Files
                    } else {
                        Pane::Findings
                    };
                }
                Effect::None
            }
            Key::Enter => self.enter(),
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
            Key::Quit | Key::Interrupt => self.quit(),
            Key::Yes | Key::No | Key::Backspace => Effect::None,
        }
    }

    fn quit(&mut self) -> Effect {
        self.should_quit = true;
        Effect::Quit
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
                    self.file_cursor = step(self.file_cursor, self.visible.len(), key, page);
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

    fn enter(&mut self) -> Effect {
        match self.screen {
            Screen::Main => match self.pane {
                Pane::Files => {
                    if self.current_findings().is_empty() {
                        if self.current_file().is_some() {
                            self.set_status("This file has no findings.", Tone::Good);
                        }
                    } else {
                        self.pane = Pane::Findings;
                    }
                    Effect::None
                }
                Pane::Findings => self.open_detail(),
            },
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
        if self.quit_armed {
            return self.quit();
        }
        self.quit_armed = true;
        self.set_status(MSG_QUIT_ARMED, Tone::Info);
        Effect::None
    }

    fn toggle_pick(&mut self) {
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
                self.buckets = bucketize(&self.reports, by);
            }
            None => {
                self.screen = Screen::Main;
                self.bucket_by = BucketBy::Category;
            }
        }
    }

    /// Replace the filter and re-derive the visible list.
    pub fn set_filter(&mut self, f: Filter) {
        self.filter = f;
        self.refresh();
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

    /// The scrub batch for the current picks, or the highlighted item.
    pub fn scrub_plan(&self) -> Result<Plan, String> {
        let index: HashMap<&Path, usize> = self
            .reports
            .iter()
            .enumerate()
            .map(|(i, r)| (r.path.as_path(), i))
            .collect();
        let mut picks: Vec<(usize, usize)> = Vec::new();
        let mut weak = 0usize;
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
        self.build_scrub(picks, weak)
    }

    /// Every removable, non-weak member of the highlighted bucket.
    pub fn bucket_plan(&self) -> Result<Plan, String> {
        let Some(b) = self.buckets.get(self.bucket_cursor) else {
            return Err(MSG_NOTHING.to_string());
        };
        let mut picks = Vec::new();
        let mut weak = 0;
        for (ri, r) in self.reports.iter().enumerate() {
            for (fi, f) in r.findings.iter().enumerate() {
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
        for (ri, fi) in picks {
            match per_file.iter_mut().find(|(r, _)| *r == ri) {
                Some((_, list)) => {
                    if !list.contains(&fi) {
                        list.push(fi);
                    }
                }
                None => per_file.push((ri, vec![fi])),
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

    /// The files a deattribute in `mode` would cover: the picks, the
    /// highlighted bucket's files, or the highlighted file. Only the reports
    /// are gathered here; reading the files is left to [`plan_deattribute`].
    pub fn deattribute_request(
        &self,
        mode: deattribute::Mode,
    ) -> Result<DeattributeRequest, String> {
        let mut paths = BTreeSet::new();
        paths.extend(self.picked_files.iter().cloned());
        paths.extend(self.picked_findings.iter().map(|(path, _)| path.clone()));
        if paths.is_empty() {
            if self.screen == Screen::Buckets {
                if let Some(bucket) = self.buckets.get(self.bucket_cursor) {
                    for report in &self.reports {
                        if report.findings.iter().any(|finding| {
                            bucket_key(bucket.by, finding).as_deref() == Some(bucket.key.as_str())
                        }) {
                            paths.insert(report.path.clone());
                        }
                    }
                }
            } else if let Some(report) = self.current_file() {
                paths.insert(report.path.clone());
            }
        }
        if paths.is_empty() {
            return Err(MSG_NOTHING.to_string());
        }
        Ok(DeattributeRequest {
            root: self.root.clone(),
            mode,
            reports: self
                .reports
                .iter()
                .filter(|report| paths.contains(&report.path))
                .cloned()
                .collect(),
        })
    }

    /// Delete the picked files, or the highlighted one.
    pub fn delete_plan(&self) -> Result<Plan, String> {
        if self.screen == Screen::Buckets {
            return Err("Select files in the file list to delete them.".to_string());
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
    let mode = req.mode;
    let mut items = Vec::new();
    let mut private_skips = Vec::new();
    let mut caveats: Vec<String> = Vec::new();
    let mut replaces = Vec::new();
    for report in &req.reports {
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
        press(&mut app, Key::End); // c/tool.exe
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
            &["b/photo.jpg: already a deattributed copy".to_string()],
            CopiesOutcome {
                failed: vec!["c/tool.exe: changed since scan".to_string()],
                ..CopiesOutcome::default()
            },
        );
        let s = app.status.as_ref().unwrap();
        assert_eq!(
            s.text,
            "Saved nothing; skipped 2: c/tool.exe: changed since scan."
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
                        let named = k > 0 && words[k - 1] == "press";
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
                "b/photo.jpg",
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
            report("a/clean.png", "png", vec![]),
            report(
                "c/tool.exe",
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
    fn left_and_right_focus_the_pane_on_their_side() {
        let mut app = sample();
        press(&mut app, Key::Right);
        assert_eq!(app.pane, Pane::Findings);
        press(&mut app, Key::Right);
        assert_eq!(app.pane, Pane::Findings, "right stays on the right pane");
        app.on_key(KeyEvent::from(KeyCode::Char('h')));
        assert_eq!(app.pane, Pane::Files);
        app.on_key(KeyEvent::from(KeyCode::Left));
        assert_eq!(app.pane, Pane::Files, "left stays on the left pane");
        app.on_key(KeyEvent::from(KeyCode::Char('l')));
        assert_eq!(app.pane, Pane::Findings);

        // The filter still takes h and l as text.
        press(&mut app, Key::Filter);
        type_text(&mut app, "hl");
        app.on_key(KeyEvent::from(KeyCode::Enter));
        assert_eq!(app.filter.describe().as_deref(), Some("hl"));
    }

    #[test]
    fn navigation_is_bounded() {
        let mut app = sample();
        assert_eq!(app.visible().len(), 3);
        assert_eq!(
            app.current_file().unwrap().path,
            PathBuf::from("root/a/clean.png")
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
                assert_eq!(path, PathBuf::from("root/c/tool.exe"));
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
        assert!(app.is_file_picked(Path::new("root/a/clean.png")));
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
        let n = |app: &App| app.visible().len();
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
        assert_eq!(app.visible().len(), 1);
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
        press(&mut app, Key::Down); // b/photo.jpg
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
        press(&mut app, Key::End); // c/tool.exe
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
        let mut fresh = report("c/tool.exe", "pe", vec![]);
        fresh.size = 2048;
        app.replace_report(fresh);
        assert_eq!(app.visible().len(), 3);
        assert_eq!(
            app.current_file().unwrap().size,
            2048,
            "cursor stays on the file"
        );
        assert_eq!(app.picked(), 0, "stale finding picks dropped");
        app.remove_report(Path::new("root/c/tool.exe"));
        assert_eq!(app.visible().len(), 2);
        app.replace_report(report("c/tool.exe", "pe", vec![]));
        assert_eq!(
            app.reports()[2].path,
            PathBuf::from("root/c/tool.exe"),
            "sorted insert"
        );
    }

    #[test]
    fn scan_line_and_help_overlay() {
        let mut app = App::new("root");
        app.total = Some(400);
        app.push_reports(vec![report("x", "pe", vec![])]);
        assert_eq!(app.scan_line(), "Scanning 1 of 400 files...");
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
        assert_eq!(app.scan_line(), "Scanning 1,234 of 1,101,278 files...");
        app.scan_done();
        assert_eq!(app.scan_line(), "Scanned 1,234 files. No findings.");
    }

    fn type_raw(app: &mut App, s: &str) -> Vec<Effect> {
        s.chars()
            .map(|c| app.on_key(KeyEvent::from(KeyCode::Char(c))))
            .collect()
    }

    #[test]
    fn picker_mode_scans_nothing_until_a_folder_is_chosen() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = App::picking(Picker::new(None, Vec::new()));
        assert!(app.is_picking());
        assert!(!app.scanning, "no scan before a folder is chosen");
        assert_eq!(app.context(), "picker");
        // Mapped keys are inert here; q is text for the picker, not quit.
        for k in Key::ALL {
            if k != Key::Interrupt {
                assert!(matches!(app.on_action(k), Effect::None), "{k:?}");
            }
        }
        let typed = type_raw(&mut app, "q");
        assert!(matches!(typed[..], [Effect::None]));
        assert!(!app.should_quit, "q is typed, not quit");
        app.on_key(KeyEvent::from(KeyCode::Backspace));

        // A trailing separator lists the folder itself, with its
        // "Scan this folder" row highlighted first.
        let typed = format!("{}{}", dir.path().display(), std::path::MAIN_SEPARATOR);
        type_raw(&mut app, &typed);
        app.anim_ms = 777;
        let effect = app.on_key(KeyEvent::from(KeyCode::Enter));
        let Effect::Scan(chosen) = effect else {
            panic!("enter on a small folder scans it: {effect:?}");
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
        app.open_picker(Picker::reopen(None, Vec::new(), &root));
        assert!(app.is_picking());
        assert_eq!(app.context(), "picker");
        for _ in 0..8 {
            if !app.is_picking() {
                break;
            }
            assert!(matches!(
                app.on_key(KeyEvent::from(KeyCode::Esc)),
                Effect::None
            ));
        }
        assert!(!app.is_picking(), "esc backs out of a reopened picker");
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
        app.open_picker(Picker::reopen(None, Vec::new(), &root));
        app.on_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        let typed = format!("{}{}", dir.path().display(), std::path::MAIN_SEPARATOR);
        type_raw(&mut app, &typed);
        let Effect::Scan(chosen) = app.on_key(KeyEvent::from(KeyCode::Enter)) else {
            panic!("enter scans the typed folder");
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
        let one = [item("root/c/tool.exe", "root/c/tool.exe", 3)];
        let s = app.saved_status(SavedKind::Scrubbed, &one, &[], &[]);
        assert_eq!(s.text, "Saved c/tool.exe (3 edits). Press u to undo.");
        assert_eq!(s.tone, Tone::Good);

        let three = [
            item("root/c/tool.exe", "root/c/tool.exe", 1),
            item("root/b/photo.jpg", "root/b/photo.jpg", 2),
            item("root/a/clean.png", "root/a/clean.png", 1),
        ];
        let s = app.saved_status(SavedKind::Scrubbed, &three, &[], &["magic".into()]);
        assert_eq!(
            s.text,
            "Saved c/tool.exe (1 edit) +2 more; refused 1. Press u to undo."
        );
        assert_eq!(s.tone, Tone::Warn);

        let copy = [item(
            "root/c/setup-tool.exe",
            "root/c/setup-tool.deattributed.exe",
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
        let tool = PathBuf::from("root/c/tool.exe");
        let photo = PathBuf::from("root/b/photo.jpg");
        app.record_saved(
            SavedKind::Scrubbed,
            &[item("root/c/tool.exe", "root/c/tool.exe", 2)],
            &[],
            &[],
        );
        assert!(
            app.status
                .as_ref()
                .unwrap()
                .text
                .starts_with("Saved c/tool.exe")
        );
        app.mark_saved(&tool, SavedKind::Scrubbed, tool.clone(), 1);
        assert_eq!(app.saved(&tool).unwrap().edits, 3, "a second scrub adds up");
        app.mark_saved(
            &photo,
            SavedKind::Deattributed,
            PathBuf::from("root/b/photo.deattributed.jpg"),
            1,
        );

        // The rescan after an edit replaces the report; the mark stays.
        app.replace_report(report("c/tool.exe", "pe", vec![]));
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
        let tool = PathBuf::from("root/c/tool.exe");
        let copy = PathBuf::from("root/c/tool.deattributed.exe");
        app.mark_saved(&tool, SavedKind::Deattributed, copy.clone(), 3);
        app.mark_saved(&tool, SavedKind::Deattributed, copy, 2);
        assert_eq!(app.saved(&tool).unwrap().edits, 2, "the copy was replaced");
    }

    #[test]
    fn esc_in_the_picker_quits() {
        let mut app = App::picking(Picker::new(None, Vec::new()));
        let mut last = Effect::None;
        for _ in 0..8 {
            last = app.on_key(KeyEvent::from(KeyCode::Esc));
            if app.should_quit {
                break;
            }
        }
        assert!(matches!(last, Effect::Quit), "{last:?}");
        assert!(app.should_quit);
        let mut app = App::picking(Picker::new(None, Vec::new()));
        assert!(matches!(app.on_action(Key::Interrupt), Effect::Quit));
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
}
