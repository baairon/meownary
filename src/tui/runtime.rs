//! The terminal side of the view: set up the screen, stream the scan in, run
//! the frame clock, feed keys to [`App`], and carry out the [`Effect`]s it
//! returns (edits, the external editor, undo, hex reads, and the scan the
//! folder picker asks for).
//!
//! Without a path the view opens on the folder picker and nothing is walked
//! or read until a folder is chosen; the scan then starts in the same
//! terminal session. The scan streams reports in walk order from the start
//! and sends the file total once the walk finishes, so the progress line
//! counts up right away and learns its denominator later.
//!
//! `o` reopens the picker over the view. The running scan keeps going while
//! the picker is up and stops only when a new path is chosen (its receiver
//! is dropped, which stops the walk and the queued tasks); backing out of the
//! picker returns to the view exactly as it was.
//!
//! The picker offers the last few picks first. They live in
//! `<state dir>/recent.json`, a JSON array of paths written only when a path
//! is chosen in the picker; a path given on the command line is never
//! recorded. A missing or unreadable file is an empty list, and a failed
//! write is ignored: the list is a convenience, never a reason to fail.
//!
//! The loop polls for input with a [`FRAME_MS`] timeout. It redraws only when
//! something changed (a key, a resize, new scan results, an effect) or, while
//! the wordmark animates, when the animation frame advances.
//!
//! The edit engine is created on the first edit, not at startup, so browsing
//! never touches the state dir. The lock is taken for each batch and released
//! right after, so a `meownary clean` in another terminal is only kept out
//! while an edit is actually running. If the engine cannot be opened or the
//! lock is held, the reason shows in the status line and the view stays
//! read-only for that action; nothing crashes.
//!
//! Deattribute plans and copy writes read whole files (a deep sweep reads up
//! to 256 MiB of one, and an archive is dry-run through its writer), so they
//! run on a worker thread and come back over a channel, like the scan. While
//! one runs the view keeps drawing, shows what it is waiting on, and ignores
//! the edit keys. Keys typed while a plan was being built are dropped when it
//! arrives, and `y` only confirms a modal that has been drawn, so nothing
//! queued ahead of a confirm can answer it. A copy write still running at
//! quit is waited for, so no copy is cut off halfway.
//!
//! The terminal is restored on every exit path: normal return, error return
//! and panic (`ratatui::try_init` installs a restoring panic hook). A panic
//! the per-file guard catches is not a crash, so it leaves the screen alone.

#![cfg(feature = "tui")]

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyEvent, KeyEventKind,
};
use ratatui::crossterm::execute;

use crate::edit::{EditEngine, EditError, Risk, UndoReport, deattribute};
use crate::model::RemovalStrategy;
use crate::scan::guard::{guarded, in_guard};
use crate::scan::{self, FileView, Registry, ScanEvent, ScanOpts, WindowedFile};

use super::app::{
    self, App, Busy, CopiesOutcome, DeattributeRequest, Effect, HexView, MSG_LOCKED, Plan,
    PlanItem, PlanKind, SavedItem, SavedKind,
};
use super::picker::Picker;
use super::theme::{Look, Tone};
use super::ui;

/// Input poll timeout and animation frame length, in milliseconds.
pub const FRAME_MS: u64 = 50;

/// Most scan results folded into the view per frame, so a huge directory
/// never stalls the keyboard.
const BATCH_MAX: usize = 4096;

/// The recent picks file inside the state dir.
pub const RECENT_FILE: &str = "recent.json";
/// How many recent picks are kept.
pub const RECENT_MAX: usize = 5;

/// Run the interactive view until the user quits: over `path` right away,
/// or, without one, starting on the folder picker.
pub fn run(path: Option<&Path>) -> io::Result<()> {
    if let Some(path) = path
        && std::fs::symlink_metadata(path).is_err()
    {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{} does not exist", path.display()),
        ));
    }
    let look = Look::from_env();
    let mut rt = match path {
        Some(path) => Runtime::start(path, look),
        None => Runtime::picking(look),
    };
    let mut terminal = init_terminal()?;
    let result = rt.event_loop(&mut terminal);
    restore_terminal();
    rt.join_writer();
    result
}

/// Take over the terminal, with bracketed paste on so a pasted path reaches
/// the picker in one piece. A terminal without paste support still works:
/// its paste arrives as keys.
fn init_terminal() -> io::Result<DefaultTerminal> {
    let terminal = ratatui::try_init()?;
    quiet_guarded_panics();
    let _ = execute!(io::stdout(), EnableBracketedPaste);
    Ok(terminal)
}

/// `ratatui::try_init` wraps the panic hook so it restores the terminal
/// before anything else runs, which would tear down the live view even for a
/// panic the per-file guard catches. Wrap it once more so a guarded panic
/// returns before that; a real panic still restores and reports.
fn quiet_guarded_panics() {
    let restore_and_report = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if in_guard() {
            return;
        }
        restore_and_report(info);
    }));
}

/// Drop every key and event already queued, so none of them lands on a
/// confirm that has not been drawn yet.
fn flush_input() -> io::Result<()> {
    while event::poll(Duration::ZERO)? {
        let _ = event::read()?;
    }
    Ok(())
}

/// A finished background job.
enum Job {
    Planned(Result<Plan, String>),
    Wrote {
        plan_skips: Vec<String>,
        out: CopiesOutcome,
    },
}

fn restore_terminal() {
    let _ = execute!(io::stdout(), DisableBracketedPaste);
    ratatui::restore();
}

struct Runtime {
    app: App,
    look: Look,
    started: Instant,
    scan_rx: Option<Receiver<ScanEvent>>,
    engine: Option<EditEngine>,
    registry: Option<Registry>,
    /// Canonical paths the engine reported, mapped back to the view's paths.
    known: HashMap<PathBuf, PathBuf>,
    /// Where the recent picks are kept.
    recent_file: PathBuf,
    /// The plan or copy write running off the input thread.
    job_rx: Option<Receiver<Job>>,
    /// The copy writer, joined at quit so a write is never cut off.
    writer: Option<JoinHandle<()>>,
}

impl Runtime {
    fn new(app: App, look: Look) -> Self {
        Self {
            app,
            look,
            started: Instant::now(),
            scan_rx: None,
            engine: None,
            registry: None,
            known: HashMap::new(),
            recent_file: crate::util::paths::state_dir().join(RECENT_FILE),
            job_rx: None,
            writer: None,
        }
    }

    /// Scan `path` from the first frame.
    fn start(path: &Path, look: Look) -> Self {
        let mut rt = Self::new(App::new(path), look);
        rt.start_scan(path);
        rt
    }

    /// Open on the picker; nothing is scanned yet.
    fn picking(look: Look) -> Self {
        Self::picking_at(look, crate::util::paths::state_dir().join(RECENT_FILE))
    }

    /// [`Runtime::picking`] with the recent picks kept in `recent_file`.
    fn picking_at(look: Look, recent_file: PathBuf) -> Self {
        let mut rt = Self::new(App::new(PathBuf::new()), look);
        rt.recent_file = recent_file;
        let picker = Picker::new(std::env::current_dir().ok(), rt.recent());
        rt.app = App::picking(picker);
        rt
    }

    /// Start streaming a scan of `path` into the view, replacing any scan
    /// still running. One walk feeds both the reports and the total.
    fn start_scan(&mut self, path: &Path) {
        let (rx, _scan) = scan::scan(path, ScanOpts::default());
        self.scan_rx = Some(rx);
    }

    /// The recent picks, newest first.
    fn recent(&self) -> Vec<PathBuf> {
        load_recent(&self.recent_file)
    }

    /// Show the picker over the view, starting at the current root.
    fn reopen_picker(&mut self) {
        let cwd = std::env::current_dir().ok();
        let picker = Picker::reopen(cwd, self.recent(), &self.app.root);
        self.app.open_picker(picker);
    }

    /// The picker chose `path`: remember it and scan it. A plan or write
    /// result for the old view has nowhere to land, so it is dropped.
    fn picked(&mut self, path: &Path) {
        let list = remember(&self.recent(), path);
        save_recent(&self.recent_file, &list);
        self.job_rx = None;
        self.start_scan(path);
    }

    fn event_loop(&mut self, terminal: &mut DefaultTerminal) -> io::Result<()> {
        let mut dirty = true;
        let mut last_frame = u64::MAX;
        loop {
            dirty |= self.drain_scan();
            match self.drain_job() {
                Some(true) => {
                    flush_input()?;
                    dirty = true;
                }
                Some(false) => dirty = true,
                None => {}
            }
            if let Some((path, offset)) = self.app.hex_request() {
                self.load_hex(path, offset);
                dirty = true;
            }
            let now = self.started.elapsed().as_millis() as u64;
            if self.look.animate {
                let frame = now / FRAME_MS;
                if frame != last_frame {
                    last_frame = frame;
                    dirty = true;
                }
            }
            if dirty {
                self.app.anim_ms = now;
                terminal.draw(|f| ui::draw(f, &mut self.app, &self.look))?;
                dirty = false;
            }
            if self.app.should_quit {
                return Ok(());
            }

            if !event::poll(Duration::from_millis(FRAME_MS))? {
                continue;
            }
            // Handle everything already queued before the next draw.
            loop {
                match event::read()? {
                    Event::Key(k) if k.kind != KeyEventKind::Release => {
                        if let Some(path) = self.key(k) {
                            self.open_editor(path, terminal)?;
                        }
                        dirty = true;
                    }
                    Event::Paste(text) => {
                        if let Some(picker) = self.app.picker.as_mut() {
                            picker.on_paste(&text);
                            dirty = true;
                        }
                    }
                    Event::Resize(..) => dirty = true,
                    _ => {}
                }
                if self.app.should_quit || !event::poll(Duration::ZERO)? {
                    break;
                }
            }
        }
    }

    /// Fold finished scan results into the view. True when anything changed.
    fn drain_scan(&mut self) -> bool {
        let mut changed = false;
        let Some(rx) = &self.scan_rx else {
            return changed;
        };
        let mut batch = Vec::new();
        let mut done = false;
        while batch.len() < BATCH_MAX {
            match rx.try_recv() {
                Ok(ScanEvent::Found(s)) => batch.push(s.report),
                Ok(ScanEvent::Counted(_)) => {}
                Ok(ScanEvent::Total(n)) => {
                    self.app.total = Some(n);
                    changed = true;
                }
                Ok(ScanEvent::Done) | Err(TryRecvError::Disconnected) => {
                    done = true;
                    break;
                }
                Err(TryRecvError::Empty) => break,
            }
        }
        if !batch.is_empty() {
            self.app.push_reports(batch);
            changed = true;
        }
        if done {
            self.scan_rx = None;
            self.app.scan_done();
            changed = true;
        }
        changed
    }

    /// Take the result of a finished plan or copy write. `None` when nothing
    /// arrived; `Some(true)` when a plan arrived, so the caller drops the
    /// keys queued meanwhile before the confirm is drawn.
    fn drain_job(&mut self) -> Option<bool> {
        let job = match self.job_rx.as_ref()?.try_recv() {
            Ok(job) => job,
            Err(TryRecvError::Empty) => return None,
            Err(TryRecvError::Disconnected) => {
                self.job_rx = None;
                self.join_writer();
                let was = self.app.busy.take();
                self.app.set_status(
                    "That action stopped on an internal error. Nothing changed.",
                    Tone::Bad,
                );
                return Some(was == Some(Busy::Planning));
            }
        };
        self.job_rx = None;
        Some(match job {
            Job::Planned(plan) => {
                self.app.plan_ready(plan);
                true
            }
            Job::Wrote { plan_skips, out } => {
                self.join_writer();
                self.app.copies_written(&plan_skips, out);
                false
            }
        })
    }

    /// Build a deattribute plan on a worker; [`Runtime::drain_job`] offers it.
    fn spawn_plan(&mut self, req: DeattributeRequest) {
        let (tx, rx) = mpsc::channel();
        let work = move || {
            let plan = guarded(|| app::plan_deattribute(&req)).unwrap_or_else(|()| {
                Err("Planning stopped on an internal error. Nothing changed.".to_string())
            });
            let _ = tx.send(Job::Planned(plan));
        };
        match thread::Builder::new()
            .name("meownary-plan".into())
            .spawn(work)
        {
            Ok(_) => self.job_rx = Some(rx),
            Err(e) => self.app.plan_ready(Err(format!(
                "Could not start planning ({e}). Nothing changed."
            ))),
        }
    }

    /// Write a confirmed deattribute plan's copies on a worker. The originals
    /// are only read, so nothing goes through the edit engine or the undo
    /// journal.
    fn spawn_writer(&mut self, plan: Plan) {
        self.join_writer();
        self.app.begin_busy(Busy::Writing);
        let root = self.app.root.clone();
        let plan_skips = plan.private_skips.clone();
        let (tx, rx) = mpsc::channel();
        let work = move || {
            let out = guarded(|| write_copies(&plan, &root)).unwrap_or_else(|()| CopiesOutcome {
                failed: vec!["the copy writer stopped on an internal error".to_string()],
                ..CopiesOutcome::default()
            });
            let _ = tx.send(Job::Wrote { plan_skips, out });
        };
        match thread::Builder::new()
            .name("meownary-copies".into())
            .spawn(work)
        {
            Ok(handle) => {
                self.job_rx = Some(rx);
                self.writer = Some(handle);
            }
            Err(e) => {
                self.app.busy = None;
                self.app.set_status(
                    format!("Saved nothing: the copy writer could not start ({e})."),
                    Tone::Bad,
                );
            }
        }
    }

    /// Wait for the copy writer, if one ran.
    fn join_writer(&mut self) {
        if let Some(handle) = self.writer.take() {
            let _ = handle.join();
        }
    }

    fn load_hex(&mut self, path: PathBuf, offset: u64) {
        let base = app::hex_base(offset);
        let read =
            WindowedFile::open(&path).and_then(|v| v.read_at(base, app::HEX_WINDOW as usize));
        self.app.hex = Some(match read {
            Ok(bytes) => HexView {
                path,
                base,
                bytes,
                error: None,
            },
            Err(e) => HexView {
                path,
                base,
                bytes: Vec::new(),
                error: Some(e.to_string()),
            },
        });
    }

    /// Feed one key to the view and carry out its effect. The editor needs
    /// the terminal, so its file is handed back for the caller to open.
    fn key(&mut self, k: KeyEvent) -> Option<PathBuf> {
        match self.app.on_key(k) {
            Effect::None | Effect::Quit => {}
            Effect::LoadHex { path, offset } => self.load_hex(path, offset),
            Effect::Apply(plan) => self.apply_plan(plan),
            Effect::PlanDeattribute(req) => self.spawn_plan(req),
            Effect::Edit(path) => return Some(path),
            Effect::Undo => self.undo(),
            Effect::Scan(path) => self.picked(&path),
            Effect::Pick => self.reopen_picker(),
        }
        None
    }

    /// Open the engine if needed and take the lock. On failure the reason is
    /// in the status line and the action does not run.
    fn ready_engine(&mut self) -> bool {
        if self.engine.is_none() {
            match EditEngine::new() {
                Ok(e) => self.engine = Some(e),
                Err(e) => {
                    self.app.set_status(
                        format!("Read-only: the trash store could not be opened ({e})."),
                        Tone::Bad,
                    );
                    return false;
                }
            }
        }
        let Some(engine) = self.engine.as_mut() else {
            return false;
        };
        match engine.acquire_lock() {
            Ok(()) => true,
            Err(EditError::Locked(_)) => {
                self.app.set_status(MSG_LOCKED, Tone::Warn);
                false
            }
            Err(e) => {
                self.app.set_status(format!("Read-only: {e}."), Tone::Bad);
                false
            }
        }
    }

    fn release(&mut self) {
        if let Some(e) = self.engine.as_mut() {
            e.release_lock();
        }
    }

    fn apply_plan(&mut self, plan: Plan) {
        if matches!(plan.kind, PlanKind::Deattribute | PlanKind::DeepDeattribute) {
            self.spawn_writer(plan);
            return;
        }
        if !self.ready_engine() {
            return;
        }
        let Some(engine) = self.engine.as_mut() else {
            return;
        };
        let out = run_plan(engine, &plan);
        self.release();
        self.known.extend(out.applied.iter().cloned());
        if plan.kind == PlanKind::Scrub && out.ok > 0 {
            let items = scrub_items(&out);
            self.app
                .record_saved(SavedKind::Scrubbed, &items, &out.skipped, &out.refused);
        } else {
            self.app.status = Some(app::batch_status(
                plan.kind,
                out.ok,
                &out.skipped,
                &out.refused,
            ));
        }
        self.app.clear_picks();
        for p in &out.touched {
            self.rescan(p);
        }
        if plan.kind == PlanKind::Delete && out.ok > 0 {
            self.app.pane = app::Pane::Files;
        }
    }

    fn open_editor(&mut self, path: PathBuf, terminal: &mut DefaultTerminal) -> io::Result<()> {
        if !self.ready_engine() {
            return Ok(());
        }
        let Some(engine) = self.engine.as_mut() else {
            return Ok(());
        };
        restore_terminal();
        println!(
            "Editing {}. The view returns when the editor closes.",
            path.display()
        );
        let result = engine.open_in_editor(&path);
        engine.release_lock();
        *terminal = init_terminal()?;
        terminal.clear()?;
        match result {
            Ok(Some(applied)) => {
                self.known.insert(applied.path, path.clone());
                self.app.set_status(
                    "Editor closed. The file changed; press u to undo the change.",
                    Tone::Good,
                );
            }
            Ok(None) => self
                .app
                .set_status("Editor closed. No changes.", Tone::Info),
            Err(EditError::Locked(_)) => self.app.set_status(MSG_LOCKED, Tone::Warn),
            Err(e) => self
                .app
                .set_status(format!("The editor could not start: {e}."), Tone::Bad),
        }
        self.rescan(&path);
        Ok(())
    }

    fn undo(&mut self) {
        if !self.ready_engine() {
            return;
        }
        let Some(engine) = self.engine.as_mut() else {
            return;
        };
        let res = engine.undo_last_report();
        engine.release_lock();
        match res {
            Ok(report) => {
                let (text, tone) = undo_status(&report);
                self.app.set_status(text, tone);
                for canon in &report.paths {
                    if let Some(p) = self.view_path(canon) {
                        self.app.clear_scrubbed(&p);
                        self.rescan(&p);
                    }
                }
            }
            Err(EditError::Locked(_)) => self.app.set_status(MSG_LOCKED, Tone::Warn),
            Err(e) => self.app.set_status(format!("Undo failed: {e}."), Tone::Bad),
        }
    }

    /// Map a canonical path from the journal back to the path the view uses.
    fn view_path(&self, canon: &Path) -> Option<PathBuf> {
        if let Some(p) = self.known.get(canon) {
            return Some(p.clone());
        }
        let root = &self.app.root;
        let root_c = crate::edit::canonical_path(root).ok()?;
        if canon == root_c {
            return Some(root.clone());
        }
        let rel = canon.strip_prefix(&root_c).ok()?;
        Some(root.join(rel))
    }

    /// Re-scan one file and replace its report (or drop it when it is gone).
    fn rescan(&mut self, path: &Path) {
        if std::fs::symlink_metadata(path).is_err() {
            self.app.remove_report(path);
            return;
        }
        let registry = self.registry.get_or_insert_with(crate::parsers::registry);
        let report = scan::scan_file(path, registry);
        self.app.replace_report(report);
    }
}

/// The recent picks in `file`, newest first. A missing or unreadable file,
/// or one that is not a JSON array of strings, is an empty list.
pub fn load_recent(file: &Path) -> Vec<PathBuf> {
    let Ok(bytes) = std::fs::read(file) else {
        return Vec::new();
    };
    let list: Vec<String> = serde_json::from_slice(&bytes).unwrap_or_default();
    let mut out: Vec<PathBuf> = Vec::new();
    for p in list
        .into_iter()
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
    {
        if !out.contains(&p) && out.len() < RECENT_MAX {
            out.push(p);
        }
    }
    out
}

/// `list` with `picked` moved to the front, without duplicates, at most
/// [`RECENT_MAX`] long.
pub fn remember(list: &[PathBuf], picked: &Path) -> Vec<PathBuf> {
    let mut out = vec![picked.to_path_buf()];
    out.extend(list.iter().filter(|p| p.as_path() != picked).cloned());
    out.truncate(RECENT_MAX);
    out
}

/// Write `list` to `file` atomically. Errors are ignored: the list is only a
/// convenience.
pub fn save_recent(file: &Path, list: &[PathBuf]) {
    let strings: Vec<String> = list
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    let Ok(json) = serde_json::to_vec_pretty(&strings) else {
        return;
    };
    if let Some(dir) = file.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = crate::util::atomic::write_atomic(file, &json);
}

/// What one confirmed batch did.
#[derive(Debug, Default)]
pub struct BatchOutcome {
    /// Edits that landed.
    pub ok: usize,
    /// Reasons for items that were tried, or passed over, and did not land.
    pub skipped: Vec<String>,
    /// Reasons for items the safety rules refused.
    pub refused: Vec<String>,
    /// The view's paths of every file an edit was attempted on, in order.
    pub touched: Vec<PathBuf>,
    /// Canonical path the engine reported, paired with the view's path.
    pub applied: Vec<(PathBuf, PathBuf)>,
}

/// Apply a confirmed plan as one undo group, with `force` (the confirm was
/// the user's go-ahead). Refused items are skipped. Once an edit changes a
/// file's length, its later items are skipped too: their scan-time offsets
/// no longer hold, and the rescan offers them again.
pub fn run_plan(engine: &mut EditEngine, plan: &Plan) -> BatchOutcome {
    let mut out = BatchOutcome::default();
    out.skipped.extend(plan.private_skips.iter().cloned());
    engine.begin_group();
    let mut reshaped: Vec<PathBuf> = Vec::new();
    for item in &plan.items {
        if let Risk::Refuse(r) = &item.risk {
            out.refused.push(r.clone());
            continue;
        }
        if reshaped.contains(&item.path) {
            out.skipped.push(
                "an earlier edit changed this file's layout; scrub again after the rescan".into(),
            );
            continue;
        }
        let res = engine.apply(
            &item.path,
            &item.marker,
            item.format.as_deref(),
            item.size,
            item.expected_hash.as_deref(),
            !matches!(plan.kind, PlanKind::Deattribute | PlanKind::DeepDeattribute),
            &item.label,
        );
        if !out.touched.contains(&item.path) {
            out.touched.push(item.path.clone());
        }
        match res {
            Ok(applied) => {
                out.ok += 1;
                out.applied.push((applied.path, item.path.clone()));
                if matches!(
                    item.marker.removal,
                    RemovalStrategy::Truncate { .. } | RemovalStrategy::StructuralRemove
                ) {
                    reshaped.push(item.path.clone());
                }
            }
            Err(EditError::Refused(r)) => out.refused.push(r),
            Err(EditError::Locked(_)) => {
                out.skipped.push(MSG_LOCKED.to_string());
                break;
            }
            Err(e) => out.skipped.push(e.to_string()),
        }
    }
    out
}

/// Write one deattributed copy per file in `plan` through the same writer as
/// `clean --deattribute`, and verify each copy written. An archive is
/// rebuilt from the files inside it; the plan's dry run already found
/// something to blank there, so a write that finds nothing means the archive
/// changed since. Every failure names the file by its display path under
/// `root`, and a panic in one file's write fails that file alone. Copies that
/// land under `root` are scanned here, so the view lists them without
/// reading anything on the input thread.
pub fn write_copies(plan: &Plan, root: &Path) -> CopiesOutcome {
    let mode = plan.mode();
    let mut out = CopiesOutcome::default();
    let mut registry: Option<Registry> = None;
    let mut saved = |out: &mut CopiesOutcome, path: &Path, output: PathBuf, edits, ok: bool| {
        if !ok {
            out.unverified.push(app::display_under(root, &output));
        }
        if app::under_root(root, &output) {
            let registry = registry.get_or_insert_with(crate::parsers::registry);
            let report = scan::scan_file(&output, registry);
            out.copies.push((path.to_path_buf(), report));
        }
        out.saved.push(SavedItem {
            path: path.to_path_buf(),
            output,
            edits,
        });
    };
    let mut by_file: Vec<(&PlanItem, Vec<deattribute::Target>)> = Vec::new();
    for item in &plan.items {
        let shown = app::display_under(root, &item.path);
        if let Some(archive) = &item.archive {
            let wrote = guarded(|| {
                deattribute::deattribute_archive_mode(&item.path, archive.kind, false, mode)
            });
            match wrote {
                Ok(Ok(done)) if done.entries_cleaned > 0 => {
                    let ok = guarded(|| {
                        deattribute::verify_archive_copy(&done.output, archive.kind, mode)
                    })
                    .is_ok_and(|v| v.ok());
                    saved(
                        &mut out,
                        &item.path,
                        done.output,
                        done.brand + done.patch,
                        ok,
                    );
                }
                Ok(Ok(_)) => out.failed.push(format!("{shown}: changed since scan")),
                Ok(Err(e)) => out
                    .failed
                    .push(format!("{shown}: {}", app::edit_error_reason(&e))),
                Err(()) => out.failed.push(format!("{shown}: unsafe edit")),
            }
            continue;
        }
        let (Some(hash), Some(kind)) = (item.expected_hash.clone(), item.credit) else {
            continue;
        };
        let target = deattribute::Target {
            kind,
            marker: item.marker.clone(),
            expected_hash: hash,
            replacement: item.replacement.clone(),
        };
        match by_file
            .iter_mut()
            .find(|(first, _)| first.path == item.path)
        {
            Some((_, targets)) => targets.push(target),
            None => by_file.push((item, vec![target])),
        }
    }
    for (first, targets) in by_file {
        let shown = app::display_under(root, &first.path);
        let format = first.format.as_deref();
        let wrote =
            guarded(|| deattribute::write_deattributed(&first.path, format, first.size, &targets));
        match wrote {
            Ok(Ok(output)) => {
                let ok = guarded(|| {
                    deattribute::verify_copy(&first.path, &output, format, &targets, mode)
                })
                .is_ok_and(|v| v.ok());
                saved(&mut out, &first.path, output, targets.len(), ok);
            }
            Ok(Err(e)) => out
                .failed
                .push(format!("{shown}: {}", app::edit_error_reason(&e))),
            Err(()) => out.failed.push(format!("{shown}: unsafe edit")),
        }
    }
    out
}

/// The files a scrub batch saved, in the order they were first edited, each
/// with how many of its edits landed.
pub fn scrub_items(out: &BatchOutcome) -> Vec<SavedItem> {
    let mut items: Vec<SavedItem> = Vec::new();
    for (_, path) in &out.applied {
        match items.iter_mut().find(|i| &i.path == path) {
            Some(item) => item.edits += 1,
            None => items.push(SavedItem {
                path: path.clone(),
                output: path.clone(),
                edits: 1,
            }),
        }
    }
    items
}

/// The status line after an undo run.
pub fn undo_status(r: &UndoReport) -> (String, Tone) {
    let n = r.reverted;
    let mut text = match (&r.failure, n) {
        (None, 0) if r.never_landed == 0 => "Nothing to undo".to_string(),
        (None, 0) => format!(
            "Cleared {} {} that were never written",
            r.never_landed,
            app::plural(r.never_landed, "edit", "edits")
        ),
        (None, n) => format!("Undid {n} {}", app::plural(n, "edit", "edits")),
        (Some(e), 0) => format!("Undo stopped: {e}"),
        (Some(e), n) => format!(
            "Undid {n} {}, then stopped: {e}",
            app::plural(n, "edit", "edits")
        ),
    };
    if r.unparsed_lines > 0 {
        text.push_str(&format!(
            " ({} unreadable journal {} left in place)",
            r.unparsed_lines,
            app::plural(r.unparsed_lines, "line", "lines")
        ));
    }
    text.push('.');
    let tone = match (&r.failure, n) {
        (Some(_), _) => Tone::Warn,
        (None, 0) => Tone::Info,
        (None, _) => Tone::Good,
    };
    (text, tone)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::model::{
        Category, Confidence, ContainerKind, Evidence, FileReport, Finding, JunkKind, Marker,
        Region, Severity, TamperKind,
    };
    use crate::tui::keymap::Key;
    use ratatui::crossterm::event::KeyModifiers;

    #[test]
    fn deattribute_writes_a_copy_and_leaves_the_original() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invented.exe");
        let mut bytes = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00".to_vec();
        bytes.resize(256, 0);
        bytes.extend_from_slice(b"patched by Invented\0");
        std::fs::write(&path, &bytes).unwrap();
        let report = scan::scan_file(&path, &crate::parsers::registry());
        let mut app = App::new(dir.path());
        app.push_reports(vec![report]);
        app.scan_done();
        let plan = app.deattribute_plan().unwrap();

        let out = write_copies(&plan, dir.path());
        assert!(out.failed.is_empty(), "{:?}", out.failed);
        assert!(out.unverified.is_empty(), "{:?}", out.unverified);
        let saved = &out.saved;
        assert_eq!(saved.len(), 1);
        assert_eq!(
            saved[0].output,
            dir.path().join("invented.deattributed.exe")
        );
        assert_eq!(std::fs::read(&path).unwrap(), bytes, "original untouched");
        let copy = std::fs::read(&saved[0].output).unwrap();
        assert_eq!(copy.len(), bytes.len());
        assert!(!copy.windows(10).any(|w| w == b"patched by"));
        assert_eq!(out.copies.len(), 1, "the copy is scanned on the worker");
        assert_eq!(out.copies[0].0, path);
        assert_eq!(out.copies[0].1.path, saved[0].output);
    }

    fn patched_exe(dir: &Path) -> (PathBuf, Vec<u8>) {
        let path = dir.join("invented.exe");
        let mut bytes = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00".to_vec();
        bytes.resize(256, 0);
        bytes.extend_from_slice(b"patched by Invented\0");
        std::fs::write(&path, &bytes).unwrap();
        (path, bytes)
    }

    #[test]
    fn a_replacement_target_writes_its_own_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let (path, bytes) = patched_exe(dir.path());
        let report = scan::scan_file(&path, &crate::parsers::registry());
        let mut app = App::new(dir.path());
        app.push_reports(vec![report]);
        app.scan_done();
        let mut plan = app.deattribute_plan().unwrap();
        let item = &mut plan.items[0];
        let region = item.marker.region;
        let len = usize::try_from(region.len).unwrap();
        item.replacement = Some(vec![b'Z'; len]);

        let out = write_copies(&plan, dir.path());
        assert!(out.failed.is_empty(), "{:?}", out.failed);
        assert_eq!(out.saved.len(), 1);
        let copy = std::fs::read(&out.saved[0].output).unwrap();
        let at = usize::try_from(region.offset).unwrap();
        assert_eq!(&copy[at..at + len], vec![b'Z'; len].as_slice());
        assert_eq!(copy.len(), bytes.len());
        assert_eq!(std::fs::read(&path).unwrap(), bytes, "original untouched");
    }

    /// Wait for the background job to land, as the frame loop does.
    fn settle(rt: &mut Runtime) -> bool {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Some(planned) = rt.drain_job() {
                return planned;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("the job finished");
    }

    #[test]
    fn deattribute_plans_and_writes_off_the_input_thread() {
        use ratatui::crossterm::event::KeyCode;
        let dir = tempfile::tempdir().unwrap();
        let (path, bytes) = patched_exe(dir.path());
        let report = scan::scan_file(&path, &crate::parsers::registry());
        let mut app = App::new(dir.path());
        app.push_reports(vec![report]);
        app.scan_done();
        let mut rt = Runtime::new(app, Look::vivid());

        rt.key(KeyEvent::from(KeyCode::Char('a')));
        assert_eq!(rt.app.busy, Some(Busy::Planning));
        assert!(settle(&mut rt), "a plan arrived");
        assert!(rt.app.busy.is_none());
        assert_eq!(rt.app.context(), "confirm");
        rt.key(KeyEvent::from(KeyCode::Char('y')));
        assert_eq!(rt.app.context(), "confirm", "not drawn yet, so y waits");

        rt.app.confirm_drawn = true;
        rt.key(KeyEvent::from(KeyCode::Char('y')));
        assert_eq!(rt.app.busy, Some(Busy::Writing));
        assert_eq!(rt.app.status.as_ref().unwrap().text, "Writing copies...");
        assert!(!settle(&mut rt), "the copies were written");
        assert!(rt.app.busy.is_none());
        let copy = dir.path().join("invented.deattributed.exe");
        assert_eq!(
            rt.app.status.as_ref().unwrap().text,
            "Saved invented.deattributed.exe beside invented.exe."
        );
        assert_eq!(rt.app.saved(&path).unwrap().output, copy);
        assert_eq!(rt.app.copy_of(&copy), Some(path.as_path()));
        assert!(rt.app.has_report(&copy));
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert!(rt.writer.is_none(), "the writer was joined");
    }

    fn finding(sig: &str, sev: Severity, marker: Marker) -> Finding {
        Finding {
            category: if sig.contains("overlay") {
                Category::Tamper(TamperKind::AppendedData)
            } else {
                Category::Junk(JunkKind::Comment)
            },
            confidence: Confidence::Strong,
            severity: sev,
            signature_id: sig.to_string(),
            title: sig.to_string(),
            evidence: Evidence::at(marker.region.offset),
            marker: Some(marker),
        }
    }

    /// The whole confirm path on real files: plan, apply as one group, rescan
    /// targets, undo the group.
    #[test]
    fn a_scrub_marks_its_file_and_undo_clears_it() {
        let state = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let data: Vec<u8> = (0..400u32).map(|i| (i % 251) as u8 + 1).collect();
        let a = work.path().join("a.bin");
        std::fs::write(&a, &data).unwrap();
        let mut ra = FileReport::new(a.clone(), 400);
        ra.findings = vec![
            finding(
                "x.comment",
                Severity::Notice,
                Marker::blank(Region::new(40, 8), ContainerKind::Raw),
            ),
            finding(
                "x.other",
                Severity::Notice,
                Marker::blank(Region::new(80, 8), ContainerKind::Raw),
            ),
        ];
        let mut app = App::new(work.path());
        app.push_reports(vec![ra]);
        app.scan_done();
        let mut rt = Runtime::new(app, Look::vivid());
        rt.engine = Some(EditEngine::open_in(state.path()).unwrap());

        let plan = rt.app.scrub_plan().unwrap();
        rt.apply_plan(plan);
        let saved = rt.app.saved(&a).expect("marked");
        assert_eq!(saved.kind, app::SavedKind::Scrubbed);
        assert_eq!(saved.edits, 2);
        assert_eq!(saved.output, a);
        assert_eq!(
            rt.app.status.as_ref().unwrap().text,
            "Saved a.bin (2 edits). Press u to undo."
        );
        assert!(rt.app.has_report(&a), "rescanned, mark kept");

        rt.undo();
        assert!(rt.app.saved(&a).is_none(), "undo clears the mark");
        assert_eq!(std::fs::read(&a).unwrap(), data);
    }

    #[test]
    fn scrub_items_count_edits_per_file() {
        let out = BatchOutcome {
            ok: 3,
            applied: vec![
                (PathBuf::from("c/a"), PathBuf::from("a")),
                (PathBuf::from("c/b"), PathBuf::from("b")),
                (PathBuf::from("c/a"), PathBuf::from("a")),
            ],
            ..BatchOutcome::default()
        };
        let items = scrub_items(&out);
        assert_eq!(items.len(), 2);
        assert_eq!(
            (items[0].path.as_path(), items[0].edits),
            (Path::new("a"), 2)
        );
        assert_eq!(items[1].output, PathBuf::from("b"));
    }

    #[test]
    fn a_confirmed_batch_lands_as_one_undo_group() {
        let state = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let data: Vec<u8> = (0..400u32).map(|i| (i % 251) as u8 + 1).collect();
        let a = work.path().join("a.bin");
        let b = work.path().join("b.bin");
        std::fs::write(&a, &data).unwrap();
        std::fs::write(&b, &data).unwrap();

        let mut ra = FileReport::new(a.clone(), 400);
        ra.findings = vec![
            finding(
                "x.comment",
                Severity::Notice,
                Marker::blank(Region::new(40, 8), ContainerKind::Raw),
            ),
            finding(
                "x.overlay",
                Severity::Warn,
                Marker::truncate_at(300, ContainerKind::Raw),
            ),
            finding(
                "x.tail",
                Severity::Notice,
                Marker::truncate_at(350, ContainerKind::Raw),
            ),
        ];
        let mut rb = FileReport::new(b.clone(), 400);
        rb.findings = vec![finding(
            "x.comment",
            Severity::Notice,
            Marker::blank(Region::new(0, 8), ContainerKind::Raw),
        )];
        let mut app = App::new(work.path());
        app.push_reports(vec![ra, rb]);
        app.scan_done();
        app.on_action(Key::Space);
        app.on_action(Key::Down);
        app.on_action(Key::Space);
        let plan = app.scrub_plan().unwrap();
        // a: blank then the earliest cut; b: offset 0 is refused.
        assert_eq!(plan.items.len(), 3, "{:?}", plan.items);

        let mut engine = EditEngine::open_in(state.path()).unwrap();
        let out = run_plan(&mut engine, &plan);
        assert_eq!(out.ok, 2, "{out:?}");
        assert_eq!(out.refused.len(), 1);
        assert!(out.skipped.is_empty());
        assert_eq!(out.touched, vec![a.clone()]);
        let now = std::fs::read(&a).unwrap();
        assert_eq!(now.len(), 300);
        assert!(now[40..48].iter().all(|&x| x == 0));
        assert_eq!(std::fs::read(&b).unwrap(), data, "refused item left alone");
        let status = app::batch_status(plan.kind, out.ok, &out.skipped, &out.refused);
        assert_eq!(status.text, "Scrubbed 2 markers; refused 1.");

        assert_eq!(engine.undo_last().unwrap(), 2, "one group");
        assert_eq!(std::fs::read(&a).unwrap(), data);
    }

    #[test]
    fn a_second_reshape_in_one_batch_waits_for_the_rescan() {
        let state = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let p = work.path().join("c.bin");
        std::fs::write(&p, vec![7u8; 200]).unwrap();
        let mut engine = EditEngine::open_in(state.path()).unwrap();
        let item = |m: Marker| app::PlanItem {
            path: p.clone(),
            format: None,
            size: 200,
            label: "t".into(),
            title: "t".into(),
            risk: crate::edit::assess(None, 200, &m),
            marker: m,
            expected_hash: None,
            replacement: None,
            credit: None,
            archive: None,
        };
        let plan = Plan {
            kind: PlanKind::Scrub,
            items: vec![
                item(Marker::truncate_at(150, ContainerKind::Raw)),
                item(Marker::truncate_at(100, ContainerKind::Raw)),
            ],
            weak_left_out: 0,
            private_skips: Vec::new(),
            caveats: Vec::new(),
            replaces: Vec::new(),
            scroll: 0,
        };
        let out = run_plan(&mut engine, &plan);
        assert_eq!(out.ok, 1);
        assert_eq!(out.skipped.len(), 1);
        assert!(out.skipped[0].contains("rescan"));
        assert_eq!(std::fs::metadata(&p).unwrap().len(), 150);
    }

    #[test]
    fn drain_scan_counts_up_then_learns_the_total() {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut rt = Runtime::new(App::new("root"), Look::vivid());
        rt.scan_rx = Some(rx);
        let found = |name: &str| {
            ScanEvent::Found(Box::new(scan::Scanned {
                report: FileReport::new(PathBuf::from("root").join(name), 1),
                error: None,
            }))
        };
        tx.send(found("a")).unwrap();
        tx.send(found("b")).unwrap();
        assert!(rt.drain_scan());
        assert_eq!(rt.app.total, None);
        assert_eq!(rt.app.scan_line(), "Scanning 2 files...");
        assert!(!rt.drain_scan(), "nothing new");

        tx.send(ScanEvent::Total(1_101_278)).unwrap();
        assert!(rt.drain_scan(), "the total alone is a change");
        assert_eq!(rt.app.total, Some(1_101_278));
        assert_eq!(rt.app.scan_line(), "Scanning 2 of 1,101,278 files...");

        tx.send(found("c")).unwrap();
        tx.send(ScanEvent::Done).unwrap();
        assert!(rt.drain_scan());
        assert!(rt.scan_rx.is_none());
        assert!(!rt.app.scanning);
        assert_eq!(rt.app.scan_line(), "Scanned 3 files. No findings.");
    }

    #[test]
    fn a_dropped_scan_still_ends() {
        let (tx, rx) = std::sync::mpsc::channel::<ScanEvent>();
        let mut rt = Runtime::new(App::new("root"), Look::vivid());
        rt.scan_rx = Some(rx);
        drop(tx);
        assert!(rt.drain_scan());
        assert!(!rt.app.scanning);
    }

    fn type_path(rt: &mut Runtime, dir: &Path) {
        use ratatui::crossterm::event::KeyCode;
        // Clear whatever the picker starts with, then type the folder with a
        // trailing separator so its "Scan this folder" row comes first.
        rt.key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        let typed = format!("{}{}", dir.display(), std::path::MAIN_SEPARATOR);
        for c in typed.chars() {
            assert!(rt.key(KeyEvent::from(KeyCode::Char(c))).is_none());
        }
    }

    fn finish(rt: &mut Runtime) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while rt.app.scanning && Instant::now() < deadline {
            rt.drain_scan();
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(!rt.app.scanning, "the scan finished");
    }

    fn names(list: &[PathBuf]) -> Vec<String> {
        list.iter()
            .map(|p| {
                p.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect()
    }

    #[test]
    fn the_picker_starts_the_scan_in_place_and_reopens() {
        use ratatui::crossterm::event::KeyCode;
        let state = tempfile::tempdir().unwrap();
        let recent_file = state.path().join(RECENT_FILE);
        let work = tempfile::tempdir().unwrap();
        std::fs::write(work.path().join("one.bin"), b"hello").unwrap();
        std::fs::write(work.path().join("two.bin"), b"world").unwrap();
        let other = tempfile::tempdir().unwrap();
        std::fs::write(other.path().join("three.bin"), b"!").unwrap();

        let mut rt = Runtime::picking_at(Look::vivid(), recent_file.clone());
        assert!(rt.app.is_picking());
        assert!(rt.scan_rx.is_none(), "no scan before a folder is chosen");
        assert!(!rt.drain_scan());

        type_path(&mut rt, work.path());
        assert!(rt.scan_rx.is_none(), "typing scans nothing");
        assert!(!recent_file.exists(), "typing records nothing");
        assert!(rt.key(KeyEvent::from(KeyCode::Enter)).is_none());
        assert!(!rt.app.is_picking());
        assert!(rt.scan_rx.is_some(), "enter starts the scan");
        assert_eq!(rt.app.context(), "files");
        let first = names(&load_recent(&recent_file));
        assert_eq!(
            first,
            names(&[work.path().to_path_buf()]),
            "the pick is recorded"
        );

        finish(&mut rt);
        assert_eq!(rt.app.reports().len(), 2);
        assert_eq!(rt.app.total, Some(2), "the total came from the same walk");
        assert_eq!(rt.app.scan_line(), "Scanned 2 files. No findings.");

        // o opens the picker over the view; backing out changes nothing.
        rt.key(KeyEvent::from(KeyCode::Char('o')));
        assert!(rt.app.is_picking());
        for _ in 0..8 {
            if !rt.app.is_picking() {
                break;
            }
            rt.key(KeyEvent::from(KeyCode::Esc));
        }
        assert!(!rt.app.is_picking());
        assert!(!rt.app.should_quit);
        assert_eq!(rt.app.reports().len(), 2, "the view is unchanged");

        // A new pick replaces the view and goes first in the recent list.
        rt.key(KeyEvent::from(KeyCode::Char('o')));
        type_path(&mut rt, other.path());
        rt.key(KeyEvent::from(KeyCode::Enter));
        assert!(!rt.app.is_picking());
        assert!(rt.app.reports().is_empty(), "a fresh view");
        finish(&mut rt);
        assert_eq!(rt.app.reports().len(), 1);
        let both = names(&load_recent(&recent_file));
        assert_eq!(
            both,
            names(&[other.path().to_path_buf(), work.path().to_path_buf()])
        );
    }

    #[test]
    fn a_command_line_path_records_nothing() {
        let work = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let mut rt = Runtime::start(work.path(), Look::vivid());
        rt.recent_file = state.path().join(RECENT_FILE);
        assert!(!rt.app.is_picking());
        finish(&mut rt);
        assert!(!rt.recent_file.exists());
    }

    #[test]
    fn recent_picks_load_dedupe_and_cap() {
        let state = tempfile::tempdir().unwrap();
        let file = state.path().join("nested").join(RECENT_FILE);
        assert!(load_recent(&file).is_empty(), "missing file");

        let p = |s: &str| PathBuf::from(s);
        let mut list = Vec::new();
        for name in ["a", "b", "c", "b", "d", "e", "f"] {
            list = remember(&list, &p(name));
        }
        assert_eq!(list, [p("f"), p("e"), p("d"), p("b"), p("c")]);
        save_recent(&file, &list);
        assert_eq!(load_recent(&file), list, "round trip, parent created");

        std::fs::write(&file, b"{ not json").unwrap();
        assert!(load_recent(&file).is_empty(), "corrupt file");
        std::fs::write(&file, br#"["x", "x", "", "y"]"#).unwrap();
        assert_eq!(load_recent(&file), [p("x"), p("y")]);

        // A write that cannot land is ignored.
        let blocked = state.path().join("file-not-dir");
        std::fs::write(&blocked, b"").unwrap();
        save_recent(&blocked.join(RECENT_FILE), &list);
    }

    #[test]
    fn undo_status_reads_right() {
        let mut r = UndoReport::default();
        assert_eq!(undo_status(&r).0, "Nothing to undo.");
        r.reverted = 3;
        assert_eq!(undo_status(&r).0, "Undid 3 edits.");
        r.failure = Some(EditError::Changed);
        r.unparsed_lines = 1;
        let (text, tone) = undo_status(&r);
        assert!(
            text.starts_with("Undid 3 edits, then stopped: file changed"),
            "{text}"
        );
        assert!(
            text.ends_with("(1 unreadable journal line left in place)."),
            "{text}"
        );
        assert_eq!(tone, Tone::Warn);
    }
}
