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
//! Everything that reads or writes files for an action runs on a worker
//! thread: deattribute plans and copy writes, scrub and delete batches, and
//! undo. The engine travels to the worker with the job and comes back with
//! its result, so opening it, taking the lock and rescanning the touched
//! files never block the keyboard; while it is out, the keys that need it
//! wait. A worker reports progress as it goes (see `progress`), drawn as the
//! activity row, and checks between files whether Esc asked it to stop. A
//! plan is dropped at once; copies and edits end after the file they are
//! on. Keys typed while a plan was being built are dropped when it arrives
//! (Ctrl+C excepted), and `y` only confirms a modal that has been drawn, so
//! nothing queued ahead of a confirm can answer it. A quit while work runs
//! waits for it to stop; a second quit leaves at once. Work that writes and
//! is still running when the view ends some other way is waited for, with
//! "Finishing" on screen, so nothing is cut off halfway.
//!
//! The terminal is restored on every exit path: normal return, error return
//! and panic (`ratatui::try_init` installs a restoring panic hook). A panic
//! the per-file guard catches is not a crash, so it leaves the screen alone.

#![cfg(feature = "tui")]

use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers,
};
use ratatui::crossterm::execute;

use crate::edit::{EditEngine, EditError, Risk, UndoReport, deattribute};
use crate::model::{FileReport, RemovalStrategy};
use crate::scan::guard::{guarded, in_guard};
use crate::scan::{
    self, CountWalk, FileView, Registry, ScanEvent, ScanOpts, WalkOpts, WindowedFile,
};

use super::app::{
    self, App, Busy, CopiesOutcome, DeattributeRequest, Effect, HexView, MSG_LOCKED, Plan,
    PlanItem, PlanKind, SavedItem, SavedKind,
};
use super::bg::Pending;
use super::keymap::Key;
use super::listing::{Listing, MAX_READ};
use super::picker::{self, Picker, Request, Suggestion, same_path};
use super::progress::{Activity, Progress, Reporter, Silent};
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
    rt.finish_job(&mut terminal);
    restore_terminal();
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
/// confirm that has not been drawn yet. Ctrl+C is never lost this way: true
/// when one was among them, for the caller to act on.
fn flush_input() -> io::Result<bool> {
    let mut interrupt = false;
    while event::poll(Duration::ZERO)? {
        if let Event::Key(k) = event::read()?
            && k.kind != KeyEventKind::Release
            && Key::from_event(&k) == Some(Key::Interrupt)
        {
            interrupt = true;
        }
    }
    Ok(interrupt)
}

/// How long a picker read started this pass may hold the frame while the
/// list waits on it.
const PICKER_GRACE: Duration = Duration::from_millis(20);
/// Fewest printable keys in one input batch that count as a paste.
const BURST: usize = 3;

/// The reads the picker asked for, each on a worker of its own, so a slow
/// folder or a stalled drive never holds the screen or another read.
#[derive(Default)]
struct PickerIo {
    /// The folder listing on its way; a newer request replaces it.
    list: Option<(PathBuf, Pending<Listing>)>,
    /// Paths being looked up.
    stats: Vec<(PathBuf, Pending<picker::Found>)>,
    /// The count of the folder the picker shows.
    count: Option<(PathBuf, CountWalk)>,
}

impl PickerIo {
    fn start(&mut self, request: Request) {
        match request {
            Request::List(dir) => {
                let at = dir.clone();
                let read = Pending::spawn("meownary-list", move |_| Listing::read(&at, MAX_READ));
                self.list = Some((dir, read));
            }
            Request::Stat(path) => {
                let at = path.clone();
                let look = Pending::spawn("meownary-stat", move |_| picker::stat(&at));
                self.stats.push((path, look));
            }
            Request::Count(dir) => {
                let walk = scan::count(&dir, WalkOpts::default(), picker::COUNT_CAP);
                self.count = Some((dir, walk));
            }
            Request::StopCount => self.count = None,
        }
    }

    /// Hand the picker every finished read. A worker that ended without an
    /// answer reads as a folder that could not be listed, or a path that is
    /// not there. True when anything arrived.
    fn deliver(&mut self, picker: &mut Picker) -> bool {
        let mut changed = false;
        if let Some((dir, read)) = &mut self.list {
            if let Some(listing) = read.poll() {
                picker.on_listing(listing);
                self.list = None;
                changed = true;
            } else if read.is_done() {
                picker.on_listing(Listing {
                    location: dir.clone(),
                    items: Vec::new(),
                    error: Some(format!("Cannot open {}: the read failed.", dir.display())),
                    truncated: false,
                });
                self.list = None;
                changed = true;
            }
        }
        let mut k = 0;
        while k < self.stats.len() {
            let look = &mut self.stats[k].1;
            let found = match look.poll() {
                Some(found) => Some(found),
                None if look.is_done() => Some(picker::Found::Missing),
                None => None,
            };
            match found {
                Some(found) => {
                    let (path, _) = self.stats.swap_remove(k);
                    picker.on_stat(&path, found);
                    changed = true;
                }
                None => k += 1,
            }
        }
        if let Some((dir, walk)) = &self.count {
            let mut done = false;
            for delta in walk.try_iter() {
                done |= delta.done;
                picker.on_count(dir, &delta);
                changed = true;
            }
            if done {
                self.count = None;
            }
        }
        changed
    }
}

/// A run of at least [`BURST`] printable keys starting at `batch[at]`: a
/// paste on a terminal without bracketed paste, too fast to be typed. Key
/// releases inside it are skipped. Returns the text and the index after it.
fn burst_at(batch: &[Event], at: usize) -> Option<(String, usize)> {
    let mut text = String::new();
    let mut end = at;
    while let Some(ev) = batch.get(end) {
        match ev {
            Event::Key(k) if k.kind == KeyEventKind::Release => {}
            Event::Key(k) => match printable(k) {
                Some(c) => text.push(c),
                None => break,
            },
            _ => break,
        }
        end += 1;
    }
    (text.chars().count() >= BURST).then_some((text, end))
}

/// The character a key types, if it types one: no Ctrl or Alt alone (AltGr,
/// which arrives as both, types).
fn printable(k: &KeyEvent) -> Option<char> {
    let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
    let alt = k.modifiers.contains(KeyModifiers::ALT);
    match k.code {
        KeyCode::Char(c) if ctrl == alt && !c.is_control() => Some(c),
        _ => None,
    }
}

/// What a background job sends back: any number of progress reports, then
/// one result.
enum Job {
    /// How the work is going. Only the latest one counts.
    Progress(Activity),
    /// A deattribute plan was built, or why not.
    Planned(Result<Plan, String>),
    /// A confirmed deattribute plan's copies were written.
    Wrote {
        plan_skips: Vec<String>,
        out: CopiesOutcome,
    },
    /// A confirmed scrub or delete batch ran.
    Applied(Box<BatchDone>),
    /// The last batch was undone.
    Undone(Box<UndoDone>),
    /// The engine could not be opened or locked, so nothing ran.
    Refused(Box<Refusal>),
}

/// Files scanned again after an edit: a fresh report, or `None` when the
/// file is gone.
type Fresh = Vec<(PathBuf, Option<FileReport>)>;

/// What a scrub or delete batch did, with the engine handed back.
struct BatchDone {
    engine: EditEngine,
    kind: PlanKind,
    out: BatchOutcome,
    fresh: Fresh,
}

/// What an undo did, with the engine handed back.
struct UndoDone {
    engine: EditEngine,
    report: UndoReport,
    /// The restored files, as the view knows them.
    restored: Vec<PathBuf>,
    fresh: Fresh,
}

/// Why an edit job did not run, with the engine handed back when it opened.
struct Refusal {
    engine: Option<EditEngine>,
    text: String,
    tone: Tone,
}

/// A job running off the input thread.
struct Running {
    /// What it is doing.
    busy: Busy,
    /// Its progress reports, then its result.
    rx: Receiver<Job>,
    /// Set to ask it to stop between items.
    stop: Arc<AtomicBool>,
    /// Its thread, waited for at exit when the job writes.
    handle: JoinHandle<()>,
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
    /// The listing of the folder the files list shows, read off the input
    /// thread.
    listing: Option<(PathBuf, Pending<Listing>)>,
    engine: Option<EditEngine>,
    registry: Option<Registry>,
    /// Canonical paths the engine reported, mapped back to the view's paths.
    known: HashMap<PathBuf, PathBuf>,
    /// Where the recent picks are kept.
    recent_file: PathBuf,
    /// The picker's reads in flight.
    picker_io: PickerIo,
    /// Fixed places for the picker instead of the user's own (tests).
    places: Option<Vec<Suggestion>>,
    /// The job running off the input thread: a plan, a copy write, an edit
    /// batch or an undo.
    job: Option<Running>,
    /// The second of the clock last drawn while a job runs.
    last_second: u64,
    /// The animation frame last drawn.
    last_frame: u64,
}

impl Runtime {
    fn new(app: App, look: Look) -> Self {
        Self {
            app,
            look,
            started: Instant::now(),
            scan_rx: None,
            listing: None,
            engine: None,
            registry: None,
            known: HashMap::new(),
            recent_file: crate::util::paths::state_dir().join(RECENT_FILE),
            picker_io: PickerIo::default(),
            places: None,
            job: None,
            last_second: u64::MAX,
            last_frame: u64::MAX,
        }
    }

    /// Scan `path` from the first frame. The path is made absolute once, so
    /// every path the view keys on is built from that one spelling.
    fn start(path: &Path, look: Look) -> Self {
        let root = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
        let mut rt = Self::new(App::new(&root), look);
        rt.start_scan(&root);
        rt
    }

    /// Open on the picker; nothing is scanned yet.
    fn picking(look: Look) -> Self {
        Self::picking_at(look, crate::util::paths::state_dir().join(RECENT_FILE))
    }

    /// [`Runtime::picking`] with the recent picks kept in `recent_file`.
    fn picking_at(look: Look, recent_file: PathBuf) -> Self {
        Self::picking_over(look, recent_file, None)
    }

    /// [`Runtime::picking_at`], listing `places` instead of the user's own
    /// when given (tests never look at the real folders and drives).
    fn picking_over(look: Look, recent_file: PathBuf, places: Option<Vec<Suggestion>>) -> Self {
        let mut rt = Self::new(App::new(PathBuf::new()), look);
        rt.recent_file = recent_file;
        rt.places = places;
        let picker = rt.fresh_picker();
        rt.app = App::picking(picker);
        rt
    }

    /// A picker over the recent picks and the places: the user's own, or
    /// the fixed ones a test gave.
    fn fresh_picker(&self) -> Picker {
        let recent = self.recent();
        match &self.places {
            Some(places) => Picker::with_suggestions(places.clone(), recent),
            None => Picker::new(std::env::current_dir().ok(), recent),
        }
    }

    /// Start streaming a scan of `path` into the view, replacing any scan
    /// still running. One walk feeds both the reports and the total.
    fn start_scan(&mut self, path: &Path) {
        let (rx, _scan) = scan::scan(path, ScanOpts::default());
        self.scan_rx = Some(rx);
        self.listing = None;
    }

    /// The recent picks, newest first.
    fn recent(&self) -> Vec<PathBuf> {
        load_recent(&self.recent_file)
    }

    /// Show the picker over the view, starting at the current root.
    fn reopen_picker(&mut self) {
        let picker = self.fresh_picker().reopened_at(self.app.reopen_target());
        self.app.open_picker(picker);
    }

    /// The picker chose `path`: remember it and scan it. A job for the old
    /// view has nowhere to land, so it is asked to stop and let go (the
    /// picker cannot open while one runs, so this only guards).
    fn picked(&mut self, path: &Path) {
        self.picker_io = PickerIo::default();
        let list = remember(&self.recent(), path);
        save_recent(&self.recent_file, &list);
        if let Some(job) = self.job.take() {
            job.stop.store(true, Ordering::Relaxed);
        }
        self.start_scan(path);
    }

    /// Milliseconds since the view started: the animation clock.
    fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    fn event_loop(&mut self, terminal: &mut DefaultTerminal) -> io::Result<()> {
        let mut dirty = true;
        loop {
            dirty |= self.pump()?;
            let now = self.started.elapsed().as_millis() as u64;
            dirty |= self.tick_due(now);
            if dirty {
                self.app.anim_ms = now;
                terminal.draw(|f| ui::draw(f, &mut self.app, &self.look))?;
                dirty = false;
            }
            if self.app.should_quit {
                return Ok(());
            }
            if event::poll(Duration::from_millis(FRAME_MS))? {
                dirty |= self.dispatch(terminal)?;
            }
        }
    }

    /// Fold in whatever other threads finished since the last pass: scan
    /// results, folder listings, the picker's reads, a plan or copy write,
    /// and the hex window the detail view waits on. True when anything
    /// changed.
    fn pump(&mut self) -> io::Result<bool> {
        let mut dirty = self.drain_scan();
        dirty |= self.drain_listing();
        dirty |= self.drain_picker_io();
        match self.drain_job() {
            Some(true) => {
                if flush_input()? {
                    self.key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
                }
                dirty = true;
            }
            Some(false) => dirty = true,
            None => {}
        }
        if let Some((path, offset)) = self.app.hex_request() {
            self.load_hex(path, offset);
            dirty = true;
        }
        Ok(dirty)
    }

    /// Whether the clock alone calls for a redraw: the wordmark's next frame,
    /// or, while a job runs, the next second, even without animation, so the
    /// elapsed time on the activity row moves.
    fn tick_due(&mut self, now: u64) -> bool {
        let mut due = false;
        if self.app.busy.is_some() {
            let second = now / 1000;
            if second != self.last_second {
                self.last_second = second;
                due = true;
            }
        }
        // Progress bars move while a scan or a job runs, even when the
        // wordmark holds still.
        let bars = !self.look.mono && (self.app.busy.is_some() || self.app.scanning);
        if !self.look.animate && !bars {
            return due;
        }
        let frame = now / FRAME_MS;
        if frame == self.last_frame {
            return due;
        }
        self.last_frame = frame;
        true
    }

    /// Handle every event already queued, so a burst of keys lands before the
    /// next draw. True when the view should redraw.
    fn dispatch(&mut self, terminal: &mut DefaultTerminal) -> io::Result<bool> {
        let mut batch = vec![event::read()?];
        while event::poll(Duration::ZERO)? {
            batch.push(event::read()?);
        }
        let mut dirty = false;
        let mut at = 0;
        while at < batch.len() && !self.app.should_quit {
            let (changed, edit) = self.handle(&batch, &mut at);
            dirty |= changed;
            if let Some(path) = edit {
                self.open_editor(path, terminal)?;
            }
        }
        Ok(dirty)
    }

    /// Handle `batch[*at]`, or while the picker is up a burst of keys
    /// starting there, and move `at` past it. Returns whether the view
    /// changed and a file to open in the editor.
    fn handle(&mut self, batch: &[Event], at: &mut usize) -> (bool, Option<PathBuf>) {
        if self.app.is_picking()
            && let Some((text, next)) = burst_at(batch, *at)
        {
            self.app.picker_text(&text, true);
            *at = next;
            return (true, None);
        }
        let ev = &batch[*at];
        *at += 1;
        match ev {
            Event::Key(k) if k.kind != KeyEventKind::Release => (true, self.key(*k)),
            Event::Paste(text) if self.app.is_picking() => {
                self.app.picker_text(text, false);
                (true, None)
            }
            Event::Resize(..) => (true, None),
            _ => (false, None),
        }
    }

    /// Read the listing the files list asks for on a worker, and hand it
    /// over once it arrives. A listing for a folder the view has left is
    /// dropped, which asks its worker to stop. True when one arrived.
    fn drain_listing(&mut self) -> bool {
        let want = self.app.listing_request();
        if self
            .listing
            .as_ref()
            .is_some_and(|(at, _)| want.as_deref() != Some(at.as_path()))
        {
            self.listing = None;
        }
        if self.listing.is_none()
            && let Some(at) = want
        {
            let dir = at.clone();
            let read = Pending::spawn("meownary-listing", move |_| Listing::read(&dir, MAX_READ));
            self.listing = Some((at, read));
        }
        let Some((at, read)) = self.listing.as_mut() else {
            return false;
        };
        if let Some(listing) = read.poll() {
            self.listing = None;
            self.app.listing_ready(listing);
            return true;
        }
        if read.is_done() {
            let at = at.clone();
            self.listing = None;
            self.app.listing_failed(&at);
        }
        false
    }

    /// Start the reads the picker asked for and hand it whatever finished.
    /// A read started now gets up to [`PICKER_GRACE`] to land when the list
    /// waits on it, so a fast folder never flashes empty; a slow one shows
    /// its gauge instead. True when anything arrived.
    fn drain_picker_io(&mut self) -> bool {
        let Some(picker) = self.app.picker.as_mut() else {
            // The picker closed: stop whatever it was waiting on.
            self.picker_io = PickerIo::default();
            return false;
        };
        let mut changed = false;
        let mut deadline: Option<Instant> = None;
        loop {
            let requests = picker.take_requests();
            if !requests.is_empty() {
                deadline.get_or_insert_with(|| Instant::now() + PICKER_GRACE);
            }
            for r in requests {
                self.picker_io.start(r);
            }
            changed |= self.picker_io.deliver(picker);
            if picker.has_requests() {
                continue;
            }
            match deadline {
                Some(d) if picker.waiting() && Instant::now() < d => {
                    thread::sleep(Duration::from_millis(1));
                }
                _ => return changed,
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
                Ok(ScanEvent::Found(s)) => batch.push(*s),
                Ok(ScanEvent::Counted(d)) => {
                    self.app.counted(&d);
                    changed = true;
                }
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
            self.app.push_scanned(batch);
            changed = true;
        }
        if done {
            self.scan_rx = None;
            self.app.scan_done();
            changed = true;
        }
        changed
    }

    /// Fold in what the running job sent since the last pass: every queued
    /// message is taken, only the latest progress counts, and a result lands
    /// in the view. `None` when nothing arrived; `Some(true)` when a plan
    /// arrived, so the caller drops the keys queued meanwhile before the
    /// confirm is drawn.
    fn drain_job(&mut self) -> Option<bool> {
        let job = self.job.as_ref()?;
        let mut progress = None;
        let mut result = None;
        let mut closed = false;
        loop {
            match job.rx.try_recv() {
                Ok(Job::Progress(a)) => progress = Some(a),
                Ok(done) => {
                    result = Some(done);
                    break;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    closed = true;
                    break;
                }
            }
        }
        if let Some(done) = result {
            // The worker ends right after its result; it is never joined
            // here, so the keyboard never waits on it.
            self.job = None;
            return Some(self.land(done));
        }
        if closed {
            // The work panicked: the guard sent nothing, and any engine it
            // held was dropped with its lock. The next edit opens a new one.
            self.job = None;
            self.app.job_failed();
            return Some(false);
        }
        self.app.activity = Some(progress?);
        Some(false)
    }

    /// Put a job's result into the view. True when it was a plan.
    fn land(&mut self, done: Job) -> bool {
        match done {
            Job::Progress(a) => self.app.activity = Some(a),
            Job::Planned(plan) => {
                self.app.plan_ready(plan);
                return true;
            }
            Job::Wrote { plan_skips, out } => self.app.copies_written(&plan_skips, out),
            Job::Applied(done) => self.batch_landed(*done),
            Job::Undone(done) => self.undo_landed(*done),
            Job::Refused(r) => {
                let Refusal { engine, text, tone } = *r;
                if engine.is_some() {
                    self.engine = engine;
                }
                self.app.job_refused(text, tone);
            }
        }
        false
    }

    /// Run `work` on a worker thread named `name` while the view shows
    /// `busy`. The work reports through the [`Progress`] it is handed (at
    /// most 20 reports a second reach the view) and returns its result,
    /// which [`Runtime::drain_job`] takes. It runs inside the panic guard, so
    /// a panic neither prints over the view nor tears it down: it sends
    /// nothing, and the drain says so.
    fn spawn_job(
        &mut self,
        busy: Busy,
        name: &str,
        work: impl FnOnce(&mut dyn Progress) -> Job + Send + 'static,
    ) -> io::Result<()> {
        let (tx, rx) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let run = move || {
            let reports = tx.clone();
            let mut reporter = Reporter::new(flag, move |a| {
                let _ = reports.send(Job::Progress(a));
            });
            if let Ok(done) = guarded(|| work(&mut reporter)) {
                let _ = tx.send(done);
            }
        };
        let handle = thread::Builder::new().name(name.to_string()).spawn(run)?;
        self.app.begin_busy(busy);
        self.app.busy_since = self.now_ms();
        self.job = Some(Running {
            busy,
            rx,
            stop,
            handle,
        });
        Ok(())
    }

    /// Ask the running job to stop between items. A job the app already let
    /// go of (a plan is dropped at once) is let go here too: its result has
    /// nowhere to land.
    fn stop_job(&mut self) {
        if let Some(job) = &self.job {
            job.stop.store(true, Ordering::Relaxed);
        }
        if self.app.busy.is_none() {
            self.job = None;
        }
    }

    /// At exit, wait for a job that writes (copies, an edit batch, an undo)
    /// so nothing is cut off halfway: it is asked to stop after its current
    /// item, and the view shows "Finishing <file>..." until it has.
    fn finish_job(&mut self, terminal: &mut DefaultTerminal) {
        let Some(job) = self.exiting_job() else {
            return;
        };
        while let Ok(msg) = job.rx.try_recv() {
            if let Job::Progress(a) = msg {
                self.app.activity = Some(a);
            }
        }
        self.app.anim_ms = self.now_ms();
        let _ = terminal.draw(|f| ui::draw(f, &mut self.app, &self.look));
        let _ = job.handle.join();
    }

    /// The job to wait for at exit, asked to stop. A plan only reads, so it
    /// is never waited for, and neither is anything after a second quit
    /// request, which leaves at once.
    fn exiting_job(&mut self) -> Option<Running> {
        let job = self.job.take()?;
        job.stop.store(true, Ordering::Relaxed);
        if job.busy == Busy::Planning || self.app.quit_after {
            return None;
        }
        Some(job)
    }

    /// Build a deattribute plan on a worker; [`Runtime::drain_job`] offers it.
    fn spawn_plan(&mut self, req: DeattributeRequest) {
        let work = move |progress: &mut dyn Progress| {
            Job::Planned(app::plan_deattribute_with(&req, progress))
        };
        if let Err(e) = self.spawn_job(Busy::Planning, "meownary-plan", work) {
            self.app.plan_ready(Err(format!(
                "Could not start planning ({e}). Nothing changed."
            )));
        }
    }

    /// Write a confirmed deattribute plan's copies on a worker. The originals
    /// are only read, so nothing goes through the edit engine or the undo
    /// journal.
    fn spawn_writer(&mut self, plan: Plan) {
        let root = self.app.root.clone();
        let plan_skips = plan.private_skips.clone();
        let work = move |progress: &mut dyn Progress| Job::Wrote {
            plan_skips,
            out: write_copies_with(&plan, &root, progress),
        };
        if let Err(e) = self.spawn_job(Busy::Writing, "meownary-copies", work) {
            self.app.job_refused(
                format!("Saved nothing: the copy writer could not start ({e})."),
                Tone::Bad,
            );
        }
    }

    /// Run a confirmed scrub or delete batch on a worker. The worker takes
    /// the engine (or opens one), takes the lock, runs the batch as one undo
    /// group, lets go of the lock, scans the touched files again and hands
    /// everything back, engine included, so the input thread never reads a
    /// file after an edit.
    fn spawn_batch(&mut self, plan: Plan) {
        let busy = if plan.kind == PlanKind::Delete {
            Busy::Deleting
        } else {
            Busy::Scrubbing
        };
        let engine = self.engine.take();
        let work = move |progress: &mut dyn Progress| {
            let mut engine = match locked_engine(engine) {
                Ok(engine) => engine,
                Err(refusal) => return Job::Refused(refusal),
            };
            let out = run_plan_with(&mut engine, &plan, progress);
            engine.release_lock();
            let fresh = rescan_paths(&out.touched, progress);
            Job::Applied(Box::new(BatchDone {
                engine,
                kind: plan.kind,
                out,
                fresh,
            }))
        };
        if let Err(e) = self.spawn_job(busy, "meownary-edit", work) {
            self.app.job_refused(
                format!("Nothing changed: the edit could not start ({e})."),
                Tone::Bad,
            );
        }
    }

    /// Undo the last batch on a worker, which hands the engine back with the
    /// restored files already scanned again.
    fn spawn_undo(&mut self) {
        let engine = self.engine.take();
        let known = self.known.clone();
        let root = self.app.root.clone();
        let work = move |progress: &mut dyn Progress| {
            let mut engine = match locked_engine(engine) {
                Ok(engine) => engine,
                Err(refusal) => return Job::Refused(refusal),
            };
            let res = engine.undo_last_report();
            engine.release_lock();
            match res {
                Ok(report) => {
                    let restored = view_paths(&report.paths, &known, &root);
                    let fresh = rescan_paths(&restored, progress);
                    Job::Undone(Box::new(UndoDone {
                        engine,
                        report,
                        restored,
                        fresh,
                    }))
                }
                Err(EditError::Locked(_)) => {
                    Job::Refused(refusal(Some(engine), MSG_LOCKED, Tone::Warn))
                }
                Err(e) => Job::Refused(refusal(
                    Some(engine),
                    format!("Undo failed: {e}."),
                    Tone::Bad,
                )),
            }
        };
        if let Err(e) = self.spawn_job(Busy::Undoing, "meownary-undo", work) {
            self.app
                .job_refused(format!("Undo could not start ({e})."), Tone::Bad);
        }
    }

    /// A scrub or delete batch came back: take the engine back, say what
    /// landed, and fold in the rescanned files.
    fn batch_landed(&mut self, done: BatchDone) {
        let BatchDone {
            engine,
            kind,
            out,
            fresh,
        } = done;
        self.engine = Some(engine);
        self.known.extend(out.applied.iter().cloned());
        self.app.end_busy();
        let items = if kind == PlanKind::Scrub {
            scrub_items(&out)
        } else {
            Vec::new()
        };
        if items.is_empty() {
            self.app.status = Some(app::batch_status(kind, out.ok, &out.skipped, &out.refused));
        } else {
            self.app
                .record_saved(SavedKind::Scrubbed, &items, &out.skipped, &out.refused);
        }
        if out.stopped {
            self.app.status = Some(app::stopped_status(
                kind,
                out.ok,
                out.not_run,
                &out.skipped,
                &out.refused,
            ));
        }
        self.app.clear_job_picks();
        self.apply_fresh(fresh);
    }

    /// An undo came back: take the engine back, say what it did, and fold in
    /// the restored files.
    fn undo_landed(&mut self, done: UndoDone) {
        let UndoDone {
            engine,
            report,
            restored,
            fresh,
        } = done;
        self.engine = Some(engine);
        self.app.end_busy();
        let (text, tone) = undo_status(&report);
        self.app.set_status(text, tone);
        for path in &restored {
            self.app.clear_scrubbed(path);
        }
        self.apply_fresh(fresh);
    }

    /// Fold rescanned files into the view: a fresh report replaces the old,
    /// and a file that is gone leaves the list.
    fn apply_fresh(&mut self, fresh: Fresh) {
        for (path, report) in fresh {
            match report {
                Some(report) => self.app.replace_report(report),
                None => self.app.remove_report(&path),
            }
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
            Effect::Undo => self.spawn_undo(),
            Effect::Stop => self.stop_job(),
            Effect::Scan(path) => self.picked(&path),
            Effect::Pick => self.reopen_picker(),
        }
        None
    }

    /// Open the engine if needed and take the lock, for the editor, which
    /// runs on this thread anyway. On failure the reason is in the status
    /// line and the editor does not open.
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

    /// Carry out a confirmed plan off the input thread: a deattribute plan
    /// writes copies, a scrub or delete runs as one undo group.
    fn apply_plan(&mut self, plan: Plan) {
        if matches!(plan.kind, PlanKind::Deattribute | PlanKind::DeepDeattribute) {
            self.spawn_writer(plan);
        } else {
            self.spawn_batch(plan);
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

    /// Re-scan one file and replace its report (or drop it when it is gone),
    /// after the editor closes.
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
        if !out.iter().any(|q| same_path(q, &p)) && out.len() < RECENT_MAX {
            out.push(p);
        }
    }
    out
}

/// `list` with `picked` moved to the front, without duplicates (ignoring
/// case on Windows), at most [`RECENT_MAX`] long.
pub fn remember(list: &[PathBuf], picked: &Path) -> Vec<PathBuf> {
    let mut out = vec![picked.to_path_buf()];
    out.extend(list.iter().filter(|p| !same_path(p, picked)).cloned());
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

/// The engine a job was handed, or a fresh one, with the lock taken. When
/// either step fails, why, with the engine handed back when it opened.
fn locked_engine(engine: Option<EditEngine>) -> Result<EditEngine, Box<Refusal>> {
    let mut engine = match engine {
        Some(engine) => engine,
        None => EditEngine::new().map_err(|e| {
            refusal(
                None,
                format!("Read-only: the trash store could not be opened ({e})."),
                Tone::Bad,
            )
        })?,
    };
    match engine.acquire_lock() {
        Ok(()) => Ok(engine),
        Err(EditError::Locked(_)) => Err(refusal(Some(engine), MSG_LOCKED, Tone::Warn)),
        Err(e) => Err(refusal(Some(engine), format!("Read-only: {e}."), Tone::Bad)),
    }
}

fn refusal(engine: Option<EditEngine>, text: impl Into<String>, tone: Tone) -> Box<Refusal> {
    Box::new(Refusal {
        engine,
        text: text.into(),
        tone,
    })
}

/// The view's paths for canonical paths the journal reported: through
/// `known`, or by their place under `root`, canonicalized once. Paths outside
/// the view are left out.
fn view_paths(canon: &[PathBuf], known: &HashMap<PathBuf, PathBuf>, root: &Path) -> Vec<PathBuf> {
    let root_c = crate::edit::canonical_path(root).ok();
    canon
        .iter()
        .filter_map(|c| {
            if let Some(p) = known.get(c) {
                return Some(p.clone());
            }
            let root_c = root_c.as_deref()?;
            if c.as_path() == root_c {
                return Some(root.to_path_buf());
            }
            c.strip_prefix(root_c).ok().map(|rel| root.join(rel))
        })
        .collect()
}

/// Scan each of `paths` again for the view, reporting each to `progress`.
fn rescan_paths(paths: &[PathBuf], progress: &mut dyn Progress) -> Fresh {
    if paths.is_empty() {
        return Vec::new();
    }
    progress.rescan(paths.len());
    let mut registry: Option<Registry> = None;
    let mut fresh = Vec::with_capacity(paths.len());
    for path in paths {
        progress.item(path, 1);
        let report = std::fs::symlink_metadata(path).is_ok().then(|| {
            let registry = registry.get_or_insert_with(crate::parsers::registry);
            scan::scan_file(path, registry)
        });
        fresh.push((path.clone(), report));
    }
    progress.end();
    fresh
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
    /// The batch stopped early at the user's request.
    pub stopped: bool,
    /// Edits a stop left untried (refused ones not counted).
    pub not_run: usize,
}

/// What one edit weighs on the activity bar: a fixed share for the journal
/// record every edit writes, plus the bytes it may copy into the trash.
fn edit_weight(item: &PlanItem) -> u64 {
    const RECORD: u64 = 64 * 1024;
    let bytes = match item.marker.removal {
        RemovalStrategy::RawBlank { .. } => item.marker.region.len,
        RemovalStrategy::Truncate { from } => item.size.saturating_sub(from),
        RemovalStrategy::StructuralRemove | RemovalStrategy::DeleteFile => item.size,
    };
    RECORD.saturating_add(bytes)
}

/// Apply a confirmed plan as one undo group, with `force` (the confirm was
/// the user's go-ahead). Refused items are skipped. Once an edit changes a
/// file's length, its later items are skipped too: their scan-time offsets
/// no longer hold, and the rescan offers them again.
pub fn run_plan(engine: &mut EditEngine, plan: &Plan) -> BatchOutcome {
    run_plan_with(engine, plan, &mut Silent)
}

/// [`run_plan`], reporting each edit to `progress`. A stop request is
/// honored only between files, so every edit of a file lands together.
pub fn run_plan_with(
    engine: &mut EditEngine,
    plan: &Plan,
    progress: &mut dyn Progress,
) -> BatchOutcome {
    let mut out = BatchOutcome::default();
    out.skipped.extend(plan.private_skips.iter().cloned());
    let weights: Vec<u64> = plan.items.iter().map(edit_weight).collect();
    let total = weights.iter().fold(0u64, |a, &w| a.saturating_add(w));
    progress.begin(plan.items.len(), total);
    engine.begin_group();
    let mut reshaped: HashSet<PathBuf> = HashSet::new();
    let mut touched: HashSet<PathBuf> = HashSet::new();
    let mut last: Option<&Path> = None;
    for (k, (item, &weight)) in plan.items.iter().zip(&weights).enumerate() {
        if last != Some(item.path.as_path()) {
            if progress.stop_requested() {
                out.stopped = true;
                out.not_run = plan.items[k..]
                    .iter()
                    .filter(|i| !matches!(i.risk, Risk::Refuse(_)))
                    .count();
                break;
            }
            last = Some(item.path.as_path());
        }
        progress.item(&item.path, weight);
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
        if touched.insert(item.path.clone()) {
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
                    reshaped.insert(item.path.clone());
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
    progress.end();
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
    write_copies_with(plan, root, &mut Silent)
}

/// [`write_copies`], reporting each copy to `progress` as it is written:
/// the archives first, then the plain files, each weighing its size. A stop
/// request is honored between copies, so none is cut off halfway.
pub fn write_copies_with(plan: &Plan, root: &Path, progress: &mut dyn Progress) -> CopiesOutcome {
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
    let mut archives: Vec<&PlanItem> = Vec::new();
    let mut by_file: Vec<(&PlanItem, Vec<deattribute::Target>)> = Vec::new();
    let mut slot: HashMap<&Path, usize> = HashMap::new();
    for item in &plan.items {
        if item.archive.is_some() {
            archives.push(item);
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
        match slot.get(item.path.as_path()) {
            Some(&k) => by_file[k].1.push(target),
            None => {
                slot.insert(item.path.as_path(), by_file.len());
                by_file.push((item, vec![target]));
            }
        }
    }
    let total = archives.len() + by_file.len();
    let weight = archives
        .iter()
        .map(|i| i.size)
        .chain(by_file.iter().map(|(i, _)| i.size))
        .fold(0u64, |a, w| a.saturating_add(w));
    progress.begin(total, weight);
    let mut started = 0;
    for item in archives {
        let Some(archive) = &item.archive else {
            continue;
        };
        if progress.stop_requested() {
            break;
        }
        started += 1;
        progress.item(&item.path, item.size);
        let shown = app::display_under(root, &item.path);
        {
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
        }
    }
    for (first, targets) in by_file {
        if progress.stop_requested() {
            break;
        }
        started += 1;
        progress.item(&first.path, first.size);
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
    if started < total {
        out.stopped = true;
        out.not_written = total - started;
    }
    progress.end();
    out
}

/// The files a scrub batch saved, in the order they were first edited, each
/// with how many of its edits landed.
pub fn scrub_items(out: &BatchOutcome) -> Vec<SavedItem> {
    let mut items: Vec<SavedItem> = Vec::new();
    let mut slot: HashMap<&Path, usize> = HashMap::new();
    for (_, path) in &out.applied {
        match slot.get(path.as_path()) {
            Some(&k) => items[k].edits += 1,
            None => {
                slot.insert(path.as_path(), items.len());
                items.push(SavedItem {
                    path: path.clone(),
                    output: path.clone(),
                    edits: 1,
                });
            }
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

    /// A Macintosh resource fork whose one `STR#` string is a copyright line,
    /// under the resource name `Glimmer Glow`, and the same fork inside an
    /// AppleDouble file. All names invented.
    fn resource_forks() -> (Vec<u8>, Vec<u8>) {
        let text = b"\xa9 2024 Glimmer Labs";
        let mut data = ((text.len() + 3) as u32).to_be_bytes().to_vec();
        data.extend_from_slice(&1u16.to_be_bytes());
        data.push(text.len() as u8);
        data.extend_from_slice(text);
        // The map: header copy and handles, then the type list at 28, one
        // reference after it and the name list at 50.
        let mut map = vec![0u8; 24];
        for v in [28u16, 50, 0] {
            map.extend_from_slice(&v.to_be_bytes());
        }
        map.extend_from_slice(b"STR#");
        for v in [0u16, 10, 128, 0] {
            map.extend_from_slice(&v.to_be_bytes());
        }
        map.extend_from_slice(&[0; 8]);
        map.extend_from_slice(b"\x0cGlimmer Glow");
        let mut fork = Vec::new();
        for v in [0x100, 0x100 + data.len(), data.len(), map.len()] {
            fork.extend_from_slice(&(v as u32).to_be_bytes());
        }
        fork.resize(0x100, 0);
        fork.extend_from_slice(&data);
        fork.extend_from_slice(&map);
        let mut double = vec![0, 5, 0x16, 7, 0, 2, 0, 0];
        double.resize(24, 0);
        double.extend_from_slice(&1u16.to_be_bytes());
        for v in [2u32, 38, fork.len() as u32] {
            double.extend_from_slice(&v.to_be_bytes());
        }
        double.extend_from_slice(&fork);
        (fork, double)
    }

    #[test]
    fn deep_deattribute_writes_verified_copies_of_resource_forks() {
        let dir = tempfile::tempdir().unwrap();
        let (fork, double) = resource_forks();
        let registry = crate::parsers::registry();
        let mut reports = Vec::new();
        for (name, bytes) in [("Glow.rsrc", &fork), ("._Glow.dll", &double)] {
            let path = dir.path().join(name);
            std::fs::write(&path, bytes).unwrap();
            app_picks(&mut reports, scan::scan_file(&path, &registry));
        }
        let formats: Vec<Option<&str>> = reports.iter().map(|r| r.format.as_deref()).collect();
        assert_eq!(formats, [Some("appledouble"), Some("rsrc")]);
        let mut app = App::new(dir.path());
        let paths: Vec<PathBuf> = reports.iter().map(|r| r.path.clone()).collect();
        app.push_reports(reports);
        app.scan_done();
        app.picked_files.extend(paths);
        assert!(
            app.deattribute_plan().is_err(),
            "the basic pass has nothing to blank in a resource fork"
        );

        let plan = app.deattribute_plan_mode(deattribute::Mode::Deep).unwrap();
        assert_eq!(plan.kind, PlanKind::DeepDeattribute);
        assert_eq!(plan.items.len(), 2, "one rewrite in each file");
        assert!(plan.items.iter().all(|item| item.replacement.is_some()));
        assert!(
            plan.private_skips
                .iter()
                .any(|s| s.ends_with("(functional name kept)")),
            "{:?}",
            plan.private_skips
        );

        let out = write_copies(&plan, dir.path());
        assert!(out.failed.is_empty(), "{:?}", out.failed);
        assert!(out.unverified.is_empty(), "{:?}", out.unverified);
        assert_eq!(out.saved.len(), 2);
        for item in &out.saved {
            let copy = std::fs::read(&item.output).unwrap();
            let has = |needle: &[u8]| copy.windows(needle.len()).any(|w| w == needle);
            assert!(!has(b"2024 Glimmer Labs"), "{}", item.output.display());
            assert!(has(b"Glimmer Glow"), "the resource name is kept");
        }
    }

    /// Keep `reports` sorted by path, the order the view holds them in.
    fn app_picks(reports: &mut Vec<FileReport>, report: FileReport) {
        let at = reports.partition_point(|r| r.path < report.path);
        reports.insert(at, report);
    }

    /// Wait until the running job has landed and the view is free again, as
    /// the frame loop does. True when a plan arrived on the way.
    fn settle(rt: &mut Runtime) -> bool {
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut planned = false;
        while rt.app.busy.is_some() {
            assert!(Instant::now() < deadline, "the job finished");
            planned |= rt.drain_job() == Some(true);
            std::thread::sleep(Duration::from_millis(2));
        }
        planned
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
        assert!(rt.job.is_none(), "the writer's job ended");
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
        assert_eq!(rt.app.busy, Some(Busy::Scrubbing), "off the input thread");
        assert!(rt.engine.is_none(), "the engine went with the job");
        settle(&mut rt);
        let saved = rt.app.saved(&a).expect("marked");
        assert_eq!(saved.kind, app::SavedKind::Scrubbed);
        assert_eq!(saved.edits, 2);
        assert_eq!(saved.output, a);
        assert_eq!(
            rt.app.status.as_ref().unwrap().text,
            "Saved a.bin (2 edits). Press u to undo."
        );
        assert!(rt.app.has_report(&a), "rescanned, mark kept");

        rt.spawn_undo();
        assert_eq!(rt.app.busy, Some(Busy::Undoing));
        settle(&mut rt);
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

        tx.send(ScanEvent::Counted(scan::CountDelta::default()))
            .unwrap();
        assert!(rt.drain_scan(), "folder counts are a change");

        tx.send(ScanEvent::Total(1_101_278)).unwrap();
        assert!(rt.drain_scan(), "the total alone is a change");
        assert_eq!(rt.app.total, Some(1_101_278));
        assert_eq!(rt.app.scan_line(), "Scanning 2 of 1,101,278 files");

        tx.send(found("c")).unwrap();
        tx.send(ScanEvent::Done).unwrap();
        assert!(rt.drain_scan());
        assert!(rt.scan_rx.is_none());
        assert!(!rt.app.scanning);
        assert_eq!(rt.app.scan_line(), "Scanned 3 files. No findings.");
    }

    #[test]
    fn the_root_is_absolute_and_its_listing_arrives_off_the_input_thread() {
        let work = tempfile::tempdir().unwrap();
        std::fs::create_dir(work.path().join("empty")).unwrap();
        std::fs::create_dir(work.path().join("sub")).unwrap();
        std::fs::write(work.path().join("sub").join("a.bin"), b"x").unwrap();
        std::fs::write(work.path().join("top.bin"), b"y").unwrap();
        let mut rt = Runtime::start(work.path(), Look::vivid());
        assert!(rt.app.root.is_absolute());
        finish(&mut rt);
        let deadline = Instant::now() + Duration::from_secs(20);
        while !rt.drain_listing() {
            assert!(Instant::now() < deadline, "the listing arrived");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(rt.listing.is_none());
        assert_eq!(rt.app.listing_request(), None);
        let names: Vec<&str> = rt.app.rows().iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["empty", "sub", "top.bin"]);
        let empty = rt.app.rows()[0].clone();
        assert_eq!(
            rt.app.folder_state(&empty),
            crate::tui::explorer::FolderState::Empty
        );
        assert!(rt.app.has_subfolders());
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

    /// Paste `dir` into the picker and let its reads land.
    fn paste_path(rt: &mut Runtime, dir: &Path) {
        rt.app.picker_text(&dir.display().to_string(), false);
        settle_picker(rt);
        let shown = rt.app.picker.as_ref().and_then(|p| p.location());
        assert_eq!(shown, Some(dir));
    }

    /// Pump the picker's reads until the list waits on nothing.
    fn settle_picker(rt: &mut Runtime) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            rt.drain_picker_io();
            if rt.app.picker.as_ref().is_none_or(|p| !p.waiting()) {
                return;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        panic!("the picker's reads landed");
    }

    fn key_event(c: char) -> Event {
        Event::Key(KeyEvent::from(KeyCode::Char(c)))
    }

    #[test]
    fn a_burst_of_printable_keys_is_a_paste() {
        let release = {
            let mut k = KeyEvent::from(KeyCode::Char('a'));
            k.kind = KeyEventKind::Release;
            Event::Key(k)
        };
        let batch = [
            key_event('a'),
            release.clone(),
            key_event('b'),
            key_event('c'),
        ];
        assert_eq!(burst_at(&batch, 0), Some(("abc".to_string(), 4)));
        assert_eq!(burst_at(&batch[..3], 0), None, "two keys are typing");
        let enter = Event::Key(KeyEvent::from(KeyCode::Enter));
        let batch = [
            key_event('s'),
            key_event('/'),
            key_event('x'),
            enter.clone(),
        ];
        assert_eq!(burst_at(&batch, 0), Some(("s/x".to_string(), 3)));
        assert_eq!(burst_at(&batch, 3), None);
        let ctrl = Event::Key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        assert_eq!(burst_at(&[key_event('a'), ctrl, key_event('b')], 0), None);
        let altgr = KeyModifiers::CONTROL | KeyModifiers::ALT;
        let slash = Event::Key(KeyEvent::new(KeyCode::Char('\\'), altgr));
        let batch = [key_event('C'), key_event(':'), slash];
        assert_eq!(burst_at(&batch, 0), Some(("C:\\".to_string(), 3)));
    }

    #[test]
    fn a_pasted_burst_never_acts_as_keys() {
        let work = tempfile::tempdir().unwrap();
        std::fs::create_dir(work.path().join("sub")).unwrap();
        let app = App::picking(Picker::with_suggestions(Vec::new(), Vec::new()));
        let mut rt = Runtime::new(app, Look::vivid());
        paste_path(&mut rt, work.path());
        // "s" alone would scan; inside a burst it is prompt text.
        let batch = [key_event('s'), key_event('u'), key_event('b')];
        let mut at = 0;
        while at < batch.len() {
            rt.handle(&batch, &mut at);
        }
        assert!(rt.app.is_picking(), "nothing was scanned");
        let picker = rt.app.picker.as_ref().unwrap();
        assert_eq!(picker.prompt(), Some("sub"));
        // One key on its own is a command.
        let batch = [Event::Key(KeyEvent::from(KeyCode::Esc)), key_event('s')];
        let mut at = 0;
        while at < batch.len() {
            rt.handle(&batch, &mut at);
        }
        assert!(!rt.app.is_picking(), "s scanned the folder");
        assert!(rt.scan_rx.is_some());
    }

    #[test]
    fn the_picker_reads_and_counts_off_the_input_thread() {
        let work = tempfile::tempdir().unwrap();
        std::fs::create_dir(work.path().join("inner")).unwrap();
        std::fs::write(work.path().join("inner").join("a.bin"), b"a").unwrap();
        std::fs::write(work.path().join("b.bin"), b"b").unwrap();
        let app = App::picking(Picker::with_suggestions(Vec::new(), Vec::new()));
        let mut rt = Runtime::new(app, Look::vivid());
        paste_path(&mut rt, work.path());
        assert_eq!(rt.app.picker.as_ref().unwrap().entries().len(), 2);
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            rt.drain_picker_io();
            let p = rt.app.picker.as_ref().unwrap();
            if p.here_count().is_some_and(|c| !c.more) {
                assert_eq!(p.here_count().unwrap().files, 2);
                let inner = p.count_of(&work.path().join("inner")).unwrap();
                assert_eq!((inner.files, inner.more), (1, false));
                break;
            }
            assert!(Instant::now() < deadline, "the count finished");
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(rt.picker_io.count.is_none(), "a finished count is let go");
        // Closing the picker drops its reads.
        rt.app.picker = None;
        rt.drain_picker_io();
        assert!(rt.picker_io.list.is_none() && rt.picker_io.stats.is_empty());
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

        let mut rt = Runtime::picking_over(Look::vivid(), recent_file.clone(), Some(Vec::new()));
        assert!(rt.app.is_picking());
        assert!(rt.scan_rx.is_none(), "no scan before a folder is chosen");
        assert!(!rt.drain_scan());

        paste_path(&mut rt, work.path());
        assert!(rt.scan_rx.is_none(), "browsing scans nothing");
        assert!(!recent_file.exists(), "browsing records nothing");
        assert!(rt.key(KeyEvent::from(KeyCode::Char('s'))).is_none());
        assert!(!rt.app.is_picking());
        assert!(rt.scan_rx.is_some(), "s starts the scan");
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

        // o opens the picker over the view, at its folder; one esc backs
        // out and changes nothing.
        rt.key(KeyEvent::from(KeyCode::Char('o')));
        assert!(rt.app.is_picking());
        settle_picker(&mut rt);
        let shown = rt.app.picker.as_ref().and_then(|p| p.location());
        assert_eq!(shown, Some(work.path()));
        rt.key(KeyEvent::from(KeyCode::Esc));
        assert!(!rt.app.is_picking());
        assert!(!rt.app.should_quit);
        assert_eq!(rt.app.reports().len(), 2, "the view is unchanged");
        rt.drain_picker_io();
        assert!(rt.picker_io.list.is_none() && rt.picker_io.count.is_none());

        // A new pick replaces the view and goes first in the recent list.
        rt.key(KeyEvent::from(KeyCode::Char('o')));
        paste_path(&mut rt, other.path());
        rt.key(KeyEvent::from(KeyCode::Char('s')));
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
        if cfg!(windows) {
            // Windows paths ignore case, so neither list keeps both spellings.
            assert_eq!(
                remember(&[p("C:\\Games")], &p("c:\\games")),
                [p("c:\\games")]
            );
            std::fs::write(&file, br#"["C:\\A", "c:\\a", "y"]"#).unwrap();
            assert_eq!(load_recent(&file), [p("C:\\A"), p("y")]);
        }

        // A write that cannot land is ignored.
        let blocked = state.path().join("file-not-dir");
        std::fs::write(&blocked, b"").unwrap();
        save_recent(&blocked.join(RECENT_FILE), &list);
    }

    use crate::tui::progress::testing::StopAfter;

    /// Three small PEs with invented credits, scanned into a view.
    fn patched_view(dir: &Path, names: &[&str]) -> App {
        let registry = crate::parsers::registry();
        let mut reports = Vec::new();
        for name in names {
            let path = dir.join(name);
            let mut bytes = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00".to_vec();
            bytes.resize(256, 0);
            bytes.extend_from_slice(b"patched by Invented\0");
            std::fs::write(&path, &bytes).unwrap();
            reports.push(scan::scan_file(&path, &registry));
        }
        let mut app = App::new(dir);
        app.push_reports(reports);
        app.scan_done();
        app
    }

    #[test]
    fn copies_stop_between_files() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = patched_view(dir.path(), &["a.exe", "b.exe", "c.exe"]);
        for _ in 0..3 {
            app.on_action(Key::Space);
            app.on_action(Key::Down);
        }
        let plan = app.deattribute_plan().unwrap();
        let mut sink = StopAfter::new(2);
        let out = write_copies_with(&plan, dir.path(), &mut sink);
        assert_eq!(sink.began, Some((3, 3 * plan.items[0].size)));
        assert_eq!(sink.items.len(), 2);
        assert_eq!(sink.ends, 1);
        assert!(out.stopped);
        assert_eq!((out.saved.len(), out.not_written), (2, 1));
        assert!(!dir.path().join("c.deattributed.exe").exists());
    }

    /// A scrub plan with two edits in a.bin and one each in b.bin and c.bin.
    fn three_file_scrub(work: &Path) -> (Plan, Vec<u8>) {
        let data: Vec<u8> = (0..400u32).map(|i| (i % 251) as u8 + 1).collect();
        let mut reports = Vec::new();
        for (name, n) in [("a.bin", 2u64), ("b.bin", 1), ("c.bin", 1)] {
            let p = work.join(name);
            std::fs::write(&p, &data).unwrap();
            let mut r = FileReport::new(p, 400);
            r.findings = (0..n)
                .map(|k| {
                    finding(
                        &format!("x.c{k}"),
                        Severity::Notice,
                        Marker::blank(Region::new(40 + 40 * k, 8), ContainerKind::Raw),
                    )
                })
                .collect();
            reports.push(r);
        }
        let mut app = App::new(work);
        app.push_reports(reports);
        app.scan_done();
        for _ in 0..3 {
            app.on_action(Key::Space);
            app.on_action(Key::Down);
        }
        (app.scrub_plan().unwrap(), data)
    }

    #[test]
    fn a_batch_stops_only_between_files() {
        let state = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let (plan, data) = three_file_scrub(work.path());
        assert_eq!(plan.items.len(), 4);
        let mut engine = EditEngine::open_in(state.path()).unwrap();
        let mut sink = StopAfter::new(1);
        let out = run_plan_with(&mut engine, &plan, &mut sink);
        assert!(out.stopped);
        assert_eq!(out.ok, 2, "both edits of the first file land");
        assert_eq!(out.not_run, 2);
        assert_eq!(sink.items.len(), 2);
        assert_eq!(std::fs::read(work.path().join("b.bin")).unwrap(), data);
        assert_eq!(std::fs::read(work.path().join("c.bin")).unwrap(), data);
        let s = app::stopped_status(plan.kind, out.ok, out.not_run, &out.skipped, &out.refused);
        assert_eq!(
            s.text,
            "Stopped: scrubbed 2 markers; 2 left in place. Press u to undo."
        );
    }

    /// Whether a fresh engine over `state` can take the lock right now.
    fn lock_is_free(state: &Path) -> bool {
        let mut fresh = EditEngine::open_in(state).unwrap();
        let free = fresh.acquire_lock().is_ok();
        fresh.release_lock();
        free
    }

    #[test]
    fn edit_jobs_hand_the_engine_back() {
        let state = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let (plan, _) = three_file_scrub(work.path());
        let mut app = App::new(work.path());
        app.push_reports(
            ["a.bin", "b.bin", "c.bin"]
                .iter()
                .map(|n| FileReport::new(work.path().join(n), 400))
                .collect(),
        );
        app.scan_done();
        let mut rt = Runtime::new(app, Look::vivid());
        rt.engine = Some(EditEngine::open_in(state.path()).unwrap());

        // Scrub.
        rt.apply_plan(plan);
        settle(&mut rt);
        assert!(rt.engine.is_some(), "scrub handed the engine back");
        assert!(lock_is_free(state.path()));
        assert!(
            rt.app
                .status
                .as_ref()
                .unwrap()
                .text
                .starts_with("Saved a.bin")
        );

        // Delete, from the findings pane: the focus stays where it was.
        rt.app.pane = app::Pane::Findings;
        let b = work.path().join("b.bin");
        rt.app.picked_files.insert(b.clone());
        let plan = rt.app.delete_plan().unwrap();
        rt.apply_plan(plan);
        assert_eq!(rt.app.busy, Some(Busy::Deleting));
        settle(&mut rt);
        assert!(rt.engine.is_some(), "delete handed the engine back");
        assert!(lock_is_free(state.path()));
        assert!(!b.exists());
        assert!(!rt.app.has_report(&b), "the rescan dropped it");
        assert_eq!(rt.app.pane, app::Pane::Findings);
        assert!(
            rt.app.picked_files.is_empty(),
            "the job's picks are cleared"
        );

        // Undo brings it back, scanned again on the worker.
        rt.spawn_undo();
        settle(&mut rt);
        assert!(rt.engine.is_some(), "undo handed the engine back");
        assert!(lock_is_free(state.path()));
        assert!(b.exists());
        assert!(rt.app.has_report(&b));
        assert_eq!(rt.app.status.as_ref().unwrap().text, "Undid 1 edit.");
    }

    #[test]
    fn a_locked_engine_says_so() {
        let state = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let (plan, data) = three_file_scrub(work.path());
        let mut holder = EditEngine::open_in(state.path()).unwrap();
        holder.acquire_lock().unwrap();
        let mut rt = Runtime::new(App::new(work.path()), Look::vivid());
        rt.engine = Some(EditEngine::open_in(state.path()).unwrap());
        rt.app.picked_files.insert(work.path().join("a.bin"));
        rt.apply_plan(plan);
        settle(&mut rt);
        let s = rt.app.status.as_ref().unwrap();
        assert_eq!((s.text.as_str(), s.tone), (MSG_LOCKED, Tone::Warn));
        assert!(rt.engine.is_some(), "the engine came back unused");
        assert_eq!(rt.app.picked(), 1, "nothing ran, so the picks stay");
        assert_eq!(std::fs::read(work.path().join("a.bin")).unwrap(), data);
    }

    #[test]
    fn a_worker_panic_drops_the_engine() {
        let state = tempfile::tempdir().unwrap();
        let mut rt = Runtime::new(App::new("root"), Look::vivid());
        let mut engine = EditEngine::open_in(state.path()).unwrap();
        engine.acquire_lock().unwrap();
        rt.engine = Some(engine);
        assert!(!lock_is_free(state.path()));
        let engine = rt.engine.take();
        rt.spawn_job(Busy::Scrubbing, "meownary-test-panic", move |_| {
            let held = engine;
            if held.is_some() {
                panic!("the batch failed");
            }
            Job::Progress(Activity::default())
        })
        .unwrap();
        settle(&mut rt);
        assert!(rt.engine.is_none(), "the next edit opens a new one");
        assert!(lock_is_free(state.path()), "the lock went with it");
        let s = rt.app.status.as_ref().unwrap();
        assert!(s.text.contains("internal error"), "{}", s.text);
        assert_eq!(s.tone, Tone::Bad);
    }

    /// A job writing `n` invented copies, `ms` milliseconds each, that stops
    /// between them when asked.
    fn slow_job(rt: &mut Runtime, n: usize, ms: u64) {
        rt.spawn_job(Busy::Writing, "meownary-test-slow", move |progress| {
            progress.begin(n, n as u64);
            let mut out = CopiesOutcome::default();
            for i in 0..n {
                if progress.stop_requested() {
                    out.stopped = true;
                    out.not_written = n - i;
                    break;
                }
                progress.item(&PathBuf::from("root").join(format!("f{i:02}.bin")), 1);
                std::thread::sleep(Duration::from_millis(ms));
            }
            progress.end();
            Job::Wrote {
                plan_skips: Vec::new(),
                out,
            }
        })
        .unwrap();
    }

    #[test]
    fn pump_stays_responsive() {
        use ratatui::crossterm::event::KeyCode;
        let mut rt = Runtime::new(App::new("root"), Look::vivid());
        rt.app.scan_done();
        slow_job(&mut rt, 20, 50);
        let mut updates = 0;
        let mut last = None;
        let mut esc: Option<(Instant, usize)> = None;
        let deadline = Instant::now() + Duration::from_secs(20);
        while rt.app.busy.is_some() {
            assert!(Instant::now() < deadline, "the job ended");
            let t = Instant::now();
            rt.pump().unwrap();
            assert!(
                t.elapsed() < Duration::from_millis(50),
                "a pump took {:?}",
                t.elapsed()
            );
            let seen = rt.app.activity.as_ref().map(|a| a.ordinal());
            if seen.is_some() && seen != last {
                updates += 1;
                last = seen;
            }
            if updates >= 5 && esc.is_none() {
                esc = Some((Instant::now(), seen.unwrap_or(0)));
                rt.key(KeyEvent::from(KeyCode::Esc));
                assert!(rt.app.stopping, "esc stops instead of arming quit");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(updates >= 5, "{updates} progress updates");
        let (at, shown) = esc.expect("esc was pressed");
        assert!(
            at.elapsed() < Duration::from_millis(400),
            "stopped within an item, after {:?}",
            at.elapsed()
        );
        let text = &rt.app.status.as_ref().unwrap().text;
        assert_eq!(text, "Stopped. No copies were written.");
        assert!(shown < 20);
        assert!(!rt.app.should_quit);
    }

    #[test]
    fn the_drain_keeps_the_latest_progress_and_waits_for_the_result() {
        let (tx, rx) = mpsc::channel();
        let mut rt = Runtime::new(App::new("root"), Look::vivid());
        rt.app.begin_busy(Busy::Writing);
        let handle = thread::spawn(|| {});
        rt.job = Some(Running {
            busy: Busy::Writing,
            rx,
            stop: Arc::new(AtomicBool::new(false)),
            handle,
        });
        assert_eq!(rt.drain_job(), None, "nothing yet");
        for done in 1..=3 {
            let mut a = Activity::default();
            a.begin(5, 5);
            a.done = done;
            tx.send(Job::Progress(a)).unwrap();
        }
        assert_eq!(rt.drain_job(), Some(false));
        assert_eq!(rt.app.activity.as_ref().unwrap().done, 3, "the latest");
        assert!(rt.app.busy.is_some(), "progress is never the result");
        tx.send(Job::Wrote {
            plan_skips: Vec::new(),
            out: CopiesOutcome::default(),
        })
        .unwrap();
        assert_eq!(rt.drain_job(), Some(false));
        assert!(rt.app.busy.is_none() && rt.job.is_none());
    }

    #[test]
    fn quit_while_busy_stops_first_and_a_second_quit_forces() {
        use ratatui::crossterm::event::KeyCode;
        // A first quit stops the job and quits once it lands.
        let mut rt = Runtime::new(App::new("root"), Look::vivid());
        slow_job(&mut rt, 50, 20);
        rt.key(KeyEvent::from(KeyCode::Char('q')));
        assert!(!rt.app.should_quit && rt.app.stopping && rt.app.quit_after);
        settle(&mut rt);
        assert!(rt.app.should_quit, "quits once the job stopped");
        assert!(rt.exiting_job().is_none(), "nothing left to wait for");

        // A second quit leaves at once, without waiting for the job.
        let mut rt = Runtime::new(App::new("root"), Look::vivid());
        slow_job(&mut rt, 50, 20);
        rt.key(KeyEvent::from(KeyCode::Char('q')));
        rt.key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(rt.app.should_quit);
        assert!(rt.app.busy.is_some(), "the job is still out");
        assert!(rt.exiting_job().is_none(), "forced: not waited for");

        // A copy still running when the view ends some other way is waited
        // for, and asked to stop first; a plan never is.
        let mut rt = Runtime::new(App::new("root"), Look::vivid());
        slow_job(&mut rt, 50, 20);
        rt.app.should_quit = true;
        let job = rt.exiting_job().expect("a writer is waited for");
        assert!(job.stop.load(Ordering::Relaxed));
        job.handle.join().unwrap();
        let mut rt = Runtime::new(App::new("root"), Look::vivid());
        rt.spawn_job(Busy::Planning, "meownary-test-plan", |_| {
            Job::Planned(Err(String::new()))
        })
        .unwrap();
        assert!(rt.exiting_job().is_none());
    }

    #[test]
    fn esc_drops_a_plan_at_once() {
        use ratatui::crossterm::event::KeyCode;
        let mut rt = Runtime::new(App::new("root"), Look::vivid());
        rt.app.scan_done();
        rt.spawn_job(Busy::Planning, "meownary-test-plan", |progress| {
            while !progress.stop_requested() {
                std::thread::sleep(Duration::from_millis(2));
            }
            Job::Planned(Err(String::new()))
        })
        .unwrap();
        rt.key(KeyEvent::from(KeyCode::Esc));
        assert!(rt.app.busy.is_none(), "dropped at once");
        assert!(rt.job.is_none());
        assert_eq!(rt.app.status.as_ref().unwrap().text, app::MSG_NEVER_MIND);
    }

    #[test]
    fn a_running_bar_redraws_every_frame_even_without_animation() {
        let mut rt = Runtime::new(App::new("root"), Look::from_flags(false, true));
        rt.app.scanning = false;
        assert!(!rt.tick_due(0), "idle and still: nothing to draw");
        rt.app.busy = Some(Busy::Writing);
        assert!(rt.tick_due(10));
        assert!(!rt.tick_due(30), "the same frame");
        assert!(rt.tick_due(60), "the bar's next frame");
        rt.app.busy = None;
        rt.app.scanning = true;
        assert!(rt.tick_due(120), "a scan's bar moves too");
        // NO_COLOR has no rainbow to move: only the clock's second ticks.
        let mut mono = Runtime::new(App::new("root"), Look::from_flags(true, false));
        mono.app.busy = Some(Busy::Writing);
        assert!(mono.tick_due(10));
        assert!(!mono.tick_due(900));
        assert!(mono.tick_due(1000));
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
