//! The scan pipeline: a path becomes a stream of per-file reports. Identity is
//! resolved first, then every applicable probe runs under the per-file guard.
//!
//! Both entry points share one core, [`OrderedScan`]: each walked entry is
//! scanned as its own task on the rayon pool, and reports come out in walk
//! order through a bounded reorder buffer, so output is deterministic and
//! memory for finished reports stays flat no matter how many files there are.
//!
//! [`scan_ordered`] walks first and then scans, so [`OrderedScan::total`] is
//! known up front. [`scan`] streams for the interactive view instead: a walker
//! thread hands entries to the pool as the walk finds them, so the first report
//! arrives while the walk is still running, and the total is sent as
//! [`ScanEvent::Total`] the moment the walk ends. Either way the tree is walked
//! once.
//!
//! The streaming walker also counts entries per folder as it goes and sends
//! the counts as [`ScanEvent::Counted`] deltas. It runs well ahead of the
//! scanning, so folder totals arrive early too, and the last delta comes just
//! before the total. [`count`] runs the same walk on its own, only counting,
//! for the picker.

pub mod guard;
pub mod probe;
pub mod reader;
pub mod walk;

use std::collections::{BTreeMap, VecDeque};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread::{self, JoinHandle};

use crate::model::FileReport;
use crate::parsers;

pub use probe::{Probe, ProbeCtx, Registry};
pub use reader::{FileView, MemView, WindowedFile};
pub use walk::{CountDelta, Totals, WalkEntry, WalkOpts};

/// The partial reason recorded when a probe (or identity) panicked.
pub const PROBE_PANICKED: &str = "probe panicked";

/// Options for a whole scan run.
#[derive(Debug, Clone, Default)]
pub struct ScanOpts {
    pub walk: WalkOpts,
}

/// A message from a running scan.
pub enum ScanEvent {
    /// One file finished, with why it is partial when it is; boxed to keep
    /// the channel message small.
    Found(Box<Scanned>),
    /// The walk counted more entries: per folder since the last `Counted`,
    /// plus how far it has got. Sent every [`walk::COUNT_BATCH`] entries
    /// while the walk runs, usually well ahead of the reports, and once more,
    /// marked done, just before `Total`.
    Counted(CountDelta),
    /// The walk finished: this many entries will be reported in all. Sent
    /// exactly once, as soon as the walk ends, possibly before the
    /// remaining Found events.
    Total(usize),
    /// Every file is done.
    Done,
}

/// One scanned file: its report, plus why it is partial when it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scanned {
    pub report: FileReport,
    /// A short reason when `report.partial` is set (for example
    /// `permission denied` or [`PROBE_PANICKED`]); `None` otherwise.
    pub error: Option<String>,
}

impl Scanned {
    /// A partial report for something that could not be read at all.
    pub fn unreadable(path: &Path, reason: impl Into<String>) -> Self {
        let mut report = FileReport::new(path.to_path_buf(), 0);
        report.partial = true;
        Self {
            report,
            error: Some(reason.into()),
        }
    }
}

/// Scan one file: identity, then applicable probes, each guarded.
pub fn scan_file(path: &Path, registry: &Registry) -> FileReport {
    scan_file_detailed(path, registry).report
}

/// [`scan_file`], also returning why the report is partial when it is.
pub fn scan_file_detailed(path: &Path, registry: &Registry) -> Scanned {
    let view = match WindowedFile::open(path) {
        Ok(v) => v,
        // Unreadable: a real, reportable outcome, not a crash.
        Err(e) => return Scanned::unreadable(path, format!("cannot read: {}", walk::short_io(&e))),
    };

    let mut report = FileReport::new(path.to_path_buf(), view.size());
    let mut panicked = false;

    // Identity first; it names the format the other probes gate on.
    let (format, mut findings) = match guard::guarded(|| parsers::identify(&view)) {
        Ok(result) => result,
        Err(()) => {
            panicked = true;
            (None, Vec::new())
        }
    };
    report.format = format.map(str::to_string);
    let fmt = report.format.as_deref();

    for probe in registry {
        if !probe_applies(probe.as_ref(), fmt) {
            continue;
        }
        let ctx = ProbeCtx::new(&view, fmt);
        match guard::guarded(|| {
            let mut local = Vec::new();
            probe.run(&ctx, &mut local);
            local
        }) {
            Ok(mut local) => findings.append(&mut local),
            Err(()) => panicked = true,
        }
    }

    report.findings = findings;
    report.partial = panicked;
    Scanned {
        report,
        error: panicked.then(|| PROBE_PANICKED.to_string()),
    }
}

fn scan_entry(entry: &WalkEntry, registry: &Registry) -> Scanned {
    match entry {
        WalkEntry::File(path) => scan_file_detailed(path, registry),
        WalkEntry::Unreadable { path, reason } => Scanned::unreadable(path, reason.clone()),
    }
}

fn probe_applies(probe: &dyn Probe, fmt: Option<&str>) -> bool {
    let wanted = probe.formats();
    wanted.is_empty() || fmt.map(|f| wanted.contains(&f)).unwrap_or(false)
}

/// Start a streaming scan on a background thread, returning the event stream
/// and the thread handle. The walk runs on a thread of its own and every entry
/// is scanned as soon as the walk finds it, so `Found` events begin before the
/// walk ends. Reports arrive in walk order, count deltas arrive as the walk
/// goes (the last one, marked done, just before `Total`), `Total` arrives once
/// when the walk ends, and `Done` comes last. Dropping the receiver stops the
/// scan: no new files start, and the walk stops at its next entry. The handle
/// finishes only once the walker has stopped too.
pub fn scan(root: &Path, opts: ScanOpts) -> (Receiver<ScanEvent>, JoinHandle<()>) {
    let (tx, rx) = channel();
    let root = root.to_path_buf();
    let handle = thread::spawn(move || {
        let (mut scan, feed) = OrderedScan::streaming(parsers::registry());
        let walker = {
            let tx = tx.clone();
            thread::spawn(move || walk_into(&root, &opts.walk, feed, &tx))
        };
        let mut complete = true;
        for item in &mut scan {
            if tx.send(ScanEvent::Found(Box::new(item))).is_err() {
                complete = false;
                break;
            }
        }
        // Dropping the scan stops queued tasks and makes the walker's next
        // hand-off fail, which ends the walk.
        drop(scan);
        if complete {
            let _ = tx.send(ScanEvent::Done);
        }
        let _ = walker.join();
    });
    (rx, handle)
}

/// The walker thread of a streaming scan: feed every entry to the scan,
/// counting entries per folder on the way, then send the last count and the
/// total. A panic inside the walk ends it early; the entries fed so far still
/// count, so the last `Counted`, `Total` and `Done` always arrive.
fn walk_into(root: &Path, opts: &WalkOpts, feed: Feed, events: &Sender<ScanEvent>) {
    let mut fed = 0;
    let mut tally = walk::Tally::new(root);
    let mut dropped = false;
    let walked = catch_unwind(AssertUnwindSafe(|| {
        for entry in walk::walk_iter(root, opts) {
            // Counted before the hand-off takes the entry; a failed hand-off
            // means nobody is listening any more.
            tally.add(entry.path());
            if !feed.push(entry) {
                dropped = true;
                break;
            }
            fed += 1;
            if let Some(delta) = tally.take(false) {
                let _ = events.send(ScanEvent::Counted(delta));
            }
        }
    }));
    let stopped = dropped || walked.is_err();
    let _ = events.send(ScanEvent::Counted(tally.finish(stopped)));
    let _ = events.send(ScanEvent::Total(fed));
    // The scan sees the walk end only after `Total` is queued, so `Done`
    // always follows it.
    drop(feed);
}

/// A running [`count`]. Dropping it stops the count at its next entry.
pub struct CountWalk {
    rx: Receiver<CountDelta>,
    stop: Arc<AtomicBool>,
}

impl CountWalk {
    /// The next delta if one is ready, without waiting. The last one has
    /// `done` set; after it this is always `None`.
    pub fn try_recv(&self) -> Option<CountDelta> {
        self.rx.try_recv().ok()
    }

    /// Every delta ready now, oldest first, without waiting.
    pub fn try_iter(&self) -> impl Iterator<Item = CountDelta> + '_ {
        self.rx.try_iter()
    }
}

impl Drop for CountWalk {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Count the entries a scan of `root` would cover, on a thread of its own,
/// for the picker. It is the scan's own walk (sorted, the state dir left out,
/// links not followed, cloud placeholders and unreadable folders counted as
/// entries), and nothing is read beyond the folder listings. Deltas arrive
/// every [`walk::COUNT_BATCH`] entries and once more, marked done, at the
/// end. The count stops with `stopped` set when more than `cap` entries turn
/// up, and it stops when the returned [`CountWalk`] is dropped.
pub fn count(root: &Path, opts: WalkOpts, cap: usize) -> CountWalk {
    let (tx, rx) = channel();
    let stop = Arc::new(AtomicBool::new(false));
    let spawned = {
        let root = root.to_path_buf();
        let stop = Arc::clone(&stop);
        let tx = tx.clone();
        thread::Builder::new()
            .name("meownary-count".to_string())
            .spawn(move || count_into(&root, &opts, cap, &stop, &tx))
    };
    if spawned.is_err() {
        // No thread to count with: end the count at once, short.
        let _ = tx.send(CountDelta {
            done: true,
            stopped: true,
            ..CountDelta::default()
        });
    }
    CountWalk { rx, stop }
}

/// The body of [`count`]: walk and tally, sending deltas, until the walk
/// ends, `cap` entries are counted with more to come, or `stop` is set. The
/// last delta always goes out (unless nobody is listening).
fn count_into(
    root: &Path,
    opts: &WalkOpts,
    cap: usize,
    stop: &AtomicBool,
    tx: &Sender<CountDelta>,
) {
    let mut tally = walk::Tally::new(root);
    let mut counted = 0;
    let mut stopped = false;
    let walked = catch_unwind(AssertUnwindSafe(|| {
        for entry in walk::walk_iter(root, opts) {
            if counted >= cap || stop.load(Ordering::Relaxed) {
                stopped = true;
                break;
            }
            tally.add(entry.path());
            counted += 1;
            if let Some(delta) = tally.take(false)
                && tx.send(delta).is_err()
            {
                stopped = true;
                break;
            }
        }
    }));
    let _ = tx.send(tally.finish(stopped || walked.is_err()));
}

/// Convenience for tests and small callers: scan everything and return the
/// reports sorted by path. Holds every report; prefer [`scan_ordered`].
pub fn scan_all(root: &Path, opts: ScanOpts) -> Vec<FileReport> {
    let mut reports: Vec<FileReport> = scan_ordered(root, opts).map(|s| s.report).collect();
    reports.sort_by(|a, b| a.path.cmp(&b.path));
    reports
}

/// Walk `root` (sorted, see [`walk::walk`]), then scan the files in parallel
/// and yield them in walk order. The walk happens before this returns, so
/// [`OrderedScan::total`] is known up front.
pub fn scan_ordered(root: &Path, opts: ScanOpts) -> OrderedScan {
    OrderedScan::start(walk::walk(root, &opts.walk), parsers::registry())
}

/// How many files may be in flight or waiting ahead of the consumer, per pool
/// thread.
const AHEAD_PER_WORKER: usize = 8;
/// The smallest look-ahead window, so a few slow files do not stall the pool.
const MIN_AHEAD: usize = 32;

/// The partial reason for a panic the per-probe guards did not catch.
const INTERNAL_ERROR: &str = "internal error";

/// What an [`OrderedScan`] waits on: finished tasks and, when streaming, the
/// walker's entries. One channel carries both, so a single blocking receive
/// wakes for whichever comes first.
enum Msg {
    /// Entry `i` (in walk order) finished scanning.
    Finished(usize, Scanned),
    /// The walk found another entry.
    Entry(WalkEntry),
    /// The walk is over; no more entries will arrive.
    WalkEnd,
}

/// The walker's end of a streaming [`OrderedScan`]. Dropping it tells the scan
/// the walk is over, so the scan ends once every fed entry is done.
struct Feed {
    tx: Sender<Msg>,
}

impl Feed {
    /// Hand one walked entry to the scan. `false` when the scan was dropped,
    /// so the walk should stop.
    fn push(&self, entry: WalkEntry) -> bool {
        self.tx.send(Msg::Entry(entry)).is_ok()
    }
}

impl Drop for Feed {
    fn drop(&mut self) {
        let _ = self.tx.send(Msg::WalkEnd);
    }
}

/// An iterator over scanned files in walk order. Each file is scanned as its
/// own task on the rayon pool, and at most a fixed window of files is queued
/// or finished ahead of the one the consumer needs next, so the reorder buffer
/// stays small. Entries come either all at once from a finished walk
/// ([`scan_ordered`]) or one at a time from a walker thread while the scan
/// runs ([`scan`]); the window takes them as they arrive. Dropping it stops
/// every task that has not started yet, and a feeding walker stops at its next
/// entry.
pub struct OrderedScan {
    /// Walked entries not yet handed out, in walk order.
    backlog: VecDeque<WalkEntry>,
    /// Paths of the entries handed to the pool and not yet yielded, oldest
    /// (entry `next`) first.
    in_flight: VecDeque<PathBuf>,
    /// Whether the walk is over, so `backlog` holds everything left to hand
    /// out.
    walked: bool,
    /// How many entries this scan has received from the walk so far.
    seen: usize,
    registry: Arc<Registry>,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    pending: BTreeMap<usize, Scanned>,
    /// The next entry index to yield.
    next: usize,
    ahead: usize,
    stop: Arc<AtomicBool>,
    /// Scan on the caller's thread instead of the pool. Set when the caller is
    /// itself a pool thread, where blocking on results could starve the pool.
    inline: bool,
}

impl OrderedScan {
    /// Scan the entries of a finished walk; [`total`](Self::total) is final
    /// from the start.
    fn start(entries: Vec<WalkEntry>, registry: Registry) -> Self {
        let mut scan = Self::new(registry);
        scan.seen = entries.len();
        scan.backlog = entries.into();
        scan.walked = true;
        scan.fill();
        scan
    }

    /// Scan entries as a walker hands them over through the returned
    /// [`Feed`]; the scan ends once the feed is dropped and every fed entry
    /// is done.
    fn streaming(registry: Registry) -> (Self, Feed) {
        let scan = Self::new(registry);
        let feed = Feed {
            tx: scan.tx.clone(),
        };
        (scan, feed)
    }

    fn new(registry: Registry) -> Self {
        let (tx, rx) = channel();
        Self {
            backlog: VecDeque::new(),
            in_flight: VecDeque::new(),
            walked: false,
            seen: 0,
            registry: Arc::new(registry),
            tx,
            rx,
            pending: BTreeMap::new(),
            next: 0,
            ahead: (rayon::current_num_threads() * AHEAD_PER_WORKER).max(MIN_AHEAD),
            stop: Arc::new(AtomicBool::new(false)),
            inline: rayon::current_thread_index().is_some(),
        }
    }

    /// How many entries the walk produced (files plus unreadable entries).
    /// Final from the start for [`scan_ordered`]; while a streaming walk is
    /// still running, the count so far.
    pub fn total(&self) -> usize {
        self.seen
    }

    fn absorb(&mut self, msg: Msg) {
        match msg {
            Msg::Finished(i, item) => {
                self.pending.insert(i, item);
            }
            Msg::Entry(entry) => {
                self.seen += 1;
                self.backlog.push_back(entry);
            }
            Msg::WalkEnd => self.walked = true,
        }
    }

    /// Take in whatever has already arrived, without waiting, then top up the
    /// window.
    fn pump(&mut self) {
        while let Ok(msg) = self.rx.try_recv() {
            self.absorb(msg);
        }
        self.fill();
    }

    /// Queue tasks until the window ahead of the consumer is full or the
    /// backlog is empty.
    fn fill(&mut self) {
        if self.inline {
            return;
        }
        while self.in_flight.len() < self.ahead {
            let Some(entry) = self.backlog.pop_front() else {
                break;
            };
            let i = self.next + self.in_flight.len();
            self.in_flight.push_back(entry.path().to_path_buf());
            let registry = Arc::clone(&self.registry);
            let stop = Arc::clone(&self.stop);
            let tx = self.tx.clone();
            rayon::spawn(move || {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                // A closed channel means the consumer is gone; nothing to do.
                let _ = tx.send(Msg::Finished(i, scan_task(&entry, &registry)));
            });
        }
    }
}

/// Scan one entry. The whole task runs under the guard as well, so even a
/// panic outside the per-probe guards yields a report: the task always sends a
/// result, and nothing unwinds into the pool.
fn scan_task(entry: &WalkEntry, registry: &Registry) -> Scanned {
    guard::guarded(|| scan_entry(entry, registry))
        .unwrap_or_else(|()| Scanned::unreadable(entry.path(), INTERNAL_ERROR))
}

impl Iterator for OrderedScan {
    type Item = Scanned;

    fn next(&mut self) -> Option<Scanned> {
        loop {
            if self.inline {
                if let Some(entry) = self.backlog.pop_front() {
                    self.next += 1;
                    return Some(scan_task(&entry, &self.registry));
                }
            } else if let Some(item) = self.pending.remove(&self.next) {
                self.next += 1;
                self.in_flight.pop_front();
                self.pump();
                return Some(item);
            }
            if self.walked && self.backlog.is_empty() && self.in_flight.is_empty() {
                return None;
            }
            // Wait for a finished task or the walker's next message.
            match self.rx.recv() {
                Ok(msg) => {
                    self.absorb(msg);
                    self.pump();
                }
                // Unreachable while `self.tx` is alive; report the file rather
                // than drop it or block.
                Err(_) => {
                    let path = self.in_flight.pop_front()?;
                    self.next += 1;
                    return Some(Scanned::unreadable(&path, INTERNAL_ERROR));
                }
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let left = self.seen.saturating_sub(self.next);
        (left, self.walked.then_some(left))
    }
}

impl Drop for OrderedScan {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Finding;
    use std::fs;
    use std::time::{Duration, Instant};

    struct Panicker;

    impl Probe for Panicker {
        fn id(&self) -> &'static str {
            "panicker"
        }
        fn run(&self, ctx: &ProbeCtx, _out: &mut Vec<Finding>) {
            if ctx.view.size() == 3 {
                panic!("deliberate test panic");
            }
        }
    }

    fn files(n: usize) -> (tempfile::TempDir, Vec<PathBuf>) {
        let dir = tempfile::tempdir().unwrap();
        let mut paths = Vec::new();
        for i in 0..n {
            let p = dir.path().join(format!("f{i:04}.bin"));
            fs::write(&p, vec![b'x'; i % 7]).unwrap();
            paths.push(p);
        }
        (dir, paths)
    }

    fn unreadable(name: &str) -> WalkEntry {
        WalkEntry::Unreadable {
            path: PathBuf::from(name),
            reason: "cannot read: test".into(),
        }
    }

    /// Run a streaming scan to the end and return its events in order.
    fn events(root: &Path) -> Vec<ScanEvent> {
        let (rx, handle) = scan(root, ScanOpts::default());
        let got = rx.into_iter().collect();
        handle.join().unwrap();
        got
    }

    /// A tree with files at several depths, an empty folder, and more
    /// entries than one count delta holds, plus each folder's direct count.
    fn nested() -> (tempfile::TempDir, Vec<(PathBuf, usize)>) {
        let dir = tempfile::tempdir().unwrap();
        let layout = [
            (vec![], 100),
            (vec!["a"], 200),
            (vec!["a", "deep"], 150),
            (vec!["b"], 20),
            (vec!["empty"], 0),
        ];
        let mut folders = Vec::new();
        for (parts, n) in layout {
            let folder = parts
                .iter()
                .fold(dir.path().to_path_buf(), |p, s| p.join(s));
            fs::create_dir_all(&folder).unwrap();
            for i in 0..n {
                fs::write(folder.join(format!("f{i:03}.bin")), b"x").unwrap();
            }
            folders.push((folder, n));
        }
        (dir, folders)
    }

    /// Every delta a count sends, through the last one.
    fn count_all(counting: &CountWalk) -> Vec<CountDelta> {
        let mut got: Vec<CountDelta> = Vec::new();
        while !got.last().is_some_and(|d| d.done) {
            let wait = Duration::from_secs(30);
            got.push(counting.rx.recv_timeout(wait).expect("the count ends"));
        }
        got
    }

    #[test]
    fn ordered_scan_yields_walk_order() {
        let (dir, paths) = files(150);
        let scan = scan_ordered(dir.path(), ScanOpts::default());
        assert_eq!(scan.total(), 150);
        let got: Vec<PathBuf> = scan.map(|s| s.report.path).collect();
        assert_eq!(got, paths);
    }

    #[test]
    fn ordered_scan_reports_sizes_and_no_errors() {
        let (dir, _) = files(10);
        for s in scan_ordered(dir.path(), ScanOpts::default()) {
            assert!(!s.report.partial, "{:?}", s.report.path);
            assert_eq!(s.error, None);
            assert_eq!(s.report.size, fs::metadata(&s.report.path).unwrap().len());
        }
    }

    #[test]
    fn scanning_from_a_pool_thread_runs_inline() {
        let (dir, paths) = files(40);
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .unwrap();
        let got: Vec<PathBuf> = pool.install(|| {
            scan_ordered(dir.path(), ScanOpts::default())
                .map(|s| s.report.path)
                .collect()
        });
        assert_eq!(got, paths);
    }

    #[test]
    fn dropping_early_stops_cleanly() {
        let (dir, _) = files(200);
        let mut scan = scan_ordered(dir.path(), ScanOpts::default());
        assert!(scan.next().is_some());
        drop(scan);
    }

    #[test]
    fn empty_walk_yields_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut scan = scan_ordered(dir.path(), ScanOpts::default());
        assert_eq!(scan.total(), 0);
        assert!(scan.next().is_none());
    }

    #[test]
    fn unreadable_entries_become_partial_reports() {
        let entries = vec![WalkEntry::Unreadable {
            path: PathBuf::from("locked"),
            reason: "cannot list directory: permission denied".into(),
        }];
        let got: Vec<Scanned> = OrderedScan::start(entries, Vec::new()).collect();
        assert_eq!(got.len(), 1);
        assert!(got[0].report.partial);
        assert_eq!(got[0].report.size, 0);
        assert_eq!(
            got[0].error.as_deref(),
            Some("cannot list directory: permission denied")
        );
    }

    #[test]
    fn probe_panic_marks_the_file_partial() {
        let (dir, paths) = files(5);
        let registry: Registry = vec![Box::new(Panicker)];
        let entries = paths.iter().cloned().map(WalkEntry::File).collect();
        let got: Vec<Scanned> = OrderedScan::start(entries, registry).collect();
        assert_eq!(got.len(), 5);
        for s in &got {
            let size3 = s.report.size == 3;
            assert_eq!(s.report.partial, size3);
            assert_eq!(s.error.as_deref(), size3.then_some(PROBE_PANICKED));
        }
        drop(dir);
    }

    #[test]
    fn missing_file_is_a_partial_report() {
        let dir = tempfile::tempdir().unwrap();
        let s = scan_file_detailed(&dir.path().join("nope.bin"), &Vec::new());
        assert!(s.report.partial);
        assert_eq!(s.error.as_deref(), Some("cannot read: not found"));
    }

    #[test]
    fn streaming_scan_yields_before_the_walk_ends() {
        let (mut scan, feed) = OrderedScan::streaming(Vec::new());
        let (tx, rx) = channel();
        let consumer = thread::spawn(move || {
            for s in &mut scan {
                let _ = tx.send(s.report.path);
            }
            scan.total()
        });
        let wait = Duration::from_secs(30);
        assert!(feed.push(unreadable("a")));
        assert_eq!(rx.recv_timeout(wait).unwrap(), PathBuf::from("a"));
        assert!(feed.push(unreadable("b")));
        assert_eq!(rx.recv_timeout(wait).unwrap(), PathBuf::from("b"));
        drop(feed);
        assert_eq!(consumer.join().unwrap(), 2);
    }

    #[test]
    fn streaming_from_a_pool_thread_runs_inline() {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .unwrap();
        let got: Vec<PathBuf> = pool.install(|| {
            let (scan, feed) = OrderedScan::streaming(Vec::new());
            for name in ["a", "b", "c"] {
                assert!(feed.push(unreadable(name)));
            }
            drop(feed);
            scan.map(|s| s.report.path).collect()
        });
        assert_eq!(got, ["a", "b", "c"].map(PathBuf::from));
    }

    #[test]
    fn dropping_a_streaming_scan_stops_the_walker() {
        let (scan, feed) = OrderedScan::streaming(Vec::new());
        drop(scan);
        assert!(!feed.push(unreadable("a")));
    }

    #[test]
    fn scan_events_end_with_done() {
        let (dir, _) = files(12);
        let mut found = 0;
        let mut counted = Totals::new(dir.path(), None);
        let mut total = None;
        let mut done = false;
        for ev in events(dir.path()) {
            match ev {
                ScanEvent::Found(_) => found += 1,
                ScanEvent::Counted(d) => counted.apply(&d),
                ScanEvent::Total(n) => total = Some(n),
                ScanEvent::Done => done = true,
            }
        }
        assert_eq!(found, 12);
        assert_eq!(total, Some(12));
        assert_eq!(counted.total(), 12);
        assert!(counted.is_done() && !counted.was_stopped());
        assert!(done);
    }

    #[test]
    fn scan_streams_walk_order_one_total_and_done_last() {
        let (dir, paths) = files(150);
        let evs = events(dir.path());
        let found: Vec<PathBuf> = evs
            .iter()
            .filter_map(|e| match e {
                ScanEvent::Found(s) => Some(s.report.path.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(found, paths);
        let totals: Vec<usize> = evs
            .iter()
            .filter_map(|e| match e {
                ScanEvent::Total(n) => Some(*n),
                _ => None,
            })
            .collect();
        assert_eq!(totals, [150]);
        let dones = evs.iter().filter(|e| matches!(e, ScanEvent::Done)).count();
        assert_eq!(dones, 1);
        assert!(matches!(evs.last(), Some(ScanEvent::Done)));
    }

    #[test]
    fn scan_of_an_empty_folder_sends_an_empty_count_then_total_zero() {
        let dir = tempfile::tempdir().unwrap();
        let evs = events(dir.path());
        assert!(matches!(
            evs.as_slice(),
            [ScanEvent::Counted(d), ScanEvent::Total(0), ScanEvent::Done]
                if d.done && !d.stopped && d.dirs.is_empty() && d.frontier.is_none()
        ));
    }

    #[test]
    fn scan_counts_every_folder_before_the_total() {
        let (dir, folders) = nested();
        let root = dir.path();
        let evs = events(root);
        let (total_at, n) = evs
            .iter()
            .enumerate()
            .find_map(|(i, e)| match e {
                ScanEvent::Total(n) => Some((i, *n)),
                _ => None,
            })
            .unwrap();
        let mut totals = Totals::new(root, None);
        let mut deltas = 0;
        for (i, ev) in evs.iter().enumerate() {
            if let ScanEvent::Counted(d) = ev {
                assert!(i < total_at, "a count after the total");
                assert!(!totals.is_done(), "a count after the last one");
                totals.apply(d);
                deltas += 1;
            }
        }
        assert!(deltas > 1, "counts arrive while the walk runs");
        assert!(totals.is_done() && !totals.was_stopped());
        assert_eq!(n, 470);
        assert_eq!(totals.total(), n as u64);
        let found = evs
            .iter()
            .filter(|e| matches!(e, ScanEvent::Found(_)))
            .count();
        assert_eq!(found, n);
        for (folder, _) in &folders {
            let under: usize = folders
                .iter()
                .filter(|(f, _)| f.starts_with(folder))
                .map(|(_, direct)| direct)
                .sum();
            assert_eq!(totals.get(folder), (under > 0).then_some(under as u64));
            assert!(totals.is_final(folder));
        }
    }

    #[test]
    fn found_events_carry_why_a_file_is_partial() {
        let dir = tempfile::tempdir().unwrap();
        let gone = dir.path().join("gone");
        let evs = events(&gone);
        let found: Vec<&Scanned> = evs
            .iter()
            .filter_map(|e| match e {
                ScanEvent::Found(s) => Some(s.as_ref()),
                _ => None,
            })
            .collect();
        assert_eq!(found.len(), 1);
        assert!(found[0].report.partial);
        assert_eq!(found[0].error.as_deref(), Some("cannot read: not found"));
        let mut totals = Totals::new(&gone, None);
        for ev in &evs {
            if let ScanEvent::Counted(d) = ev {
                totals.apply(d);
            }
        }
        assert_eq!(totals.get(&gone), Some(1), "the root is its own entry");
    }

    #[test]
    fn count_matches_the_walk() {
        let (dir, folders) = nested();
        let root = dir.path();
        let counting = count(root, WalkOpts::default(), usize::MAX);
        let deltas = count_all(&counting);
        assert!(deltas.len() > 1, "counts arrive while the walk runs");
        assert_eq!(counting.try_recv(), None, "nothing after the last delta");
        let mut totals = Totals::new(root, None);
        for d in &deltas {
            totals.apply(d);
        }
        assert!(!totals.was_stopped());
        let walked = walk::walk(root, &WalkOpts::default());
        assert_eq!(totals.total(), walked.len() as u64);
        for (folder, _) in &folders {
            let under = walked
                .iter()
                .filter(|e| e.path().starts_with(folder))
                .count();
            assert_eq!(totals.get(folder).unwrap_or(0), under as u64);
        }
    }

    #[test]
    fn count_stops_at_its_cap() {
        let (dir, _) = files(50);
        let capped = count_all(&count(dir.path(), WalkOpts::default(), 10));
        let mut totals = Totals::new(dir.path(), None);
        for d in &capped {
            totals.apply(d);
        }
        assert_eq!(totals.total(), 10);
        assert!(totals.is_done() && totals.was_stopped());
        // A cap the walk never goes past leaves the count whole.
        let whole = count_all(&count(dir.path(), WalkOpts::default(), 50));
        assert!(whole.iter().all(|d| !d.stopped));
    }

    #[test]
    fn a_stopped_count_ends_at_its_next_entry() {
        let (dir, _) = files(20);
        let (tx, rx) = channel();
        let stop = AtomicBool::new(true);
        count_into(dir.path(), &WalkOpts::default(), usize::MAX, &stop, &tx);
        drop(tx);
        let got: Vec<CountDelta> = rx.into_iter().collect();
        assert_eq!(got.len(), 1);
        assert!(got[0].done && got[0].stopped);
        assert!(got[0].dirs.is_empty(), "nothing counted after the stop");
    }

    #[test]
    fn dropping_a_count_walk_stops_it() {
        let (dir, _) = files(300);
        let counting = count(dir.path(), WalkOpts::default(), usize::MAX);
        let stop = Arc::clone(&counting.stop);
        drop(counting);
        assert!(
            stop.load(Ordering::Relaxed),
            "the drop asks the count to stop"
        );
        // The count thread lets go of the flag once it has ended.
        let deadline = Instant::now() + Duration::from_secs(30);
        while Arc::strong_count(&stop) > 1 {
            assert!(Instant::now() < deadline, "the count thread ended");
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn dropping_the_receiver_stops_the_scan() {
        let (dir, _) = files(400);
        let (rx, handle) = scan(dir.path(), ScanOpts::default());
        // Counts and `Total` may come first when the walk outruns the first
        // report.
        loop {
            match rx.recv() {
                Ok(ScanEvent::Found(_)) => break,
                Ok(_) => {}
                Err(_) => panic!("scan ended before any file was found"),
            }
        }
        drop(rx);
        // Returns only once the scan thread and the walker have both stopped.
        handle.join().unwrap();
    }
}
