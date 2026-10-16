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
pub use walk::{WalkEntry, WalkOpts};

/// The partial reason recorded when a probe (or identity) panicked.
pub const PROBE_PANICKED: &str = "probe panicked";

/// Options for a whole scan run.
#[derive(Debug, Clone, Default)]
pub struct ScanOpts {
    pub walk: WalkOpts,
}

/// A message from a running scan.
pub enum ScanEvent {
    /// One file finished; boxed to keep the channel message small.
    Found(Box<FileReport>),
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
/// walk ends. Reports arrive in walk order, `Total` arrives once when the walk
/// ends, and `Done` comes last. Dropping the receiver stops the scan: no new
/// files start, and the walk stops at its next entry. The handle finishes only
/// once the walker has stopped too.
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
            if tx.send(ScanEvent::Found(Box::new(item.report))).is_err() {
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

/// The walker thread of a streaming scan: feed every entry to the scan, then
/// send the total. A panic inside the walk ends it early; the entries fed so
/// far still count, so `Total` and `Done` always arrive.
fn walk_into(root: &Path, opts: &WalkOpts, feed: Feed, events: &Sender<ScanEvent>) {
    let mut fed = 0;
    let _ = catch_unwind(AssertUnwindSafe(|| {
        for entry in walk::walk_iter(root, opts) {
            if !feed.push(entry) {
                break;
            }
            fed += 1;
        }
    }));
    let _ = events.send(ScanEvent::Total(fed));
    // The scan sees the walk end only after `Total` is queued, so `Done`
    // always follows it.
    drop(feed);
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
    use std::time::Duration;

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
        let mut total = None;
        let mut done = false;
        for ev in events(dir.path()) {
            match ev {
                ScanEvent::Found(_) => found += 1,
                ScanEvent::Total(n) => total = Some(n),
                ScanEvent::Done => done = true,
            }
        }
        assert_eq!(found, 12);
        assert_eq!(total, Some(12));
        assert!(done);
    }

    #[test]
    fn scan_streams_walk_order_one_total_and_done_last() {
        let (dir, paths) = files(150);
        let evs = events(dir.path());
        let found: Vec<PathBuf> = evs
            .iter()
            .filter_map(|e| match e {
                ScanEvent::Found(r) => Some(r.path.clone()),
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
    fn scan_of_an_empty_folder_sends_total_zero_then_done() {
        let dir = tempfile::tempdir().unwrap();
        let evs = events(dir.path());
        assert!(matches!(
            evs.as_slice(),
            [ScanEvent::Total(0), ScanEvent::Done]
        ));
    }

    #[test]
    fn dropping_the_receiver_stops_the_scan() {
        let (dir, _) = files(400);
        let (rx, handle) = scan(dir.path(), ScanOpts::default());
        // `Total` may come first when the walk outruns the first report.
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
