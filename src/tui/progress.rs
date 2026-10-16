//! Live progress for the work the view runs off the input thread: building a
//! deattribute plan, writing its copies, an edit batch, an undo. The work
//! reports through a [`Progress`] sink as it goes (how much there is, which
//! file it is on, the rescan after an edit) and checks the sink between
//! files for a request to stop. The view keeps the latest [`Activity`] and
//! draws it as the activity row.
//!
//! [`Reporter`] is the sink a worker gets: it keeps the running [`Activity`]
//! and hands a copy to a callback (the job channel) at most 20 times a
//! second, always on the start and the end, and at once when an item starts
//! that is a sizable share of the whole job, so the row names a long item
//! for as long as it runs. [`Silent`] reports nowhere and never stops, for
//! the plain wrappers and tests.

#![cfg(feature = "tui")]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// How a running job is doing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Activity {
    /// Items finished.
    pub done: usize,
    /// Items in all.
    pub total: usize,
    /// What the finished items weigh: roughly the bytes they read or wrote.
    pub done_weight: u64,
    /// What every item weighs together.
    pub total_weight: u64,
    /// The item being worked on, with its weight.
    pub current: Option<(PathBuf, u64)>,
    /// The work itself is done and the files it touched are being scanned
    /// again; the counts are the rescan's.
    pub rescanning: bool,
}

impl Activity {
    /// Work starts: `total` items weighing `total_weight` together.
    pub fn begin(&mut self, total: usize, total_weight: u64) {
        *self = Self {
            total,
            total_weight,
            ..Self::default()
        };
    }

    /// Work on `path`, weighing `weight`, starts; the item before it is done.
    pub fn item(&mut self, path: &Path, weight: u64) {
        self.finish_current();
        self.current = Some((path.to_path_buf(), weight));
    }

    /// The last item is done.
    pub fn end(&mut self) {
        self.finish_current();
    }

    /// The work is done; `total` touched files are scanned again next, each
    /// an item weighing 1.
    pub fn rescan(&mut self, total: usize) {
        *self = Self {
            total,
            total_weight: total as u64,
            rescanning: true,
            ..Self::default()
        };
    }

    fn finish_current(&mut self) {
        if let Some((_, weight)) = self.current.take() {
            self.done += 1;
            self.done_weight = self.done_weight.saturating_add(weight);
        }
    }

    /// The item the row counts: the one being worked on, or how many are
    /// done between items. Never past the total.
    pub fn ordinal(&self) -> usize {
        let n = self.done + usize::from(self.current.is_some());
        if self.total > 0 { n.min(self.total) } else { n }
    }

    /// How full the bar is: by weight, or by count when nothing weighs
    /// anything.
    pub fn ratio(&self) -> f64 {
        if self.total_weight > 0 {
            self.done_weight as f64 / self.total_weight as f64
        } else if self.total > 0 {
            self.done as f64 / self.total as f64
        } else {
            0.0
        }
    }

    /// The bar's span for the item being worked on, as ratios of the whole.
    pub fn inflight(&self) -> Option<(f64, f64)> {
        let (_, weight) = self.current.as_ref()?;
        if self.total_weight > 0 {
            let whole = self.total_weight as f64;
            let from = self.done_weight as f64 / whole;
            Some((from, from + *weight as f64 / whole))
        } else if self.total > 0 {
            let whole = self.total as f64;
            Some((self.done as f64 / whole, (self.done + 1) as f64 / whole))
        } else {
            None
        }
    }
}

/// Where long work reports how it is going, and learns whether to stop.
pub trait Progress {
    /// Work starts: `total` items weighing `total_weight` together.
    fn begin(&mut self, total: usize, total_weight: u64);
    /// Work on `path`, weighing `weight`, starts; the item before it is done.
    fn item(&mut self, path: &Path, weight: u64);
    /// The last item is done.
    fn end(&mut self);
    /// The work is done; `total` touched files are scanned again next, each
    /// announced with [`Progress::item`] and closed with [`Progress::end`].
    fn rescan(&mut self, total: usize);
    /// Whether the view asked the work to stop. Work checks between items,
    /// never inside one.
    fn stop_requested(&self) -> bool;
}

/// A sink that reports nowhere and never asks to stop.
#[derive(Debug, Clone, Copy, Default)]
pub struct Silent;

impl Progress for Silent {
    fn begin(&mut self, _total: usize, _total_weight: u64) {}
    fn item(&mut self, _path: &Path, _weight: u64) {}
    fn end(&mut self) {}
    fn rescan(&mut self, _total: usize) {}
    fn stop_requested(&self) -> bool {
        false
    }
}

/// The least time between two routine reports: at most 20 a second.
pub const REPORT_GAP: Duration = Duration::from_millis(50);

/// An item weighing at least 1/`HEAVY_SHARE` of the whole job is reported as
/// soon as it starts, however soon after the last report: it may take a
/// while, and the row must name it meanwhile. At most this many items can be
/// that heavy, so the extra reports stay few.
pub const HEAVY_SHARE: u64 = 64;

/// The sink a worker reports through: it keeps the running [`Activity`] and
/// hands copies to `send`, throttled as the module docs describe.
pub struct Reporter<F: FnMut(Activity)> {
    activity: Activity,
    stop: Arc<AtomicBool>,
    send: F,
    last_sent: Option<Instant>,
}

impl<F: FnMut(Activity)> Reporter<F> {
    /// A reporter that hands each report to `send` and asks the work to stop
    /// once `stop` turns true.
    pub fn new(stop: Arc<AtomicBool>, send: F) -> Self {
        Self {
            activity: Activity::default(),
            stop,
            send,
            last_sent: None,
        }
    }

    /// Everything reported so far, sent or not.
    pub fn activity(&self) -> &Activity {
        &self.activity
    }

    fn send_now(&mut self) {
        self.last_sent = Some(Instant::now());
        (self.send)(self.activity.clone());
    }

    fn due(&self, weight: u64) -> bool {
        let heavy = weight > 0 && weight.saturating_mul(HEAVY_SHARE) >= self.activity.total_weight;
        heavy || self.last_sent.is_none_or(|t| t.elapsed() >= REPORT_GAP)
    }
}

impl<F: FnMut(Activity)> Progress for Reporter<F> {
    fn begin(&mut self, total: usize, total_weight: u64) {
        self.activity.begin(total, total_weight);
        self.send_now();
    }

    fn item(&mut self, path: &Path, weight: u64) {
        self.activity.item(path, weight);
        if self.due(weight) {
            self.send_now();
        }
    }

    fn end(&mut self) {
        self.activity.end();
        self.send_now();
    }

    fn rescan(&mut self, total: usize) {
        self.activity.rescan(total);
        self.send_now();
    }

    fn stop_requested(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activity_counts_items_and_weights() {
        let mut a = Activity::default();
        a.begin(3, 100);
        assert_eq!((a.ordinal(), a.ratio()), (0, 0.0));
        a.item(Path::new("a"), 20);
        assert_eq!(a.ordinal(), 1);
        assert_eq!(a.inflight(), Some((0.0, 0.2)));
        a.item(Path::new("b"), 80);
        assert_eq!((a.done, a.done_weight), (1, 20));
        a.end();
        assert_eq!((a.done, a.ratio(), a.current.clone()), (2, 1.0, None));
        a.rescan(4);
        assert!(a.rescanning);
        assert_eq!((a.done, a.total, a.total_weight), (0, 4, 4));
        let mut empty = Activity::default();
        empty.begin(2, 0);
        empty.item(Path::new("x"), 0);
        empty.end();
        assert_eq!(empty.ratio(), 0.5, "counts stand in when nothing weighs");
    }

    #[test]
    fn the_reporter_throttles_but_always_sends_begin_and_end() {
        let mut sent = Vec::new();
        let started = Instant::now();
        {
            let stop = Arc::new(AtomicBool::new(false));
            let mut r = Reporter::new(stop, |a| sent.push(a));
            r.begin(10_000, 10_000);
            for _ in 0..10_000 {
                r.item(Path::new("f"), 1);
            }
            r.end();
        }
        let gaps = (started.elapsed().as_millis() / 50) as usize;
        assert!(sent.len() <= gaps + 3, "{} sends", sent.len());
        assert_eq!(sent.first().map(|a| a.total), Some(10_000));
        assert_eq!(sent.last().map(|a| a.done), Some(10_000));
    }

    #[test]
    fn a_heavy_item_is_sent_at_once_and_stop_is_read() {
        let mut sent = Vec::new();
        let stop = Arc::new(AtomicBool::new(false));
        {
            let mut r = Reporter::new(Arc::clone(&stop), |a| sent.push(a));
            r.begin(3, 100);
            r.item(Path::new("small"), 1);
            r.item(Path::new("big"), 98);
            assert!(!r.stop_requested());
            stop.store(true, Ordering::Relaxed);
            assert!(r.stop_requested());
        }
        let last = sent.last().and_then(|a| a.current.clone());
        assert_eq!(last, Some((PathBuf::from("big"), 98)));
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    /// A sink that records what work reported, and asks it to stop once
    /// `limit` items have started.
    #[derive(Debug, Default)]
    pub(crate) struct StopAfter {
        pub limit: usize,
        pub began: Option<(usize, u64)>,
        pub items: Vec<(PathBuf, u64)>,
        pub ends: usize,
    }

    impl StopAfter {
        pub fn new(limit: usize) -> Self {
            Self {
                limit,
                ..Self::default()
            }
        }
    }

    impl Progress for StopAfter {
        fn begin(&mut self, total: usize, total_weight: u64) {
            self.began = Some((total, total_weight));
        }
        fn item(&mut self, path: &Path, weight: u64) {
            self.items.push((path.to_path_buf(), weight));
        }
        fn end(&mut self) {
            self.ends += 1;
        }
        fn rescan(&mut self, _total: usize) {}
        fn stop_requested(&self) -> bool {
            self.items.len() >= self.limit
        }
    }
}
