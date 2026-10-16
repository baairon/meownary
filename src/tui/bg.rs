//! Work that must not block the input thread. A [`Pending`] value is
//! computed on a worker thread of its own, and the input thread polls for it
//! once a frame instead of waiting.
//!
//! Dropping a [`Pending`] asks its worker to stop and never waits for it, so
//! leaving a folder or quitting is instant. The worker sees the stop flag,
//! ends on its own, and its result is thrown away.
//!
//! The work runs inside the scan's panic guard, so a worker that panics
//! neither prints over the view nor restores the terminal under it: it just
//! ends with nothing to take. A worker that could not start looks the same.
//! Callers handle both one way: [`Pending::is_done`] turns true while
//! [`Pending::poll`] never gave a value.

#![cfg(feature = "tui")]

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;

use crate::scan::guard::guarded;

/// A value being computed on a worker thread.
pub struct Pending<T> {
    /// `None` once the value was taken, or once the worker is known to have
    /// ended without one.
    rx: Option<Receiver<T>>,
    /// Set when this handle is dropped, so the work can stop early.
    stop: Arc<AtomicBool>,
    /// The worker thread's name, for debugging.
    name: String,
}

impl<T: Send + 'static> Pending<T> {
    /// Run `work` on a new thread called `name`. The work gets a stop flag
    /// that turns true once this handle is dropped; long work should check
    /// it and return early, since nothing can take its result any more.
    ///
    /// If the thread cannot start, `work` never runs and the handle is done
    /// at once, with nothing to take.
    pub fn spawn(name: &str, work: impl FnOnce(&AtomicBool) -> T + Send + 'static) -> Self {
        let (tx, rx) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let run = move || {
            // A panic sends nothing; `tx` is dropped, and the handle learns
            // that nothing will arrive.
            if let Ok(value) = guarded(|| work(&flag)) {
                let _ = tx.send(value);
            }
        };
        let name = name.to_string();
        let started = thread::Builder::new().name(name.clone()).spawn(run).is_ok();
        Self {
            rx: started.then_some(rx),
            stop,
            name,
        }
    }
}

impl<T> Pending<T> {
    /// The value, once it has arrived. Never blocks, and gives the value
    /// exactly once.
    pub fn poll(&mut self) -> Option<T> {
        let rx = self.rx.as_ref()?;
        match rx.try_recv() {
            Ok(value) => {
                self.rx = None;
                Some(value)
            }
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => {
                self.rx = None;
                None
            }
        }
    }

    /// Whether nothing more will arrive: [`poll`](Self::poll) gave the value,
    /// or found that the worker ended without one (it panicked, or never
    /// started).
    pub fn is_done(&self) -> bool {
        self.rx.is_none()
    }

    /// Block until the worker ends and take its value; `None` when it was
    /// already taken or the worker ended without one. For tests and shutdown.
    pub fn wait(mut self) -> Option<T> {
        self.rx.take()?.recv().ok()
    }
}

impl<T> Drop for Pending<T> {
    /// Ask the worker to stop, without joining it.
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl<T> fmt::Debug for Pending<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pending")
            .field("name", &self.name)
            .field("done", &self.is_done())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;

    const LONG: Duration = Duration::from_secs(10);

    /// Poll the way the frame loop does until the work is over.
    fn poll_until_done<T>(pending: &mut Pending<T>) -> Option<T> {
        let deadline = Instant::now() + LONG;
        while Instant::now() < deadline {
            if let Some(value) = pending.poll() {
                return Some(value);
            }
            if pending.is_done() {
                return None;
            }
            thread::sleep(Duration::from_millis(1));
        }
        panic!("the worker never finished");
    }

    #[test]
    fn the_value_arrives_exactly_once() {
        let (open, gate) = mpsc::channel::<()>();
        let mut pending = Pending::spawn("meownary-test-value", move |_| {
            let _ = gate.recv();
            42
        });
        assert_eq!(pending.poll(), None, "nothing yet, and no waiting");
        assert!(!pending.is_done());
        open.send(()).unwrap();
        assert_eq!(poll_until_done(&mut pending), Some(42));
        assert!(pending.is_done());
        assert_eq!(pending.poll(), None, "the value comes once");
        assert!(format!("{pending:?}").contains("meownary-test-value"));

        let pending = Pending::spawn("meownary-test-wait", |_| "done");
        assert_eq!(pending.wait(), Some("done"));
    }

    #[test]
    fn dropping_asks_the_worker_to_stop_without_waiting() {
        let (started_tx, started) = mpsc::channel();
        let (seen_tx, seen) = mpsc::channel();
        let (open, gate) = mpsc::channel::<()>();
        let pending = Pending::spawn("meownary-test-stop", move |stop| {
            let _ = started_tx.send(stop.load(Ordering::Relaxed));
            let deadline = Instant::now() + LONG;
            while !stop.load(Ordering::Relaxed) && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(1));
            }
            let _ = seen_tx.send(stop.load(Ordering::Relaxed));
            // Hold the thread until the test lets go, so a drop that joined
            // it would hang here.
            let _ = gate.recv_timeout(LONG);
        });
        assert_eq!(started.recv_timeout(LONG), Ok(false));

        let dropped = Instant::now();
        drop(pending);
        assert!(
            dropped.elapsed() < LONG / 2,
            "drop never waits for the worker"
        );
        assert_eq!(seen.recv_timeout(LONG), Ok(true));
        let _ = open.send(());
    }

    #[test]
    fn a_panicking_worker_never_yields() {
        let mut pending = Pending::spawn("meownary-test-panic", |_| -> u32 {
            panic!("the work failed");
        });
        assert_eq!(poll_until_done(&mut pending), None);
        assert!(pending.is_done());
        assert_eq!(pending.poll(), None);

        let pending = Pending::spawn("meownary-test-panic", |_| -> u32 {
            panic!("the work failed");
        });
        assert_eq!(pending.wait(), None);
    }
}
