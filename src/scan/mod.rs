//! The scan pipeline: a path becomes a stream of per-file reports. Identity is
//! resolved first, then every applicable probe runs under the per-file guard,
//! across a rayon pool, streamed back over a channel so a long directory scan
//! never blocks a caller (the TUI stays responsive, headless prints as it goes).

pub mod guard;
pub mod probe;
pub mod reader;
pub mod walk;

use std::path::Path;
use std::sync::mpsc::{Receiver, channel};
use std::thread::{self, JoinHandle};

use rayon::prelude::*;

use crate::model::FileReport;
use crate::parsers;

pub use probe::{Probe, ProbeCtx, Registry};
pub use reader::{FileView, MemView, WindowedFile};
pub use walk::WalkOpts;

/// Options for a whole scan run.
#[derive(Debug, Clone, Default)]
pub struct ScanOpts {
    pub walk: WalkOpts,
}

/// A message from a running scan.
pub enum ScanEvent {
    /// One file finished; boxed to keep the channel message small.
    Found(Box<FileReport>),
    /// Every file is done.
    Done,
}

/// Scan one already-opened file: identity, then applicable probes, each guarded.
pub fn scan_file(path: &Path, registry: &Registry) -> FileReport {
    let view = match WindowedFile::open(path) {
        Ok(v) => v,
        Err(_) => {
            // Unreadable: a real, reportable outcome, not a crash.
            let mut r = FileReport::new(path.to_path_buf(), 0);
            r.partial = true;
            return r;
        }
    };

    let mut report = FileReport::new(path.to_path_buf(), view.size());

    // Identity first; it names the format the other probes gate on.
    let (format, mut findings) = match guard::guarded(|| parsers::identify(&view)) {
        Ok(result) => result,
        Err(()) => {
            report.partial = true;
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
            Err(()) => report.partial = true,
        }
    }

    report.findings = findings;
    report
}

fn probe_applies(probe: &dyn Probe, fmt: Option<&str>) -> bool {
    let wanted = probe.formats();
    wanted.is_empty() || fmt.map(|f| wanted.contains(&f)).unwrap_or(false)
}

/// Start a scan on a background thread, returning the event stream and the
/// thread handle. The caller drains `Receiver` until `ScanEvent::Done`.
pub fn scan(root: &Path, opts: ScanOpts) -> (Receiver<ScanEvent>, JoinHandle<()>) {
    let (tx, rx) = channel();
    let root = root.to_path_buf();
    let handle = thread::spawn(move || {
        let registry = parsers::registry();
        let files = walk::collect_files(&root, &opts.walk);
        files.into_par_iter().for_each_with(tx.clone(), |tx, path| {
            let report = scan_file(&path, &registry);
            let _ = tx.send(ScanEvent::Found(Box::new(report)));
        });
        let _ = tx.send(ScanEvent::Done);
    });
    (rx, handle)
}

/// Convenience for headless and tests: scan everything and return the reports
/// sorted by path (deterministic, since rayon completes out of order).
pub fn scan_all(root: &Path, opts: ScanOpts) -> Vec<FileReport> {
    let registry = parsers::registry();
    let files = walk::collect_files(root, &opts.walk);
    let mut reports: Vec<FileReport> = files.par_iter().map(|p| scan_file(p, &registry)).collect();
    reports.sort_by(|a, b| a.path.cmp(&b.path));
    reports
}
