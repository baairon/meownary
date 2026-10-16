//! The no-TUI runners behind `scan`, `clean`, and `undo`. Output goes to
//! stdout as data (human lines or JSON Lines); notes go to stderr. Every runner
//! returns a process exit code from [`crate::cli::args::exit`].
//!
//! Every stdout write goes through one locked handle. When a write fails (the
//! reader closed the pipe), the runner stops quietly and exits with the code it
//! had computed so far; it never panics on a closed pipe.

use std::borrow::Cow;
use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::Value;

use crate::cli::args::{CleanSelector, CleanUnit, exit};
use crate::cli::style::Style;
use crate::edit::deattribute::{self, Kind as CreditKind, Reason as CreditReason};
use crate::edit::{self, EditEngine, EditError, Journal, Risk, UndoRecord};
use crate::model::{
    Confidence, ContainerKind, FileReport, Finding, Marker, Region, RemovalStrategy, Severity,
};
use crate::scan::{self, ScanOpts, Scanned};
use crate::util::paths::state_dir;

// ---------------------------------------------------------------------------
// Shared output plumbing

/// Write one line to stderr, ignoring failures (stderr may be closed too).
fn note(msg: &str) {
    let mut err = io::stderr().lock();
    let _ = writeln!(err, "meownary: {msg}");
}

/// Locked stdout plus the optional progress line on stderr.
struct Sink {
    out: io::StdoutLock<'static>,
    progress: Progress,
    /// Set once a stdout write fails; nothing more is written after that.
    closed: bool,
}

impl Sink {
    fn new(progress: Progress) -> Self {
        Self {
            out: io::stdout().lock(),
            progress,
            closed: false,
        }
    }

    /// Write one line. Returns `false` once stdout is gone.
    fn line(&mut self, text: &str) -> bool {
        if self.closed {
            return false;
        }
        self.progress.clear();
        if writeln!(self.out, "{text}").is_err() {
            self.closed = true;
        }
        !self.closed
    }

    /// Serialize `event` as one JSON line.
    fn json<T: Serialize>(&mut self, event: &T) -> bool {
        match serde_json::to_string(event) {
            Ok(s) => self.line(&s),
            // Our event types always serialize; treat a failure like a closed sink.
            Err(_) => false,
        }
    }

    fn tick(&mut self, done: usize) {
        self.progress.tick(done);
    }

    /// Erase the progress line and flush stdout.
    fn finish(&mut self) {
        self.progress.clear();
        if !self.closed && self.out.flush().is_err() {
            self.closed = true;
        }
    }
}

/// A live `scanned N/M` counter on stderr, erased before any stdout line.
struct Progress {
    enabled: bool,
    total: usize,
    /// Characters currently drawn (0 when nothing is on screen).
    shown: usize,
    last: Option<Instant>,
}

impl Progress {
    const EVERY: Duration = Duration::from_millis(80);

    /// Shown only when stderr is a terminal and the output is not JSON.
    fn for_run(json_out: bool, total: usize) -> Self {
        Self {
            enabled: !json_out && io::stderr().is_terminal(),
            total,
            shown: 0,
            last: None,
        }
    }

    fn off() -> Self {
        Self {
            enabled: false,
            total: 0,
            shown: 0,
            last: None,
        }
    }

    fn tick(&mut self, done: usize) {
        if !self.enabled || done >= self.total {
            return;
        }
        let now = Instant::now();
        if self
            .last
            .is_some_and(|t| now.duration_since(t) < Self::EVERY)
        {
            return;
        }
        let text = format!("scanned {done}/{}", self.total);
        let pad = self.shown.saturating_sub(text.len());
        let mut err = io::stderr().lock();
        let _ = write!(err, "\r{text}{}", " ".repeat(pad));
        let _ = err.flush();
        self.shown = text.len() + pad;
        self.last = Some(now);
    }

    fn clear(&mut self) {
        if self.shown == 0 {
            return;
        }
        let mut err = io::stderr().lock();
        let _ = write!(err, "\r{}\r", " ".repeat(self.shown));
        let _ = err.flush();
        self.shown = 0;
    }
}

/// `None` when `path` exists (or exists but cannot be inspected, which the
/// walk reports as a partial entry); otherwise a usage message.
pub fn missing_path(path: &Path) -> Option<String> {
    match fs::metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            Some(format!("no such file or directory: {}", path.display()))
        }
        _ => None,
    }
}

/// Print a note when the whole walk is skipped because `path` lies inside the
/// state directory.
fn note_state_dir(path: &Path) {
    if scan::walk::inside_state_dir(path) {
        note(&format!(
            "{} is inside meownary's state directory, which is never scanned",
            path.display()
        ));
    }
}

fn state_store_error(e: &io::Error) {
    note(&format!(
        "cannot open the state store at {}: {e}",
        state_dir().display()
    ));
}

/// Whether an edit error means another meownary holds the state store.
/// Matched by variant name so this compiles whether or not the engine has a
/// `Locked` variant.
fn is_locked(e: &EditError) -> bool {
    format!("{e:?}").starts_with("Locked")
}

fn lossy(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Make text safe for a terminal: control characters and bidirectional
/// overrides (which can disguise a file name) are shown as `\u{..}` escapes.
fn terminal_safe(s: &str) -> Cow<'_, str> {
    fn risky(c: char) -> bool {
        c.is_control()
            || matches!(c, '\u{200e}' | '\u{200f}' | '\u{061c}')
            || ('\u{202a}'..='\u{202e}').contains(&c)
            || ('\u{2066}'..='\u{2069}').contains(&c)
    }
    if !s.chars().any(risky) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if risky(c) {
            out.push_str(&format!("\\u{{{:x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

fn display_path(path: &Path) -> String {
    terminal_safe(&path.to_string_lossy()).into_owned()
}

pub(crate) fn severity_slug(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Notice => "notice",
        Severity::Warn => "warn",
        Severity::Alert => "alert",
    }
}

pub(crate) fn confidence_slug(c: Confidence) -> &'static str {
    match c {
        Confidence::Weak => "weak",
        Confidence::Moderate => "moderate",
        Confidence::Strong => "strong",
    }
}

fn op_slug(r: &RemovalStrategy) -> &'static str {
    match r {
        RemovalStrategy::RawBlank { .. } => "raw_blank",
        RemovalStrategy::Truncate { .. } => "truncate",
        RemovalStrategy::StructuralRemove => "structural_remove",
        RemovalStrategy::DeleteFile => "delete_file",
    }
}

/// The container's serialized (snake_case) name.
fn container_slug(c: ContainerKind) -> String {
    serde_json::to_value(c)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// The bytes a marker touches: its region, except that a truncate covers
/// everything from the cut to the end and a delete covers the whole file.
fn marker_span(marker: &Marker, size: u64) -> (u64, u64) {
    match marker.removal {
        RemovalStrategy::Truncate { from } => (from, size.saturating_sub(from)),
        RemovalStrategy::DeleteFile => (0, size),
        _ => (marker.region.offset, marker.region.len),
    }
}

#[derive(Serialize)]
struct MarkerJson {
    op: &'static str,
    offset: u64,
    len: u64,
    container: String,
}

impl MarkerJson {
    fn new(marker: &Marker, size: u64) -> Self {
        let (offset, len) = marker_span(marker, size);
        Self {
            op: op_slug(&marker.removal),
            offset,
            len,
            container: container_slug(marker.container),
        }
    }
}

/// The category's inner detail as JSON (`null` for a category without one).
fn category_detail(f: &Finding) -> Value {
    serde_json::to_value(&f.category)
        .ok()
        .and_then(|v| v.get("detail").cloned())
        .unwrap_or(Value::Null)
}

// ---------------------------------------------------------------------------
// scan

#[derive(Serialize)]
struct IdentifyEvent<'a> {
    event: &'static str,
    path: String,
    format: Option<&'a str>,
    size: u64,
    partial: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
}

#[derive(Serialize)]
struct FindingEvent<'a> {
    event: &'static str,
    path: String,
    category: &'static str,
    confidence: &'static str,
    severity: &'static str,
    signature: &'a str,
    title: &'a str,
    offset: u64,
    note: Option<&'a str>,
    removable: bool,
    category_detail: Value,
    marker: Option<MarkerJson>,
}

#[derive(Serialize, Default, Clone, Copy)]
struct BySeverity {
    info: usize,
    notice: usize,
    warn: usize,
    alert: usize,
}

#[derive(Serialize)]
struct ScanDone {
    event: &'static str,
    files: usize,
    partial_files: usize,
    findings: usize,
    by_severity: BySeverity,
    worst: Option<&'static str>,
    exit: i32,
}

/// Running totals for a scan.
#[derive(Default)]
struct Tally {
    files: usize,
    partial: usize,
    findings: usize,
    by: BySeverity,
    worst: Option<Severity>,
}

impl Tally {
    fn add(&mut self, r: &FileReport) {
        self.files += 1;
        if r.partial {
            self.partial += 1;
        }
        for f in &r.findings {
            self.findings += 1;
            match f.severity {
                Severity::Info => self.by.info += 1,
                Severity::Notice => self.by.notice += 1,
                Severity::Warn => self.by.warn += 1,
                Severity::Alert => self.by.alert += 1,
            }
            self.worst = self.worst.max(Some(f.severity));
        }
    }

    fn exit_code(&self, fail_on: Option<Severity>) -> i32 {
        if let (Some(threshold), Some(worst)) = (fail_on, self.worst)
            && worst >= threshold
        {
            return exit::FINDINGS;
        }
        if self.partial > 0 {
            return exit::PARTIAL;
        }
        exit::OK
    }
}

/// `meownary scan <path>`.
pub fn run_scan(path: &Path, json_out: bool, no_color: bool, fail_on: Option<Severity>) -> i32 {
    if let Some(why) = missing_path(path) {
        note(&why);
        return exit::USAGE;
    }
    let style = if json_out {
        Style::plain()
    } else {
        Style::detect(no_color)
    };
    note_state_dir(path);

    let scan = scan::scan_ordered(path, ScanOpts::default());
    let mut sink = Sink::new(Progress::for_run(json_out, scan.total()));
    let mut tally = Tally::default();

    for item in scan {
        tally.add(&item.report);
        let ok = if json_out {
            emit_report_json(&mut sink, &item)
        } else {
            emit_report_human(&mut sink, &item, &style)
        };
        if !ok {
            break;
        }
        sink.tick(tally.files);
    }

    let code = tally.exit_code(fail_on);
    if json_out {
        sink.json(&ScanDone {
            event: "done",
            files: tally.files,
            partial_files: tally.partial,
            findings: tally.findings,
            by_severity: tally.by,
            worst: tally.worst.map(severity_slug),
            exit: code,
        });
    } else {
        sink.line("");
        sink.line(&summary_line(&tally, &style));
    }
    sink.finish();
    code
}

fn emit_report_json(sink: &mut Sink, item: &Scanned) -> bool {
    let r = &item.report;
    let path = lossy(&r.path);
    let ok = sink.json(&IdentifyEvent {
        event: "identify",
        path: path.clone(),
        format: r.format.as_deref(),
        size: r.size,
        partial: r.partial,
        error: if r.partial {
            Some(item.error.as_deref().unwrap_or("unknown"))
        } else {
            None
        },
    });
    if !ok {
        return false;
    }
    for f in &r.findings {
        let ok = sink.json(&FindingEvent {
            event: "finding",
            path: path.clone(),
            category: f.category.slug(),
            confidence: confidence_slug(f.confidence),
            severity: severity_slug(f.severity),
            signature: &f.signature_id,
            title: &f.title,
            offset: f.evidence.offset,
            note: f.evidence.note.as_deref(),
            removable: f.is_removable(),
            category_detail: category_detail(f),
            marker: f.marker.as_ref().map(|m| MarkerJson::new(m, r.size)),
        });
        if !ok {
            return false;
        }
    }
    true
}

/// The widest a title column grows before rows simply run long.
const TITLE_COL_MAX: usize = 56;

fn pad(s: &str, width: usize) -> String {
    let n = s.chars().count();
    if n >= width {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(width - n))
    }
}

fn emit_report_human(sink: &mut Sink, item: &Scanned, style: &Style) -> bool {
    let r = &item.report;
    let fmt = r.format.as_deref().unwrap_or("unknown");
    let partial = if r.partial {
        format!(
            "  (partial: {})",
            terminal_safe(item.error.as_deref().unwrap_or("unknown"))
        )
    } else {
        String::new()
    };
    let head = format!(
        "{}  [{fmt}]  {} finding(s){partial}",
        display_path(&r.path),
        r.findings.len()
    );
    if !sink.line(&head) {
        return false;
    }

    let titles: Vec<String> = r
        .findings
        .iter()
        .map(|f| terminal_safe(&f.title).into_owned())
        .collect();
    let title_w = titles
        .iter()
        .map(|t| t.chars().count())
        .max()
        .unwrap_or(0)
        .min(TITLE_COL_MAX);
    let any_removable = r.findings.iter().any(Finding::is_removable);
    let sig_w = if any_removable {
        r.findings
            .iter()
            .map(|f| f.signature_id.chars().count())
            .max()
            .unwrap_or(0)
    } else {
        0
    };

    for (f, title) in r.findings.iter().zip(&titles) {
        let sev = style.severity(f.severity, &pad(severity_slug(f.severity), 6));
        let sig = terminal_safe(&f.signature_id);
        let row = if f.is_removable() {
            format!(
                "    {sev}  {}  {}  {}  *",
                pad(confidence_slug(f.confidence), 8),
                pad(title, title_w),
                pad(&sig, sig_w)
            )
        } else {
            format!(
                "    {sev}  {}  {}  {sig}",
                pad(confidence_slug(f.confidence), 8),
                pad(title, title_w)
            )
        };
        if !sink.line(row.trim_end()) {
            return false;
        }
    }
    true
}

fn summary_line(t: &Tally, style: &Style) -> String {
    let worst = match t.worst {
        Some(s) => style.severity(s, severity_slug(s)),
        None => "none".to_string(),
    };
    let detail = if t.findings == 0 {
        String::new()
    } else {
        format!(
            " ({} alert, {} warn, {} notice, {} info)",
            t.by.alert, t.by.warn, t.by.notice, t.by.info
        )
    };
    format!(
        "scanned {} file(s): {} finding(s){detail}, {} partial, worst {worst}",
        t.files, t.findings, t.partial
    )
}

// ---------------------------------------------------------------------------
// clean

/// Why a clean action was skipped. `key()` is the stable reason prefix used in
/// messages and the `by_reason` counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SkipKind {
    NoMarker,
    Weak,
    NeedsForce,
    Refused,
    Changed,
    Unsupported,
    Io,
    Other,
}

impl SkipKind {
    fn key(self) -> &'static str {
        match self {
            SkipKind::NoMarker => "no removable marker",
            SkipKind::Weak => "weak confidence",
            SkipKind::NeedsForce => "needs --force",
            SkipKind::Refused => "refused",
            SkipKind::Changed => "changed since scan",
            SkipKind::Unsupported => "unsupported",
            SkipKind::Io => "io error",
            SkipKind::Other => "error",
        }
    }

    /// The phrase used in the human summary, after a count.
    fn summary(self) -> &'static str {
        match self {
            SkipKind::NeedsForce => "need --force",
            other => other.key(),
        }
    }
}

struct Skip {
    kind: SkipKind,
    detail: Option<String>,
}

impl Skip {
    fn new(kind: SkipKind) -> Self {
        Self { kind, detail: None }
    }

    fn with(kind: SkipKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: Some(detail.into()),
        }
    }

    fn reason(&self) -> String {
        match &self.detail {
            Some(d) => format!("{}: {d}", self.kind.key()),
            None => self.kind.key().to_string(),
        }
    }
}

enum Outcome {
    WouldClean,
    Cleaned(u64),
    Skipped(Skip),
    /// Another meownary holds the state store: stop the whole run.
    Locked(String),
}

/// One thing to try in a file: the finding it answers to and the marker to
/// remove (`None` when the finding has nothing removable).
struct Action<'a> {
    finding: &'a Finding,
    marker: Option<Marker>,
    label: String,
}

/// What earlier edits in the same file have already changed, so a later marker
/// that points into removed bytes is skipped rather than misapplied, and each
/// edit is checked against the size the file has now rather than at scan time.
#[derive(Default)]
struct FileEdits {
    cut: Option<u64>,
    removed: Vec<Region>,
    /// The file's size after the edits so far, or `None` once it is unknown
    /// (later edits are then skipped as changed).
    size: Option<u64>,
}

impl FileEdits {
    fn new(size: u64) -> Self {
        Self {
            size: Some(size),
            ..Self::default()
        }
    }

    fn stale(&self, m: &Marker) -> bool {
        if matches!(m.removal, RemovalStrategy::DeleteFile) {
            return false;
        }
        let start = m.region.offset;
        let end = m.region.end().max(start.saturating_add(1));
        self.cut.is_some_and(|c| start >= c)
            || self
                .removed
                .iter()
                .any(|r| start < r.end() && r.offset < end)
    }

    /// Note an edit that passed (or, in a dry run, would pass). `size_now`
    /// gives the file's size after a container rewrite, when it is known.
    fn record(&mut self, m: &Marker, size_now: impl FnOnce() -> Option<u64>) {
        match m.removal {
            RemovalStrategy::Truncate { from } => {
                self.cut = Some(self.cut.map_or(from, |c| c.min(from)));
                self.size = self.size.map(|s| s.min(from));
            }
            RemovalStrategy::StructuralRemove => {
                self.removed.push(m.region);
                self.size = size_now();
            }
            RemovalStrategy::DeleteFile => self.size = None,
            RemovalStrategy::RawBlank { .. } => {}
        }
    }
}

/// Where an edit starts, for ordering: a truncate's cut point, else the region.
fn edit_start(m: &Marker) -> u64 {
    match m.removal {
        RemovalStrategy::Truncate { from } => from,
        _ => m.region.offset,
    }
}

/// Length-preserving edits first (in finding order), then edits that change
/// the file's length from the highest offset down, so earlier offsets stay put.
fn order_actions(actions: &mut [Action]) {
    actions.sort_by_key(|a| match &a.marker {
        Some(m)
            if matches!(
                m.removal,
                RemovalStrategy::Truncate { .. } | RemovalStrategy::StructuralRemove
            ) =>
        {
            (1, Reverse(edit_start(m)))
        }
        _ => (0, Reverse(0)),
    });
}

fn plan<'a>(
    r: &FileReport,
    matched: &[&'a Finding],
    unit: CleanUnit,
    force: bool,
) -> Vec<Action<'a>> {
    match unit {
        CleanUnit::Marker => {
            let mut actions: Vec<Action> = matched
                .iter()
                .map(|f| Action {
                    finding: f,
                    marker: f.marker.clone(),
                    label: f.signature_id.clone(),
                })
                .collect();
            order_actions(&mut actions);
            actions
        }
        CleanUnit::File => {
            // One delete per file, answering to the loudest finding that is
            // allowed to drive it (weak ones only with --force).
            let pick = matched
                .iter()
                .filter(|f| force || f.confidence != Confidence::Weak)
                .max_by_key(|f| (f.severity, f.confidence))
                .or_else(|| matched.iter().max_by_key(|f| (f.severity, f.confidence)));
            let Some(finding) = pick else {
                return Vec::new();
            };
            vec![Action {
                finding,
                marker: Some(Marker {
                    region: Region::new(0, r.size),
                    removal: RemovalStrategy::DeleteFile,
                    container: ContainerKind::Generic,
                    reversible: true,
                }),
                label: "delete file".to_string(),
            }]
        }
    }
}

/// The skip for a failed edit, or `None` when the failure must stop the run
/// (another meownary holds the state store). Variants the engine may add are
/// matched by name, so this compiles with or without them.
fn skip_for(e: &EditError) -> Option<Skip> {
    Some(match e {
        EditError::Refused(r) => Skip::with(SkipKind::Refused, r.clone()),
        EditError::NeedsForce(r) => Skip::with(SkipKind::NeedsForce, r.clone()),
        EditError::Changed => Skip::new(SkipKind::Changed),
        EditError::Unsupported(r) => Skip::with(SkipKind::Unsupported, r.clone()),
        EditError::Io(io) => Skip::with(SkipKind::Io, io.to_string()),
        #[allow(unreachable_patterns)]
        other => {
            if is_locked(other) {
                return None;
            }
            if format!("{other:?}").starts_with("Symlink") {
                return Some(Skip::with(
                    SkipKind::Refused,
                    "edits never follow symbolic links",
                ));
            }
            Skip::with(SkipKind::Other, other.to_string())
        }
    })
}

/// Decide one action. With no engine (a dry run) every check still runs and a
/// passing action is reported as `WouldClean`.
fn decide(
    engine: &mut Option<EditEngine>,
    edits: &mut FileEdits,
    r: &FileReport,
    action: &Action,
    force: bool,
) -> Outcome {
    let Some(marker) = &action.marker else {
        return Outcome::Skipped(Skip::new(SkipKind::NoMarker));
    };
    if action.finding.confidence == Confidence::Weak && !force {
        return Outcome::Skipped(Skip::new(SkipKind::Weak));
    }
    let Some(size) = edits.size else {
        return Outcome::Skipped(Skip::new(SkipKind::Changed));
    };
    if edits.stale(marker) {
        return Outcome::Skipped(Skip::new(SkipKind::Changed));
    }
    let format = r.format.as_deref();
    match edit::assess(format, size, marker) {
        Risk::Refuse(why) => return Outcome::Skipped(Skip::with(SkipKind::Refused, why)),
        Risk::Warn(why) if !force => {
            return Outcome::Skipped(Skip::with(SkipKind::NeedsForce, why));
        }
        _ => {}
    }
    let Some(engine) = engine.as_mut() else {
        // Dry run: the same checks passed, so a real run would apply this. A
        // rewrite's new size is unknown without doing it; keep the old one.
        edits.record(marker, || Some(size));
        return Outcome::WouldClean;
    };
    match engine.apply(&r.path, marker, format, size, None, force, &action.label) {
        Ok(applied) => {
            edits.record(marker, || fs::metadata(&r.path).ok().map(|m| m.len()));
            Outcome::Cleaned(applied.undo_id)
        }
        Err(e) => match skip_for(&e) {
            Some(skip) => Outcome::Skipped(skip),
            None => Outcome::Locked(e.to_string()),
        },
    }
}

#[derive(Serialize)]
struct CleanEvent<'a> {
    event: &'static str,
    path: String,
    label: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    undo_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    signature: &'a str,
    category: &'static str,
    severity: &'static str,
    op: Option<&'static str>,
    offset: Option<u64>,
    len: Option<u64>,
}

#[derive(Serialize)]
struct CleanDone {
    event: &'static str,
    cleaned: usize,
    skipped: usize,
    dry_run: bool,
    by_reason: BTreeMap<&'static str, usize>,
    files: usize,
    partial_files: usize,
    exit: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Default)]
struct CleanTally {
    files: usize,
    partial: usize,
    matched: usize,
    cleaned: usize,
    skipped: BTreeMap<SkipKind, usize>,
}

impl CleanTally {
    fn skipped_total(&self) -> usize {
        self.skipped.values().sum()
    }

    fn by_reason(&self) -> BTreeMap<&'static str, usize> {
        self.skipped.iter().map(|(k, n)| (k.key(), *n)).collect()
    }

    fn exit_code(&self) -> i32 {
        if self.matched > 0 && self.cleaned == 0 {
            return exit::FINDINGS;
        }
        if self.partial > 0 {
            return exit::PARTIAL;
        }
        exit::OK
    }
}

fn selector_matches(sel: &CleanSelector, f: &Finding) -> bool {
    match sel {
        CleanSelector::Category(slug) => f.category.slug() == slug.as_str(),
        CleanSelector::Signature(id) => f.signature_id == *id,
        CleanSelector::Deattribute => false,
    }
}

#[derive(Serialize)]
struct CreditEvent {
    event: &'static str,
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    entry: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    op: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    len: Option<u64>,
}

/// One copy saved (or, in a dry run, one copy that would be saved).
#[derive(Serialize)]
struct CopyEvent {
    event: &'static str,
    path: String,
    output: String,
    edits: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    entries: Option<usize>,
}

#[derive(Serialize)]
struct CreditDone {
    event: &'static str,
    cleaned: usize,
    saved: usize,
    skipped: usize,
    dry_run: bool,
    files: usize,
    partial_files: usize,
    exit: i32,
}

fn emit_credit_skip(
    sink: &mut Sink,
    path: &Path,
    kind: CreditKind,
    reason: CreditReason,
    json_out: bool,
) -> bool {
    if json_out {
        return sink.json(&CreditEvent {
            event: "skipped",
            path: lossy(path),
            entry: None,
            kind: Some(kind.slug()),
            reason: Some(reason.slug()),
            output: None,
            op: None,
            offset: None,
            len: None,
        });
    }
    sink.line(&format!(
        "{:<10}  {}  {}",
        "skipped",
        display_path(path),
        reason.slug()
    ))
}

/// Report one copy: per-region `would_clean`/`cleaned` events plus one
/// `would_save`/`saved` event in JSON, or one `saved` line for people.
fn emit_copy(
    sink: &mut Sink,
    original: &Path,
    output: &Path,
    targets: &[deattribute::Target],
    dry_run: bool,
    json_out: bool,
) -> bool {
    if json_out {
        let event = if dry_run { "would_clean" } else { "cleaned" };
        for target in targets {
            if !sink.json(&CreditEvent {
                event,
                path: lossy(original),
                entry: None,
                kind: Some(target.kind.slug()),
                reason: None,
                output: Some(lossy(output)),
                op: Some("raw_blank"),
                offset: Some(target.marker.region.offset),
                len: Some(target.marker.region.len),
            }) {
                return false;
            }
        }
        return sink.json(&CopyEvent {
            event: if dry_run { "would_save" } else { "saved" },
            path: lossy(original),
            output: lossy(output),
            edits: targets.len(),
            entries: None,
        });
    }
    let name = original
        .file_name()
        .map_or_else(|| lossy(original), |n| n.to_string_lossy().into_owned());
    let mut detail = vec![format!("from {}", terminal_safe(&name))];
    for kind in [CreditKind::Brand, CreditKind::Patch] {
        let n = targets.iter().filter(|t| t.kind == kind).count();
        if n > 0 {
            detail.push(format!("{n} {}", kind.slug()));
        }
    }
    let verb = if dry_run { "would save" } else { "saved" };
    sink.line(&format!(
        "{verb:<10}  {}  ({})",
        display_path(output),
        detail.join(", ")
    ))
}

/// The summary line: skips first, then the copies, so the line always ends
/// with what was (or would be) saved.
fn deattribute_summary(
    saved: usize,
    skipped: usize,
    reasons: &BTreeMap<&'static str, usize>,
    dry_run: bool,
) -> String {
    let mut s = String::new();
    if skipped > 0 {
        s.push_str(&format!("skipped {skipped}"));
        if !reasons.is_empty() {
            let parts: Vec<String> = reasons
                .iter()
                .map(|(reason, n)| format!("{n} {reason}"))
                .collect();
            s.push_str(&format!(" ({})", parts.join(", ")));
        }
        s.push_str(", ");
    }
    let copies = if saved == 1 { "copy" } else { "copies" };
    if dry_run {
        s.push_str(&format!("would save {saved} {copies}"));
    } else {
        let beside = if saved == 1 {
            "beside its original"
        } else {
            "beside their originals"
        };
        s.push_str(&format!("saved {saved} {copies} {beside}"));
    }
    s
}

/// What one archive added to the run's totals.
#[derive(Default)]
struct ArchiveStep {
    matched: usize,
    cleaned: usize,
    saved: usize,
    partial: usize,
    /// One slug per skipped line printed.
    reasons: Vec<&'static str>,
    /// False once stdout is closed.
    open: bool,
}

/// One skip inside (or about) an archive: `entry` is the path inside it.
fn emit_archive_skip(
    sink: &mut Sink,
    archive: &Path,
    entry: Option<&str>,
    reason: &'static str,
    json_out: bool,
) -> bool {
    if json_out {
        return sink.json(&CreditEvent {
            event: "skipped",
            path: lossy(archive),
            entry: entry.map(str::to_string),
            kind: None,
            reason: Some(reason),
            output: None,
            op: None,
            offset: None,
            len: None,
        });
    }
    let shown = match entry {
        Some(entry) => format!("{}:{entry}", archive.to_string_lossy()),
        None => archive.to_string_lossy().into_owned(),
    };
    sink.line(&format!(
        "{:<10}  {}  {reason}",
        "skipped",
        terminal_safe(&shown)
    ))
}

/// Report a saved (or would-be-saved) archive copy.
fn emit_archive_copy(
    sink: &mut Sink,
    original: &Path,
    outcome: &deattribute::ArchiveOutcome,
    files: Option<usize>,
    dry_run: bool,
    json_out: bool,
) -> bool {
    let edits = outcome.brand + outcome.patch;
    if json_out {
        return sink.json(&CopyEvent {
            event: if dry_run { "would_save" } else { "saved" },
            path: lossy(original),
            output: lossy(&outcome.output),
            edits,
            entries: Some(outcome.entries_cleaned),
        });
    }
    let name = original
        .file_name()
        .map_or_else(|| lossy(original), |n| n.to_string_lossy().into_owned());
    let cleaned = outcome.entries_cleaned;
    let inside = match files.map(|n| n.max(cleaned)) {
        Some(total) => format!(
            "{cleaned} of {total} {} inside cleaned",
            if total == 1 { "file" } else { "files" }
        ),
        None => format!(
            "{cleaned} {} inside cleaned",
            if cleaned == 1 { "file" } else { "files" }
        ),
    };
    let mut detail = vec![format!("from {}: {inside}", terminal_safe(&name))];
    for (n, kind) in [
        (outcome.brand, CreditKind::Brand),
        (outcome.patch, CreditKind::Patch),
    ] {
        if n > 0 {
            detail.push(format!("{n} {}", kind.slug()));
        }
    }
    let verb = if dry_run { "would save" } else { "saved" };
    sink.line(&format!(
        "{verb:<10}  {}  ({})",
        display_path(&outcome.output),
        detail.join(", ")
    ))
}

/// Deattribute one archive through the files inside it and report the result.
fn deattribute_archive_file(
    sink: &mut Sink,
    path: &Path,
    kind: deattribute::ArchiveKind,
    dry_run: bool,
    json_out: bool,
) -> ArchiveStep {
    let mut step = ArchiveStep::default();
    let outcome = match deattribute::deattribute_archive(path, kind, dry_run) {
        Ok(outcome) => outcome,
        Err(e) => {
            let reason = match e {
                EditError::Changed => CreditReason::Changed,
                EditError::Io(_) => CreditReason::Io,
                _ => CreditReason::Unsafe,
            };
            step.partial = 1;
            step.reasons.push(reason.slug());
            step.open = emit_archive_skip(sink, path, None, reason.slug(), json_out);
            return step;
        }
    };
    step.open = true;
    for (entry, reason) in &outcome.skipped {
        step.reasons.push(reason.slug());
        if !matches!(
            reason,
            CreditReason::UnsupportedEntry | CreditReason::EntryTooLarge
        ) {
            step.matched += 1;
        }
        if !emit_archive_skip(sink, path, Some(entry), reason.slug(), json_out) {
            step.open = false;
            return step;
        }
    }
    if outcome.entries_cleaned == 0 {
        step.reasons.push(deattribute::NOTHING_INSIDE);
        step.open = emit_archive_skip(sink, path, None, deattribute::NOTHING_INSIDE, json_out);
        return step;
    }
    let files = deattribute::archive_file_count(path, kind);
    step.saved = 1;
    step.cleaned = outcome.brand + outcome.patch;
    step.matched += step.cleaned;
    step.open = emit_archive_copy(sink, path, &outcome, files, dry_run, json_out);
    step
}

/// The quiet deattribution action: for each file with credits to blank, save
/// a copy beside it with `.deattributed` before the last extension. The
/// original is never written, so this opens no state store and leaves nothing
/// to undo; a dry run differs only in not saving. Copies from earlier runs are
/// left out of the walk, so a rerun replaces each copy instead of stacking
/// another. It deliberately has no access to audit labels in its output types,
/// including error paths.
fn run_deattribute(path: &Path, dry_run: bool, json_out: bool) -> i32 {
    if missing_path(path).is_some() {
        note("path unavailable");
        return exit::USAGE;
    }
    if fs::metadata(path).is_ok_and(|m| m.is_file()) && deattribute::is_deattributed(path) {
        note("the path is already a deattributed copy; run it on the original");
        return exit::USAGE;
    }
    let scan = scan::scan_ordered(path, ScanOpts::default());
    let mut sink = Sink::new(Progress::for_run(json_out, scan.total()));
    let mut seen = 0usize;
    let mut files = 0usize;
    let mut partial_files = 0usize;
    let mut matched = 0usize;
    let mut cleaned = 0usize;
    let mut saved = 0usize;
    let mut skipped = 0usize;
    let mut reasons: BTreeMap<&'static str, usize> = BTreeMap::new();
    'files: for item in scan {
        seen += 1;
        let r = &item.report;
        // A copy from an earlier run is never a source: leave it out quietly.
        if deattribute::is_deattributed(&r.path) {
            sink.tick(seen);
            continue;
        }
        files += 1;
        if r.partial {
            partial_files += 1;
        }
        // An archive carries no attribution itself: it is cleaned through the
        // files inside it.
        if let Some(kind) = deattribute::archive_kind(&r.path, r.format.as_deref()) {
            let step = deattribute_archive_file(&mut sink, &r.path, kind, dry_run, json_out);
            matched += step.matched;
            cleaned += step.cleaned;
            saved += step.saved;
            partial_files += step.partial;
            skipped += step.reasons.len();
            for reason in step.reasons {
                *reasons.entry(reason).or_default() += 1;
            }
            if !step.open {
                break 'files;
            }
            sink.tick(seen);
            continue;
        }
        let Ok(view) = scan::WindowedFile::open(&r.path) else {
            if !r.partial {
                partial_files += 1;
            }
            sink.tick(seen);
            continue;
        };
        let plan = deattribute::plan(r, &view);
        drop(view);
        matched += plan.targets.len() + plan.skipped.len();
        for s in &plan.skipped {
            skipped += 1;
            *reasons.entry(s.reason.slug()).or_default() += 1;
            if !emit_credit_skip(&mut sink, &r.path, s.kind, s.reason, json_out) {
                break 'files;
            }
        }
        if plan.targets.is_empty() {
            sink.tick(seen);
            continue;
        }
        let outcome = if dry_run {
            Ok(deattribute::deattributed_name(&r.path))
        } else {
            deattribute::write_deattributed(&r.path, r.format.as_deref(), r.size, &plan.targets)
        };
        match outcome {
            Ok(output) => {
                saved += 1;
                cleaned += plan.targets.len();
                if !emit_copy(
                    &mut sink,
                    &r.path,
                    &output,
                    &plan.targets,
                    dry_run,
                    json_out,
                ) {
                    break 'files;
                }
                if !dry_run {
                    let again = scan::scan_file_detailed(&output, &crate::parsers::registry());
                    let remaining = scan::WindowedFile::open(&output)
                        .ok()
                        .map(|v| deattribute::plan(&again.report, &v).targets.len());
                    if again.report.partial || remaining.is_none_or(|n| n > 0) {
                        partial_files += 1;
                        note("verification incomplete for an edited file");
                    }
                }
            }
            Err(e) => {
                let reason = match e {
                    EditError::Changed => CreditReason::Changed,
                    EditError::Io(_) => CreditReason::Io,
                    _ => CreditReason::Unsafe,
                };
                let mut kinds: Vec<CreditKind> = Vec::new();
                for target in &plan.targets {
                    if !kinds.contains(&target.kind) {
                        kinds.push(target.kind);
                    }
                }
                for kind in kinds {
                    skipped += 1;
                    *reasons.entry(reason.slug()).or_default() += 1;
                    if !emit_credit_skip(&mut sink, &r.path, kind, reason, json_out) {
                        break 'files;
                    }
                }
            }
        }
        sink.tick(seen);
    }
    let code = if partial_files > 0 {
        exit::PARTIAL
    } else if matched > 0 && saved == 0 {
        exit::FINDINGS
    } else {
        exit::OK
    };
    if json_out {
        sink.json(&CreditDone {
            event: "done",
            cleaned,
            saved,
            skipped,
            dry_run,
            files,
            partial_files,
            exit: code,
        });
    } else {
        sink.line(&deattribute_summary(saved, skipped, &reasons, dry_run));
    }
    sink.finish();
    code
}

/// `meownary clean <path> ...`.
pub fn run_clean(
    path: &Path,
    selector: &CleanSelector,
    unit: CleanUnit,
    dry_run: bool,
    force: bool,
    json_out: bool,
) -> i32 {
    if matches!(selector, CleanSelector::Deattribute) {
        return run_deattribute(path, dry_run, json_out);
    }
    if let Some(why) = missing_path(path) {
        note(&why);
        return exit::USAGE;
    }

    // Open the store before touching anything, so a broken store means no edit
    // was attempted. A dry run never writes, so it never opens the store.
    let mut engine = if dry_run {
        None
    } else {
        match EditEngine::new() {
            Ok(mut e) => {
                e.begin_group();
                Some(e)
            }
            Err(e) => {
                state_store_error(&e);
                note("no edit was attempted");
                if json_out {
                    let mut sink = Sink::new(Progress::off());
                    sink.json(&CleanDone {
                        event: "done",
                        cleaned: 0,
                        skipped: 0,
                        dry_run,
                        by_reason: BTreeMap::new(),
                        files: 0,
                        partial_files: 0,
                        exit: exit::NO_TRASH,
                        error: Some(e.to_string()),
                    });
                    sink.finish();
                }
                return exit::NO_TRASH;
            }
        }
    };
    note_state_dir(path);

    let scan = scan::scan_ordered(path, ScanOpts::default());
    let mut sink = Sink::new(Progress::for_run(json_out, scan.total()));
    let mut tally = CleanTally::default();
    let mut locked: Option<String> = None;

    'files: for item in scan {
        let r = &item.report;
        tally.files += 1;
        if r.partial {
            tally.partial += 1;
        }
        let matched: Vec<&Finding> = r
            .findings
            .iter()
            .filter(|f| selector_matches(selector, f))
            .collect();
        if !matched.is_empty() {
            tally.matched += matched.len();
            let mut edits = FileEdits::new(r.size);
            for action in plan(r, &matched, unit, force) {
                let outcome = decide(&mut engine, &mut edits, r, &action, force);
                if let Outcome::Locked(why) = outcome {
                    locked = Some(why);
                    break 'files;
                }
                if !emit_clean(&mut sink, r, &action, &outcome, json_out) {
                    break 'files;
                }
                match outcome {
                    Outcome::WouldClean | Outcome::Cleaned(_) => tally.cleaned += 1,
                    Outcome::Skipped(s) => *tally.skipped.entry(s.kind).or_default() += 1,
                    Outcome::Locked(_) => {}
                }
            }
        }
        sink.tick(tally.files);
    }

    let code = if locked.is_some() {
        exit::NO_TRASH
    } else {
        tally.exit_code()
    };
    if let Some(why) = &locked {
        note(&format!("stopped: {why}"));
    }

    if json_out {
        sink.json(&CleanDone {
            event: "done",
            cleaned: tally.cleaned,
            skipped: tally.skipped_total(),
            dry_run,
            by_reason: tally.by_reason(),
            files: tally.files,
            partial_files: tally.partial,
            exit: code,
            error: locked,
        });
    } else {
        sink.line(&clean_summary(&tally, dry_run));
        if !dry_run && tally.cleaned > 0 {
            sink.line("run `meownary undo` to put everything back");
        }
    }
    sink.finish();
    if !json_out && tally.partial > 0 {
        note(&format!(
            "{} file(s) could not be fully scanned",
            tally.partial
        ));
    }
    code
}

fn emit_clean(
    sink: &mut Sink,
    r: &FileReport,
    a: &Action,
    outcome: &Outcome,
    json_out: bool,
) -> bool {
    let (event, undo_id, reason) = match outcome {
        Outcome::WouldClean => ("would_clean", None, None),
        Outcome::Cleaned(id) => ("cleaned", Some(*id), None),
        Outcome::Skipped(s) => ("skipped", None, Some(s.reason())),
        Outcome::Locked(_) => return true,
    };
    let span = a.marker.as_ref().map(|m| (m, marker_span(m, r.size)));
    if json_out {
        return sink.json(&CleanEvent {
            event,
            path: lossy(&r.path),
            label: &a.label,
            undo_id,
            reason,
            signature: &a.finding.signature_id,
            category: a.finding.category.slug(),
            severity: severity_slug(a.finding.severity),
            op: span.map(|(m, _)| op_slug(&m.removal)),
            offset: span.map(|(_, (o, _))| o),
            len: span.map(|(_, (_, l))| l),
        });
    }
    let verb = match outcome {
        Outcome::WouldClean => "would clean",
        Outcome::Cleaned(_) => "cleaned",
        _ => "skipped",
    };
    let mut line = format!(
        "{verb:<11}  {}  [{}]",
        display_path(&r.path),
        terminal_safe(&a.label)
    );
    match (outcome, span) {
        (Outcome::Skipped(s), _) => {
            line.push_str("  ");
            line.push_str(&terminal_safe(&s.reason()));
        }
        (Outcome::WouldClean, Some((m, (offset, len)))) => {
            line.push_str(&format!(
                "  {} {len} byte(s) at {offset}",
                op_slug(&m.removal)
            ));
        }
        _ => {}
    }
    sink.line(&line)
}

fn clean_summary(t: &CleanTally, dry_run: bool) -> String {
    let verb = if dry_run { "would clean" } else { "cleaned" };
    let skipped = t.skipped_total();
    let mut s = format!("{verb} {}, skipped {skipped}", t.cleaned);
    if t.matched == 0 {
        s.push_str(" (no findings matched)");
    } else if skipped > 0 {
        let mut parts: Vec<(SkipKind, usize)> = t.skipped.iter().map(|(k, n)| (*k, *n)).collect();
        parts.sort_by_key(|(k, n)| (Reverse(*n), *k));
        let parts: Vec<String> = parts
            .iter()
            .map(|(k, n)| format!("{n} {}", k.summary()))
            .collect();
        s.push_str(&format!(" ({})", parts.join(", ")));
    }
    s
}

// ---------------------------------------------------------------------------
// undo

#[derive(Serialize)]
struct UndoneEvent {
    event: &'static str,
    count: usize,
}

#[derive(Serialize)]
struct UndoDone {
    event: &'static str,
    undone: usize,
    exit: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// The records an undo is about to revert, newest first, read from the journal
/// before the engine rewrites it. `None` when the journal cannot be read.
fn planned_undo(all: bool) -> Option<Vec<UndoRecord>> {
    let records = Journal::open().and_then(|j| j.records()).ok()?;
    let mut chosen: Vec<UndoRecord> = if all {
        records
    } else {
        let last = records.iter().map(|r| r.group).max();
        records
            .into_iter()
            .filter(|r| Some(r.group) == last)
            .collect()
    };
    chosen.reverse();
    Some(chosen)
}

/// `meownary undo`.
pub fn run_undo(all: bool, json_out: bool) -> i32 {
    let mut engine = match EditEngine::new() {
        Ok(e) => e,
        Err(e) => {
            state_store_error(&e);
            if json_out {
                let mut sink = Sink::new(Progress::off());
                sink.json(&UndoDone {
                    event: "done",
                    undone: 0,
                    exit: exit::NO_TRASH,
                    error: Some(e.to_string()),
                });
                sink.finish();
            }
            return exit::NO_TRASH;
        }
    };
    let planned = planned_undo(all);
    let result = if all {
        engine.undo_all()
    } else {
        engine.undo_last()
    };

    let mut sink = Sink::new(Progress::off());
    let code = match result {
        Ok(n) => {
            if json_out {
                sink.json(&UndoneEvent {
                    event: "undone",
                    count: n,
                });
                sink.json(&UndoDone {
                    event: "done",
                    undone: n,
                    exit: exit::OK,
                    error: None,
                });
            } else {
                if let Some(records) = planned.filter(|p| p.len() == n) {
                    for rec in &records {
                        let line = format!(
                            "restored  {}  [{}]",
                            display_path(&rec.path),
                            terminal_safe(&rec.label)
                        );
                        if !sink.line(&line) {
                            break;
                        }
                    }
                }
                sink.line(&format!("undid {n} edit(s)"));
            }
            exit::OK
        }
        Err(e) => {
            let code = if is_locked(&e) {
                exit::NO_TRASH
            } else {
                exit::FINDINGS
            };
            if json_out {
                sink.json(&UndoDone {
                    event: "done",
                    undone: 0,
                    exit: code,
                    error: Some(e.to_string()),
                });
            }
            sink.finish();
            note(&format!("undo failed: {e}"));
            code
        }
    };
    sink.finish();
    code
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Category, Evidence, JunkKind};

    fn finding(sig: &str, conf: Confidence, marker: Option<Marker>) -> Finding {
        Finding {
            category: Category::Junk(JunkKind::Comment),
            confidence: conf,
            severity: Severity::Notice,
            signature_id: sig.to_string(),
            title: "t".to_string(),
            evidence: Evidence::at(10),
            marker,
        }
    }

    fn report(findings: Vec<Finding>) -> FileReport {
        let mut r = FileReport::new("x.bin".into(), 1000);
        r.findings = findings;
        r
    }

    #[test]
    fn terminal_safe_escapes_controls_and_bidi() {
        assert_eq!(terminal_safe("plain.txt"), "plain.txt");
        assert_eq!(terminal_safe("a\u{202e}gpj.exe"), "a\\u{202e}gpj.exe");
        assert_eq!(terminal_safe("a\x1b[31mb"), "a\\u{1b}[31mb");
        assert_eq!(terminal_safe("tab\there"), "tab\\u{9}here");
    }

    #[test]
    fn tally_exit_codes() {
        let mut t = Tally::default();
        assert_eq!(t.exit_code(Some(Severity::Info)), exit::OK);
        let mut r = report(vec![finding("a.b", Confidence::Strong, None)]);
        t.add(&r);
        assert_eq!(t.exit_code(None), exit::OK);
        assert_eq!(t.exit_code(Some(Severity::Notice)), exit::FINDINGS);
        assert_eq!(t.exit_code(Some(Severity::Warn)), exit::OK);
        r.partial = true;
        r.findings.clear();
        t.add(&r);
        assert_eq!(t.exit_code(Some(Severity::Warn)), exit::PARTIAL);
        assert_eq!(t.exit_code(Some(Severity::Notice)), exit::FINDINGS);
        assert_eq!(t.by.notice, 1);
        assert_eq!(t.files, 2);
    }

    #[test]
    fn marker_json_spans() {
        let blank = Marker::blank(Region::new(20, 5), ContainerKind::JpegApp1);
        let j = serde_json::to_value(MarkerJson::new(&blank, 100)).unwrap();
        assert_eq!(
            j,
            serde_json::json!({"op":"raw_blank","offset":20,"len":5,"container":"jpeg_app1"})
        );
        let cut = Marker::truncate_at(60, ContainerKind::PeOverlay);
        let j = serde_json::to_value(MarkerJson::new(&cut, 100)).unwrap();
        assert_eq!(
            j,
            serde_json::json!({"op":"truncate","offset":60,"len":40,"container":"pe_overlay"})
        );
    }

    #[test]
    fn category_detail_serializes_inner_value() {
        let f = finding("a.b", Confidence::Strong, None);
        assert_eq!(category_detail(&f), serde_json::json!("comment"));
        let mut g = f.clone();
        g.category = Category::Bundleware;
        assert_eq!(category_detail(&g), Value::Null);
    }

    #[test]
    fn length_changing_edits_go_last_from_the_top_down() {
        let fs = vec![
            finding(
                "cut",
                Confidence::Strong,
                Some(Marker::truncate_at(500, ContainerKind::Raw)),
            ),
            finding(
                "blank",
                Confidence::Strong,
                Some(Marker::blank(Region::new(700, 4), ContainerKind::Raw)),
            ),
            finding(
                "structural",
                Confidence::Strong,
                Some(Marker {
                    region: Region::new(800, 10),
                    removal: RemovalStrategy::StructuralRemove,
                    container: ContainerKind::PngChunk,
                    reversible: true,
                }),
            ),
            finding("none", Confidence::Strong, None),
        ];
        let r = report(fs.clone());
        let matched: Vec<&Finding> = r.findings.iter().collect();
        let labels: Vec<String> = plan(&r, &matched, CleanUnit::Marker, false)
            .into_iter()
            .map(|a| a.label)
            .collect();
        assert_eq!(labels, ["blank", "none", "structural", "cut"]);
    }

    #[test]
    fn stale_markers_after_a_cut_or_removal() {
        let mut e = FileEdits::new(1000);
        e.record(&Marker::truncate_at(500, ContainerKind::Raw), || None);
        assert_eq!(e.size, Some(500));
        assert!(e.stale(&Marker::blank(Region::new(600, 4), ContainerKind::Raw)));
        assert!(!e.stale(&Marker::blank(Region::new(100, 4), ContainerKind::Raw)));
        e.record(
            &Marker {
                region: Region::new(200, 50),
                removal: RemovalStrategy::StructuralRemove,
                container: ContainerKind::PngChunk,
                reversible: true,
            },
            || Some(450),
        );
        assert_eq!(e.size, Some(450));
        assert!(e.stale(&Marker::blank(Region::new(240, 20), ContainerKind::Raw)));
        assert!(!e.stale(&Marker::blank(Region::new(250, 20), ContainerKind::Raw)));
    }

    #[test]
    fn dry_run_decisions_match_the_safety_rules() {
        let mut none: Option<EditEngine> = None;
        let weak = finding(
            "w",
            Confidence::Weak,
            Some(Marker::blank(Region::new(10, 4), ContainerKind::Raw)),
        );
        let r = report(vec![weak.clone()]);
        let a = Action {
            finding: &r.findings[0],
            marker: weak.marker.clone(),
            label: "w".into(),
        };
        let mut edits = FileEdits::new(r.size);
        assert!(matches!(
            decide(&mut none, &mut edits, &r, &a, false),
            Outcome::Skipped(Skip {
                kind: SkipKind::Weak,
                ..
            })
        ));
        assert!(matches!(
            decide(&mut none, &mut edits, &r, &a, true),
            Outcome::WouldClean
        ));

        let strong = report(vec![finding("s", Confidence::Strong, None)]);
        let matched: Vec<&Finding> = strong.findings.iter().collect();
        let del = plan(&strong, &matched, CleanUnit::File, false);
        assert_eq!(del.len(), 1);
        match decide(
            &mut none,
            &mut FileEdits::new(1000),
            &strong,
            &del[0],
            false,
        ) {
            Outcome::Skipped(s) => assert_eq!(s.kind, SkipKind::NeedsForce),
            _ => panic!("delete without --force must be skipped"),
        }
        assert!(matches!(
            decide(&mut none, &mut FileEdits::new(1000), &strong, &del[0], true),
            Outcome::WouldClean
        ));
    }

    #[test]
    fn unknown_size_after_a_rewrite_skips_as_changed() {
        let blank = Marker::blank(Region::new(10, 4), ContainerKind::Raw);
        let r = report(vec![finding("s", Confidence::Strong, Some(blank.clone()))]);
        let a = Action {
            finding: &r.findings[0],
            marker: Some(blank),
            label: "s".into(),
        };
        let mut edits = FileEdits::new(r.size);
        edits.record(
            &Marker {
                region: Region::new(500, 20),
                removal: RemovalStrategy::StructuralRemove,
                container: ContainerKind::PngChunk,
                reversible: true,
            },
            || None,
        );
        assert!(matches!(
            decide(&mut None, &mut edits, &r, &a, true),
            Outcome::Skipped(Skip {
                kind: SkipKind::Changed,
                ..
            })
        ));
    }

    #[test]
    fn truncates_order_by_their_cut_point() {
        let mut odd = Marker::truncate_at(100, ContainerKind::Raw);
        odd.region = Region::new(0, 0);
        let fs = vec![
            finding("low", Confidence::Strong, Some(odd)),
            finding(
                "high",
                Confidence::Strong,
                Some(Marker::truncate_at(900, ContainerKind::Raw)),
            ),
        ];
        let r = report(fs);
        let matched: Vec<&Finding> = r.findings.iter().collect();
        let labels: Vec<String> = plan(&r, &matched, CleanUnit::Marker, false)
            .into_iter()
            .map(|a| a.label)
            .collect();
        assert_eq!(labels, ["high", "low"]);
    }

    #[test]
    fn clean_summary_breaks_down_skips() {
        let mut t = CleanTally {
            matched: 5,
            cleaned: 3,
            ..CleanTally::default()
        };
        t.skipped.insert(SkipKind::NeedsForce, 2);
        assert_eq!(
            clean_summary(&t, false),
            "cleaned 3, skipped 2 (2 need --force)"
        );
        t.skipped.insert(SkipKind::NoMarker, 1);
        assert_eq!(
            clean_summary(&t, true),
            "would clean 3, skipped 3 (2 need --force, 1 no removable marker)"
        );
        let empty = CleanTally::default();
        assert_eq!(
            clean_summary(&empty, false),
            "cleaned 0, skipped 0 (no findings matched)"
        );
    }

    #[test]
    fn clean_exit_codes() {
        let mut t = CleanTally::default();
        assert_eq!(t.exit_code(), exit::OK);
        t.matched = 2;
        assert_eq!(t.exit_code(), exit::FINDINGS);
        t.cleaned = 1;
        assert_eq!(t.exit_code(), exit::OK);
        t.partial = 1;
        assert_eq!(t.exit_code(), exit::PARTIAL);
    }
}
