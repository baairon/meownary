//! The no-TUI runners behind `scan`, `clean`, and `undo`. Output goes to
//! stdout as data (human lines or JSON Lines); notes go to stderr. Every runner
//! returns a process exit code from [`crate::cli::args::exit`].

use std::path::Path;

use serde_json::json;

use crate::cli::args::{CleanSelector, CleanUnit, exit};
use crate::edit::{EditEngine, EditError};
use crate::model::{Confidence, ContainerKind, Finding, Marker, Region, RemovalStrategy, Severity};
use crate::scan::{self, ScanOpts};

fn severity_slug(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Notice => "notice",
        Severity::Warn => "warn",
        Severity::Alert => "alert",
    }
}

fn confidence_slug(c: Confidence) -> &'static str {
    match c {
        Confidence::Weak => "weak",
        Confidence::Moderate => "moderate",
        Confidence::Strong => "strong",
    }
}

/// `meownary scan <path>`.
pub fn run_scan(path: &Path, json_out: bool, _no_color: bool, fail_on: Option<Severity>) -> i32 {
    let reports = scan::scan_all(path, ScanOpts::default());

    let mut worst: Option<Severity> = None;
    let mut partial_files = 0usize;

    for r in &reports {
        if r.partial {
            partial_files += 1;
        }
        if let Some(s) = r.max_severity() {
            worst = worst.max(Some(s));
        }

        if json_out {
            println!(
                "{}",
                json!({
                    "event": "identify",
                    "path": r.path,
                    "format": r.format,
                    "size": r.size,
                    "partial": r.partial,
                })
            );
            for f in &r.findings {
                println!("{}", finding_json(&r.path, f));
            }
        } else {
            print_human(r);
        }
    }

    if json_out {
        println!(
            "{}",
            json!({ "event": "done", "files": reports.len(), "partial_files": partial_files })
        );
    } else if partial_files > 0 {
        eprintln!("note: {partial_files} file(s) could not be fully scanned");
    }

    if let (Some(threshold), Some(w)) = (fail_on, worst) {
        if w >= threshold {
            return exit::FINDINGS;
        }
    }
    exit::OK
}

fn finding_json(path: &Path, f: &Finding) -> String {
    json!({
        "event": "finding",
        "path": path,
        "category": f.category.slug(),
        "confidence": confidence_slug(f.confidence),
        "severity": severity_slug(f.severity),
        "signature": f.signature_id,
        "title": f.title,
        "offset": f.evidence.offset,
        "note": f.evidence.note,
        "removable": f.is_removable(),
    })
    .to_string()
}

fn print_human(r: &crate::model::FileReport) {
    let fmt = r.format.as_deref().unwrap_or("unknown");
    let flag = if r.partial { "  (partial)" } else { "" };
    let display = r.path.display();
    if r.findings.is_empty() {
        println!("{display}  [{fmt}]{flag}");
        return;
    }
    println!("{display}  [{fmt}]  {} finding(s){flag}", r.findings.len());
    for f in &r.findings {
        let mark = if f.is_removable() { " *" } else { "" };
        println!(
            "    {:<6} {:<8} {}  [{}]{mark}",
            severity_slug(f.severity),
            confidence_slug(f.confidence),
            f.title,
            f.signature_id,
        );
    }
}

fn selector_matches(sel: &CleanSelector, f: &Finding) -> bool {
    match sel {
        CleanSelector::Category(slug) => f.category.slug() == slug.as_str(),
        CleanSelector::Signature(id) => f.signature_id == *id,
    }
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
    let reports = scan::scan_all(path, ScanOpts::default());

    let mut engine = if dry_run {
        None
    } else {
        match EditEngine::new() {
            Ok(mut e) => {
                e.begin_group();
                Some(e)
            }
            Err(_) => {
                eprintln!("cannot create the trash store; no edit attempted");
                return exit::NO_TRASH;
            }
        }
    };

    let mut cleaned = 0usize;
    let mut skipped = 0usize;

    for r in &reports {
        let matched: Vec<&Finding> = r
            .findings
            .iter()
            .filter(|f| selector_matches(selector, f))
            .collect();
        if matched.is_empty() {
            continue;
        }

        match unit {
            CleanUnit::File => {
                // One delete per file, if anything matched.
                let marker = Marker {
                    region: Region::new(0, 0),
                    removal: RemovalStrategy::DeleteFile,
                    container: ContainerKind::Generic,
                    reversible: true,
                };
                if act(
                    &mut engine,
                    &r.path,
                    &marker,
                    r.format.as_deref(),
                    r.size,
                    force,
                    "delete file",
                    dry_run,
                    json_out,
                ) {
                    cleaned += 1;
                } else {
                    skipped += 1;
                }
            }
            CleanUnit::Marker => {
                for f in matched {
                    let Some(marker) = &f.marker else {
                        skipped += 1;
                        continue;
                    };
                    if act(
                        &mut engine,
                        &r.path,
                        marker,
                        r.format.as_deref(),
                        r.size,
                        force,
                        &f.signature_id,
                        dry_run,
                        json_out,
                    ) {
                        cleaned += 1;
                    } else {
                        skipped += 1;
                    }
                }
            }
        }
    }

    if json_out {
        println!(
            "{}",
            json!({ "event": "done", "cleaned": cleaned, "skipped": skipped, "dry_run": dry_run })
        );
    } else {
        let verb = if dry_run { "would clean" } else { "cleaned" };
        println!("{verb} {cleaned} marker(s), skipped {skipped}");
        if !dry_run && cleaned > 0 {
            println!("run `meownary undo` to put everything back");
        }
    }
    exit::OK
}

/// Apply one removal (or describe it, when `dry_run`). Returns whether it counted
/// as cleaned.
#[allow(clippy::too_many_arguments)]
fn act(
    engine: &mut Option<EditEngine>,
    path: &Path,
    marker: &Marker,
    format: Option<&str>,
    size: u64,
    force: bool,
    label: &str,
    dry_run: bool,
    json_out: bool,
) -> bool {
    if dry_run {
        if json_out {
            println!(
                "{}",
                json!({ "event": "would_clean", "path": path, "label": label })
            );
        } else {
            println!("  would clean {} [{label}]", path.display());
        }
        return true;
    }

    let engine = engine.as_mut().expect("engine present when not dry-run");
    match engine.apply(path, marker, format, size, None, force, label) {
        Ok(applied) => {
            if json_out {
                println!(
                    "{}",
                    json!({ "event": "cleaned", "path": path, "label": label, "undo_id": applied.undo_id })
                );
            } else {
                println!("  cleaned {} [{label}]", path.display());
            }
            true
        }
        Err(e) => {
            report_skip(path, label, &e, json_out);
            false
        }
    }
}

fn report_skip(path: &Path, label: &str, e: &EditError, json_out: bool) {
    if json_out {
        println!(
            "{}",
            json!({ "event": "skipped", "path": path, "label": label, "reason": e.to_string() })
        );
    } else {
        eprintln!("  skipped {} [{label}]: {e}", path.display());
    }
}

/// `meownary undo`.
pub fn run_undo(all: bool) -> i32 {
    let mut engine = match EditEngine::new() {
        Ok(e) => e,
        Err(_) => {
            eprintln!("cannot open the trash store");
            return exit::NO_TRASH;
        }
    };
    let result = if all {
        engine.undo_all()
    } else {
        engine.undo_last()
    };
    match result {
        Ok(n) => {
            println!("undid {n} edit(s)");
            exit::OK
        }
        Err(e) => {
            eprintln!("undo failed: {e}");
            exit::FINDINGS
        }
    }
}
