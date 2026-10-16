//! A small hand-rolled argument parser. meownary's surface is a handful of
//! verbs, so a discriminated `Command` plus a tolerant reader beats pulling in
//! a macro-heavy parser. Anything malformed becomes `Command::Invalid`, which
//! `main` prints with the help text and the usage exit code.

use std::path::PathBuf;

use crate::model::Severity;

/// Process exit codes, documented in [`HELP_TEXT`].
pub mod exit {
    pub const OK: i32 = 0;
    /// `scan --fail-on` threshold was met.
    pub const FINDINGS: i32 = 1;
    pub const USAGE: i32 = 2;
    /// The trash store could not be created, so no edit is safe.
    pub const NO_TRASH: i32 = 73;
    /// Some files could not be scanned; results are partial.
    pub const PARTIAL: i32 = 75;
    pub const INTERRUPTED: i32 = 130;
}

/// What to clean against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CleanSelector {
    Category(String),
    Signature(String),
}

/// The unit a clean acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanUnit {
    /// Scrub just the detected marker bytes (default).
    Marker,
    /// Delete the whole file that carries a matching finding.
    File,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Open the interactive TUI on a file or directory.
    Tui {
        path: PathBuf,
    },
    /// Scan and report, no TUI.
    Scan {
        path: PathBuf,
        json: bool,
        no_color: bool,
        fail_on: Option<Severity>,
    },
    /// Clean matching markers (or files) in bulk.
    Clean {
        path: PathBuf,
        selector: CleanSelector,
        unit: CleanUnit,
        dry_run: bool,
        force: bool,
        json: bool,
    },
    /// Undo the last clean group, or everything.
    Undo {
        all: bool,
    },
    Version,
    Help,
    /// A usage error; `why` explains it.
    Invalid {
        why: String,
    },
}

fn parse_severity(s: &str) -> Option<Severity> {
    match s.to_ascii_lowercase().as_str() {
        "info" => Some(Severity::Info),
        "notice" => Some(Severity::Notice),
        "warn" => Some(Severity::Warn),
        "alert" => Some(Severity::Alert),
        _ => None,
    }
}

/// Split `--flag=value` into its parts; otherwise return the token unchanged.
fn split_eq(arg: &str) -> (&str, Option<&str>) {
    match arg.split_once('=') {
        Some((k, v)) => (k, Some(v)),
        None => (arg, None),
    }
}

/// Parse `argv` (already without the program name).
pub fn parse(argv: &[String]) -> Command {
    let args: Vec<&str> = argv
        .iter()
        .map(String::as_str)
        .filter(|a| !a.is_empty())
        .collect();
    if args.is_empty() {
        return Command::Tui {
            path: PathBuf::from("."),
        };
    }

    match args[0] {
        "scan" => parse_scan(&args[1..]),
        "clean" => parse_clean(&args[1..]),
        "undo" => parse_undo(&args[1..]),
        "-v" | "--version" => Command::Version,
        "-h" | "--help" => Command::Help,
        other if other.starts_with('-') => Command::Invalid {
            why: format!("unknown option: {other}"),
        },
        // A bare path: open the TUI on it.
        _ => {
            if args.len() > 1 {
                return Command::Invalid {
                    why: format!("unexpected argument: {}", args[1]),
                };
            }
            Command::Tui {
                path: PathBuf::from(args[0]),
            }
        }
    }
}

fn parse_scan(rest: &[&str]) -> Command {
    let mut path: Option<PathBuf> = None;
    let mut json = false;
    let mut no_color = false;
    let mut fail_on = None;

    let mut i = 0;
    while i < rest.len() {
        let (key, inline) = split_eq(rest[i]);
        match key {
            "--json" => json = true,
            "--no-color" => no_color = true,
            "-h" | "--help" => return Command::Help,
            "--fail-on" => {
                let v = match inline {
                    Some(v) => v.to_string(),
                    None => {
                        i += 1;
                        match rest.get(i) {
                            Some(v) => v.to_string(),
                            None => return invalid("--fail-on needs a severity"),
                        }
                    }
                };
                match parse_severity(&v) {
                    Some(s) => fail_on = Some(s),
                    None => return invalid("--fail-on expects info|notice|warn|alert"),
                }
            }
            other if other.starts_with('-') => {
                return invalid(&format!("unknown scan option: {other}"));
            }
            _ => {
                if path.is_some() {
                    return invalid("scan takes a single path");
                }
                path = Some(PathBuf::from(rest[i]));
            }
        }
        i += 1;
    }

    Command::Scan {
        path: path.unwrap_or_else(|| PathBuf::from(".")),
        json,
        no_color,
        fail_on,
    }
}

fn parse_clean(rest: &[&str]) -> Command {
    let mut path: Option<PathBuf> = None;
    let mut selector: Option<CleanSelector> = None;
    let mut unit = CleanUnit::Marker;
    let mut dry_run = false;
    let mut force = false;
    let mut json = false;

    let mut i = 0;
    while i < rest.len() {
        let (key, inline) = split_eq(rest[i]);
        let take_value = |inline: Option<&str>, i: &mut usize| -> Option<String> {
            if let Some(v) = inline {
                return Some(v.to_string());
            }
            *i += 1;
            rest.get(*i).map(|s| s.to_string())
        };
        match key {
            "--dry-run" => dry_run = true,
            "--force" => force = true,
            "--json" => json = true,
            "--marker" => unit = CleanUnit::Marker,
            "--file" => unit = CleanUnit::File,
            "-h" | "--help" => return Command::Help,
            "--category" => match take_value(inline, &mut i) {
                Some(v) => selector = Some(CleanSelector::Category(v)),
                None => return invalid("--category needs a value"),
            },
            "--signature" => match take_value(inline, &mut i) {
                Some(v) => selector = Some(CleanSelector::Signature(v)),
                None => return invalid("--signature needs a value"),
            },
            other if other.starts_with('-') => {
                return invalid(&format!("unknown clean option: {other}"));
            }
            _ => {
                if path.is_some() {
                    return invalid("clean takes a single path");
                }
                path = Some(PathBuf::from(rest[i]));
            }
        }
        i += 1;
    }

    let Some(path) = path else {
        return invalid("clean needs a path");
    };
    let Some(selector) = selector else {
        return invalid("clean needs --category <slug> or --signature <id>");
    };
    Command::Clean {
        path,
        selector,
        unit,
        dry_run,
        force,
        json,
    }
}

fn parse_undo(rest: &[&str]) -> Command {
    let mut all = false;
    for arg in rest {
        match split_eq(arg).0 {
            "--all" => all = true,
            "--last" => all = false,
            "-h" | "--help" => return Command::Help,
            other => return invalid(&format!("unknown undo option: {other}")),
        }
    }
    Command::Undo { all }
}

fn invalid(why: &str) -> Command {
    Command::Invalid {
        why: why.to_string(),
    }
}

pub const HELP_TEXT: &str = "\
meownary, know what a file really is

usage
  meownary [<path>]                 open the interactive view on a file or folder
  meownary scan <path> [flags]      scan and report, no interactive view
  meownary clean <path> <select>    remove matching markers in bulk
  meownary undo [--last|--all]      undo the last clean (or everything)
  meownary --version                print the version
  meownary --help                   print this

scan flags
  --json                            one JSON object per line (identify, finding, done)
  --no-color                        never colorize (also auto-off when piped)
  --fail-on <info|notice|warn|alert>
                                    exit 1 if any finding reaches this severity

clean
  --category <slug>                 select findings by category (identity, brand,
                                    integrity, tamper, deception, bundleware, junk)
  --signature <id>                  select findings by exact signature id
  --marker                          scrub just the marker bytes (default)
  --file                            delete whole files that carry a match
  --dry-run                         show what would change, touch nothing
  --force                           allow warn-level edits (never refused ones)
  --json                            machine-readable output

exit codes
  0    ok
  1    scan --fail-on threshold met
  2    the command was wrong
  73   the trash store could not be created (no edit attempted)
  75   some files could not be scanned (partial results)
  130  interrupted

every edit copies the original to meownary's trash first; `undo` puts it back.
";
