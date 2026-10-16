//! A small hand-rolled argument parser. meownary's surface is a handful of
//! verbs, so a discriminated `Command` plus a strict reader beats pulling in a
//! macro-heavy parser. Anything malformed becomes `Command::Invalid`, which
//! `main` prints with a pointer to `--help` and the usage exit code.
//!
//! Rules: option values may not start with `-`; boolean flags reject
//! `=value`; `--` ends options so later arguments are always paths.

use std::ffi::OsString;
use std::path::PathBuf;

use crate::model::Severity;

/// Process exit codes, documented in [`HELP_TEXT`] and the README.
pub mod exit {
    pub const OK: i32 = 0;
    /// `scan --fail-on` threshold was met; `clean` matched findings but could
    /// apply none of them; `undo` failed; the interactive view failed.
    pub const FINDINGS: i32 = 1;
    /// A usage error: bad command, flag, value, or a path that does not exist.
    pub const USAGE: i32 = 2;
    /// The state store (trash and undo journal) could not be opened or
    /// created, or another meownary holds it, so no edit is safe.
    pub const NO_TRASH: i32 = 73;
    /// Some files could not be fully scanned; results are partial.
    pub const PARTIAL: i32 = 75;
    /// The status the Rust runtime exits with after an internal error (a panic
    /// outside the per-file guard).
    pub const INTERNAL: i32 = 101;
    /// What a shell reports after Ctrl-C (128 + SIGINT). meownary installs no
    /// signal handler; on Windows the system's Ctrl-C status is used instead.
    pub const INTERRUPTED: i32 = 130;
}

/// The category slugs `--category` accepts, in display order.
pub const CATEGORIES: [&str; 7] = [
    "identity",
    "brand",
    "integrity",
    "tamper",
    "deception",
    "bundleware",
    "junk",
];

/// What to clean against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CleanSelector {
    Category(String),
    Signature(String),
    Deattribute,
    DeepDeattribute,
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
    /// Open the interactive TUI on a file or directory, or on a folder picker
    /// when no path was given. Nothing defaults to the current directory.
    Tui {
        path: Option<PathBuf>,
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
        json: bool,
    },
    Version,
    Help,
    /// A usage error; `why` explains it.
    Invalid {
        why: String,
    },
}

/// One accepted option: its spelling and whether it takes a value.
#[derive(Debug, Clone, Copy)]
struct Flag {
    name: &'static str,
    takes_value: bool,
}

const fn switch(name: &'static str) -> Flag {
    Flag {
        name,
        takes_value: false,
    }
}

const fn valued(name: &'static str) -> Flag {
    Flag {
        name,
        takes_value: true,
    }
}

const TOP_FLAGS: &[Flag] = &[
    switch("-h"),
    switch("--help"),
    switch("-v"),
    switch("--version"),
];

const SCAN_FLAGS: &[Flag] = &[
    switch("-h"),
    switch("--help"),
    switch("--json"),
    switch("--no-color"),
    valued("--fail-on"),
];

const CLEAN_FLAGS: &[Flag] = &[
    switch("-h"),
    switch("--help"),
    valued("--category"),
    valued("--signature"),
    switch("--deattribute"),
    switch("--deep"),
    switch("--marker"),
    switch("--file"),
    switch("--dry-run"),
    switch("--force"),
    switch("--json"),
];

const UNDO_FLAGS: &[Flag] = &[
    switch("-h"),
    switch("--help"),
    switch("--last"),
    switch("--all"),
    switch("--json"),
];

/// A lexed argument: a known flag (with its value, if it takes one) or a
/// positional.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tok<'a> {
    Flag(&'static str, Option<&'a str>),
    Pos(&'a str),
}

/// Whether `arg` is spelled like an option. A lone `-` is a positional.
fn is_option(arg: &str) -> bool {
    arg.len() > 1 && arg.starts_with('-')
}

/// Split `--flag=value` into its parts; otherwise return the token unchanged.
fn split_eq(arg: &str) -> (&str, Option<&str>) {
    match arg.split_once('=') {
        Some((k, v)) => (k, Some(v)),
        None => (arg, None),
    }
}

/// Lex `args` against `specs`. `cmd` names the subcommand in messages.
fn lex<'a>(cmd: &str, args: &[&'a str], specs: &[Flag]) -> Result<Vec<Tok<'a>>, String> {
    let mut out = Vec::new();
    let mut i = 0;
    let mut options_done = false;
    while i < args.len() {
        let arg = args[i];
        i += 1;
        if options_done || !is_option(arg) {
            out.push(Tok::Pos(arg));
            continue;
        }
        if arg == "--" {
            options_done = true;
            continue;
        }
        let (key, inline) = split_eq(arg);
        let Some(spec) = specs.iter().find(|f| f.name == key) else {
            return Err(if cmd.is_empty() {
                format!("unknown option: {key}")
            } else {
                format!("unknown {cmd} option: {key}")
            });
        };
        if !spec.takes_value {
            if inline.is_some() {
                return Err(format!("{key} does not take a value"));
            }
            out.push(Tok::Flag(spec.name, None));
            continue;
        }
        let value = match inline {
            Some(v) => v,
            None => match args.get(i) {
                Some(v) => {
                    i += 1;
                    v
                }
                None => return Err(format!("{key} needs a value")),
            },
        };
        if value.is_empty() {
            return Err(format!("{key} needs a value"));
        }
        if value.starts_with('-') {
            return Err(format!("{key} needs a value, got the option {value}"));
        }
        out.push(Tok::Flag(spec.name, Some(value)));
    }
    Ok(out)
}

fn wants_help(toks: &[Tok]) -> bool {
    toks.iter()
        .any(|t| matches!(t, Tok::Flag("-h" | "--help", _)))
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

/// Parse `argv` (already without the program name).
pub fn parse(argv: &[String]) -> Command {
    let args: Vec<&str> = argv.iter().map(String::as_str).collect();
    match args.first().copied() {
        None => Command::Tui { path: None },
        Some("scan") => parse_scan(&args[1..]),
        Some("clean") => parse_clean(&args[1..]),
        Some("undo") => parse_undo(&args[1..]),
        Some(_) => parse_top(&args),
    }
}

/// Parse raw OS arguments. Arguments that are not valid Unicode are read
/// lossily for flag matching, but a path keeps its exact original bytes, so a
/// non-UTF-8 path on the command line still names the right file.
pub fn parse_os(argv: &[OsString]) -> Command {
    let lossy: Vec<String> = argv
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let mut cmd = parse(&lossy);
    let path = match &mut cmd {
        Command::Tui { path: Some(path) }
        | Command::Scan { path, .. }
        | Command::Clean { path, .. } => path,
        _ => return cmd,
    };
    if path
        .to_str()
        .is_some_and(|p| p.contains(char::REPLACEMENT_CHARACTER))
    {
        let shown = path.to_string_lossy().into_owned();
        if let Some(i) = lossy
            .iter()
            .enumerate()
            .position(|(i, l)| *l == shown && argv[i].to_str().is_none())
        {
            *path = PathBuf::from(&argv[i]);
        }
    }
    cmd
}

/// Quote a token for display in a suggestion when it holds whitespace.
fn shell_word(arg: &str) -> String {
    if arg.is_empty() || arg.chars().any(char::is_whitespace) {
        format!("\"{arg}\"")
    } else {
        arg.to_string()
    }
}

fn scan_suggestion(args: &[&str]) -> String {
    let words: Vec<String> = args.iter().map(|a| shell_word(a)).collect();
    format!("did you mean `meownary scan {}`?", words.join(" "))
}

/// Whether `arg` is something only `scan` understands.
fn is_scan_flag(arg: &str) -> bool {
    let key = split_eq(arg).0;
    SCAN_FLAGS
        .iter()
        .any(|f| f.name == key && !matches!(key, "-h" | "--help"))
}

/// No subcommand: `meownary`, `meownary <path>`, `--help`, or `--version`.
fn parse_top(args: &[&str]) -> Command {
    let toks = match lex("", args, TOP_FLAGS) {
        Ok(t) => t,
        Err(why) => {
            if args.iter().any(|a| is_scan_flag(a)) {
                return invalid(&format!("{why}; {}", scan_suggestion(args)));
            }
            return invalid(&why);
        }
    };
    if wants_help(&toks) {
        return Command::Help;
    }
    let positionals: Vec<&str> = toks
        .iter()
        .filter_map(|t| match t {
            Tok::Pos(p) => Some(*p),
            Tok::Flag(..) => None,
        })
        .collect();
    if toks
        .iter()
        .any(|t| matches!(t, Tok::Flag("-v" | "--version", _)))
    {
        if toks.len() > 1 {
            return invalid("--version takes no arguments");
        }
        return Command::Version;
    }
    match positionals.as_slice() {
        [] => Command::Tui { path: None },
        [""] => invalid("the path is empty"),
        [path] => Command::Tui {
            path: Some(PathBuf::from(path)),
        },
        [_, extra, ..] => invalid(&format!(
            "unexpected argument: {extra} (the interactive view takes one path)"
        )),
    }
}

fn parse_scan(rest: &[&str]) -> Command {
    let toks = match lex("scan", rest, SCAN_FLAGS) {
        Ok(t) => t,
        Err(why) => return invalid(&why),
    };
    if wants_help(&toks) {
        return Command::Help;
    }
    let mut path: Option<&str> = None;
    let mut json = false;
    let mut no_color = false;
    let mut fail_on = None;

    for tok in toks {
        match tok {
            Tok::Flag("--json", _) => json = true,
            Tok::Flag("--no-color", _) => no_color = true,
            Tok::Flag("--fail-on", Some(v)) => {
                if fail_on.is_some() {
                    return invalid("--fail-on given more than once");
                }
                match parse_severity(v) {
                    Some(s) => fail_on = Some(s),
                    None => {
                        return invalid(&format!(
                            "--fail-on expects info, notice, warn, or alert, got {v}"
                        ));
                    }
                }
            }
            Tok::Flag(other, _) => return invalid(&format!("unexpected flag: {other}")),
            Tok::Pos(p) => {
                if let Some(first) = path {
                    return invalid(&format!(
                        "scan takes one path, got {first} and {p} (use -- before a path that starts with -)"
                    ));
                }
                path = Some(p);
            }
        }
    }
    let Some(path) = path else {
        return invalid("scan needs a path");
    };
    if path.is_empty() {
        return invalid("the path is empty");
    }

    Command::Scan {
        path: PathBuf::from(path),
        json,
        no_color,
        fail_on,
    }
}

fn parse_clean(rest: &[&str]) -> Command {
    let toks = match lex("clean", rest, CLEAN_FLAGS) {
        Ok(t) => t,
        Err(why) => return invalid(&why),
    };
    if wants_help(&toks) {
        return Command::Help;
    }
    let mut path: Option<&str> = None;
    let mut selector: Option<CleanSelector> = None;
    let mut unit: Option<CleanUnit> = None;
    let mut dry_run = false;
    let mut force = false;
    let mut json = false;
    let mut deep = false;

    for tok in toks {
        match tok {
            Tok::Flag("--dry-run", _) => dry_run = true,
            Tok::Flag("--force", _) => force = true,
            Tok::Flag("--json", _) => json = true,
            Tok::Flag("--deep", _) => deep = true,
            Tok::Flag("--deattribute", _) => {
                if selector == Some(CleanSelector::Deattribute) {
                    return invalid("--deattribute given more than once");
                }
                if selector.is_some() {
                    return invalid("choose one --deattribute, --category, or --signature");
                }
                selector = Some(CleanSelector::Deattribute);
            }
            Tok::Flag(flag @ ("--marker" | "--file"), _) => {
                let this = if flag == "--file" {
                    CleanUnit::File
                } else {
                    CleanUnit::Marker
                };
                if unit.is_some_and(|u| u != this) {
                    return invalid("choose one of --marker or --file");
                }
                unit = Some(this);
            }
            Tok::Flag(flag @ ("--category" | "--signature"), Some(v)) => {
                if selector.is_some() {
                    return invalid("choose one --deattribute, --category, or --signature");
                }
                selector = Some(if flag == "--category" {
                    let slug = v.to_ascii_lowercase();
                    if !CATEGORIES.contains(&slug.as_str()) {
                        return invalid(&format!(
                            "unknown category: {v} (valid: {})",
                            CATEGORIES.join(", ")
                        ));
                    }
                    CleanSelector::Category(slug)
                } else {
                    CleanSelector::Signature(v.to_string())
                });
            }
            Tok::Flag(other, _) => return invalid(&format!("unexpected flag: {other}")),
            Tok::Pos(p) => {
                if let Some(first) = path {
                    return invalid(&format!(
                        "clean takes one path, got {first} and {p} (use -- before a path that starts with -)"
                    ));
                }
                path = Some(p);
            }
        }
    }

    let Some(path) = path else {
        return invalid("clean needs a path");
    };
    if path.is_empty() {
        return invalid("the path is empty");
    }
    if deep && selector != Some(CleanSelector::Deattribute) {
        return invalid("--deep requires --deattribute");
    }
    let Some(selector) = selector else {
        return invalid("clean needs --deattribute, --category <slug>, or --signature <id>");
    };
    let selector = if deep {
        CleanSelector::DeepDeattribute
    } else {
        selector
    };
    if selector == CleanSelector::Deattribute || selector == CleanSelector::DeepDeattribute {
        if let Some(unit) = unit {
            let flag = if unit == CleanUnit::File {
                "--file"
            } else {
                "--marker"
            };
            return invalid(&format!("--deattribute cannot be combined with {flag}"));
        }
        if force {
            return invalid("--deattribute does not use --force");
        }
    }
    Command::Clean {
        path: PathBuf::from(path),
        selector,
        unit: unit.unwrap_or(CleanUnit::Marker),
        dry_run,
        force,
        json,
    }
}

fn parse_undo(rest: &[&str]) -> Command {
    let toks = match lex("undo", rest, UNDO_FLAGS) {
        Ok(t) => t,
        Err(why) => return invalid(&why),
    };
    if wants_help(&toks) {
        return Command::Help;
    }
    let mut all: Option<bool> = None;
    let mut json = false;
    for tok in toks {
        match tok {
            Tok::Flag(flag @ ("--all" | "--last"), _) => {
                let this = flag == "--all";
                if all.is_some_and(|a| a != this) {
                    return invalid("choose one of --last or --all");
                }
                all = Some(this);
            }
            Tok::Flag("--json", _) => json = true,
            Tok::Flag(other, _) => return invalid(&format!("unexpected flag: {other}")),
            Tok::Pos(p) => {
                return invalid(&format!(
                    "undo takes no path (got {p}); it reverts the journal, newest first"
                ));
            }
        }
    }
    Command::Undo {
        all: all.unwrap_or(false),
        json,
    }
}

fn invalid(why: &str) -> Command {
    Command::Invalid {
        why: why.to_string(),
    }
}

pub const HELP_TEXT: &str = "\
usage
  meownary                          open the interactive view and pick a folder
  meownary <path>                   open the interactive view on <path>
  meownary scan <path> [flags]      scan and report, no interactive view
  meownary clean <path> <select> [flags]
                                    remove matching markers in bulk
  meownary clean <path> --deattribute [--deep] [--dry-run] [--json]
                                    write a copy with brand labels and patch
                                    credits blanked, beside each file
  meownary undo [flags]             undo the last clean (or everything)
  meownary -v, --version            print the version
  meownary -h, --help               print this

scan flags
  --json                            JSON Lines: identify, finding, done
                                    (default: human-readable text)
  --no-color                        never colorize (default: color severities
                                    only on a terminal, and never when NO_COLOR
                                    is set)
  --fail-on <info|notice|warn|alert>
                                    exit 1 when any finding reaches this
                                    severity, in any letter case (default: off)

clean flags (<select> is --deattribute, one --category, or one --signature)
  --deattribute                     save <name>.deattributed.<ext> beside each
                                    file, with brand labels and patched-by
                                    credits blanked; the original is never
                                    changed, an older copy is replaced, and
                                    copies are never used as sources
                                    zip, tar and tar.gz: deattributes the
                                    files inside
                                    includes weak hits; exclusive with
                                    --category, --signature, --marker, --file,
                                    --force
                                    prints paths, kinds, counts, and safe
                                    offsets; never matched text, titles,
                                    notes, evidence, or signature ids
  --deep                            with --deattribute: also sweep data
                                    strings (PE, ELF, Mach-O, text), the PE
                                    export DLL name, PDB path, and timestamps;
                                    may break loading or licensing
  --category <slug>                 select findings by category: identity,
                                    brand, integrity, tamper, deception,
                                    bundleware, junk
  --signature <id>                  select findings by exact signature id
  --marker                          scrub just the marker bytes (default)
  --file                            delete whole files that carry a match
                                    (a warn-level edit, so it needs --force)
  --dry-run                         run every safety check and report what
                                    would change, touch nothing (default: off)
  --force                           allow warn-level edits and weak findings;
                                    refused edits stay refused (default: off)
  --json                            JSON Lines: would_clean, cleaned, skipped,
                                    done, plus would_save, saved, and caveat
                                    with --deattribute (default: human-readable
                                    text)

undo flags
  --last                            undo the most recent clean (default)
  --all                             undo everything in the journal
  --json                            JSON Lines: undone, done (default: text)

other
  --                                end of options; later arguments are paths
  MEOWNARY_STATE_DIR                where the trash store and undo journal live
                                    (default: the platform data directory)
  NO_COLOR                          set and non-empty: never colorize

exit codes
  0    ok
  1    scan --fail-on threshold met; clean matched findings but applied none;
       undo failed; the interactive view failed
  2    usage error: bad command, flag, or value, or a path that does not exist
  73   the state store could not be opened or created, or another meownary
       holds it (no edit attempted)
  75   some files could not be fully scanned (partial results); --deattribute
       also counts a copy it could not write or verify, and there 75 wins
       over 1 (elsewhere 1 wins)
  101  internal error (please report it)
  130  interrupted by Ctrl-C (as reported by the shell)

every scrub or delete copies the original to meownary's trash first; `undo`
puts it back. --deattribute only writes copies, so it has nothing to undo.
symbolic links are not followed; meownary's state directory is never scanned.
";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{BrandKind, Category, DeceptionKind, JunkKind, SignatureStatus, TamperKind};

    fn p(args: &[&str]) -> Command {
        let v: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        parse(&v)
    }

    fn why(cmd: Command) -> String {
        match cmd {
            Command::Invalid { why } => why,
            other => panic!("expected a usage error, got {other:?}"),
        }
    }

    /// `flag` appears in `text` as a whole token.
    fn mentions(text: &str, flag: &str) -> bool {
        text.match_indices(flag).any(|(i, _)| {
            let before = text[..i].chars().next_back();
            let after = text[i + flag.len()..].chars().next();
            before.is_none_or(|c| c.is_whitespace() || "[(|,".contains(c))
                && after.is_none_or(|c| !(c.is_alphanumeric() || c == '-' || c == '_'))
        })
    }

    #[test]
    fn every_accepted_flag_is_in_help() {
        for flag in TOP_FLAGS
            .iter()
            .chain(SCAN_FLAGS)
            .chain(CLEAN_FLAGS)
            .chain(UNDO_FLAGS)
        {
            assert!(
                mentions(HELP_TEXT, flag.name),
                "{} is missing from HELP_TEXT",
                flag.name
            );
        }
        assert!(mentions(HELP_TEXT, "--"));
    }

    #[test]
    fn every_exit_code_is_in_help() {
        let section = HELP_TEXT.split("exit codes\n").nth(1).unwrap();
        for code in [
            exit::OK,
            exit::FINDINGS,
            exit::USAGE,
            exit::NO_TRASH,
            exit::PARTIAL,
            exit::INTERNAL,
            exit::INTERRUPTED,
        ] {
            let prefix = format!("  {code} ");
            assert!(
                section.lines().any(|l| l.starts_with(&prefix)),
                "exit code {code} is missing from HELP_TEXT"
            );
        }
    }

    #[test]
    fn help_lines_fit_80_columns() {
        for line in HELP_TEXT.lines() {
            assert!(line.chars().count() <= 80, "too wide: {line}");
        }
    }

    #[test]
    fn categories_match_the_model_slugs() {
        let all = [
            Category::Identity {
                declared_ext: None,
                true_format: String::new(),
                mismatch: false,
            },
            Category::Brand(BrandKind::Vendor),
            Category::Integrity(SignatureStatus::Present),
            Category::Tamper(TamperKind::Patched),
            Category::Deception(DeceptionKind::Rtlo),
            Category::Bundleware,
            Category::Junk(JunkKind::Exif),
        ];
        let slugs: Vec<&str> = all.iter().map(Category::slug).collect();
        assert_eq!(slugs, CATEGORIES);
    }

    fn tui(path: &str) -> Command {
        Command::Tui {
            path: Some(PathBuf::from(path)),
        }
    }

    #[test]
    fn bare_opens_the_view_on_the_folder_picker() {
        assert_eq!(p(&[]), Command::Tui { path: None });
        assert_eq!(p(&["--"]), Command::Tui { path: None });
        assert_eq!(parse_os(&[]), Command::Tui { path: None });
    }

    #[test]
    fn a_path_opens_the_view_on_it() {
        assert_eq!(p(&["dir"]), tui("dir"));
        assert_eq!(p(&["dl"]), tui("dl"));
        assert_eq!(p(&["--", "scan"]), tui("scan"));
        assert_eq!(p(&["--", "-odd"]), tui("-odd"));
        assert_eq!(p(&["-"]), tui("-"));
        assert!(why(p(&[""])).contains("empty"));
    }

    #[test]
    fn help_usage_names_every_entry_point() {
        for line in [
            "  meownary                          open the interactive view and pick a folder",
            "  meownary <path>                   open the interactive view on <path>",
            "  meownary scan <path> [flags]      scan and report, no interactive view",
        ] {
            assert!(HELP_TEXT.lines().any(|l| l == line), "missing: {line}");
        }
        assert!(!HELP_TEXT.contains("current directory"));
        assert!(!HELP_TEXT.contains("[<path>]"));
    }

    #[test]
    fn help_descriptions_share_one_column() {
        let body = HELP_TEXT.split("exit codes\n").next().unwrap();
        for line in body.lines() {
            let Some(entry) = line.strip_prefix("  ") else {
                continue;
            };
            if entry.starts_with(' ') {
                continue;
            }
            let Some(gap) = entry.find("  ") else {
                continue;
            };
            let desc = 2 + gap + (entry.len() - gap - entry[gap..].trim_start().len());
            assert_eq!(desc, 36, "misaligned: {line}");
        }
    }

    #[test]
    fn second_positional_hints_at_scan() {
        let w = why(p(&["dl", "--json"]));
        assert!(w.contains("did you mean `meownary scan dl --json`?"), "{w}");
        let w = why(p(&["dl", "--fail-on=warn"]));
        assert!(w.contains("did you mean `meownary scan"), "{w}");
        let w = why(p(&["dl", "other"]));
        assert!(w.contains("unexpected argument: other"), "{w}");
        assert!(!w.contains("did you mean"), "{w}");
        let w = why(p(&["--bogus"]));
        assert_eq!(w, "unknown option: --bogus");
    }

    #[test]
    fn version_and_help() {
        assert_eq!(p(&["--version"]), Command::Version);
        assert_eq!(p(&["-v"]), Command::Version);
        assert_eq!(p(&["--help"]), Command::Help);
        assert_eq!(p(&["-h"]), Command::Help);
        assert_eq!(p(&["scan", "--help"]), Command::Help);
        assert_eq!(p(&["clean", "-h"]), Command::Help);
        assert_eq!(p(&["undo", "--help"]), Command::Help);
        assert!(why(p(&["--version", "x"])).contains("no arguments"));
        assert!(why(p(&["--version=1"])).contains("does not take a value"));
    }

    #[test]
    fn scan_flags() {
        assert_eq!(
            p(&["scan", "dl", "--json", "--no-color", "--fail-on", "WARN"]),
            Command::Scan {
                path: PathBuf::from("dl"),
                json: true,
                no_color: true,
                fail_on: Some(Severity::Warn)
            }
        );
        assert_eq!(
            p(&["scan", "--fail-on=Alert", "--", "-dash"]),
            Command::Scan {
                path: PathBuf::from("-dash"),
                json: false,
                no_color: false,
                fail_on: Some(Severity::Alert)
            }
        );
        assert_eq!(
            p(&["scan", "--", "scan"]),
            Command::Scan {
                path: PathBuf::from("scan"),
                json: false,
                no_color: false,
                fail_on: None
            }
        );
    }

    #[test]
    fn scan_usage_errors() {
        assert_eq!(why(p(&["scan"])), "scan needs a path");
        assert_eq!(why(p(&["scan", "--json"])), "scan needs a path");
        assert_eq!(why(p(&["scan", "--fail-on", "warn"])), "scan needs a path");
        assert_eq!(why(p(&["scan", "--"])), "scan needs a path");
        assert!(why(p(&["scan", "--fail-on"])).contains("needs a value"));
        assert!(why(p(&["scan", "--fail-on", "loud"])).contains("info, notice, warn, or alert"));
        assert!(why(p(&["scan", "--fail-on", "--json"])).contains("got the option --json"));
        assert!(why(p(&["scan", "--fail-on="])).contains("needs a value"));
        assert!(
            why(p(&["scan", "--fail-on", "warn", "--fail-on", "info"])).contains("more than once")
        );
        assert!(why(p(&["scan", "--json=yes"])).contains("does not take a value"));
        assert!(why(p(&["scan", "--no-color=1"])).contains("does not take a value"));
        assert!(why(p(&["scan", "a", "b"])).contains("one path"));
        assert!(why(p(&["scan", "--bogus"])).contains("unknown scan option: --bogus"));
        assert!(why(p(&["scan", "--file"])).contains("unknown scan option"));
        assert!(why(p(&["scan", ""])).contains("empty"));
    }

    #[test]
    fn clean_parses_selectors_and_units() {
        assert_eq!(
            p(&["clean", "dl", "--category", "JUNK", "--dry-run"]),
            Command::Clean {
                path: PathBuf::from("dl"),
                selector: CleanSelector::Category("junk".into()),
                unit: CleanUnit::Marker,
                dry_run: true,
                force: false,
                json: false
            }
        );
        assert_eq!(
            p(&[
                "clean",
                "--signature=identity.ext_mismatch",
                "--file",
                "--force",
                "--json",
                "dl"
            ]),
            Command::Clean {
                path: PathBuf::from("dl"),
                selector: CleanSelector::Signature("identity.ext_mismatch".into()),
                unit: CleanUnit::File,
                dry_run: false,
                force: true,
                json: true
            }
        );
    }

    #[test]
    fn clean_usage_errors() {
        let w = why(p(&["clean", "dl", "--category", "nope"]));
        assert!(w.contains("unknown category: nope"), "{w}");
        for slug in CATEGORIES {
            assert!(w.contains(slug), "{w}");
        }
        assert!(
            why(p(&["clean", "dl", "--category", "--force"])).contains("got the option --force")
        );
        assert!(why(p(&["clean", "dl", "--signature"])).contains("needs a value"));
        assert!(
            why(p(&["clean", "dl", "--force=yes", "--category", "junk"]))
                .contains("does not take a value")
        );
        assert!(why(p(&["clean", "--category", "junk"])).contains("needs a path"));
        assert!(
            why(p(&["clean", "dl"]))
                .contains("--deattribute, --category <slug>, or --signature <id>")
        );
        assert!(
            why(p(&[
                "clean",
                "dl",
                "--category",
                "junk",
                "--signature",
                "x.y"
            ]))
            .contains("choose one")
        );
        assert!(
            why(p(&[
                "clean",
                "dl",
                "--category",
                "junk",
                "--file",
                "--marker"
            ]))
            .contains("--marker or --file")
        );
        assert!(why(p(&["clean", "a", "b", "--category", "junk"])).contains("one path"));
        assert!(
            why(p(&[
                "clean",
                "dl",
                "--category",
                "junk",
                "--fail-on",
                "warn"
            ]))
            .contains("unknown clean option")
        );
        assert!(why(p(&["clean", "dl", "--", "--category", "junk"])).contains("one path"));
    }

    #[test]
    fn deep_needs_deattribute_in_either_order() {
        for args in [
            &["clean", "dl", "--deattribute", "--deep"][..],
            &["clean", "dl", "--deep", "--deattribute"],
        ] {
            assert_eq!(
                p(args),
                Command::Clean {
                    path: PathBuf::from("dl"),
                    selector: CleanSelector::DeepDeattribute,
                    unit: CleanUnit::Marker,
                    dry_run: false,
                    force: false,
                    json: false
                }
            );
        }
        assert!(why(p(&["clean", "dl", "--deep"])).contains("--deep requires --deattribute"));
        assert!(
            why(p(&["clean", "dl", "--deep", "--category", "junk"]))
                .contains("--deep requires --deattribute")
        );
        assert!(
            why(p(&["clean", "dl", "--deep", "--deattribute", "--force"]))
                .contains("does not use --force")
        );
        assert!(
            why(p(&["clean", "dl", "--deep", "--deattribute", "--file"]))
                .contains("cannot be combined with --file")
        );
    }

    #[test]
    fn deattribute_rejects_a_repeat_and_unit_flags() {
        assert!(
            why(p(&["clean", "dl", "--deattribute", "--deattribute"]))
                .contains("--deattribute given more than once")
        );
        assert!(
            why(p(&["clean", "dl", "--deattribute", "--marker"]))
                .contains("cannot be combined with --marker")
        );
        assert!(
            why(p(&["clean", "dl", "--file", "--deattribute"]))
                .contains("cannot be combined with --file")
        );
        assert!(
            why(p(&["clean", "dl", "--deattribute", "--category", "junk"])).contains("choose one")
        );
    }

    #[test]
    fn undo_flags() {
        assert_eq!(
            p(&["undo"]),
            Command::Undo {
                all: false,
                json: false
            }
        );
        assert_eq!(
            p(&["undo", "--all", "--json"]),
            Command::Undo {
                all: true,
                json: true
            }
        );
        assert_eq!(
            p(&["undo", "--last"]),
            Command::Undo {
                all: false,
                json: false
            }
        );
        assert!(why(p(&["undo", "--all", "--last"])).contains("--last or --all"));
        assert!(why(p(&["undo", "dl"])).contains("takes no path"));
        assert!(why(p(&["undo", "--bogus"])).contains("unknown undo option"));
    }

    #[test]
    fn parse_os_matches_parse_for_unicode() {
        let raw: Vec<OsString> = ["scan", "dl", "--json"]
            .iter()
            .map(OsString::from)
            .collect();
        assert_eq!(parse_os(&raw), p(&["scan", "dl", "--json"]));
    }

    #[cfg(unix)]
    #[test]
    fn parse_os_keeps_non_utf8_path_bytes() {
        use std::os::unix::ffi::OsStringExt;
        let bad = OsString::from_vec(vec![b'd', 0xff, b'l']);
        let raw = vec![
            OsString::from("scan"),
            bad.clone(),
            OsString::from("--json"),
        ];
        match parse_os(&raw) {
            Command::Scan { path, json, .. } => {
                assert!(json);
                assert_eq!(path.as_os_str(), bad.as_os_str());
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn lone_dash_is_a_path() {
        assert_eq!(
            p(&["scan", "-"]),
            Command::Scan {
                path: PathBuf::from("-"),
                json: false,
                no_color: false,
                fail_on: None
            }
        );
    }
}
