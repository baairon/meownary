//! meownary binary: parse the command line and dispatch. The engine and runners
//! live in the library crate.

use std::any::Any;
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use meownary::cli::{self, Command, exit};

/// Where internal errors should be reported.
const ISSUES: &str = "https://github.com/baairon/meownary/issues";

fn main() -> ExitCode {
    install_panic_hook();
    let argv: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let code = match cli::args::parse_os(&argv) {
        Command::Version => {
            print_out(&format!("meownary {}\n", env!("CARGO_PKG_VERSION")));
            exit::OK
        }
        Command::Help => {
            print_out(cli::HELP_TEXT);
            exit::OK
        }
        Command::Invalid { why } => usage_error(&why),
        Command::Scan {
            path,
            json,
            no_color,
            fail_on,
        } => cli::headless::run_scan(&path, json, no_color, fail_on),
        Command::Clean {
            path,
            selector,
            unit,
            dry_run,
            force,
            json,
        } => cli::headless::run_clean(&path, &selector, unit, dry_run, force, json),
        Command::Undo { all, json } => cli::headless::run_undo(all, json),
        Command::Tui { path } => run_tui(path.as_deref()),
    };
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}

/// Report a usage error with a pointer to `--help`.
fn usage_error(why: &str) -> i32 {
    print_err(&format!(
        "meownary: {why}\nrun `meownary --help` for usage\n"
    ));
    exit::USAGE
}

/// Write to stdout, ignoring a closed pipe (`meownary --help | head -1`).
fn print_out(text: &str) {
    let mut out = io::stdout().lock();
    let _ = out.write_all(text.as_bytes());
    let _ = out.flush();
}

fn print_err(text: &str) {
    let mut err = io::stderr().lock();
    let _ = err.write_all(text.as_bytes());
}

/// One line per internal error, with a backtrace only when `RUST_BACKTRACE`
/// asks for one. Panics inside the per-file scan guard stay silent: the guard
/// catches them and the file is reported as partial (`probe panicked`).
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        if meownary::scan::guard::in_guard() {
            return;
        }
        let msg = payload_message(info.payload());
        let mut err = io::stderr().lock();
        let _ = writeln!(
            err,
            "meownary: internal error: {msg} (please report at {ISSUES})"
        );
        if backtrace_wanted() {
            if let Some(loc) = info.location() {
                let _ = writeln!(err, "at {}:{}:{}", loc.file(), loc.line(), loc.column());
            }
            let _ = writeln!(err, "{}", std::backtrace::Backtrace::force_capture());
        }
    }));
}

fn payload_message(payload: &(dyn Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic".to_string()
    }
}

fn backtrace_wanted() -> bool {
    std::env::var_os("RUST_BACKTRACE").is_some_and(|v| !v.is_empty() && v != "0")
}

/// Open the interactive view: `None` starts on the folder picker, `Some`
/// opens straight on that path.
#[cfg(feature = "tui")]
fn run_tui(path: Option<&Path>) -> i32 {
    if let Some(why) = path.and_then(cli::headless::missing_path) {
        print_err(&format!("meownary: {why}\n"));
        return exit::USAGE;
    }
    match meownary::tui::run(path) {
        Ok(()) => exit::OK,
        Err(e) => {
            print_err(&format!("meownary: the interactive view failed: {e}\n"));
            exit::FINDINGS
        }
    }
}

/// Built without the interactive view: a path falls back to a plain scan, and
/// there is no folder picker, so a bare `meownary` needs a path.
#[cfg(not(feature = "tui"))]
fn run_tui(path: Option<&Path>) -> i32 {
    match path {
        Some(path) => cli::headless::run_scan(path, false, false, None),
        None => {
            usage_error("this build has no interactive view, so it needs a path: meownary <path>")
        }
    }
}
