//! meownary binary: parse the command line and dispatch. The engine and runners
//! live in the library crate.

use std::path::Path;
use std::process::ExitCode;

use meownary::cli::{self, Command};

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let code = match cli::parse(&argv) {
        Command::Version => {
            println!("meownary {}", env!("CARGO_PKG_VERSION"));
            cli::exit::OK
        }
        Command::Help => {
            println!("{}", cli::HELP_TEXT);
            cli::exit::OK
        }
        Command::Invalid { why } => {
            eprintln!("{why}\n");
            eprintln!("{}", cli::HELP_TEXT);
            cli::exit::USAGE
        }
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
        Command::Undo { all } => cli::headless::run_undo(all),
        Command::Tui { path } => run_tui(&path),
    };
    ExitCode::from(code as u8)
}

#[cfg(feature = "tui")]
fn run_tui(path: &Path) -> i32 {
    match meownary::tui::run(path) {
        Ok(()) => cli::exit::OK,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

#[cfg(not(feature = "tui"))]
fn run_tui(path: &Path) -> i32 {
    // Built without the interactive view: fall back to a plain scan.
    meownary::cli::headless::run_scan(path, false, false, None)
}
