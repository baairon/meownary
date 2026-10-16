//! Terminal styling for human output. Color marks severity only, and only when
//! stdout is a terminal that understands ANSI escapes, `NO_COLOR` is unset or
//! empty, and `--no-color` was not given. JSON output is never styled.

use std::ffi::OsStr;
use std::io::{self, IsTerminal};

use crate::model::Severity;

/// Whether to emit ANSI color, decided once per run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Style {
    color: bool,
}

impl Style {
    /// Never color.
    pub fn plain() -> Self {
        Self { color: false }
    }

    /// Decide from the environment: stdout must be a terminal, `NO_COLOR`
    /// unset or empty, and `no_color_flag` (the `--no-color` flag) false.
    pub fn detect(no_color_flag: bool) -> Self {
        let env = std::env::var_os("NO_COLOR");
        let tty = io::stdout().is_terminal();
        Self {
            color: color_allowed(no_color_flag, env.as_deref(), tty) && ansi_ok(),
        }
    }

    pub fn enabled(&self) -> bool {
        self.color
    }

    /// Wrap `text` in the color for `severity`. Pad before calling so the
    /// escape codes never disturb column alignment.
    pub fn severity(&self, severity: Severity, text: &str) -> String {
        match (self.color, severity_code(severity)) {
            (true, Some(code)) => format!("\x1b[{code}m{text}\x1b[0m"),
            _ => text.to_string(),
        }
    }
}

/// The policy half of [`Style::detect`], kept pure so it can be tested.
pub fn color_allowed(no_color_flag: bool, no_color_env: Option<&OsStr>, stdout_tty: bool) -> bool {
    !no_color_flag && stdout_tty && no_color_env.is_none_or(OsStr::is_empty)
}

/// SGR parameters per severity; info stays in the terminal's default color.
fn severity_code(s: Severity) -> Option<&'static str> {
    match s {
        Severity::Info => None,
        Severity::Notice => Some("36"),
        Severity::Warn => Some("33"),
        Severity::Alert => Some("1;31"),
    }
}

/// Whether the terminal will interpret escapes rather than print them.
#[cfg(all(windows, feature = "tui"))]
fn ansi_ok() -> bool {
    // Enables virtual terminal processing on the console when it can.
    crossterm::ansi_support::supports_ansi()
}

#[cfg(all(windows, not(feature = "tui")))]
fn ansi_ok() -> bool {
    // Without a console API to enable escapes, trust terminals that announce
    // themselves (Windows Terminal, mintty, and other emulators set these).
    std::env::var_os("WT_SESSION").is_some()
        || std::env::var_os("TERM").is_some_and(|t| !t.is_empty() && t != "dumb")
}

#[cfg(not(windows))]
fn ansi_ok() -> bool {
    std::env::var_os("TERM").is_none_or(|t| t != "dumb")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn color_needs_a_terminal_and_no_opt_out() {
        assert!(color_allowed(false, None, true));
        assert!(color_allowed(false, Some(OsStr::new("")), true));
        assert!(!color_allowed(false, Some(OsStr::new("1")), true));
        assert!(!color_allowed(true, None, true));
        assert!(!color_allowed(false, None, false));
    }

    #[test]
    fn plain_never_adds_escapes() {
        let s = Style::plain();
        assert!(!s.enabled());
        assert_eq!(s.severity(Severity::Alert, "alert "), "alert ");
    }

    #[test]
    fn color_wraps_all_but_info() {
        let s = Style { color: true };
        assert_eq!(s.severity(Severity::Info, "info"), "info");
        assert_eq!(s.severity(Severity::Warn, "warn"), "\x1b[33mwarn\x1b[0m");
        assert_eq!(
            s.severity(Severity::Alert, "alert"),
            "\x1b[1;31malert\x1b[0m"
        );
    }
}
