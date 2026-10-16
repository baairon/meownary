//! Open a file in the user's external editor and block until it exits. The
//! engine snapshots the file first and compares hashes afterward, so a save is
//! recorded as an undoable change and a no-op edit leaves no trace.
//!
//! The editor comes from `$VISUAL`, then `$EDITOR`, else `notepad` on Windows
//! and `vi` elsewhere. The value is split like a simple shell word list:
//! whitespace separates words, and single or double quotes group a word that
//! contains spaces, so `"C:\Program Files\Editor\ed.exe" --wait` works.
//! Backslashes are literal, which keeps Windows paths intact.

use std::io;
use std::path::Path;
use std::process::{Command, ExitStatus};

/// The fallback editor when neither variable is set.
pub const FALLBACK_EDITOR: &str = if cfg!(windows) { "notepad" } else { "vi" };

/// Resolve the editor command: `$VISUAL`, then `$EDITOR`, else `notepad` on
/// Windows and `vi` elsewhere. The string may carry arguments ("code --wait").
pub fn editor_command() -> String {
    let visual = std::env::var("VISUAL").ok();
    let editor = std::env::var("EDITOR").ok();
    editor_command_from(visual.as_deref(), editor.as_deref())
}

/// The pure core of [`editor_command`]: the first non-blank of `visual` and
/// `editor`, else the platform fallback.
pub fn editor_command_from(visual: Option<&str>, editor: Option<&str>) -> String {
    [visual, editor]
        .into_iter()
        .flatten()
        .find(|v| !v.trim().is_empty())
        .map(|v| v.trim().to_string())
        .unwrap_or_else(|| FALLBACK_EDITOR.to_string())
}

/// Split a command line into words. Whitespace separates words; a single- or
/// double-quoted run is part of one word (quotes removed); an unclosed quote
/// runs to the end. Backslashes have no special meaning.
pub fn split_command(cmd: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut quote: Option<char> = None;
    for c in cmd.chars() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => cur.push(c),
            None if c == '"' || c == '\'' => {
                quote = Some(c);
                in_word = true;
            }
            None if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            None => {
                cur.push(c);
                in_word = true;
            }
        }
    }
    if in_word {
        words.push(cur);
    }
    words
}

/// Spawn the editor on `path` and wait.
pub fn spawn_editor(path: &Path) -> io::Result<ExitStatus> {
    spawn_command(&editor_command(), path)
}

/// Spawn `cmd` (split with [`split_command`]) with `path` appended, and wait.
/// On Windows, a bare program name that is not found is retried with `.cmd`
/// and `.bat`, so editors installed as script shims (`code`) still open.
pub fn spawn_command(cmd: &str, path: &Path) -> io::Result<ExitStatus> {
    let mut words = split_command(cmd);
    if words.is_empty() {
        words.push(FALLBACK_EDITOR.to_string());
    }
    let prog = words.remove(0);
    let run = |program: &str| Command::new(program).args(&words).arg(path).status();
    match run(&prog) {
        Err(e) if e.kind() == io::ErrorKind::NotFound && cfg!(windows) && !has_ext(&prog) => {
            for ext in ["cmd", "bat"] {
                if let Ok(status) = run(&format!("{prog}.{ext}")) {
                    return Ok(status);
                }
            }
            Err(e)
        }
        other => other,
    }
}

fn has_ext(prog: &str) -> bool {
    Path::new(prog).extension().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visual_then_editor_then_fallback() {
        assert_eq!(
            editor_command_from(Some("code --wait"), Some("vim")),
            "code --wait"
        );
        assert_eq!(editor_command_from(Some("   "), Some("nano")), "nano");
        assert_eq!(editor_command_from(None, Some(" hx ")), "hx");
        assert_eq!(editor_command_from(None, None), FALLBACK_EDITOR);
        assert_eq!(editor_command_from(Some(""), Some("")), FALLBACK_EDITOR);
    }

    #[test]
    fn splits_quotes_and_spaces() {
        assert_eq!(split_command("code --wait"), vec!["code", "--wait"]);
        assert_eq!(
            split_command(r#""C:\Program Files\Ed It\ed.exe" -n  --x"#),
            vec![r"C:\Program Files\Ed It\ed.exe", "-n", "--x"]
        );
        assert_eq!(
            split_command("'/opt/my editor/bin/ed' +1"),
            vec!["/opt/my editor/bin/ed", "+1"]
        );
        assert_eq!(
            split_command(r#"ed --title="a b""#),
            vec!["ed", "--title=a b"]
        );
        assert_eq!(split_command(r#""unclosed path"#), vec!["unclosed path"]);
        assert_eq!(split_command(r#"ed """#), vec!["ed", ""]);
        assert!(split_command("   ").is_empty());
    }

    #[test]
    fn missing_program_is_an_error_not_a_panic() {
        let err = spawn_command("meownary-no-such-editor-xyz", Path::new("f")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }
}
