//! Open a file in the user's external editor and block until it exits. The
//! engine snapshots the file first and compares hashes afterward, so a save is
//! recorded as an undoable change and a no-op edit leaves no trace.

use std::io;
use std::path::Path;
use std::process::{Command, ExitStatus};

/// Resolve the editor command: `$VISUAL`, then `$EDITOR`, else `notepad` on
/// Windows and `vi` elsewhere. The string may carry arguments ("code --wait").
pub fn editor_command() -> String {
    for var in ["VISUAL", "EDITOR"] {
        if let Ok(v) = std::env::var(var) {
            if !v.trim().is_empty() {
                return v;
            }
        }
    }
    if cfg!(windows) {
        "notepad".to_string()
    } else {
        "vi".to_string()
    }
}

/// Spawn the editor on `path` and wait. Whitespace in the command separates the
/// program from its arguments.
pub fn spawn_editor(path: &Path) -> io::Result<ExitStatus> {
    let cmd = editor_command();
    let mut parts = cmd.split_whitespace();
    let prog = parts.next().unwrap_or("notepad");
    let mut command = Command::new(prog);
    for arg in parts {
        command.arg(arg);
    }
    command.arg(path);
    command.status()
}
