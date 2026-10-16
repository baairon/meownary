//! Helpers shared by the CLI integration tests: run the real binary against a
//! private state directory and synthetic files, and read its output.

#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::Value;
use tempfile::TempDir;

/// The bytes of a tiny executable stand-in: enough for identity to call it PE.
pub fn mz_bytes() -> Vec<u8> {
    let mut v = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00".to_vec();
    v.resize(256, 0);
    v
}

/// A command for the meownary binary whose state lives in `state`.
pub fn meownary(state: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_meownary"));
    cmd.env("MEOWNARY_STATE_DIR", state)
        .env_remove("RUST_BACKTRACE")
        .stdin(Stdio::null());
    cmd
}

/// One finished run.
pub struct Run {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl Run {
    /// Parse stdout as JSON Lines, failing the test on any malformed line.
    pub fn events(&self) -> Vec<Value> {
        self.stdout
            .lines()
            .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("not JSON ({e}): {l}")))
            .collect()
    }

    pub fn assert_code(&self, want: i32) -> &Self {
        assert_eq!(
            self.code,
            Some(want),
            "exit code\n--- stdout\n{}\n--- stderr\n{}",
            self.stdout,
            self.stderr
        );
        self
    }
}

/// Run meownary with `args` against the state dir `state`.
pub fn run(state: &Path, args: &[&str]) -> Run {
    run_in(state, None, args)
}

/// [`run`], optionally from working directory `cwd`.
pub fn run_in(state: &Path, cwd: Option<&Path>, args: &[&str]) -> Run {
    let mut cmd = meownary(state);
    cmd.args(args);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    let out = cmd.output().expect("run meownary");
    Run {
        code: out.status.code(),
        stdout: String::from_utf8(out.stdout).expect("stdout is UTF-8"),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// A scratch folder plus a separate, private state directory.
pub struct Fixture {
    pub dir: TempDir,
    pub state: TempDir,
}

impl Fixture {
    /// The standard tree: an `MZ` file named `photo.jpg`, a plain text file,
    /// an empty file, and a nested directory with one more text file.
    pub fn standard() -> Self {
        let fx = Self::empty();
        let p = fx.dir.path();
        fs::write(p.join("photo.jpg"), mz_bytes()).unwrap();
        fs::write(p.join("notes.txt"), b"just some notes\n").unwrap();
        fs::write(p.join("empty.bin"), b"").unwrap();
        fs::create_dir_all(p.join("sub").join("deeper")).unwrap();
        fs::write(
            p.join("sub").join("deeper").join("inner.txt"),
            b"nested text\n",
        )
        .unwrap();
        fx
    }

    pub fn empty() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
            state: tempfile::tempdir().unwrap(),
        }
    }

    pub fn root(&self) -> &str {
        self.dir.path().to_str().expect("temp path is UTF-8")
    }

    pub fn path(&self, rel: &str) -> PathBuf {
        rel.split('/')
            .fold(self.dir.path().to_path_buf(), |p, c| p.join(c))
    }

    /// The path as meownary prints it (the root joined with each component).
    pub fn shown(&self, rel: &str) -> String {
        self.path(rel).to_string_lossy().into_owned()
    }

    pub fn run(&self, args: &[&str]) -> Run {
        run(self.state.path(), args)
    }
}

/// Events of one kind.
pub fn of_kind<'a>(events: &'a [Value], kind: &str) -> Vec<&'a Value> {
    events.iter().filter(|e| e["event"] == kind).collect()
}
