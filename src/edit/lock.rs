//! The state-dir lock. One meownary process at a time may write the journal or
//! the trash store, so two runs can never interleave journal records.
//!
//! The lock is a file created with `create_new`, holding the owner's pid, a
//! timestamp and a random token. The owner refreshes the timestamp on every
//! mutating call and removes the file on drop. A lock whose timestamp is more
//! than [`STALE_AFTER`] seconds old is treated as abandoned (a crashed run)
//! and taken over. Liveness is judged by the timestamp alone, so two engines
//! in one process exclude each other as well.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use super::fsio;

/// Seconds after which an unrefreshed lock is considered abandoned.
pub const STALE_AFTER: u64 = 60 * 60;

/// The lock file name inside the state dir.
pub const LOCK_NAME: &str = "meownary.lock";

/// Who holds a lock, as read from its file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Holder {
    pub pid: Option<u32>,
    pub ts: Option<u64>,
    token: Option<String>,
}

impl Holder {
    /// A short human description ("pid 1234, 12s ago").
    pub fn describe(&self) -> String {
        let pid = self
            .pid
            .map(|p| format!("pid {p}"))
            .unwrap_or_else(|| "unknown pid".to_string());
        match self.ts {
            Some(ts) => format!("{pid}, {}s ago", fsio::now_secs().saturating_sub(ts)),
            None => pid,
        }
    }
}

/// Why a lock could not be taken.
#[derive(Debug)]
pub enum LockError {
    /// Another live owner holds it.
    Held(Holder),
    Io(io::Error),
}

/// A held lock. Removed on drop if it is still ours.
#[derive(Debug)]
pub struct LockFile {
    path: PathBuf,
    token: String,
}

impl LockFile {
    /// Take the lock in `dir`, taking over an abandoned one.
    pub fn acquire(dir: &Path) -> Result<LockFile, LockError> {
        fs::create_dir_all(dir).map_err(LockError::Io)?;
        let path = dir.join(LOCK_NAME);
        let token = fsio::unique_tag();
        for _ in 0..3 {
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut f) => {
                    let body = body(&token);
                    let res = f.write_all(body.as_bytes()).and_then(|_| f.sync_all());
                    if let Err(e) = res {
                        drop(f);
                        let _ = fs::remove_file(&path);
                        return Err(LockError::Io(e));
                    }
                    return Ok(LockFile { path, token });
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    let holder = read_holder(&path);
                    if is_stale(&path, &holder) {
                        let _ = fs::remove_file(&path);
                        continue;
                    }
                    return Err(LockError::Held(holder));
                }
                Err(e) => return Err(LockError::Io(e)),
            }
        }
        Err(LockError::Held(read_holder(&path)))
    }

    /// Whether the file on disk still names us as the owner.
    pub fn still_ours(&self) -> bool {
        read_holder(&self.path).token.as_deref() == Some(self.token.as_str())
    }

    /// Refresh the timestamp so a long session is never mistaken for a
    /// crashed one. Returns false if the lock is no longer ours.
    pub fn refresh(&self) -> bool {
        if !self.still_ours() {
            return false;
        }
        fs::write(&self.path, body(&self.token)).is_ok()
    }

    /// Where the lock file lives.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for LockFile {
    fn drop(&mut self) {
        if self.still_ours() {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn body(token: &str) -> String {
    format!(
        "pid={}\nts={}\ntoken={token}\n",
        std::process::id(),
        fsio::now_secs()
    )
}

fn read_holder(path: &Path) -> Holder {
    let text = fs::read_to_string(path).unwrap_or_default();
    let mut h = Holder {
        pid: None,
        ts: None,
        token: None,
    };
    for line in text.lines() {
        if let Some((k, v)) = line.split_once('=') {
            match k.trim() {
                "pid" => h.pid = v.trim().parse().ok(),
                "ts" => h.ts = v.trim().parse().ok(),
                "token" => h.token = Some(v.trim().to_string()),
                _ => {}
            }
        }
    }
    h
}

fn is_stale(path: &Path, holder: &Holder) -> bool {
    let now = fsio::now_secs();
    let ts = holder.ts.or_else(|| {
        fs::metadata(path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
    });
    match ts {
        Some(ts) => now.saturating_sub(ts) > STALE_AFTER,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclusive_then_released() {
        let dir = tempfile::tempdir().unwrap();
        let a = LockFile::acquire(dir.path()).unwrap();
        match LockFile::acquire(dir.path()) {
            Err(LockError::Held(h)) => assert_eq!(h.pid, Some(std::process::id())),
            other => panic!("expected Held, got {other:?}"),
        }
        assert!(a.refresh());
        drop(a);
        assert!(!dir.path().join(LOCK_NAME).exists());
        let _b = LockFile::acquire(dir.path()).unwrap();
    }

    #[test]
    fn stale_lock_is_taken_over() {
        let dir = tempfile::tempdir().unwrap();
        let old = fsio::now_secs() - STALE_AFTER - 10;
        fs::write(
            dir.path().join(LOCK_NAME),
            format!("pid=1\nts={old}\ntoken=x\n"),
        )
        .unwrap();
        let lock = LockFile::acquire(dir.path()).unwrap();
        assert!(lock.still_ours());
    }
}
