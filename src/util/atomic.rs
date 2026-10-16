//! Atomic whole-file replacement (write to a temp sibling, fsync, rename).
//! Used by structural container rewrites so a crash can never leave a
//! half-written file in place.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Distinguishes temp files written by concurrent calls in one process.
static SEQ: AtomicU64 = AtomicU64::new(0);

/// Replace `path`'s contents with `data` atomically on the same volume. On Unix
/// the replacement keeps the original file's mode (an executable stays
/// executable). On failure the temp file is removed and `path` is untouched.
pub fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let tmp = temp_sibling(path);
    let result = write_then_rename(path, &tmp, data);
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn temp_sibling(path: &Path) -> PathBuf {
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    dir.join(format!(".meownary.tmp.{}.{seq}", std::process::id()))
}

fn write_then_rename(path: &Path, tmp: &Path, data: &[u8]) -> io::Result<()> {
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    // Unix mode bits carry meaning (an executable must stay executable). On
    // Windows the only bit is read-only, and copying it would block the rename.
    #[cfg(unix)]
    if let Ok(meta) = fs::metadata(path) {
        fs::set_permissions(tmp, meta.permissions())?;
    }
    fs::rename(tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leftovers(dir: &Path) -> Vec<String> {
        fs::read_dir(dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(".meownary.tmp."))
            .collect()
    }

    #[test]
    fn replaces_contents_and_leaves_no_temp() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f.bin");
        fs::write(&p, b"old contents").unwrap();
        write_atomic(&p, b"new").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"new");
        assert!(leftovers(dir.path()).is_empty());
    }

    #[test]
    fn creates_a_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("fresh.jsonl");
        write_atomic(&p, b"line\n").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"line\n");
    }

    #[test]
    fn failure_cleans_up_the_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        // Renaming a file over a directory fails on every platform.
        let target = dir.path().join("taken");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("inside"), b"x").unwrap();
        assert!(write_atomic(&target, b"data").is_err());
        assert!(leftovers(dir.path()).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn keeps_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("tool");
        fs::write(&p, b"#!/bin/sh\n").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        write_atomic(&p, b"#!/bin/sh\necho hi\n").unwrap();
        let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
    }
}
