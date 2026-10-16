//! The trash store. Before any edit, the original bytes (a region, a truncated
//! tail, or a whole file) are copied here so an edit is always reversible.
//!
//! Each engine gets its own session folder, created lazily on the first stash
//! and named from the pid, the wall clock in nanoseconds and a process-wide
//! counter, so two engines (even in one process) never share or collide on a
//! folder. A session folder that ends up empty is removed, both when a stash
//! is discarded and when the `Trash` is dropped.

use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

use super::fsio;
use crate::util::paths::trash_dir;

/// A per-session trash directory under a trash root.
pub struct Trash {
    root: PathBuf,
    dir: Option<PathBuf>,
    seq: u64,
}

impl Trash {
    /// A trash rooted at the default location (`util::paths::trash_dir`).
    /// Nothing is created on disk until the first stash.
    pub fn new() -> io::Result<Self> {
        Ok(Self::in_dir(trash_dir()))
    }

    /// A trash rooted at `root`. Nothing is created until the first stash.
    pub fn in_dir(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            dir: None,
            seq: 0,
        }
    }

    /// The trash root every session folder lives under.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The current session folder, if one has been created.
    pub fn session_dir(&self) -> Option<&Path> {
        self.dir.as_deref()
    }

    fn session(&mut self) -> io::Result<PathBuf> {
        if let Some(d) = &self.dir
            && d.is_dir()
        {
            return Ok(d.clone());
        }
        fs::create_dir_all(&self.root)?;
        let mut last = None;
        for _ in 0..16 {
            let d = self
                .root
                .join(format!("{}-{}", fsio::now_secs(), fsio::unique_tag()));
            match fs::create_dir(&d) {
                Ok(()) => {
                    self.dir = Some(d.clone());
                    return Ok(d);
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last = Some(e),
                Err(e) => return Err(e),
            }
        }
        Err(last.unwrap_or_else(|| io::Error::other("could not create a trash session")))
    }

    /// A fresh, not-yet-existing path in the session folder. Creates the
    /// session folder if needed.
    pub fn reserve(&mut self, suffix: &str) -> io::Result<PathBuf> {
        let dir = self.session()?;
        loop {
            self.seq += 1;
            let p = dir.join(format!("{:06}-{}", self.seq, sanitize(suffix)));
            if fs::symlink_metadata(&p).is_err() {
                return Ok(p);
            }
        }
    }

    /// Save a blob of bytes, returning the path it was written to.
    pub fn stash_bytes(&mut self, data: &[u8], suffix: &str) -> io::Result<PathBuf> {
        let p = self.reserve(suffix)?;
        let res = (|| {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&p)?;
            io::Write::write_all(&mut f, data)?;
            f.sync_all()
        })();
        match res {
            Ok(()) => Ok(p),
            Err(e) => {
                self.discard(&p);
                Err(e)
            }
        }
    }

    /// Stream `len` bytes at `offset` of `file` into a new stash, returning its
    /// path and the blake3 of the copied bytes. Never buffers the whole range.
    pub fn stash_range(
        &mut self,
        file: &File,
        offset: u64,
        len: u64,
        suffix: &str,
    ) -> io::Result<(PathBuf, String)> {
        let p = self.reserve(suffix)?;
        match fsio::copy_range_to_new(file, offset, len, &p) {
            Ok(h) => Ok((p, h)),
            Err(e) => {
                self.prune();
                Err(e)
            }
        }
    }

    /// Copy a whole file into a new stash (the original is left in place).
    pub fn stash_copy(&mut self, src: &Path, suffix: &str) -> io::Result<PathBuf> {
        let p = self.reserve(suffix)?;
        match fsio::copy_to_new(src, &p) {
            Ok(_) => Ok(p),
            Err(e) => {
                self.prune();
                Err(e)
            }
        }
    }

    /// Move an entire file into the trash (same volume: rename; else a streamed
    /// copy, fsync, then unlink).
    pub fn stash_file(&mut self, src: &Path) -> io::Result<PathBuf> {
        let base = src
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "file".to_string());
        let dst = self.reserve(&base)?;
        match move_file(src, &dst) {
            Ok(()) => Ok(dst),
            Err(e) => {
                self.prune();
                Err(e)
            }
        }
    }

    /// Remove a stash file and, if its session folder is now empty, the folder.
    pub fn discard(&mut self, p: &Path) {
        let _ = fs::remove_file(p);
        self.prune();
    }

    /// Remove the session folder if it is empty.
    fn prune(&mut self) {
        if let Some(d) = &self.dir
            && (fs::remove_dir(d).is_ok() || !d.exists())
        {
            self.dir = None;
        }
    }
}

impl Drop for Trash {
    fn drop(&mut self) {
        self.prune();
    }
}

/// Move `src` to `dst` (which must not exist): rename on the same volume, else
/// copy with `create_new`, fsync, and unlink the source.
pub(crate) fn move_file(src: &Path, dst: &Path) -> io::Result<()> {
    if fs::symlink_metadata(dst).is_ok() {
        return Err(io::ErrorKind::AlreadyExists.into());
    }
    if fs::rename(src, dst).is_ok() {
        return Ok(());
    }
    fsio::copy_to_new(src, dst)?;
    if let Err(e) = fs::remove_file(src) {
        let _ = fs::remove_file(dst);
        return Err(e);
    }
    Ok(())
}

/// Remove `dir` if it is an empty direct child of `root`.
pub(crate) fn prune_session(root: &Path, dir: &Path) {
    if dir.parent() == Some(root) {
        let _ = fs::remove_dir(dir);
    }
}

/// Keep stash names short and portable: no separators or reserved characters.
fn sanitize(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .take(80)
        .collect();
    if cleaned.is_empty() {
        "blob".to_string()
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sessions_are_lazy_unique_and_pruned() {
        let root = tempfile::tempdir().unwrap();
        let mut a = Trash::in_dir(root.path());
        let mut b = Trash::in_dir(root.path());
        assert!(a.session_dir().is_none());
        assert_eq!(
            fs::read_dir(root.path()).unwrap().count(),
            0,
            "nothing created up front"
        );

        let pa = a.stash_bytes(b"one", "x").unwrap();
        let pb = b.stash_bytes(b"two", "x").unwrap();
        assert_ne!(
            pa.parent(),
            pb.parent(),
            "two engines never share a session"
        );
        assert_eq!(fs::read(&pa).unwrap(), b"one");

        a.discard(&pa);
        assert!(a.session_dir().is_none(), "empty session folder removed");
        drop(b);
        assert_eq!(
            fs::read_dir(root.path()).unwrap().count(),
            1,
            "b keeps its non-empty session"
        );
        assert_eq!(sanitize("a/b:c"), "a_b_c");
    }
}
