//! The trash store. Before any edit, the original bytes (a region, a truncated
//! tail, or a whole file) are copied here so an edit is always reversible. Each
//! run gets its own session subdirectory.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::util::paths::trash_dir;

/// A per-session trash directory.
pub struct Trash {
    dir: PathBuf,
    seq: u64,
}

impl Trash {
    /// Create (or reuse) a session trash dir under the state dir.
    pub fn new() -> io::Result<Self> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let dir = trash_dir().join(format!("{ts}-{}", std::process::id()));
        fs::create_dir_all(&dir)?;
        Ok(Self { dir, seq: 0 })
    }

    fn next_name(&mut self, suffix: &str) -> PathBuf {
        self.seq += 1;
        self.dir.join(format!("{:06}-{suffix}", self.seq))
    }

    /// Save a blob of bytes, returning the path it was written to.
    pub fn stash_bytes(&mut self, data: &[u8], suffix: &str) -> io::Result<PathBuf> {
        let p = self.next_name(suffix);
        fs::write(&p, data)?;
        Ok(p)
    }

    /// Move an entire file into the trash (same volume: rename; else copy+unlink).
    pub fn stash_file(&mut self, src: &Path) -> io::Result<PathBuf> {
        let base = src
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "file".to_string());
        let dst = self.next_name(&base);
        match fs::rename(src, &dst) {
            Ok(()) => Ok(dst),
            Err(_) => {
                fs::copy(src, &dst)?;
                fs::remove_file(src)?;
                Ok(dst)
            }
        }
    }
}
