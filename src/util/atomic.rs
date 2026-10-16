//! Atomic whole-file replacement (write to a temp sibling, fsync, rename).
//! Used by structural container rewrites so a crash can never leave a
//! half-written file in place.

use std::fs;
use std::io::{self, Write};
use std::path::Path;

/// Replace `path`'s contents with `data` atomically on the same volume.
pub fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = dir.join(format!(".meownary.tmp.{}", std::process::id()));
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}
