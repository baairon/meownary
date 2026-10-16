//! Turning a path into a list of files to scan. A single file yields itself; a
//! directory is walked (recursively by default). We deliberately do not honor
//! `.gitignore`: an audit tool must see every file, including hidden ones.

use std::path::{Path, PathBuf};

use walkdir::WalkDir;

#[derive(Debug, Clone)]
pub struct WalkOpts {
    pub recursive: bool,
    pub follow_symlinks: bool,
}

impl Default for WalkOpts {
    fn default() -> Self {
        // Recurse, but never follow symlinks (loop-safe, and we audit the link
        // target only when it is itself inside the tree).
        Self {
            recursive: true,
            follow_symlinks: false,
        }
    }
}

/// Collect every regular file under `root`. Unreadable entries are skipped
/// rather than aborting the walk.
pub fn collect_files(root: &Path, opts: &WalkOpts) -> Vec<PathBuf> {
    let mut wd = WalkDir::new(root).follow_links(opts.follow_symlinks);
    if !opts.recursive {
        wd = wd.max_depth(1);
    }
    wd.into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .map(walkdir::DirEntry::into_path)
        .collect()
}
