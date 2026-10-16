//! Turning a path into a list of files to scan. A single file yields itself; a
//! directory is walked (recursively by default). We deliberately do not honor
//! `.gitignore`: an audit tool must see every file, including hidden ones.
//!
//! The walk is sorted by file name so every run lists files in the same order.
//! Symbolic links are not followed: a link is never scanned and a linked
//! directory is never entered (a link given as the root itself is resolved).
//! meownary's own state directory (its trash store and undo journal) is always
//! left out, so it never scans or cleans its own trash.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

use crate::util::paths::state_dir;

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

/// One item the walk produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalkEntry {
    /// A regular file to scan.
    File(PathBuf),
    /// An entry that could not be read (a directory that cannot be listed, for
    /// example). It becomes a partial report instead of vanishing.
    Unreadable { path: PathBuf, reason: String },
}

impl WalkEntry {
    pub fn path(&self) -> &Path {
        match self {
            WalkEntry::File(p) => p,
            WalkEntry::Unreadable { path, .. } => path,
        }
    }
}

/// Walk `root` in sorted order, leaving out meownary's state directory.
/// Unreadable entries are returned as [`WalkEntry::Unreadable`].
pub fn walk(root: &Path, opts: &WalkOpts) -> Vec<WalkEntry> {
    walk_iter(root, opts).collect()
}

/// Walk `root` lazily, in the same sorted order as [`walk`], leaving out
/// meownary's state directory. Entries are produced as the walk finds them.
pub fn walk_iter(root: &Path, opts: &WalkOpts) -> impl Iterator<Item = WalkEntry> + Send + 'static {
    let exclude = excluded_dir(root, &state_dir());
    walk_iter_excluding(root, opts, exclude)
}

/// Collect every regular file under `root`, in sorted order. Unreadable entries
/// are skipped rather than aborting the walk; use [`walk`] to see them.
pub fn collect_files(root: &Path, opts: &WalkOpts) -> Vec<PathBuf> {
    walk(root, opts)
        .into_iter()
        .filter_map(|e| match e {
            WalkEntry::File(p) => Some(p),
            WalkEntry::Unreadable { .. } => None,
        })
        .collect()
}

/// Whether `root` lies inside meownary's state directory, which every walk
/// leaves out (so such a walk yields nothing).
pub fn inside_state_dir(root: &Path) -> bool {
    excluded_dir(root, &state_dir()).is_some_and(|x| x == root)
}

/// The walk works on `root` as the user spelled it, so the directory to skip is
/// expressed the same way: `root` joined with the state directory's path
/// relative to it. Returns `root` itself when the walk starts inside the state
/// directory, and `None` when the two do not overlap (or cannot be resolved).
fn excluded_dir(root: &Path, state: &Path) -> Option<PathBuf> {
    let state = fs::canonicalize(state).ok()?;
    let canon_root = fs::canonicalize(root).ok()?;
    if canon_root.starts_with(&state) {
        return Some(root.to_path_buf());
    }
    let rel = state.strip_prefix(&canon_root).ok()?;
    Some(root.join(rel))
}

#[cfg(test)]
fn walk_excluding(root: &Path, opts: &WalkOpts, exclude: Option<&Path>) -> Vec<WalkEntry> {
    walk_iter_excluding(root, opts, exclude.map(Path::to_path_buf)).collect()
}

/// The one walk implementation. walkdir's iterator is already lazy, so this
/// only maps its entries; nothing is collected.
fn walk_iter_excluding(
    root: &Path,
    opts: &WalkOpts,
    exclude: Option<PathBuf>,
) -> impl Iterator<Item = WalkEntry> + Send + 'static {
    let mut wd = WalkDir::new(root)
        .follow_links(opts.follow_symlinks)
        .sort_by_file_name();
    if !opts.recursive {
        wd = wd.max_depth(1);
    }
    let root = root.to_path_buf();
    wd.into_iter()
        .filter_entry(move |e| exclude.as_deref().is_none_or(|x| e.path() != x))
        .filter_map(move |entry| match entry {
            Ok(e) if !e.file_type().is_file() => None,
            Ok(e) if entry_cloud_only(&e) => Some(WalkEntry::Unreadable {
                path: e.into_path(),
                reason: CLOUD_ONLY_REASON.to_string(),
            }),
            Ok(e) => Some(WalkEntry::File(e.into_path())),
            Err(err) => {
                let path = err.path().unwrap_or(&root).to_path_buf();
                let reason = walk_reason(&err, &path);
                Some(WalkEntry::Unreadable { path, reason })
            }
        })
}

const CLOUD_ONLY_REASON: &str = "cloud-only file, not downloaded";

/// Windows file attributes that mark a cloud placeholder (OneDrive and other
/// cloud providers) whose content is not on disk. Opening or reading such a
/// file makes the provider download it, so the walk never hands it on.
const FILE_ATTRIBUTE_OFFLINE: u32 = 0x0000_1000;
const FILE_ATTRIBUTE_RECALL_ON_OPEN: u32 = 0x0004_0000;
const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;

/// Whether these Windows file attributes mark a cloud-only placeholder.
#[cfg_attr(not(windows), allow(dead_code))]
fn cloud_only(attrs: u32) -> bool {
    attrs
        & (FILE_ATTRIBUTE_OFFLINE
            | FILE_ATTRIBUTE_RECALL_ON_OPEN
            | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS)
        != 0
}

/// Whether a walked file is a cloud-only placeholder. On Windows, walkdir keeps
/// the metadata std builds from the directory listing (`WIN32_FIND_DATAW`), so
/// reading the attributes here never opens the file. When following links, or
/// for the root itself, walkdir has already stat'ed the path before we see it;
/// that asks for attributes only and reads no data.
#[cfg(windows)]
fn entry_cloud_only(e: &walkdir::DirEntry) -> bool {
    use std::os::windows::fs::MetadataExt;
    e.metadata().is_ok_and(|m| cloud_only(m.file_attributes()))
}

#[cfg(not(windows))]
fn entry_cloud_only(_: &walkdir::DirEntry) -> bool {
    // Only Windows marks placeholders through file attributes.
    false
}

fn walk_reason(err: &walkdir::Error, path: &Path) -> String {
    if err.loop_ancestor().is_some() {
        return "symlink loop".to_string();
    }
    let what = match fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => "cannot list directory",
        _ => "cannot read",
    };
    match err.io_error() {
        Some(e) => format!("{what}: {}", short_io(e)),
        None => what.to_string(),
    }
}

/// A short, stable description of an I/O error for partial-report reasons.
pub fn short_io(e: &io::Error) -> String {
    match e.kind() {
        io::ErrorKind::PermissionDenied => "permission denied".to_string(),
        io::ErrorKind::NotFound => "not found".to_string(),
        io::ErrorKind::Interrupted => "interrupted".to_string(),
        io::ErrorKind::UnexpectedEof => "unexpected end of file".to_string(),
        _ => e.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        fs::create_dir_all(p.join("b/inner")).unwrap();
        fs::create_dir_all(p.join("state/trash")).unwrap();
        fs::write(p.join("c.txt"), b"c").unwrap();
        fs::write(p.join("a.txt"), b"a").unwrap();
        fs::write(p.join("b/inner/z.bin"), b"z").unwrap();
        fs::write(p.join("b/y.bin"), b"y").unwrap();
        fs::write(p.join("state/trash/old.bin"), b"o").unwrap();
        dir
    }

    fn names(root: &Path, entries: &[WalkEntry]) -> Vec<String> {
        entries
            .iter()
            .map(|e| {
                let rel = e.path().strip_prefix(root).unwrap();
                let parts: Vec<String> = rel
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect();
                parts.join("/")
            })
            .collect()
    }

    #[test]
    fn walk_is_sorted_and_deterministic() {
        let dir = tree();
        let got = walk_excluding(dir.path(), &WalkOpts::default(), None);
        assert_eq!(
            names(dir.path(), &got),
            [
                "a.txt",
                "b/inner/z.bin",
                "b/y.bin",
                "c.txt",
                "state/trash/old.bin"
            ]
        );
    }

    #[test]
    fn state_dir_is_left_out() {
        let dir = tree();
        let exclude = excluded_dir(dir.path(), &dir.path().join("state")).unwrap();
        assert_eq!(exclude, dir.path().join("state"));
        let got = walk_excluding(dir.path(), &WalkOpts::default(), Some(&exclude));
        assert_eq!(
            names(dir.path(), &got),
            ["a.txt", "b/inner/z.bin", "b/y.bin", "c.txt"]
        );
    }

    #[test]
    fn root_inside_state_dir_yields_nothing() {
        let dir = tree();
        let root = dir.path().join("state").join("trash");
        let exclude = excluded_dir(&root, &dir.path().join("state")).unwrap();
        assert_eq!(exclude, root);
        assert!(walk_excluding(&root, &WalkOpts::default(), Some(&exclude)).is_empty());
    }

    #[test]
    fn unrelated_state_dir_excludes_nothing() {
        let dir = tree();
        let other = tempfile::tempdir().unwrap();
        assert_eq!(excluded_dir(dir.path(), other.path()), None);
        assert_eq!(excluded_dir(dir.path(), &dir.path().join("missing")), None);
    }

    #[test]
    fn non_recursive_stays_at_top() {
        let dir = tree();
        let opts = WalkOpts {
            recursive: false,
            follow_symlinks: false,
        };
        let got = walk_excluding(dir.path(), &opts, None);
        assert_eq!(names(dir.path(), &got), ["a.txt", "c.txt"]);
    }

    #[test]
    fn single_file_root_yields_itself() {
        let dir = tree();
        let f = dir.path().join("a.txt");
        assert_eq!(
            walk_excluding(&f, &WalkOpts::default(), None),
            [WalkEntry::File(f.clone())]
        );
    }

    #[test]
    fn missing_root_is_an_unreadable_entry() {
        let dir = tree();
        let gone = dir.path().join("gone");
        let got = walk_excluding(&gone, &WalkOpts::default(), None);
        assert_eq!(got.len(), 1);
        match &got[0] {
            WalkEntry::Unreadable { path, reason } => {
                assert_eq!(path, &gone);
                assert_eq!(reason, "cannot read: not found");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn walk_iter_yields_the_same_sequence_as_walk() {
        let dir = tree();
        let flat = WalkOpts {
            recursive: false,
            follow_symlinks: false,
        };
        for opts in [WalkOpts::default(), flat] {
            let lazy: Vec<WalkEntry> = walk_iter(dir.path(), &opts).collect();
            assert_eq!(lazy, walk(dir.path(), &opts));
        }
        let exclude = dir.path().join("state");
        let lazy: Vec<WalkEntry> =
            walk_iter_excluding(dir.path(), &WalkOpts::default(), Some(exclude.clone())).collect();
        assert_eq!(
            lazy,
            walk_excluding(dir.path(), &WalkOpts::default(), Some(&exclude))
        );
        assert_eq!(
            names(dir.path(), &lazy),
            ["a.txt", "b/inner/z.bin", "b/y.bin", "c.txt"]
        );
    }

    #[test]
    fn walk_iter_can_run_on_another_thread() {
        let dir = tree();
        let iter = walk_iter(dir.path(), &WalkOpts::default());
        let got = std::thread::spawn(move || iter.count()).join().unwrap();
        assert_eq!(got, walk(dir.path(), &WalkOpts::default()).len());
    }

    #[test]
    fn cloud_only_attributes() {
        assert!(cloud_only(FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS));
        assert!(cloud_only(FILE_ATTRIBUTE_RECALL_ON_OPEN));
        assert!(cloud_only(FILE_ATTRIBUTE_OFFLINE));
        // A placeholder also carries other bits (archive, reparse point, pinned).
        assert!(cloud_only(0x0040_0000 | 0x0000_0400 | 0x0000_0020));
        assert!(!cloud_only(0));
        // Normal, archive, read-only, hidden, reparse point and a pinned,
        // fully present cloud file (FILE_ATTRIBUTE_PINNED) are all readable.
        for attrs in [0x80, 0x20, 0x01, 0x02, 0x0000_0400, 0x0008_0000 | 0x20] {
            assert!(!cloud_only(attrs), "{attrs:#x}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn unlistable_directory_becomes_unreadable_entry() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tree();
        let locked = dir.path().join("b");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        let readable = fs::read_dir(&locked).is_ok();
        let got = walk_excluding(dir.path(), &WalkOpts::default(), None);
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        if readable {
            return; // running as root: permissions are not enforced
        }
        assert!(got.iter().any(|e| matches!(
            e,
            WalkEntry::Unreadable { path, reason }
                if path == &locked && reason == "cannot list directory: permission denied"
        )));
    }
}
