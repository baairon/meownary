//! Turning a path into a list of files to scan. A single file yields itself; a
//! directory is walked (recursively by default). We deliberately do not honor
//! `.gitignore`: an audit tool must see every file, including hidden ones.
//!
//! The walk is sorted by file name so every run lists files in the same order.
//! Symbolic links are not followed: a link is never scanned and a linked
//! directory is never entered (a link given as the root itself is resolved).
//! meownary's own state directory (its trash store and undo journal) is always
//! left out, so it never scans or cleans its own trash.
//!
//! Walk order is `Path` order: names are sorted within a folder and each
//! subfolder is walked whole before its next sibling, so components compare
//! one by one (`b/x` before `b-c` before `b.txt`, which string order gets
//! wrong). That makes counting cheap: a [`Tally`] counts entries per folder
//! as the walk finds them and hands out [`CountDelta`]s, [`Totals`] adds the
//! deltas up per folder, and [`passed`] tells when the walk has moved beyond
//! a folder, so its count is complete.

use std::collections::HashMap;
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

/// How many entries a [`Tally`] counts between deltas.
pub const COUNT_BATCH: usize = 256;

/// Entries counted since the last delta, per folder (direct entries, not
/// recursive), plus the walk frontier.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CountDelta {
    /// Each folder with how many entries the walk found directly in it since
    /// the last delta, in walk order. A folder comes up again when the walk
    /// returns to it after a subfolder. An entry equal to the walk's root (a
    /// single-file root, or a root that cannot be read) counts toward the
    /// root itself.
    pub dirs: Vec<(PathBuf, u32)>,
    /// The newest entry the walk has produced; `None` before the first one.
    pub frontier: Option<PathBuf>,
    /// The walk is over and this is its last delta.
    pub done: bool,
    /// The walk ended before it got through everything (it was stopped,
    /// reached its cap or failed), so the counts fall short.
    pub stopped: bool,
}

/// Counts walked entries per folder and hands the counts out as
/// [`CountDelta`]s. A folder's direct entries come one after another until
/// the walk enters a subfolder, so each run of them is a single counter.
#[derive(Debug, Clone)]
pub struct Tally {
    root: PathBuf,
    /// The folder the current run of entries is in, and how many of them
    /// have not gone out in a delta yet.
    run: Option<(PathBuf, u32)>,
    /// Finished runs waiting for the next delta.
    dirs: Vec<(PathBuf, u32)>,
    /// Entries added since the last delta.
    since: usize,
    /// The newest entry; its buffer is reused from entry to entry.
    last: Option<PathBuf>,
}

impl Tally {
    /// A tally for a walk of `root`.
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            run: None,
            dirs: Vec::new(),
            since: 0,
            last: None,
        }
    }

    /// Count one walked entry toward the folder it is in. An entry equal to
    /// the root counts toward the root itself.
    pub fn add(&mut self, entry: &Path) {
        let dir = if entry == self.root {
            entry
        } else {
            entry.parent().unwrap_or(entry)
        };
        match &mut self.run {
            Some((run_dir, n)) if run_dir.as_path() == dir => *n = n.saturating_add(1),
            slot => {
                if let Some(run) = slot.take().filter(|(_, n)| *n > 0) {
                    self.dirs.push(run);
                }
                *slot = Some((dir.to_path_buf(), 1));
            }
        }
        self.since += 1;
        match &mut self.last {
            Some(last) => entry.clone_into(last),
            None => self.last = Some(entry.to_path_buf()),
        }
    }

    /// The counts since the last delta, once [`COUNT_BATCH`] entries have
    /// piled up, or sooner when `force` is set and any are pending. `None`
    /// otherwise.
    pub fn take(&mut self, force: bool) -> Option<CountDelta> {
        let due = self.since >= COUNT_BATCH || (force && self.since > 0);
        due.then(|| self.delta(false, false))
    }

    /// The last delta: whatever is still pending, with `done` set, and
    /// `stopped` when the walk ended early.
    pub fn finish(mut self, stopped: bool) -> CountDelta {
        self.delta(true, stopped)
    }

    fn delta(&mut self, done: bool, stopped: bool) -> CountDelta {
        let mut dirs = std::mem::take(&mut self.dirs);
        if let Some((dir, n)) = &mut self.run
            && *n > 0
        {
            dirs.push((dir.clone(), *n));
            *n = 0;
        }
        self.since = 0;
        CountDelta {
            dirs,
            frontier: self.last.clone(),
            done,
            stopped,
        }
    }
}

/// True once a walk whose newest entry is `frontier` has moved past
/// everything under `dir`. Both are compared as `Path`s, never as strings.
pub fn passed(frontier: &Path, dir: &Path) -> bool {
    frontier > dir && !frontier.starts_with(dir)
}

/// Recursive entry counts per folder, built from [`CountDelta`]s. With a
/// depth limit only the root and the folders down to that many levels under
/// it are kept; deeper counts roll up into their ancestor at the limit.
#[derive(Debug, Clone)]
pub struct Totals {
    root: PathBuf,
    depth: Option<usize>,
    /// Recursive counts of the folders with anything counted under them.
    counts: HashMap<PathBuf, u64>,
    /// Every entry counted.
    total: u64,
    frontier: Option<PathBuf>,
    done: bool,
    stopped: bool,
}

impl Totals {
    /// Empty totals for a walk of `root`, keeping folders down to `depth`
    /// levels under it (`None` keeps them all).
    pub fn new(root: &Path, depth: Option<usize>) -> Self {
        Self {
            root: root.to_path_buf(),
            depth,
            counts: HashMap::new(),
            total: 0,
            frontier: None,
            done: false,
            stopped: false,
        }
    }

    /// Fold in one delta: each direct count goes to its folder and every
    /// ancestor up to the root, leaving out folders below the depth limit.
    pub fn apply(&mut self, d: &CountDelta) {
        let limit = self.depth.unwrap_or(usize::MAX);
        for (dir, n) in &d.dirs {
            let n = u64::from(*n);
            self.total += n;
            let Ok(rel) = dir.strip_prefix(&self.root) else {
                // Not under the root (never so in a walk of it): only the
                // root's own count takes it.
                bump(&mut self.counts, &self.root, n);
                continue;
            };
            let levels = rel.components().count();
            for (up, folder) in dir.ancestors().take(levels + 1).enumerate() {
                if levels - up <= limit {
                    bump(&mut self.counts, folder, n);
                }
            }
        }
        if d.frontier.is_some() {
            self.frontier.clone_from(&d.frontier);
        }
        self.done |= d.done;
        self.stopped |= d.stopped;
    }

    /// The recursive count under `dir` so far; `None` when nothing under it
    /// has been counted yet, or it lies below the depth limit.
    pub fn get(&self, dir: &Path) -> Option<u64> {
        self.counts.get(dir).copied()
    }

    /// Every entry counted so far: the root's recursive count.
    pub fn total(&self) -> u64 {
        self.total
    }

    /// Whether `dir`'s count is final: the walk is done, or it has moved past
    /// everything under `dir`. A stopped walk is done too, with short counts
    /// (see [`was_stopped`](Self::was_stopped)).
    pub fn is_final(&self, dir: &Path) -> bool {
        self.done || self.frontier.as_deref().is_some_and(|f| passed(f, dir))
    }

    /// Whether the walk is over.
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Whether the walk ended before it got through everything.
    pub fn was_stopped(&self) -> bool {
        self.stopped
    }
}

/// Add `n` to `dir`'s count, allocating its key only the first time.
fn bump(counts: &mut HashMap<PathBuf, u64>, dir: &Path, n: u64) {
    if let Some(c) = counts.get_mut(dir) {
        *c += n;
    } else {
        counts.insert(dir.to_path_buf(), n);
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

    /// `root` joined with a `/`-separated relative path.
    fn at(root: &Path, rel: &str) -> PathBuf {
        rel.split('/')
            .fold(root.to_path_buf(), |p, part| p.join(part))
    }

    #[test]
    fn tally_counts_runs_per_folder_in_walk_order() {
        let root = Path::new("root");
        // Walk order over a.txt, b/, c.txt, d/, an empty folder, a folder
        // that cannot be listed (an entry of its own) and z.txt.
        let walked = [
            "a.txt",
            "b/inner/z.bin",
            "b/inner/zz.bin",
            "b/y.bin",
            "c.txt",
            "d/e/f/g.bin",
            "locked",
            "z.txt",
        ];
        let mut tally = Tally::new(root);
        for rel in walked {
            tally.add(&at(root, rel));
        }
        let d = tally.finish(false);
        let r = root.to_path_buf();
        assert_eq!(
            d.dirs,
            [
                (r.clone(), 1),
                (at(root, "b/inner"), 2),
                (at(root, "b"), 1),
                (r.clone(), 1),
                (at(root, "d/e/f"), 1),
                (r.clone(), 2),
            ]
        );
        assert_eq!(d.frontier, Some(at(root, "z.txt")));
        assert!(d.done && !d.stopped);

        let mut totals = Totals::new(root, None);
        totals.apply(&d);
        assert_eq!(totals.total(), 8);
        assert_eq!(totals.get(root), Some(8));
        assert_eq!(totals.get(&at(root, "b")), Some(3));
        assert_eq!(totals.get(&at(root, "b/inner")), Some(2));
        assert_eq!(totals.get(&at(root, "d")), Some(1));
        assert_eq!(totals.get(&at(root, "d/e")), Some(1));
        assert_eq!(totals.get(&at(root, "d/e/f")), Some(1));
        assert_eq!(totals.get(&at(root, "empty")), None, "never counted");
        assert_eq!(
            totals.get(&at(root, "locked")),
            None,
            "an entry, not a folder"
        );
        assert!(totals.is_done() && !totals.was_stopped());
    }

    #[test]
    fn tally_hands_out_a_delta_every_batch() {
        let root = Path::new("root");
        let mut tally = Tally::new(root);
        assert_eq!(tally.take(true), None, "nothing pending");
        let mut deltas = Vec::new();
        for i in 0..600 {
            tally.add(&root.join(format!("f{i:04}")));
            deltas.extend(tally.take(false));
        }
        assert_eq!(deltas.len(), 2);
        let batch = (root.to_path_buf(), COUNT_BATCH as u32);
        assert!(deltas.iter().all(|d| d.dirs == [batch.clone()]));
        assert_eq!(deltas[1].frontier, Some(root.join("f0511")));
        assert!(deltas.iter().all(|d| !d.done && !d.stopped));
        assert_eq!(tally.take(false), None, "88 pending is not a batch");
        let forced = tally.take(true).unwrap();
        assert_eq!(forced.dirs, [(root.to_path_buf(), 88)]);
        assert_eq!(tally.take(true), None);
        tally.add(&root.join("g"));
        let last = tally.finish(true);
        assert_eq!(last.dirs, [(root.to_path_buf(), 1)]);
        assert!(last.done && last.stopped);

        let mut totals = Totals::new(root, None);
        for d in deltas.iter().chain([&forced, &last]) {
            totals.apply(d);
        }
        assert_eq!(totals.total(), 601, "every entry once");
        assert!(totals.is_done() && totals.was_stopped());
    }

    #[test]
    fn an_entry_equal_to_the_root_counts_toward_the_root() {
        // A single-file root, or a root that cannot be read, is its own only
        // entry.
        let root = Path::new("dir").join("only.bin");
        let mut tally = Tally::new(&root);
        tally.add(&root);
        let d = tally.finish(false);
        assert_eq!(d.dirs, [(root.clone(), 1)]);
        let mut totals = Totals::new(&root, None);
        totals.apply(&d);
        assert_eq!(totals.get(&root), Some(1));
        assert_eq!(totals.get(Path::new("dir")), None);
        assert_eq!(totals.total(), 1);
        // An empty walk still ends with a delta, holding nothing.
        let empty = Tally::new(&root).finish(false);
        assert_eq!(empty.dirs, []);
        assert_eq!(empty.frontier, None);
        assert!(empty.done);
    }

    #[test]
    fn totals_roll_up_below_the_depth_limit() {
        let root = Path::new("root");
        let d = CountDelta {
            dirs: vec![
                (root.to_path_buf(), 2),
                (at(root, "a"), 1),
                (at(root, "a/b"), 3),
                (at(root, "a/b/c/d"), 4),
                (at(root, "e"), 5),
            ],
            frontier: Some(at(root, "e/x")),
            done: false,
            stopped: false,
        };
        let mut all = Totals::new(root, None);
        all.apply(&d);
        assert_eq!(all.get(root), Some(15));
        assert_eq!(all.get(&at(root, "a")), Some(8));
        assert_eq!(all.get(&at(root, "a/b")), Some(7));
        assert_eq!(all.get(&at(root, "a/b/c")), Some(4));
        assert_eq!(all.get(&at(root, "a/b/c/d")), Some(4));

        let mut one = Totals::new(root, Some(1));
        one.apply(&d);
        assert_eq!(one.total(), 15);
        assert_eq!(one.get(root), Some(15));
        assert_eq!(one.get(&at(root, "a")), Some(8), "a/b and below roll up");
        assert_eq!(one.get(&at(root, "a/b")), None);
        assert_eq!(one.get(&at(root, "a/b/c/d")), None);
        assert_eq!(one.get(&at(root, "e")), Some(5));

        let mut flat = Totals::new(root, Some(0));
        flat.apply(&d);
        assert_eq!(flat.get(root), Some(15));
        assert_eq!(flat.get(&at(root, "a")), None);
    }

    #[test]
    fn passed_compares_paths_not_strings() {
        let p = Path::new;
        // Components compare one by one, so b/x sorts before the siblings
        // b-c and b.txt, though string order puts b-c first.
        assert!(p("b/x") < p("b-c") && p("b-c") < p("b.txt"));
        assert!("b-c" < "b/x");
        let b = p("b");
        assert!(!passed(p("a"), b), "not there yet");
        assert!(!passed(b, b), "at the folder itself");
        assert!(!passed(p("b/x"), b), "inside it");
        assert!(!passed(p("b/x/y/z"), b));
        assert!(passed(p("b-c"), b));
        assert!(passed(p("b.txt"), b));
        assert!(passed(p("c"), b));
        assert!(passed(p("b-c"), p("b/x")));
        assert!(!passed(p("b-c"), p("b.txt")));
        // Nothing under a root is ever past it.
        assert!(!passed(p("/x/y"), p("/")));
    }

    #[test]
    fn is_final_follows_the_frontier() {
        let root = Path::new("root");
        let mut totals = Totals::new(root, None);
        assert!(!totals.is_final(root));
        totals.apply(&CountDelta {
            dirs: vec![(at(root, "b/inner"), 1), (at(root, "b"), 1)],
            frontier: Some(at(root, "b/y.bin")),
            done: false,
            stopped: false,
        });
        assert!(totals.is_final(&at(root, "a")), "passed with nothing in it");
        assert!(totals.is_final(&at(root, "b/inner")));
        assert!(!totals.is_final(&at(root, "b")), "the walk is inside b");
        assert!(!totals.is_final(&at(root, "c")), "not reached");
        assert!(!totals.is_final(root));
        // A delta without a frontier keeps the last one.
        totals.apply(&CountDelta::default());
        assert_eq!(totals.frontier, Some(at(root, "b/y.bin")));
        assert!(!totals.is_final(&at(root, "c")));
        totals.apply(&CountDelta {
            done: true,
            ..CountDelta::default()
        });
        assert!(totals.is_final(&at(root, "c")) && totals.is_final(root));
        assert_eq!(totals.get(&at(root, "b")), Some(2));
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
