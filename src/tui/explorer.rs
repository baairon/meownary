//! The folder the files list shows. A scan's reports arrive as one flat,
//! path-sorted list; the explorer lays out one folder of it as rows: its
//! subfolders first, then its files, each group in natural order. Rows are
//! the union of three sources: the folder's listing (read off the input
//! thread, when it can be read), the tree's subfolders, and the reports
//! directly in it. Listed entries the scan never enters, such as links,
//! still get a row, and the scan's own entries need no listing at all.
//!
//! Rows change only when the folder does. A new subfolder or file is merged
//! into its place, so rows already shown never reorder while a scan streams
//! in; the folder's `generation` in the [`Tree`] says when a full rebuild
//! is due instead. The app keeps the highlight by path.
//!
//! With a filter on, the rows are every matching file under the folder
//! instead, in path order, each named by its path under the folder.

#![cfg(feature = "tui")]

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::model::FileReport;
use crate::scan::walk::passed;

use super::app::{self, Filter, Match};
use super::listing::{Item, Listing, natural_cmp};
use super::tree::{Tree, direct_files, subtree};

/// What a folder's listing says about one entry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Listed {
    /// A link or junction, which a scan never follows.
    pub link: bool,
    /// A cloud placeholder whose content is not on disk.
    pub cloud: bool,
    pub hidden: bool,
    /// meownary's own state folder, which every scan leaves out.
    pub excluded: bool,
}

/// One row of the files list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub path: PathBuf,
    /// The bare name, or with a filter on, the path under the folder.
    pub name: String,
    pub dir: bool,
    /// What the folder's listing said, when it listed the entry.
    pub listed: Option<Listed>,
}

impl Row {
    fn new(path: &Path, dir: bool) -> Self {
        Self {
            name: name_of(path),
            path: path.to_path_buf(),
            dir,
            listed: None,
        }
    }

    fn from_item(item: &Item, excluded: bool) -> Self {
        Self {
            path: item.path.clone(),
            name: item.name.clone(),
            dir: item.dir,
            listed: Some(Listed {
                link: item.link,
                cloud: item.cloud,
                hidden: item.hidden,
                excluded,
            }),
        }
    }
}

/// The name a row shows for `path`.
pub fn name_of(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

/// Folders first, then files, each by name as a person reads it, with the
/// exact path breaking any tie.
fn order(a: &Row, b: &Row) -> Ordering {
    b.dir
        .cmp(&a.dir)
        .then_with(|| natural_cmp(&a.name, &b.name))
        .then_with(|| a.path.cmp(&b.path))
}

fn by_path(a: &Row, b: &Row) -> Ordering {
    a.path.cmp(&b.path)
}

/// Sort `rows` by `cmp` and keep one row per path, keeping what a listing
/// said about it.
fn settle(rows: &mut Vec<Row>, cmp: fn(&Row, &Row) -> Ordering) {
    rows.sort_by(cmp);
    rows.dedup_by(|later, kept| {
        if later.path != kept.path {
            return false;
        }
        if kept.listed.is_none() {
            kept.listed = later.listed;
        }
        true
    });
}

/// Merge `new` into `rows`, both in `cmp` order, in one pass. A row already
/// there stays as it is.
fn merge(rows: &mut Vec<Row>, mut new: Vec<Row>, cmp: fn(&Row, &Row) -> Ordering) {
    if new.is_empty() {
        return;
    }
    settle(&mut new, cmp);
    let old = std::mem::take(rows);
    let mut out = Vec::with_capacity(old.len() + new.len());
    let mut a = old.into_iter().peekable();
    let mut b = new.into_iter().peekable();
    loop {
        let next = match (a.peek(), b.peek()) {
            (Some(x), Some(y)) => match cmp(x, y) {
                Ordering::Less => a.next(),
                Ordering::Greater => b.next(),
                Ordering::Equal => {
                    b.next();
                    a.next()
                }
            },
            (Some(_), None) => a.next(),
            (None, Some(_)) => b.next(),
            (None, None) => break,
        };
        out.extend(next);
    }
    *rows = out;
}

/// What a folder row shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FolderState {
    /// The scan has not reached it; the walk may have counted it already.
    Pending {
        expected: Option<u64>,
        exact: bool,
    },
    /// The scan is inside it right now.
    Scanning {
        scanned: u64,
        expected: Option<u64>,
        exact: bool,
    },
    Done,
    /// Scanned, with no files in it.
    Empty,
    /// It could not be listed, with why.
    Unreadable(String),
    /// The scan left it out: a link, or meownary's own folder.
    NotScanned,
}

/// Whether the scan is finished with `path`: it ended, or its newest entry
/// sorts past everything under `path`.
pub fn is_final(tree: &Tree, path: &Path, scanning: bool) -> bool {
    !scanning || tree.frontier().is_some_and(|f| passed(f, path))
}

/// The state of the folder at `path`, which its listing describes as
/// `listed`.
pub fn folder_state(
    tree: &Tree,
    path: &Path,
    listed: Option<Listed>,
    scanning: bool,
) -> FolderState {
    let node = tree.find(path).map(|i| tree.node(i));
    if let Some(why) = node.and_then(|n| n.unreadable.clone()) {
        return FolderState::Unreadable(why);
    }
    let counts = tree.counts();
    let expected = counts.get(path);
    let exact = counts.is_final(path) && !counts.was_stopped();
    if is_final(tree, path, scanning) {
        return match node {
            Some(n) if n.agg.files > 0 => FolderState::Done,
            _ if listed.is_some_and(|l| l.link || l.excluded) => FolderState::NotScanned,
            _ => FolderState::Empty,
        };
    }
    if tree
        .frontier()
        .is_some_and(|f| f != path && f.starts_with(path))
    {
        return FolderState::Scanning {
            scanned: node.map_or(0, |n| n.walked),
            expected,
            exact,
        };
    }
    FolderState::Pending { expected, exact }
}

/// Whether two paths from different sources name the same entry: the
/// view's own paths compare exactly, but a path from elsewhere (the state
/// dir) may differ in case on Windows.
fn same_path(a: &Path, b: &Path) -> bool {
    if cfg!(windows) {
        let low = |p: &Path| p.to_string_lossy().to_lowercase().replace('/', "\\");
        low(a).trim_end_matches('\\') == low(b).trim_end_matches('\\')
    } else {
        a == b
    }
}

/// The report at `path` in `reports`, which is sorted by path.
pub fn find_report<'a>(reports: &'a [FileReport], path: &Path) -> Option<&'a FileReport> {
    reports
        .binary_search_by(|r| r.path.as_path().cmp(path))
        .ok()
        .map(|i| &reports[i])
}

/// The folder the files list shows, and its rows.
#[derive(Debug, Clone)]
pub struct Explorer {
    root: PathBuf,
    cwd: PathBuf,
    rows: Vec<Row>,
    /// The rows are filter matches.
    filtered: bool,
    /// The lowercased text the filter rows were built for, so typing more
    /// narrows them instead of searching again.
    narrowed: Option<String>,
    /// The cwd's `generation` the rows are current with.
    built: Option<u64>,
    /// Each folder left, with the row highlighted in it.
    remembered: HashMap<PathBuf, PathBuf>,
    listings: HashMap<PathBuf, Listing>,
    /// Folders whose listing could not be had at all.
    failed: HashSet<PathBuf>,
    /// The row to highlight once it shows up, until the user moves.
    pub want: Option<PathBuf>,
    state_dir: Option<PathBuf>,
}

/// Listings kept for folders visited, before older ones are dropped.
const LISTINGS_KEPT: usize = 64;

impl Explorer {
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            cwd: root.to_path_buf(),
            rows: Vec::new(),
            filtered: false,
            narrowed: None,
            built: None,
            remembered: HashMap::new(),
            listings: HashMap::new(),
            failed: HashSet::new(),
            want: None,
            state_dir: None,
        }
    }

    pub fn cwd(&self) -> &Path {
        &self.cwd
    }

    pub fn rows(&self) -> &[Row] {
        &self.rows
    }

    pub fn at_root(&self) -> bool {
        self.cwd == self.root
    }

    /// Show `dir`; the caller rebuilds the rows.
    pub fn set_cwd(&mut self, dir: &Path) {
        self.cwd = dir.to_path_buf();
        self.built = None;
        self.narrowed = None;
        self.want = None;
    }

    pub fn remember(&mut self, folder: &Path, row: &Path) {
        self.remembered
            .insert(folder.to_path_buf(), row.to_path_buf());
    }

    pub fn remembered(&self, folder: &Path) -> Option<&Path> {
        self.remembered.get(folder).map(PathBuf::as_path)
    }

    /// Whether `path` is covered by the cwd: under it, or outside the root
    /// while the cwd is the root.
    fn covers(&self, path: &Path) -> bool {
        path.starts_with(&self.cwd) || (self.at_root() && !path.starts_with(&self.root))
    }

    /// Whether a report at `path` is a direct file of the cwd.
    fn direct(&self, path: &Path) -> bool {
        path.parent() == Some(self.cwd.as_path())
            || path == self.cwd
            || (self.at_root() && !path.starts_with(&self.root))
    }

    fn filter_row(&self, path: &Path) -> Row {
        Row {
            name: app::display_under(&self.cwd, path),
            path: path.to_path_buf(),
            dir: false,
            listed: None,
        }
    }

    /// Lay the rows out again from scratch, for `filter`.
    pub fn rebuild(&mut self, tree: &Tree, reports: &[FileReport], filter: &Filter) {
        if filter.is_active() {
            self.rebuild_filtered(reports, filter);
        } else {
            self.filtered = false;
            self.narrowed = None;
            self.rows = self.browse_rows(tree, reports);
        }
        self.built = tree.find(&self.cwd).map(|i| tree.node(i).generation());
    }

    /// Rebuild only when the cwd's direct entries changed since the rows
    /// were laid out (a change the merges did not cover).
    pub fn sync(&mut self, tree: &Tree, reports: &[FileReport], filter: &Filter) {
        let now = tree.find(&self.cwd).map(|i| tree.node(i).generation());
        if !self.filtered && now != self.built {
            self.rebuild(tree, reports, filter);
        }
    }

    fn browse_rows(&self, tree: &Tree, reports: &[FileReport]) -> Vec<Row> {
        let mut rows = Vec::new();
        if let Some(ci) = tree.find(&self.cwd) {
            for &k in &tree.node(ci).children {
                rows.push(Row::new(&tree.node(k).path, true));
            }
        }
        for r in direct_files(reports, &self.cwd, &self.root) {
            rows.push(Row::new(&r.path, false));
        }
        if let Some(listing) = self.listings.get(&self.cwd) {
            for item in &listing.items {
                let excluded = item.dir
                    && self
                        .state_dir
                        .as_deref()
                        .is_some_and(|s| same_path(s, &item.path));
                rows.push(Row::from_item(item, excluded));
            }
        }
        settle(&mut rows, order);
        rows
    }

    fn rebuild_filtered(&mut self, reports: &[FileReport], filter: &Filter) {
        let text = match filter {
            Filter::Text(t) => Some(t.to_lowercase()),
            _ => None,
        };
        let narrows = self.filtered
            && matches!((&text, &self.narrowed), (Some(new), Some(old)) if new.contains(old.as_str()));
        if narrows {
            self.rows.retain(|row| {
                find_report(reports, &row.path)
                    .is_some_and(|r| app::file_match(filter, r) != Match::None)
            });
        } else {
            let range = if self.at_root() {
                0..reports.len()
            } else {
                subtree(reports, &self.cwd)
            };
            self.rows = reports[range]
                .iter()
                .filter(|r| app::file_match(filter, r) != Match::None)
                .map(|r| self.filter_row(&r.path))
                .collect();
        }
        self.filtered = true;
        self.narrowed = text;
    }

    /// Fold in what one change added: folders the tree `created` and the
    /// reports `added`. Only what belongs in the rows is merged in.
    pub fn absorb(
        &mut self,
        tree: &Tree,
        created: &[usize],
        added: &[&FileReport],
        filter: &Filter,
    ) {
        if self.filtered {
            let new: Vec<Row> = added
                .iter()
                .filter(|r| self.covers(&r.path) && app::file_match(filter, r) != Match::None)
                .map(|r| self.filter_row(&r.path))
                .collect();
            merge(&mut self.rows, new, by_path);
            return;
        }
        let cwd = tree.find(&self.cwd);
        let mut new = Vec::new();
        if let Some(ci) = cwd {
            for &k in created {
                if tree.node(k).parent == Some(ci) {
                    new.push(Row::new(&tree.node(k).path, true));
                }
            }
        }
        for r in added {
            if self.direct(&r.path) {
                new.push(Row::new(&r.path, false));
            }
        }
        merge(&mut self.rows, new, order);
        if self.built.is_some() || cwd.is_some() {
            self.built = cwd.map(|i| tree.node(i).generation());
        }
    }

    /// A report changed in place: with a filter on, it may now match or no
    /// longer match.
    pub fn recheck(&mut self, r: &FileReport, filter: &Filter) {
        if !self.filtered || !self.covers(&r.path) {
            return;
        }
        let matches = app::file_match(filter, r) != Match::None;
        match self.rows.binary_search_by(|row| row.path.cmp(&r.path)) {
            Ok(at) if !matches => {
                self.rows.remove(at);
            }
            Err(at) if matches => self.rows.insert(at, self.filter_row(&r.path)),
            _ => {}
        }
    }

    /// The file at `path` is gone.
    pub fn forget(&mut self, tree: &Tree, path: &Path) {
        self.rows.retain(|r| r.path != path);
        if let Some(listing) = path.parent().and_then(|p| self.listings.get_mut(p)) {
            listing.items.retain(|i| i.path != path);
        }
        if !self.filtered {
            self.built = tree.find(&self.cwd).map(|i| tree.node(i).generation());
        }
    }

    /// The folder whose listing the rows still lack, if any.
    pub fn listing_request(&self) -> Option<&Path> {
        let have = self.listings.contains_key(&self.cwd) || self.failed.contains(&self.cwd);
        (!have && !self.cwd.as_os_str().is_empty()).then_some(self.cwd.as_path())
    }

    /// A listing arrived. True when it is the cwd's, so the rows need a
    /// rebuild.
    pub fn listing_ready(&mut self, listing: Listing) -> bool {
        if self.state_dir.is_none() {
            self.state_dir = Some(crate::util::paths::state_dir());
        }
        if self.listings.len() >= LISTINGS_KEPT {
            let cwd = self.cwd.clone();
            self.listings.retain(|at, _| *at == cwd);
        }
        let mine = listing.location == self.cwd;
        self.listings.insert(listing.location.clone(), listing);
        mine
    }

    /// The listing of `at` could not be had: stop asking for it.
    pub fn listing_failed(&mut self, at: &Path) {
        self.failed.insert(at.to_path_buf());
    }

    /// Whether the listing of `dir` holds any folder.
    pub fn lists_folders(&self, dir: &Path) -> bool {
        self.listings
            .get(dir)
            .is_some_and(|l| l.items.iter().any(|i| i.dir))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(names: &[(&str, bool)]) -> Vec<Row> {
        names
            .iter()
            .map(|&(n, dir)| Row::new(&Path::new("r").join(n), dir))
            .collect()
    }

    fn names(rows: &[Row]) -> Vec<&str> {
        rows.iter().map(|r| r.name.as_str()).collect()
    }

    #[test]
    fn folders_come_first_in_natural_order() {
        let mut r = rows(&[
            ("f10.txt", false),
            ("b10", true),
            ("f2.txt", false),
            ("B2", true),
            ("a.txt", false),
        ]);
        settle(&mut r, order);
        assert_eq!(names(&r), ["B2", "b10", "a.txt", "f2.txt", "f10.txt"]);
    }

    #[test]
    fn merging_keeps_rows_in_place_and_drops_repeats() {
        let mut r = rows(&[("b", true), ("a.txt", false), ("c.txt", false)]);
        settle(&mut r, order);
        let mut listed = rows(&[("c.txt", false)]);
        listed[0].listed = Some(Listed::default());
        merge(
            &mut r,
            rows(&[("a", true), ("b.txt", false), ("a.txt", false)]),
            order,
        );
        assert_eq!(names(&r), ["a", "b", "a.txt", "b.txt", "c.txt"]);
        merge(&mut r, listed, order);
        assert_eq!(r.len(), 5, "a repeat is dropped");
    }

    #[test]
    fn same_path_ignores_case_only_on_windows() {
        let (a, b) = (
            Path::new("C:/Data/Meownary"),
            Path::new("c:\\data\\meownary"),
        );
        assert_eq!(same_path(a, b), cfg!(windows));
        assert!(same_path(Path::new("x/y"), Path::new("x/y")));
    }
}
