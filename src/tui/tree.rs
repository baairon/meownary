//! The scan as a tree of folders. Every folder that holds a scanned file has
//! a node with everything under it added up (files, findings per severity,
//! removable markers, partial files, bytes), so the explorer reads a folder's
//! totals without walking its files, and the header reads the root's.
//!
//! Nodes live in one arena, indexed by path. Adding a report costs O(depth):
//! its folder is found through a one-entry cache (a batch arrives in walk
//! order, so siblings come together), and its counts go to that folder and
//! every ancestor. Removing or replacing a report takes back exactly what it
//! added, and the per-severity counts keep a folder's worst severity exact.
//!
//! Each node keeps two stamps from one clock: `generation` moves when its direct
//! entries change (a new subfolder, a file added or removed), and `stamp`
//! moves when anything under it changes. The explorer rebuilds a folder's
//! rows only when its `generation` moves, and caches what it reads from a folder's
//! reports per `stamp`.
//!
//! The tree also follows the scan itself: how many entries the scan has
//! delivered, the newest of them (the frontier), how many each folder has
//! had delivered, and the walk's own counts ([`Totals`]), which run ahead of
//! the scan. Only the scan's own entries drive these: a copy written later is
//! added like any report but never moves the frontier or the counts.
//!
//! Every key is a view path built from the one root the scan was given, so
//! plain path equality is exact here.

#![cfg(feature = "tui")]

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::model::{Confidence, FileReport, Severity};
use crate::scan::walk::{CountDelta, Totals};

/// What is under a folder, added up.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Agg {
    pub files: usize,
    /// Files with at least one finding.
    pub flagged: usize,
    pub findings: usize,
    /// Findings with a removable marker.
    pub removable: usize,
    /// Removable findings of weak confidence, which bulk actions leave out.
    pub weak: usize,
    /// Files that could only be partly read.
    pub partial: usize,
    pub bytes: u64,
    /// Findings per severity, quietest first (see [`severity_slot`]).
    pub severity: [usize; 4],
}

impl Agg {
    /// What one report adds.
    pub fn of(r: &FileReport) -> Self {
        let mut a = Self {
            files: 1,
            flagged: usize::from(!r.findings.is_empty()),
            findings: r.findings.len(),
            partial: usize::from(r.partial),
            bytes: r.size,
            ..Self::default()
        };
        for f in &r.findings {
            if f.is_removable() {
                a.removable += 1;
                if f.confidence == Confidence::Weak {
                    a.weak += 1;
                }
            }
            a.severity[severity_slot(f.severity)] += 1;
        }
        a
    }

    fn add(&mut self, o: &Agg) {
        self.files += o.files;
        self.flagged += o.flagged;
        self.findings += o.findings;
        self.removable += o.removable;
        self.weak += o.weak;
        self.partial += o.partial;
        self.bytes += o.bytes;
        for (s, n) in self.severity.iter_mut().zip(o.severity) {
            *s += n;
        }
    }

    fn sub(&mut self, o: &Agg) {
        self.files = self.files.saturating_sub(o.files);
        self.flagged = self.flagged.saturating_sub(o.flagged);
        self.findings = self.findings.saturating_sub(o.findings);
        self.removable = self.removable.saturating_sub(o.removable);
        self.weak = self.weak.saturating_sub(o.weak);
        self.partial = self.partial.saturating_sub(o.partial);
        self.bytes = self.bytes.saturating_sub(o.bytes);
        for (s, n) in self.severity.iter_mut().zip(o.severity) {
            *s = s.saturating_sub(n);
        }
    }

    /// Findings of alert severity.
    pub fn alerts(&self) -> usize {
        self.severity[severity_slot(Severity::Alert)]
    }

    /// The loudest severity of any finding under the folder.
    pub fn worst(&self) -> Option<Severity> {
        SEVERITIES
            .iter()
            .rev()
            .find(|&&s| self.severity[severity_slot(s)] > 0)
            .copied()
    }
}

/// Every severity, quietest first.
pub const SEVERITIES: [Severity; 4] = [
    Severity::Info,
    Severity::Notice,
    Severity::Warn,
    Severity::Alert,
];

/// Where a severity's count sits in [`Agg::severity`].
pub fn severity_slot(s: Severity) -> usize {
    match s {
        Severity::Info => 0,
        Severity::Notice => 1,
        Severity::Warn => 2,
        Severity::Alert => 3,
    }
}

/// One folder.
#[derive(Debug, Clone)]
pub struct Node {
    pub path: PathBuf,
    pub parent: Option<usize>,
    /// Subfolders, in the order the scan reached them.
    pub children: Vec<usize>,
    /// Every report under the folder, at any depth, copies included.
    pub agg: Agg,
    /// Entries the scan delivered under the folder, counted the way the walk
    /// counts them (unreadable entries too, copies never).
    pub walked: u64,
    /// Why the folder could not be listed, when it could not.
    pub unreadable: Option<String>,
    generation: u64,
    stamp: u64,
}

impl Node {
    fn new(path: PathBuf, parent: Option<usize>) -> Self {
        Self {
            path,
            parent,
            children: Vec::new(),
            agg: Agg::default(),
            walked: 0,
            unreadable: None,
            generation: 0,
            stamp: 0,
        }
    }

    /// Moves whenever the folder's direct entries change.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Moves whenever anything under the folder changes.
    pub fn stamp(&self) -> u64 {
        self.stamp
    }
}

/// The folders of one scan.
#[derive(Debug, Clone)]
pub struct Tree {
    root: PathBuf,
    nodes: Vec<Node>,
    index: HashMap<PathBuf, usize>,
    clock: u64,
    /// The folder the last report went to.
    last: Option<usize>,
    /// Why each partial report is partial, when the scan said.
    reasons: HashMap<PathBuf, String>,
    frontier: Option<PathBuf>,
    scanned: usize,
    counts: Totals,
}

impl Tree {
    /// An empty tree for a scan of `root`. Node 0 is the root.
    pub fn new(root: &Path) -> Self {
        let mut index = HashMap::new();
        index.insert(root.to_path_buf(), 0);
        Self {
            root: root.to_path_buf(),
            nodes: vec![Node::new(root.to_path_buf(), None)],
            index,
            clock: 0,
            last: None,
            reasons: HashMap::new(),
            frontier: None,
            scanned: 0,
            counts: Totals::new(root, None),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn node(&self, i: usize) -> &Node {
        &self.nodes[i]
    }

    /// The folder at `path`, if any report or scanned entry made one.
    pub fn find(&self, path: &Path) -> Option<usize> {
        self.index.get(path).copied()
    }

    /// Everything under the root: the whole scan.
    pub fn root_agg(&self) -> Agg {
        self.nodes[0].agg
    }

    /// Why the report at `path` is partial, when the scan said.
    pub fn reason(&self, path: &Path) -> Option<&str> {
        self.reasons.get(path).map(String::as_str)
    }

    /// The newest entry the scan delivered.
    pub fn frontier(&self) -> Option<&Path> {
        self.frontier.as_deref()
    }

    /// Entries the scan delivered, unreadable ones and repeats included.
    pub fn scanned(&self) -> usize {
        self.scanned
    }

    /// The walk's own counts, which run ahead of the scan.
    pub fn counts(&self) -> &Totals {
        &self.counts
    }

    /// Fold in one of the walk's count deltas.
    pub fn counted(&mut self, delta: &CountDelta) {
        self.counts.apply(delta);
    }

    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    /// The scan delivered an entry at `path` (a file, or a folder it could
    /// not list): count it toward its folder and every ancestor, the way the
    /// walk counts it, and move the frontier. `created` collects folders made
    /// on the way.
    pub fn entry(&mut self, path: &Path, created: &mut Vec<usize>) {
        self.scanned += 1;
        if self.frontier.as_deref().is_none_or(|f| path > f) {
            self.frontier = Some(path.to_path_buf());
        }
        let mut at = Some(self.folder_for(path, created));
        while let Some(i) = at {
            self.nodes[i].walked += 1;
            at = self.nodes[i].parent;
        }
    }

    /// A folder the scan could not list, with why.
    pub fn add_unreadable(&mut self, path: &Path, reason: &str, created: &mut Vec<usize>) {
        let i = if path == self.root || !path.starts_with(&self.root) {
            0
        } else {
            self.ensure(path, created)
        };
        self.nodes[i].unreadable = Some(reason.to_string());
        let t = self.tick();
        self.stamp_up(i, t);
    }

    /// Add a report, with why it is partial when the scan said. Returns its
    /// folder.
    pub fn add(&mut self, r: &FileReport, reason: Option<&str>, created: &mut Vec<usize>) -> usize {
        let i = self.folder_for(&r.path, created);
        self.apply(i, &Agg::of(r), None);
        let t = self.tick();
        self.nodes[i].generation = t;
        match reason {
            Some(why) if r.partial => {
                self.reasons.insert(r.path.clone(), why.to_string());
            }
            _ => {}
        }
        i
    }

    /// Take a report back out.
    pub fn remove(&mut self, r: &FileReport) {
        let Some(i) = self.locate(&r.path) else {
            return;
        };
        self.apply(i, &Agg::default(), Some(&Agg::of(r)));
        let t = self.tick();
        self.nodes[i].generation = t;
        self.reasons.remove(&r.path);
    }

    /// Swap the report `old` for `new`, which has the same path. A rescan
    /// carries no reason, so any old one goes.
    pub fn replace(&mut self, old: &FileReport, new: &FileReport) {
        let Some(i) = self.locate(&new.path) else {
            return;
        };
        self.apply(i, &Agg::of(new), Some(&Agg::of(old)));
        self.reasons.remove(&new.path);
    }

    /// Add `plus` and take `minus` from folder `i` and every ancestor.
    fn apply(&mut self, i: usize, plus: &Agg, minus: Option<&Agg>) {
        let t = self.tick();
        let mut at = Some(i);
        while let Some(k) = at {
            let node = &mut self.nodes[k];
            if let Some(m) = minus {
                node.agg.sub(m);
            }
            node.agg.add(plus);
            node.stamp = t;
            at = node.parent;
        }
    }

    fn stamp_up(&mut self, i: usize, t: u64) {
        let mut at = Some(i);
        while let Some(k) = at {
            self.nodes[k].stamp = t;
            at = self.nodes[k].parent;
        }
    }

    /// The folder an entry at `path` belongs to, made with its ancestors as
    /// needed: the root for the root itself (a single-file scan) and for
    /// anything outside it, otherwise the entry's parent.
    fn folder_for(&mut self, path: &Path, created: &mut Vec<usize>) -> usize {
        if path == self.root {
            return 0;
        }
        let Some(parent) = path.parent() else {
            return 0;
        };
        if let Some(i) = self.last
            && self.nodes[i].path == parent
        {
            return i;
        }
        let i = if parent.starts_with(&self.root) {
            self.ensure(parent, created)
        } else {
            0
        };
        self.last = Some(i);
        i
    }

    /// The folder a report at `path` was added to, without making one.
    fn locate(&self, path: &Path) -> Option<usize> {
        if path == self.root {
            return Some(0);
        }
        match path.parent() {
            Some(parent) if parent.starts_with(&self.root) => self.find(parent),
            _ => Some(0),
        }
    }

    /// The node for `dir`, which is under the root, made with any missing
    /// ancestors.
    fn ensure(&mut self, dir: &Path, created: &mut Vec<usize>) -> usize {
        if let Some(&i) = self.index.get(dir) {
            return i;
        }
        let parent = match dir.parent() {
            Some(p) if p.starts_with(&self.root) => self.ensure(p, created),
            _ => 0,
        };
        let i = self.nodes.len();
        self.nodes.push(Node::new(dir.to_path_buf(), Some(parent)));
        self.index.insert(dir.to_path_buf(), i);
        self.nodes[parent].children.push(i);
        let t = self.tick();
        self.nodes[parent].generation = t;
        created.push(i);
        i
    }
}

/// The reports at or under `dir` in `reports`, which is sorted by path: one
/// contiguous run, found by binary search on `Path` order alone (`b/x` sorts
/// before `b-c` and `b.txt`, so no string prefix test is ever needed).
pub fn subtree(reports: &[FileReport], dir: &Path) -> std::ops::Range<usize> {
    let lo = reports.partition_point(|r| r.path.as_path() < dir);
    let hi = lo + reports[lo..].partition_point(|r| r.path.starts_with(dir));
    lo..hi
}

/// The reports directly in `dir`, in path order: the run under it, jumping
/// over each subfolder's own run by binary search, so the cost is the direct
/// files plus a search per subfolder. A report equal to `dir` (a single-file
/// scan) counts as direct. At the scan's `root`, reports outside it count as
/// direct too, so nothing the view holds is ever out of reach.
pub fn direct_files<'a>(reports: &'a [FileReport], dir: &Path, root: &Path) -> Vec<&'a FileReport> {
    let range = subtree(reports, dir);
    let mut out = Vec::new();
    if dir == root {
        out.extend(&reports[..range.start]);
    }
    let mut i = range.start;
    while i < range.end {
        let path = &reports[i].path;
        let Ok(rel) = path.strip_prefix(dir) else {
            i += 1;
            continue;
        };
        let mut parts = rel.components();
        match (parts.next(), parts.next()) {
            (Some(first), Some(_)) => {
                let sub = dir.join(first);
                i += reports[i..range.end].partition_point(|r| r.path.starts_with(&sub));
            }
            _ => {
                out.push(&reports[i]);
                i += 1;
            }
        }
    }
    if dir == root {
        out.extend(&reports[range.end..]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Category, ContainerKind, Evidence, Finding, JunkKind, Marker, Region};

    fn finding(sev: Severity, conf: Confidence, removable: bool) -> Finding {
        Finding {
            category: Category::Junk(JunkKind::Exif),
            confidence: conf,
            severity: sev,
            signature_id: "x.y".to_string(),
            title: "t".to_string(),
            evidence: Evidence::at(8),
            marker: removable.then(|| Marker::blank(Region::new(8, 4), ContainerKind::Raw)),
        }
    }

    fn report(path: &str, findings: Vec<Finding>, partial: bool) -> FileReport {
        let mut r = FileReport::new(PathBuf::from(path), 100 + path.len() as u64);
        r.findings = findings;
        r.partial = partial;
        r
    }

    /// The aggregate of every report at or under `dir`, the slow way.
    fn brute(reports: &[FileReport], dir: &Path) -> Agg {
        let mut a = Agg::default();
        for r in reports.iter().filter(|r| r.path.starts_with(dir)) {
            a.add(&Agg::of(r));
        }
        a
    }

    fn sample() -> Vec<FileReport> {
        use Confidence::{Strong, Weak};
        use Severity::{Alert, Info, Notice, Warn};
        let mut v = vec![
            report("r/a.txt", vec![finding(Info, Strong, false)], false),
            report("r/b/x/deep.bin", vec![finding(Alert, Strong, true)], false),
            report("r/b/y.bin", vec![], true),
            report(
                "r/b-c/z.bin",
                vec![finding(Warn, Weak, true), finding(Notice, Strong, true)],
                false,
            ),
            report("r/b.txt", vec![finding(Notice, Strong, true)], false),
            report("r/c/d/e/f.bin", vec![], false),
        ];
        v.sort_by(|a, b| a.path.cmp(&b.path));
        v
    }

    fn folders(reports: &[FileReport]) -> Vec<PathBuf> {
        let mut out: Vec<PathBuf> = reports
            .iter()
            .flat_map(|r| r.path.ancestors().skip(1).map(Path::to_path_buf))
            .filter(|p| p.starts_with("r"))
            .collect();
        out.sort();
        out.dedup();
        out
    }

    fn check(tree: &Tree, reports: &[FileReport]) {
        for dir in folders(reports) {
            let i = tree.find(&dir).unwrap_or_else(|| panic!("{dir:?}"));
            assert_eq!(tree.node(i).agg, brute(reports, &dir), "{dir:?}");
        }
    }

    #[test]
    fn aggregates_match_a_brute_force_count_through_add_replace_and_remove() {
        let mut reports = sample();
        let mut tree = Tree::new(Path::new("r"));
        let mut created = Vec::new();
        for r in &reports {
            tree.add(r, None, &mut created);
        }
        check(&tree, &reports);
        assert_eq!(tree.root_agg().files, 6);
        assert_eq!(tree.root_agg().alerts(), 1);
        assert_eq!(tree.root_agg().worst(), Some(Severity::Alert));
        let b = tree.find(Path::new("r/b")).unwrap();
        assert_eq!(tree.node(b).agg.partial, 1);
        let bc = tree.find(Path::new("r/b-c")).unwrap();
        assert_eq!(tree.node(bc).agg.weak, 1);
        assert_eq!(tree.node(bc).agg.removable, 2);

        // Replace the alert with a clean rescan: the worst drops exactly.
        let at = reports
            .iter()
            .position(|r| r.path == Path::new("r/b/x/deep.bin"))
            .unwrap();
        let fresh = report(
            "r/b/x/deep.bin",
            vec![finding(Severity::Info, Confidence::Strong, false)],
            false,
        );
        tree.replace(&reports[at], &fresh);
        reports[at] = fresh;
        check(&tree, &reports);
        assert_eq!(tree.root_agg().alerts(), 0);
        assert_eq!(tree.node(b).agg.worst(), Some(Severity::Info));

        // Remove a file: its folder keeps its node, now emptier.
        let gone = reports.remove(
            reports
                .iter()
                .position(|r| r.path == Path::new("r/b-c/z.bin"))
                .unwrap(),
        );
        tree.remove(&gone);
        check(&tree, &reports);
        assert_eq!(tree.node(bc).agg, Agg::default());
        assert_eq!(tree.root_agg().worst(), Some(Severity::Notice));
    }

    #[test]
    fn folders_and_generations() {
        let reports = sample();
        let mut tree = Tree::new(Path::new("r"));
        let mut created = Vec::new();
        tree.add(&reports[0], None, &mut created);
        assert!(created.is_empty(), "a root file makes no folder");
        let root_gen = tree.node(0).generation();
        tree.add(&reports[1], None, &mut created);
        let names: Vec<&Path> = created
            .iter()
            .map(|&i| tree.node(i).path.as_path())
            .collect();
        assert_eq!(
            names,
            [Path::new("r/b"), Path::new("r/b/x")],
            "ancestors first"
        );
        assert!(
            tree.node(0).generation() > root_gen,
            "a new subfolder moves the root's gen"
        );
        let b = tree.find(Path::new("r/b")).unwrap();
        let (b_gen, root_gen) = (tree.node(b).generation(), tree.node(0).generation());
        let root_stamp = tree.node(0).stamp();
        created.clear();
        tree.add(&reports[2], None, &mut created); // r/b/y.bin
        assert!(created.is_empty());
        assert!(tree.node(b).generation() > b_gen, "a new direct file");
        assert_eq!(
            tree.node(0).generation(),
            root_gen,
            "nothing direct changed at the root"
        );
        assert!(
            tree.node(0).stamp() > root_stamp,
            "but something under it did"
        );
        assert_eq!(tree.node(0).children, [b]);
    }

    #[test]
    fn entries_drive_the_frontier_and_walked_counts_but_copies_never_do() {
        let mut tree = Tree::new(Path::new("r"));
        let mut created = Vec::new();
        for p in ["r/a.txt", "r/b/x/deep.bin", "r/b/y.bin"] {
            tree.entry(Path::new(p), &mut created);
        }
        assert_eq!(tree.scanned(), 3);
        assert_eq!(tree.frontier(), Some(Path::new("r/b/y.bin")));
        let b = tree.find(Path::new("r/b")).unwrap();
        assert_eq!(tree.node(b).walked, 2);
        assert_eq!(tree.node(0).walked, 3);
        // A copy is a report like any other, but not a scanned entry.
        tree.add(
            &report("r/zz.deattributed.bin", vec![], false),
            None,
            &mut created,
        );
        assert_eq!(tree.scanned(), 3);
        assert_eq!(tree.frontier(), Some(Path::new("r/b/y.bin")));
        assert_eq!(tree.node(0).walked, 3);
        assert_eq!(tree.root_agg().files, 1);
        // An entry behind the frontier never moves it back.
        tree.entry(Path::new("r/a.txt"), &mut created);
        assert_eq!(tree.frontier(), Some(Path::new("r/b/y.bin")));
        assert_eq!(tree.scanned(), 4);
    }

    #[test]
    fn unreadable_folders_and_reasons() {
        let mut tree = Tree::new(Path::new("r"));
        let mut created = Vec::new();
        tree.entry(Path::new("r/locked"), &mut created);
        tree.add_unreadable(
            Path::new("r/locked"),
            "cannot list directory: permission denied",
            &mut created,
        );
        let locked = tree.find(Path::new("r/locked")).unwrap();
        assert_eq!(
            tree.node(locked).unreadable.as_deref(),
            Some("cannot list directory: permission denied")
        );
        assert_eq!(
            tree.node(locked).walked,
            0,
            "the walk counts it toward its parent"
        );
        assert_eq!(tree.node(0).walked, 1);
        assert_eq!(tree.root_agg().files, 0, "not a file");

        let cloud = report("r/cloud.docx", vec![], true);
        tree.add(
            &cloud,
            Some("cloud-only file, not downloaded"),
            &mut created,
        );
        assert_eq!(
            tree.reason(&cloud.path),
            Some("cloud-only file, not downloaded")
        );
        tree.replace(&cloud, &report("r/cloud.docx", vec![], false));
        assert_eq!(tree.reason(&cloud.path), None, "a rescan carries no reason");
        // A reason for a report that is not partial is not kept.
        tree.add(
            &report("r/fine.txt", vec![], false),
            Some("ignored"),
            &mut created,
        );
        assert_eq!(tree.reason(Path::new("r/fine.txt")), None);
    }

    #[test]
    fn a_single_file_root_and_outsiders_count_toward_the_root() {
        let mut tree = Tree::new(Path::new("dir/only.bin"));
        let mut created = Vec::new();
        tree.entry(Path::new("dir/only.bin"), &mut created);
        tree.add(&report("dir/only.bin", vec![], false), None, &mut created);
        assert!(created.is_empty());
        assert_eq!(tree.node(0).walked, 1);
        assert_eq!(tree.root_agg().files, 1);
        assert_eq!(tree.find(Path::new("dir")), None, "never above the root");

        let mut tree = Tree::new(Path::new("r"));
        let far = report(
            "elsewhere/x.bin",
            vec![finding(Severity::Warn, Confidence::Strong, true)],
            false,
        );
        tree.add(&far, None, &mut created);
        assert_eq!(tree.root_agg().files, 1);
        tree.remove(&far);
        assert_eq!(tree.root_agg(), Agg::default());
    }

    #[test]
    fn drive_roots_hold_their_folders() {
        let root = if cfg!(windows) { r"C:\" } else { "/" };
        let mut tree = Tree::new(Path::new(root));
        let mut created = Vec::new();
        let file = Path::new(root).join("Users").join("me").join("x.bin");
        tree.add(&FileReport::new(file, 1), None, &mut created);
        assert_eq!(created.len(), 2);
        let users = tree.find(&Path::new(root).join("Users")).unwrap();
        assert_eq!(tree.node(users).parent, Some(0));
        assert_eq!(tree.root_agg().files, 1);
    }

    #[test]
    fn direct_files_jump_over_subfolders_in_path_order() {
        let mut reports = sample();
        reports.push(report("elsewhere/far.bin", vec![], false));
        reports.sort_by(|a, b| a.path.cmp(&b.path));
        let names = |v: Vec<&FileReport>| -> Vec<String> {
            v.iter()
                .map(|r| r.path.to_string_lossy().replace('\\', "/"))
                .collect()
        };
        let root = Path::new("r");
        assert_eq!(
            names(direct_files(&reports, root, root)),
            ["elsewhere/far.bin", "r/a.txt", "r/b.txt"],
            "b/x and b-c are jumped over; an outsider shows at the root"
        );
        assert_eq!(
            names(direct_files(&reports, Path::new("r/b"), root)),
            ["r/b/y.bin"]
        );
        assert!(direct_files(&reports, Path::new("r/c/d"), root).is_empty());
        assert_eq!(subtree(&reports, Path::new("r/b")).len(), 2);
        assert_eq!(subtree(&reports, Path::new("r/b-c")).len(), 1);
        assert_eq!(subtree(&reports, Path::new("r/nothing")).len(), 0);
        // A single-file scan's report is its own direct file.
        let only = vec![report("dir/only.bin", vec![], false)];
        let file = Path::new("dir/only.bin");
        assert_eq!(names(direct_files(&only, file, file)), ["dir/only.bin"]);
    }
}
