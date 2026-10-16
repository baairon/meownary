//! The first-run picker: a keyboard file browser that picks a file or a
//! folder to scan.
//!
//! The input line is both the path and a live filter. Empty input lists recent
//! picks and places (known folders, drives, home). Input ending in a separator
//! lists that folder; any other input lists its parent, filtered by the last
//! segment. Letters always type, because paths contain h, j, k, l and q; only
//! arrows and control keys navigate.
//!
//! This is pure state with no terminal. `ui` draws it and the runtime feeds it
//! keys until [`Picker::on_key`] returns [`PickOutcome::Scan`],
//! [`PickOutcome::Back`] or [`PickOutcome::Quit`]. The runtime also loads and
//! saves the recent list; the picker only shows it.

#![cfg(feature = "tui")]

use std::path::{Component, MAIN_SEPARATOR, Path, PathBuf};

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

/// Most directory entries read from one folder.
const MAX_READ: usize = 10_000;
/// Most matching entries shown; [`Picker::hidden`] counts the rest.
const MAX_SHOWN: usize = 500;
/// Most recent picks listed.
const MAX_RECENT: usize = 5;
/// Rows moved by page up and page down.
const PAGE: usize = 10;

const HERE_LABEL: &str = "Scan this folder";
const CLOUD_WARNING: &str =
    "This file is only in the cloud. meownary never downloads files, so it cannot scan it.";

/// A suggested folder: a short label and its path. [`Picker::with_suggestions`]
/// turns these into [`EntryKind::Place`] rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suggestion {
    pub label: String,
    pub path: PathBuf,
}

/// What a row in the list stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// "Scan this folder": the folder being listed.
    Here,
    /// "..": the folder above.
    Parent,
    /// A recent pick, file or folder. Its label is the full path.
    Recent,
    /// A known folder, the current folder, a drive, or home.
    Place,
    Dir,
    File,
    /// A cloud placeholder whose content is not on disk. It cannot be scanned.
    CloudFile,
}

/// One row in the list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Folder labels end with the OS separator.
    pub label: String,
    pub path: PathBuf,
    pub kind: EntryKind,
    /// Size in bytes, for files only.
    pub size: Option<u64>,
}

/// How a [`Message`] reads: a nudge, a caution, or a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    Hint,
    Warn,
    Error,
}

/// One line of feedback under the list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub text: String,
    pub kind: MessageKind,
}

/// What the caller does after a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PickOutcome {
    /// Keep showing the picker.
    Stay,
    /// Scan this file or folder. The path is absolute.
    Scan(PathBuf),
    /// Close a reopened picker and return to the main view unchanged.
    Back,
    /// Leave the app.
    Quit,
}

/// The picker's state.
#[derive(Debug, Clone)]
pub struct Picker {
    input: String,
    /// Recent rows then place rows, shown while the input is empty.
    places: Vec<Entry>,
    /// The folder being listed, `None` while showing places.
    location: Option<PathBuf>,
    /// The last folder read. Filtering re-uses it; only a new location reads.
    listing: Option<Listing>,
    entries: Vec<Entry>,
    selected: Option<usize>,
    hidden: usize,
    message: Option<Message>,
    /// The standing message for the current view (a listing error or note),
    /// restored when a transient message clears.
    note: Option<Message>,
    /// The large root awaiting a second enter.
    confirm: Option<PathBuf>,
    home: Option<PathBuf>,
    cwd: Option<PathBuf>,
    /// Opened from the main view: the final esc returns Back.
    reopened: bool,
}

impl Picker {
    /// Recent picks that still exist, then the user's known folders that
    /// exist, the current folder, the drives, and home.
    pub fn new(cwd: Option<PathBuf>, recent: Vec<PathBuf>) -> Self {
        let dirs = directories::UserDirs::new();
        let home = dirs.as_ref().map(|d| d.home_dir().to_path_buf());
        let mut places: Vec<Entry> = Vec::new();
        if let Some(d) = &dirs {
            let known = [
                ("Downloads", d.download_dir()),
                ("Desktop", d.desktop_dir()),
                ("Documents", d.document_dir()),
                ("Pictures", d.picture_dir()),
                ("Videos", d.video_dir()),
                ("Music", d.audio_dir()),
            ];
            for (label, path) in known {
                if let Some(path) = path
                    && path.is_dir()
                {
                    push_place(&mut places, label, path.to_path_buf());
                }
            }
        }
        if let Some(cwd) = &cwd
            && cwd.is_dir()
            && !is_large_root(cwd, home.as_deref())
        {
            push_place(&mut places, "Current folder", cwd.clone());
        }
        for root in drive_roots() {
            let label = root.display().to_string();
            push_place(&mut places, &label, root);
        }
        if let Some(home) = &home {
            push_place(&mut places, "Home", home.clone());
        }
        Self::build(places, recent, home, cwd)
    }

    /// Fixed places, with no filesystem lookups for them (for previews and
    /// tests). Recent picks are still checked for existence.
    pub fn with_suggestions(places: Vec<Suggestion>, recent: Vec<PathBuf>) -> Self {
        let home = directories::BaseDirs::new().map(|d| d.home_dir().to_path_buf());
        let places = places
            .into_iter()
            .map(|s| Entry {
                label: s.label,
                path: s.path,
                kind: EntryKind::Place,
                size: None,
            })
            .collect();
        Self::build(places, recent, home, None)
    }

    /// Reopened from the main view on `current`. The input starts at
    /// current's parent with `current` highlighted. A final esc returns Back,
    /// not Quit.
    pub fn reopen(cwd: Option<PathBuf>, recent: Vec<PathBuf>, current: &Path) -> Self {
        let mut picker = Self::new(cwd, recent);
        picker.reopened = true;
        picker.show(current);
        picker
    }

    fn build(
        places: Vec<Entry>,
        recent: Vec<PathBuf>,
        home: Option<PathBuf>,
        cwd: Option<PathBuf>,
    ) -> Self {
        let mut rows = recent_entries(recent);
        rows.extend(places);
        let mut picker = Self {
            input: String::new(),
            places: rows,
            location: None,
            listing: None,
            entries: Vec::new(),
            selected: None,
            hidden: 0,
            message: None,
            note: None,
            confirm: None,
            home,
            cwd,
            reopened: false,
        };
        picker.refresh(None);
        picker
    }

    /// Handle one key. Release events are ignored.
    pub fn on_key(&mut self, ev: KeyEvent) -> PickOutcome {
        if ev.kind == KeyEventKind::Release {
            return PickOutcome::Stay;
        }
        let ctrl = ev.modifiers.contains(KeyModifiers::CONTROL);
        // AltGr arrives as Ctrl+Alt, and some layouts type `\` or `~` with it.
        let altgr = ctrl && ev.modifiers.contains(KeyModifiers::ALT);
        match ev.code {
            KeyCode::Char('c') if ctrl && !altgr => return PickOutcome::Quit,
            KeyCode::Char('u') if ctrl && !altgr => self.set_input(String::new()),
            KeyCode::Char('w') if ctrl && !altgr => self.delete_segment(),
            KeyCode::Char(c) if (!ctrl || altgr) && !c.is_control() => {
                self.input.push(c);
                self.refresh(None);
            }
            KeyCode::Backspace => {
                self.input.pop();
                self.refresh(None);
            }
            KeyCode::Up => self.step(-1, true),
            KeyCode::Down => self.step(1, true),
            KeyCode::PageUp => self.step(-(PAGE as isize), false),
            KeyCode::PageDown => self.step(PAGE as isize, false),
            KeyCode::Home => self.jump(false),
            KeyCode::End => self.jump(true),
            KeyCode::Right => self.open(false),
            KeyCode::Tab => self.open(true),
            KeyCode::Left => self.up(),
            KeyCode::Enter => return self.enter(),
            KeyCode::Esc => return self.escape(),
            _ => {}
        }
        PickOutcome::Stay
    }

    /// Append pasted text in one step, so a pasted path lists only its final
    /// folder. Line breaks are dropped.
    pub fn on_paste(&mut self, text: &str) {
        self.input.extend(text.chars().filter(|c| !c.is_control()));
        self.refresh(None);
    }

    /// The path line. The cursor is always at its end.
    pub fn input(&self) -> &str {
        &self.input
    }

    /// The folder being listed; `None` while showing places.
    pub fn location(&self) -> Option<&Path> {
        self.location.as_deref()
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The highlighted entry, if any.
    pub fn selected(&self) -> Option<usize> {
        self.selected
    }

    /// Matching entries left out past the 500 shown.
    pub fn hidden(&self) -> usize {
        self.hidden
    }

    pub fn message(&self) -> Option<&Message> {
        self.message.as_ref()
    }

    /// A very large folder awaits a second enter.
    pub fn confirming(&self) -> bool {
        self.confirm.is_some()
    }

    fn set_input(&mut self, input: String) {
        self.input = input;
        self.refresh(None);
    }

    /// List `path`'s parent with `path` highlighted, or the root itself.
    fn show(&mut self, path: &Path) {
        let path = normalize(path);
        match path.parent() {
            Some(parent) => {
                self.input = dir_input(parent);
                self.refresh(Some(&path));
            }
            None => self.set_input(dir_input(&path)),
        }
    }

    fn descend(&mut self, dir: &Path) {
        self.set_input(dir_input(dir));
    }

    /// Recompute the view from the input. Reads the folder only when the
    /// location changed. Highlights `want` if listed, else the entry named
    /// exactly like the filter, else the first match, else the Here row.
    fn refresh(&mut self, want: Option<&Path>) {
        self.confirm = None;
        self.hidden = 0;
        let Some(parsed) = self.parse() else {
            self.location = None;
            self.entries = self.places.clone();
            self.note = None;
            self.message = None;
            self.selected = (!self.entries.is_empty()).then_some(0);
            self.highlight(want);
            return;
        };
        if self
            .listing
            .as_ref()
            .is_none_or(|l| l.location != parsed.location)
        {
            self.listing = Some(Listing::read(&parsed.location));
        }
        let Some(listing) = &self.listing else { return };

        let mut entries = Vec::new();
        if listing.error.is_none() {
            entries.push(Entry {
                label: HERE_LABEL.to_string(),
                path: parsed.location.clone(),
                kind: EntryKind::Here,
                size: None,
            });
        }
        if let Some(parent) = parsed.location.parent() {
            entries.push(Entry {
                label: "..".to_string(),
                path: parent.to_path_buf(),
                kind: EntryKind::Parent,
                size: None,
            });
        }
        let head = entries.len();

        let filter = parsed.filter.to_lowercase();
        // Group 0 and 1: folders by prefix, then by substring. 2 and 3: files.
        let mut matched: Vec<(u8, &Item)> = listing
            .items
            .iter()
            .filter_map(|item| {
                let rank = if item.lower.starts_with(&filter) {
                    0
                } else if item.lower.contains(&filter) {
                    1
                } else {
                    return None;
                };
                Some((if item.dir { rank } else { 2 + rank }, item))
            })
            .collect();
        // Stable, so each group keeps the listing's name order.
        matched.sort_by_key(|&(group, _)| group);
        self.hidden = matched.len().saturating_sub(MAX_SHOWN);

        let (mut exact, mut exact_ci) = (None, None);
        for (_, item) in matched.into_iter().take(MAX_SHOWN) {
            if !filter.is_empty() {
                if exact.is_none() && item.name == parsed.filter {
                    exact = Some(entries.len());
                }
                if exact_ci.is_none() && item.lower == filter {
                    exact_ci = Some(entries.len());
                }
            }
            entries.push(item.entry());
        }

        let here = listing.error.is_none().then_some(0);
        self.selected = if filter.is_empty() {
            here
        } else {
            exact
                .or(exact_ci)
                .or((entries.len() > head).then_some(head))
                .or(here)
        };
        self.note = listing.note();
        self.message = self.note.clone();
        self.location = Some(parsed.location);
        self.entries = entries;
        self.highlight(want);
    }

    fn highlight(&mut self, want: Option<&Path>) {
        let Some(want) = want else { return };
        let found = self.entries.iter().position(|e| {
            !matches!(e.kind, EntryKind::Here | EntryKind::Parent) && same_path(&e.path, want)
        });
        if found.is_some() {
            self.selected = found;
        }
    }

    /// Split the input into the folder to list and the filter.
    fn parse(&self) -> Option<Parsed> {
        let typed = self.input.trim().trim_matches('"');
        if typed.is_empty() {
            return None;
        }
        if typed == "~"
            && let Some(home) = &self.home
        {
            let home = normalize(home);
            let filter = home
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let location = home.parent().map(Path::to_path_buf).unwrap_or(home);
            return Some(Parsed {
                dir: dir_input(&location),
                filter,
                location,
                sep: MAIN_SEPARATOR,
            });
        }
        if is_drive_letter(typed) {
            let location = PathBuf::from(format!("{typed}{MAIN_SEPARATOR}"));
            return Some(Parsed {
                dir: dir_input(&location),
                filter: String::new(),
                location,
                sep: MAIN_SEPARATOR,
            });
        }
        let (dir, filter, sep) = match typed.rfind(['/', '\\']) {
            Some(i) => (&typed[..=i], &typed[i + 1..], typed[i..].chars().next()),
            None => ("", typed, None),
        };
        Some(Parsed {
            location: self.resolve(dir),
            dir: dir.to_string(),
            filter: filter.to_string(),
            sep: sep.unwrap_or(MAIN_SEPARATOR),
        })
    }

    /// An absolute path for typed text: `~` expanded, relative to the
    /// current folder, `.` and `..` resolved.
    fn resolve(&self, typed: &str) -> PathBuf {
        let typed = if typed.is_empty() {
            ".".to_string()
        } else if cfg!(windows) {
            typed.to_string()
        } else {
            typed.replace('\\', "/")
        };
        let path = expand_tilde(&typed, self.home.as_deref());
        let path = match &self.cwd {
            Some(cwd) if path.is_relative() => cwd.join(path),
            _ => path,
        };
        normalize(&path)
    }

    /// Drop a transient message and a pending confirm, keeping the view's note.
    fn settle(&mut self) {
        self.confirm = None;
        self.message = self.note.clone();
    }

    fn step(&mut self, delta: isize, wrap: bool) {
        let n = self.entries.len();
        if n == 0 {
            return;
        }
        let i = match self.selected {
            None if delta > 0 => 0,
            None => n - 1,
            Some(i) if wrap => (i as isize + delta).rem_euclid(n as isize) as usize,
            Some(i) => (i as isize + delta).clamp(0, n as isize - 1) as usize,
        };
        self.selected = Some(i);
        self.settle();
    }

    fn jump(&mut self, last: bool) {
        if !self.entries.is_empty() {
            self.selected = Some(if last { self.entries.len() - 1 } else { 0 });
            self.settle();
        }
    }

    /// Right or tab: step into the highlighted folder, or put the highlighted
    /// file's path on the line.
    fn open(&mut self, tab: bool) {
        let entry = self.selected.and_then(|i| self.entries.get(i)).cloned();
        let Some(entry) = entry else {
            self.settle();
            if tab {
                self.hint("No match");
            }
            return;
        };
        match entry.kind {
            EntryKind::Here => {
                self.settle();
                if tab && self.parse().is_some_and(|p| !p.filter.is_empty()) {
                    self.hint("No match");
                }
            }
            EntryKind::Parent => self.descend(&entry.path),
            EntryKind::Dir | EntryKind::File | EntryKind::CloudFile => {
                let parsed = self.parse();
                let Some(p) = parsed else { return };
                let mut input = p.dir;
                input.push_str(entry.label.trim_end_matches(MAIN_SEPARATOR));
                if entry.kind == EntryKind::Dir {
                    input.push(p.sep);
                }
                self.set_input(input);
            }
            EntryKind::Recent | EntryKind::Place => {
                if entry.path.is_dir() {
                    self.descend(&entry.path);
                } else if entry.kind == EntryKind::Recent {
                    self.show(&entry.path);
                } else {
                    self.set_input(entry.path.display().to_string());
                }
            }
        }
    }

    /// Left: clear the filter, else go up a folder and highlight the one we
    /// came from. A no-op at a root or in places.
    fn up(&mut self) {
        let Some(p) = self.parse() else { return };
        if !p.filter.is_empty() {
            self.set_input(p.dir);
            return;
        }
        let Some(parent) = p.location.parent() else {
            return;
        };
        self.input = dir_input(parent);
        self.refresh(Some(&p.location));
    }

    fn enter(&mut self) -> PickOutcome {
        let entry = self.selected.and_then(|i| self.entries.get(i)).cloned();
        let Some(entry) = entry else {
            return self.enter_typed();
        };
        match entry.kind {
            EntryKind::Parent => {
                self.descend(&entry.path);
                PickOutcome::Stay
            }
            EntryKind::CloudFile => self.cloud_warning(),
            EntryKind::Recent if path_cloud_only(&entry.path) => self.cloud_warning(),
            _ => self.scan(entry.path),
        }
    }

    /// Enter with nothing highlighted: take the typed path as it is.
    fn enter_typed(&mut self) -> PickOutcome {
        let typed = self.input.trim().trim_matches('"').to_string();
        if typed.is_empty() {
            self.confirm = None;
            self.hint("Type a path, or pick an entry.");
            return PickOutcome::Stay;
        }
        let path = self.resolve(&typed);
        if !path.exists() {
            self.confirm = None;
            self.message = Some(Message {
                text: format!("No such file or folder: {typed}"),
                kind: MessageKind::Error,
            });
            return PickOutcome::Stay;
        }
        if path_cloud_only(&path) {
            return self.cloud_warning();
        }
        self.scan(path)
    }

    fn scan(&mut self, path: PathBuf) -> PickOutcome {
        let path = normalize(&path);
        if let Some(kind) = large_root_kind(&path, self.home.as_deref())
            && self.confirm.as_ref() != Some(&path)
        {
            self.message = Some(Message {
                text: kind.warning(),
                kind: MessageKind::Warn,
            });
            self.confirm = Some(path);
            return PickOutcome::Stay;
        }
        self.confirm = None;
        PickOutcome::Scan(path)
    }

    fn cloud_warning(&mut self) -> PickOutcome {
        self.confirm = None;
        self.message = Some(Message {
            text: CLOUD_WARNING.to_string(),
            kind: MessageKind::Warn,
        });
        PickOutcome::Stay
    }

    /// Esc: cancel a confirm, else clear the filter, else clear the input,
    /// else leave.
    fn escape(&mut self) -> PickOutcome {
        if self.confirm.is_some() {
            self.settle();
            return PickOutcome::Stay;
        }
        if let Some(p) = self.parse()
            && !p.filter.is_empty()
        {
            self.set_input(p.dir);
            return PickOutcome::Stay;
        }
        if !self.input.is_empty() {
            self.set_input(String::new());
            return PickOutcome::Stay;
        }
        if self.reopened {
            PickOutcome::Back
        } else {
            PickOutcome::Quit
        }
    }

    /// Ctrl+W: delete the last path segment, or the filter.
    fn delete_segment(&mut self) {
        let kept = self.input.trim_end_matches(['/', '\\']).len();
        self.input.truncate(kept);
        match self.input.rfind(['/', '\\']) {
            Some(i) => self.input.truncate(i + 1),
            None => self.input.clear(),
        }
        self.refresh(None);
    }

    fn hint(&mut self, text: &str) {
        self.message = Some(Message {
            text: text.to_string(),
            kind: MessageKind::Hint,
        });
    }
}

/// The input split into a folder and a filter.
struct Parsed {
    /// The typed folder part, ending with a separator, or empty.
    dir: String,
    /// The last segment, matched against names in `location`.
    filter: String,
    location: PathBuf,
    /// The separator the user typed last, kept when completing.
    sep: char,
}

/// One folder's contents, read once per location.
#[derive(Debug, Clone)]
struct Listing {
    location: PathBuf,
    /// Sorted by name, ignoring case.
    items: Vec<Item>,
    error: Option<String>,
    truncated: bool,
}

impl Listing {
    fn read(location: &Path) -> Self {
        let mut items = Vec::new();
        let mut error = None;
        let mut truncated = false;
        match std::fs::read_dir(location) {
            Err(e) => error = Some(list_error(location, &e)),
            Ok(read) => {
                for (n, entry) in read.enumerate() {
                    if n == MAX_READ {
                        truncated = true;
                        break;
                    }
                    if let Ok(entry) = entry {
                        items.push(Item::from_entry(&entry));
                    }
                }
            }
        }
        items.sort_by(|a, b| a.lower.cmp(&b.lower).then_with(|| a.name.cmp(&b.name)));
        Self {
            location: location.to_path_buf(),
            items,
            error,
            truncated,
        }
    }

    fn note(&self) -> Option<Message> {
        if let Some(text) = &self.error {
            return Some(Message {
                text: text.clone(),
                kind: MessageKind::Error,
            });
        }
        self.truncated.then(|| Message {
            text: format!("Only the first {MAX_READ} items in this folder are listed."),
            kind: MessageKind::Hint,
        })
    }
}

fn list_error(location: &Path, e: &std::io::Error) -> String {
    let at = location.display();
    match e.kind() {
        std::io::ErrorKind::NotFound => format!("No such folder: {at}"),
        std::io::ErrorKind::NotADirectory => format!("Not a folder: {at}"),
        std::io::ErrorKind::PermissionDenied => format!("Cannot open {at}: access denied."),
        _ => format!("Cannot open {at}: {e}"),
    }
}

/// One directory entry, from the listing's own metadata.
#[derive(Debug, Clone)]
struct Item {
    name: String,
    lower: String,
    path: PathBuf,
    dir: bool,
    cloud: bool,
    size: Option<u64>,
}

impl Item {
    /// On Windows the metadata comes from the directory listing itself
    /// (`WIN32_FIND_DATAW`), so this never opens the file. That matters for
    /// cloud placeholders, which download when opened.
    fn from_entry(entry: &std::fs::DirEntry) -> Self {
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        let meta = entry.metadata().ok();
        #[cfg(windows)]
        let (dir, cloud) = {
            use std::os::windows::fs::MetadataExt;
            const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
            // Directory links and junctions carry the directory attribute too.
            let attrs = meta.as_ref().map_or(0, |m| m.file_attributes());
            let dir = attrs & FILE_ATTRIBUTE_DIRECTORY != 0;
            (dir, !dir && cloud_only(attrs))
        };
        #[cfg(not(windows))]
        let (dir, cloud) = {
            let dir = entry
                .file_type()
                .is_ok_and(|t| t.is_dir() || (t.is_symlink() && path.is_dir()));
            (dir, false)
        };
        Self {
            lower: name.to_lowercase(),
            size: if dir { None } else { meta.map(|m| m.len()) },
            name,
            path,
            dir,
            cloud,
        }
    }

    fn entry(&self) -> Entry {
        let (label, kind) = if self.dir {
            (format!("{}{MAIN_SEPARATOR}", self.name), EntryKind::Dir)
        } else if self.cloud {
            (self.name.clone(), EntryKind::CloudFile)
        } else {
            (self.name.clone(), EntryKind::File)
        };
        Entry {
            label,
            path: self.path.clone(),
            kind,
            size: self.size,
        }
    }
}

/// Windows file attributes that mark a cloud placeholder (OneDrive and other
/// providers) whose content is not on disk. Matches the scan walk.
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

/// Whether a path outside a listing (a recent pick or a typed path) is a
/// cloud-only file. This asks for attributes only and reads no data.
#[cfg(windows)]
fn path_cloud_only(path: &Path) -> bool {
    use std::os::windows::fs::MetadataExt;
    std::fs::symlink_metadata(path).is_ok_and(|m| !m.is_dir() && cloud_only(m.file_attributes()))
}

#[cfg(not(windows))]
fn path_cloud_only(_: &Path) -> bool {
    false
}

/// Recent picks that still exist, at most five, in the given order.
fn recent_entries(recent: Vec<PathBuf>) -> Vec<Entry> {
    let mut out: Vec<Entry> = Vec::new();
    for path in recent {
        if out.len() == MAX_RECENT {
            break;
        }
        if out.iter().any(|e| same_path(&e.path, &path)) {
            continue;
        }
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        out.push(Entry {
            label: path.display().to_string(),
            size: meta.is_file().then_some(meta.len()),
            path,
            kind: EntryKind::Recent,
        });
    }
    out
}

fn push_place(places: &mut Vec<Entry>, label: &str, path: PathBuf) {
    if places.iter().any(|e| same_path(&e.path, &path)) {
        return;
    }
    places.push(Entry {
        label: label.to_string(),
        path,
        kind: EntryKind::Place,
        size: None,
    });
}

/// Drive roots that exist on Windows (A: and B: are skipped), or `/`.
fn drive_roots() -> Vec<PathBuf> {
    if cfg!(windows) {
        ('C'..='Z')
            .map(|d| PathBuf::from(format!("{d}:\\")))
            .filter(|p| p.is_dir())
            .collect()
    } else {
        vec![PathBuf::from("/")]
    }
}

/// `C:` style input on Windows: the drive's root.
fn is_drive_letter(typed: &str) -> bool {
    let b = typed.as_bytes();
    cfg!(windows) && b.len() == 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
}

/// A folder's path as input text, ending with a separator.
fn dir_input(path: &Path) -> String {
    let mut s = path.display().to_string();
    if !s.ends_with(['/', '\\']) {
        s.push(MAIN_SEPARATOR);
    }
    s
}

/// Which kind of very large root a path is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LargeRoot {
    /// A drive root such as `C:\`, or `/`.
    Drive { filesystem: bool },
    /// The user's home folder.
    Home,
    /// The folder holding every home folder, such as `C:\Users`.
    Users,
}

impl LargeRoot {
    fn warning(self) -> String {
        let what = match self {
            LargeRoot::Drive { filesystem: true } => "That is the whole filesystem.",
            LargeRoot::Drive { filesystem: false } => "That is a whole drive.",
            LargeRoot::Home => "That is your whole home folder.",
            LargeRoot::Users => "That holds every user's home folder.",
        };
        format!(
            "{what} Scanning it can take a long time. \
             Press enter again to scan it, or pick a smaller folder."
        )
    }
}

/// True for a root big enough to confirm before scanning: the home folder,
/// its parent (such as `C:\Users`), a drive root such as `C:\`, or `/`.
pub fn is_large_root(path: &Path, home: Option<&Path>) -> bool {
    large_root_kind(path, home).is_some()
}

fn large_root_kind(path: &Path, home: Option<&Path>) -> Option<LargeRoot> {
    let path = normalize(path);
    if path.parent().is_none() {
        let filesystem = !path.components().any(|c| matches!(c, Component::Prefix(_)));
        return Some(LargeRoot::Drive { filesystem });
    }
    let home = normalize(home?);
    if same_path(&path, &home) {
        return Some(LargeRoot::Home);
    }
    if home.parent().is_some_and(|users| same_path(&path, users)) {
        return Some(LargeRoot::Users);
    }
    None
}

/// Expand a leading `~` (alone, or before `/` or `\`) to the home folder.
fn expand_tilde(input: &str, home: Option<&Path>) -> PathBuf {
    match (home, input.strip_prefix('~')) {
        (Some(home), Some("")) => home.to_path_buf(),
        (Some(home), Some(rest)) if rest.starts_with(['/', '\\']) => {
            home.join(rest.trim_start_matches(['/', '\\']))
        }
        _ => PathBuf::from(input),
    }
}

/// Make a path absolute and drop `.` and `..` lexically, without touching
/// symlinks or adding a `\\?\` prefix the way `canonicalize` does on Windows.
fn normalize(path: &Path) -> PathBuf {
    let abs = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let mut out = PathBuf::new();
    for c in abs.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Path equality that ignores case on Windows.
fn same_path(a: &Path, b: &Path) -> bool {
    if !cfg!(windows) {
        return a == b;
    }
    let mut a = a.components();
    let mut b = b.components();
    loop {
        match (a.next(), b.next()) {
            (None, None) => return true,
            (Some(x), Some(y)) => {
                let x = x.as_os_str().to_string_lossy().to_lowercase();
                let y = y.as_os_str().to_string_lossy().to_lowercase();
                if x != y {
                    return false;
                }
            }
            _ => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEP: char = MAIN_SEPARATOR;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::from(code)
    }

    fn ctrl(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    fn press(p: &mut Picker, code: KeyCode) -> PickOutcome {
        p.on_key(key(code))
    }

    fn type_str(p: &mut Picker, s: &str) {
        for c in s.chars() {
            assert_eq!(p.on_key(key(KeyCode::Char(c))), PickOutcome::Stay);
        }
    }

    fn set(p: &mut Picker, s: &str) {
        p.on_key(ctrl('u'));
        type_str(p, s);
    }

    /// A picker with no places, no recents and no home.
    fn bare() -> Picker {
        let mut p = Picker::with_suggestions(Vec::new(), Vec::new());
        p.home = None;
        p
    }

    fn highlighted(p: &Picker) -> &Entry {
        &p.entries()[p.selected().expect("a highlight")]
    }

    fn labels(p: &Picker) -> Vec<&str> {
        p.entries().iter().map(|e| e.label.as_str()).collect()
    }

    fn dir_label(name: &str) -> String {
        format!("{name}{SEP}")
    }

    /// tmp/
    ///   alpha/ (inner/, a.txt)
    ///   beta/
    ///   notes.txt (5 bytes)
    fn tree() -> (tempfile::TempDir, String) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("alpha").join("inner")).unwrap();
        std::fs::write(root.join("alpha").join("a.txt"), b"a").unwrap();
        std::fs::create_dir(root.join("beta")).unwrap();
        std::fs::write(root.join("notes.txt"), b"hello").unwrap();
        let base = dir_input(root);
        (tmp, base)
    }

    #[test]
    fn places_when_input_is_empty() {
        let (tmp, _) = tree();
        let places = vec![
            Suggestion {
                label: "Downloads".into(),
                path: tmp.path().join("alpha"),
            },
            Suggestion {
                label: "Home".into(),
                path: tmp.path().to_path_buf(),
            },
        ];
        let p = Picker::with_suggestions(places, Vec::new());
        assert_eq!(p.input(), "");
        assert_eq!(p.location(), None);
        assert_eq!(labels(&p), ["Downloads", "Home"]);
        assert!(p.entries().iter().all(|e| e.kind == EntryKind::Place));
        assert_eq!(p.selected(), Some(0));
        assert_eq!(p.hidden(), 0);
        assert!(p.message().is_none());
    }

    #[test]
    fn recents_come_first_and_missing_ones_are_skipped() {
        let (tmp, _) = tree();
        let file = tmp.path().join("notes.txt");
        let alpha = tmp.path().join("alpha");
        let recent = vec![
            file.clone(),
            tmp.path().join("gone"),
            alpha.clone(),
            file.clone(),
        ];
        let places = vec![Suggestion {
            label: "Desktop".into(),
            path: tmp.path().join("beta"),
        }];
        let p = Picker::with_suggestions(places, recent);
        let kinds: Vec<_> = p.entries().iter().map(|e| e.kind).collect();
        assert_eq!(
            kinds,
            [EntryKind::Recent, EntryKind::Recent, EntryKind::Place]
        );
        assert_eq!(p.entries()[0].label, file.display().to_string());
        assert_eq!(p.entries()[0].size, Some(5));
        assert_eq!(p.entries()[1].path, alpha);
        assert_eq!(p.entries()[1].size, None);

        let many: Vec<PathBuf> = (0..7)
            .map(|i| {
                let d = tmp.path().join(format!("r{i}"));
                std::fs::create_dir(&d).unwrap();
                d
            })
            .collect();
        let p = Picker::with_suggestions(Vec::new(), many);
        assert_eq!(p.entries().len(), MAX_RECENT);
    }

    #[test]
    fn newest_recent_is_highlighted_and_enter_rescans_it() {
        let (tmp, _) = tree();
        let file = tmp.path().join("notes.txt");
        let mut p = Picker::with_suggestions(Vec::new(), vec![file.clone()]);
        assert_eq!(p.selected(), Some(0));
        assert_eq!(press(&mut p, KeyCode::Enter), PickOutcome::Scan(file));
    }

    #[test]
    fn right_on_a_recent_file_opens_its_folder_with_it_highlighted() {
        let (tmp, base) = tree();
        let file = tmp.path().join("notes.txt");
        let mut p = Picker::with_suggestions(Vec::new(), vec![file.clone()]);
        press(&mut p, KeyCode::Right);
        assert_eq!(p.input(), base);
        assert_eq!(highlighted(&p).path, file);
    }

    #[test]
    fn a_folder_lists_here_parent_folders_then_files() {
        let (tmp, base) = tree();
        let mut p = bare();
        set(&mut p, &base);
        assert_eq!(p.location(), Some(tmp.path()));
        let alpha = dir_label("alpha");
        let beta = dir_label("beta");
        assert_eq!(
            labels(&p),
            [HERE_LABEL, "..", alpha.as_str(), beta.as_str(), "notes.txt"]
        );
        assert_eq!(p.entries()[0].kind, EntryKind::Here);
        assert_eq!(p.entries()[1].kind, EntryKind::Parent);
        assert_eq!(p.entries()[4].kind, EntryKind::File);
        assert_eq!(p.entries()[4].size, Some(5));
        assert_eq!(p.selected(), Some(0), "an empty filter highlights Here");
    }

    #[test]
    fn descend_with_right_tab_and_enter_on_parent() {
        let (tmp, base) = tree();
        let mut p = bare();
        set(&mut p, &base);
        press(&mut p, KeyCode::Down);
        press(&mut p, KeyCode::Down);
        assert_eq!(highlighted(&p).label, dir_label("alpha"));
        press(&mut p, KeyCode::Right);
        assert_eq!(p.input(), format!("{base}alpha{SEP}"));
        assert_eq!(p.location(), Some(tmp.path().join("alpha").as_path()));

        type_str(&mut p, "in");
        assert_eq!(highlighted(&p).label, dir_label("inner"));
        press(&mut p, KeyCode::Tab);
        assert_eq!(p.input(), format!("{base}alpha{SEP}inner{SEP}"));

        // Enter on ".." goes up instead of scanning.
        press(&mut p, KeyCode::Down);
        assert_eq!(highlighted(&p).kind, EntryKind::Parent);
        assert_eq!(press(&mut p, KeyCode::Enter), PickOutcome::Stay);
        assert_eq!(p.location(), Some(tmp.path().join("alpha").as_path()));
    }

    #[test]
    fn forward_slashes_are_kept_when_completing() {
        let (tmp, _) = tree();
        let base = format!("{}/", tmp.path().display());
        let mut p = bare();
        set(&mut p, &format!("{base}al"));
        press(&mut p, KeyCode::Tab);
        assert_eq!(p.input(), format!("{base}alpha/"));
        assert_eq!(p.location(), Some(tmp.path().join("alpha").as_path()));
    }

    #[test]
    fn left_goes_up_and_highlights_the_folder_we_left() {
        let (tmp, base) = tree();
        let mut p = bare();
        set(&mut p, &format!("{base}alpha{SEP}in"));
        press(&mut p, KeyCode::Left);
        assert_eq!(
            p.input(),
            format!("{base}alpha{SEP}"),
            "left clears the filter first"
        );
        press(&mut p, KeyCode::Left);
        assert_eq!(p.input(), base);
        assert_eq!(highlighted(&p).path, tmp.path().join("alpha"));
    }

    #[test]
    fn left_is_a_no_op_at_a_root_and_in_places() {
        let mut p = bare();
        press(&mut p, KeyCode::Left);
        assert_eq!(p.input(), "");
        let root = if cfg!(windows) { "C:\\" } else { "/" };
        set(&mut p, root);
        assert!(p.entries().iter().all(|e| e.kind != EntryKind::Parent));
        press(&mut p, KeyCode::Left);
        assert_eq!(p.input(), root);
    }

    #[test]
    fn filter_puts_prefix_before_substring_ignoring_case() {
        let tmp = tempfile::tempdir().unwrap();
        for d in ["keynotes", "Notes2", "note", "other"] {
            std::fs::create_dir(tmp.path().join(d)).unwrap();
        }
        for f in ["footnotes.md", "notes.txt", "zzz.txt"] {
            std::fs::write(tmp.path().join(f), b"x").unwrap();
        }
        let mut p = bare();
        set(&mut p, &format!("{}NOTE", dir_input(tmp.path())));
        let (note, notes2, keynotes) = (
            dir_label("note"),
            dir_label("Notes2"),
            dir_label("keynotes"),
        );
        assert_eq!(
            labels(&p),
            [
                HERE_LABEL,
                "..",
                note.as_str(),
                notes2.as_str(),
                keynotes.as_str(),
                "notes.txt",
                "footnotes.md",
            ]
        );
        assert_eq!(highlighted(&p).label, note, "an exact name wins");

        type_str(&mut p, "s");
        assert_eq!(highlighted(&p).label, notes2, "else the first match");

        type_str(&mut p, "zzzz");
        assert_eq!(highlighted(&p).kind, EntryKind::Here, "else Here");
        press(&mut p, KeyCode::Tab);
        assert_eq!(p.message().map(|m| m.text.as_str()), Some("No match"));
    }

    #[test]
    fn a_typed_file_path_is_highlighted_and_enter_scans_it() {
        let (tmp, base) = tree();
        let file = tmp.path().join("notes.txt");
        let mut p = bare();
        set(&mut p, &format!("{base}NOTES.TXT"));
        assert_eq!(highlighted(&p).path, file);
        assert_eq!(
            press(&mut p, KeyCode::Enter),
            PickOutcome::Scan(file.clone())
        );

        // A pasted path with quotes, the way Windows copies one.
        p.on_key(ctrl('u'));
        p.on_paste(&format!("\"{}\"\r\n", file.display()));
        assert_eq!(highlighted(&p).path, file);

        // Right on a file puts its path on the line.
        set(&mut p, &format!("{base}no"));
        press(&mut p, KeyCode::Right);
        assert_eq!(p.input(), format!("{base}notes.txt"));
    }

    #[test]
    fn enter_on_here_scans_the_folder() {
        let (tmp, base) = tree();
        let mut p = bare();
        set(&mut p, &format!("{base}alpha{SEP}"));
        assert_eq!(highlighted(&p).kind, EntryKind::Here);
        assert_eq!(
            press(&mut p, KeyCode::Enter),
            PickOutcome::Scan(tmp.path().join("alpha"))
        );
    }

    #[test]
    fn matches_past_the_cap_are_counted_as_hidden() {
        let tmp = tempfile::tempdir().unwrap();
        for i in 0..MAX_SHOWN + 20 {
            std::fs::write(tmp.path().join(format!("f{i:04}")), b"").unwrap();
        }
        let mut p = bare();
        set(&mut p, &dir_input(tmp.path()));
        assert_eq!(p.entries().len(), 2 + MAX_SHOWN);
        assert_eq!(p.hidden(), 20);
        type_str(&mut p, "f00");
        assert_eq!(p.entries().len(), 2 + 100);
        assert_eq!(p.hidden(), 0);
    }

    #[test]
    fn a_folder_that_cannot_be_listed_shows_an_error() {
        let (tmp, base) = tree();
        let mut p = bare();
        set(&mut p, &format!("{base}missing{SEP}"));
        let msg = p.message().unwrap();
        assert_eq!(msg.kind, MessageKind::Error);
        assert!(msg.text.starts_with("No such folder"), "{}", msg.text);
        assert_eq!(p.entries().len(), 1);
        assert_eq!(p.entries()[0].kind, EntryKind::Parent);
        assert_eq!(p.entries()[0].path, tmp.path());
        assert_eq!(p.selected(), None);

        // Enter with nothing highlighted checks the typed path.
        assert_eq!(press(&mut p, KeyCode::Enter), PickOutcome::Stay);
        let msg = p.message().unwrap();
        assert_eq!(msg.kind, MessageKind::Error);
        assert!(msg.text.starts_with("No such file or folder"));

        set(&mut p, &format!("{base}notes.txt{SEP}"));
        assert_eq!(p.message().map(|m| m.kind), Some(MessageKind::Error));
        assert_eq!(p.selected(), None);
    }

    #[test]
    fn cloud_only_files_are_never_scanned() {
        assert!(cloud_only(FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS));
        assert!(cloud_only(FILE_ATTRIBUTE_RECALL_ON_OPEN));
        assert!(cloud_only(FILE_ATTRIBUTE_OFFLINE));
        assert!(cloud_only(0x0040_0000 | 0x0000_0400 | 0x0000_0020));
        assert!(!cloud_only(0));
        // Archive, pinned, unpinned: present on disk.
        for attrs in [0x20, 0x0008_0000, 0x0010_0000] {
            assert!(!cloud_only(attrs), "{attrs:#x}");
        }

        let (tmp, base) = tree();
        let mut p = bare();
        set(&mut p, &base);
        if let Some(listing) = &mut p.listing {
            for item in &mut listing.items {
                item.cloud = !item.dir;
            }
        }
        type_str(&mut p, "notes.txt");
        let entry = highlighted(&p);
        assert_eq!(entry.kind, EntryKind::CloudFile);
        assert_eq!(entry.path, tmp.path().join("notes.txt"));
        assert_eq!(press(&mut p, KeyCode::Enter), PickOutcome::Stay);
        let msg = p.message().unwrap();
        assert_eq!(msg.kind, MessageKind::Warn);
        assert_eq!(msg.text, CLOUD_WARNING);
    }

    #[test]
    fn large_root_needs_a_second_enter() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("me");
        std::fs::create_dir(&home).unwrap();
        let mut p = bare();
        p.home = Some(home.clone());

        // `~` lists home's parent with home highlighted.
        set(&mut p, "~");
        assert_eq!(highlighted(&p).path, home);
        assert_eq!(press(&mut p, KeyCode::Enter), PickOutcome::Stay);
        assert!(p.confirming());
        let msg = p.message().unwrap();
        assert_eq!(msg.kind, MessageKind::Warn);
        assert_eq!(
            msg.text,
            "That is your whole home folder. Scanning it can take a long time. \
             Press enter again to scan it, or pick a smaller folder."
        );
        assert_eq!(
            press(&mut p, KeyCode::Enter),
            PickOutcome::Scan(home.clone())
        );

        // Esc cancels a pending confirm and keeps the input.
        assert_eq!(press(&mut p, KeyCode::Enter), PickOutcome::Stay);
        assert_eq!(press(&mut p, KeyCode::Esc), PickOutcome::Stay);
        assert!(!p.confirming());
        assert!(p.message().is_none());
        assert_eq!(p.input(), "~");

        // Moving the highlight drops the confirm too.
        assert_eq!(press(&mut p, KeyCode::Enter), PickOutcome::Stay);
        press(&mut p, KeyCode::Down);
        assert!(!p.confirming());

        // The Here row of the folder above home.
        set(&mut p, &dir_input(tmp.path()));
        assert_eq!(press(&mut p, KeyCode::Enter), PickOutcome::Stay);
        assert!(
            p.message()
                .unwrap()
                .text
                .starts_with("That holds every user's home folder.")
        );
        assert_eq!(
            press(&mut p, KeyCode::Enter),
            PickOutcome::Scan(tmp.path().to_path_buf())
        );
    }

    #[test]
    fn large_roots() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("me");
        let root = if cfg!(windows) {
            Path::new("C:\\")
        } else {
            Path::new("/")
        };
        assert!(is_large_root(root, None));
        assert!(is_large_root(&home, Some(&home)));
        assert!(is_large_root(tmp.path(), Some(&home)));
        assert!(is_large_root(&home.join("x").join(".."), Some(&home)));
        assert!(!is_large_root(&home.join("Downloads"), Some(&home)));
        assert!(!is_large_root(&home, None));
        if cfg!(windows) {
            assert!(is_large_root(Path::new("D:/"), None));
            let upper = PathBuf::from(home.display().to_string().to_uppercase());
            assert!(is_large_root(&upper, Some(&home)));
            assert_eq!(
                large_root_kind(Path::new("C:\\"), None).unwrap().warning(),
                "That is a whole drive. Scanning it can take a long time. \
                 Press enter again to scan it, or pick a smaller folder."
            );
        } else {
            assert_eq!(
                large_root_kind(Path::new("/"), None),
                Some(LargeRoot::Drive { filesystem: true })
            );
        }
    }

    #[test]
    fn tilde_expands_to_home() {
        let (tmp, _) = tree();
        let mut p = bare();
        p.home = Some(tmp.path().to_path_buf());
        set(&mut p, "~/al");
        assert_eq!(p.location(), Some(tmp.path()));
        press(&mut p, KeyCode::Tab);
        assert_eq!(p.input(), "~/alpha/");
        assert_eq!(
            press(&mut p, KeyCode::Enter),
            PickOutcome::Scan(tmp.path().join("alpha"))
        );
        assert_eq!(expand_tilde("~\\a", Some(tmp.path())), tmp.path().join("a"));
        assert_eq!(expand_tilde("~a", Some(tmp.path())), PathBuf::from("~a"));
        assert_eq!(expand_tilde("~/a", None), PathBuf::from("~/a"));
    }

    #[test]
    fn typing_editing_and_letters() {
        let (_tmp, base) = tree();
        let mut p = bare();
        type_str(&mut p, "hjklq");
        assert_eq!(p.input(), "hjklq", "letters always type");
        press(&mut p, KeyCode::Backspace);
        assert_eq!(p.input(), "hjkl");
        p.on_key(ctrl('u'));
        assert_eq!(p.input(), "");

        set(&mut p, &format!("{base}alpha{SEP}in"));
        p.on_key(ctrl('w'));
        assert_eq!(p.input(), format!("{base}alpha{SEP}"));
        p.on_key(ctrl('w'));
        assert_eq!(p.input(), base);

        // Backspace over a separator shows the siblings.
        set(&mut p, &format!("{base}alpha{SEP}"));
        press(&mut p, KeyCode::Backspace);
        assert_eq!(highlighted(&p).label, dir_label("alpha"));

        let altgr = KeyModifiers::CONTROL | KeyModifiers::ALT;
        p.on_key(ctrl('u'));
        p.on_key(KeyEvent::new(KeyCode::Char('\\'), altgr));
        assert_eq!(p.input(), "\\");

        let mut release = key(KeyCode::Char('a'));
        release.kind = KeyEventKind::Release;
        p.on_key(release);
        assert_eq!(p.input(), "\\");
    }

    #[test]
    fn arrows_pages_home_and_end() {
        let tmp = tempfile::tempdir().unwrap();
        for i in 0..30 {
            std::fs::create_dir(tmp.path().join(format!("d{i:02}"))).unwrap();
        }
        let mut p = bare();
        set(&mut p, &dir_input(tmp.path()));
        let n = p.entries().len();
        assert_eq!(n, 32);
        press(&mut p, KeyCode::Up);
        assert_eq!(p.selected(), Some(n - 1), "up wraps");
        press(&mut p, KeyCode::Down);
        assert_eq!(p.selected(), Some(0), "down wraps");
        press(&mut p, KeyCode::PageDown);
        assert_eq!(p.selected(), Some(10));
        press(&mut p, KeyCode::PageUp);
        press(&mut p, KeyCode::PageUp);
        assert_eq!(p.selected(), Some(0), "pages stop at the ends");
        press(&mut p, KeyCode::End);
        assert_eq!(p.selected(), Some(n - 1));
        press(&mut p, KeyCode::Home);
        assert_eq!(p.selected(), Some(0));
    }

    #[test]
    fn esc_cancels_then_clears_filter_then_input_then_quits() {
        let (_tmp, base) = tree();
        let mut p = bare();
        set(&mut p, &format!("{base}al"));
        assert_eq!(press(&mut p, KeyCode::Esc), PickOutcome::Stay);
        assert_eq!(p.input(), base);
        assert_eq!(press(&mut p, KeyCode::Esc), PickOutcome::Stay);
        assert_eq!(p.input(), "");
        assert_eq!(p.location(), None);
        assert_eq!(press(&mut p, KeyCode::Esc), PickOutcome::Quit);

        type_str(&mut p, "x");
        assert_eq!(p.on_key(ctrl('c')), PickOutcome::Quit);
    }

    #[test]
    fn reopen_highlights_the_current_path_and_esc_goes_back() {
        let (tmp, _) = tree();
        let current = tmp.path().join("alpha").join("a.txt");
        let mut p = Picker::reopen(None, Vec::new(), &current);
        assert_eq!(p.input(), dir_input(&tmp.path().join("alpha")));
        assert_eq!(highlighted(&p).path, current);

        assert_eq!(press(&mut p, KeyCode::Esc), PickOutcome::Stay);
        assert_eq!(p.input(), "");
        assert_eq!(press(&mut p, KeyCode::Esc), PickOutcome::Back);
        assert_eq!(p.on_key(ctrl('c')), PickOutcome::Quit);

        let folder = tmp.path().join("beta");
        let p = Picker::reopen(None, Vec::new(), &folder);
        assert_eq!(highlighted(&p).path, folder);
    }

    #[test]
    fn no_dashes_in_messages() {
        let kinds = [
            LargeRoot::Drive { filesystem: true },
            LargeRoot::Drive { filesystem: false },
            LargeRoot::Home,
            LargeRoot::Users,
        ];
        let mut texts: Vec<String> = kinds.iter().map(|k| k.warning()).collect();
        texts.push(CLOUD_WARNING.to_string());
        for text in texts {
            assert!(!text.contains(['\u{2013}', '\u{2014}']), "{text}");
        }
    }
}
