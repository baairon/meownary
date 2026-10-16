//! The first-run picker: a keyboard file browser that picks a file or a
//! folder to scan, with browse keys like the main view's.
//!
//! Letters are commands, never path typing: arrows and `j`/`k` move, Enter
//! (or Right, or `l`) opens a folder or scans a file, Left (or `h`, or
//! Backspace) goes up a folder, and `s` scans the folder being shown. Typing
//! happens in the prompt `/` opens, which filters the folder or takes a
//! path, and a paste jumps to the path it names. `q` is deliberately not a
//! key: a paste on a terminal without bracketed paste arrives as keys, and
//! the runtime hands a burst of them over as prompt text instead.
//!
//! The top level lists recent picks, the user's known folders, the current
//! folder, home and the drives. A folder's pinned "Scan this folder" row
//! shows how many files a scan would cover, counted while the picker sits
//! there, and its subfolders show their own counts from the same walk.
//!
//! This is pure state: no terminal and no disk. Every read goes out as a
//! [`Request`] through [`Picker::take_requests`]; the runtime runs each on a
//! worker and hands the answer back through [`Picker::on_listing`],
//! [`Picker::on_stat`] and [`Picker::on_count`], so a slow folder or a
//! stalled network drive never holds the screen. Tests drive it the same
//! way, synchronously. The runtime also loads and saves the recent list;
//! the picker only shows it.

#![cfg(feature = "tui")]

use std::collections::HashMap;
use std::path::{Component, MAIN_SEPARATOR, Path, PathBuf};

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::scan::{CountDelta, Totals};

use super::app::{plural, thousands};
use super::listing::{Item, Listing, MAX_READ, path_cloud_only};

/// Most recent picks listed.
const MAX_RECENT: usize = 5;
/// The most files one count gets through before it stops, short.
pub const COUNT_CAP: usize = 10_000_000;

/// The label of the pinned row that scans the folder being shown.
pub const HERE_LABEL: &str = "Scan this folder";
const CLOUD_WARNING: &str =
    "This file is only in the cloud. meownary never downloads files, so it cannot scan it.";
const KEYS_HINT: &str = "Letters are keys here. Press / to filter or type a path.";
const UNREADABLE: &str = "This folder cannot be read, so there is nothing to scan.";

/// A suggested folder: a short label and its path. [`Picker::with_suggestions`]
/// lists these as they are, with no lookups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suggestion {
    pub label: String,
    pub path: PathBuf,
}

/// What a row in the list stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A recent pick, file or folder. Its label is the full path.
    Recent,
    /// A known folder, the current folder, or home.
    Place,
    /// A drive root such as `C:\`, or `/`.
    Drive,
    /// A folder inside the folder being shown.
    Dir,
    /// A file inside the folder being shown.
    File,
}

/// One row in the list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Folder labels end with the OS separator.
    pub label: String,
    pub path: PathBuf,
    pub kind: EntryKind,
    /// A folder, or a link to one: Enter opens it.
    pub dir: bool,
    /// A cloud placeholder whose content is not on disk. It cannot be scanned.
    pub cloud: bool,
    /// A dot-name, or an entry marked hidden or system: drawn faint and
    /// listed after the rest.
    pub hidden: bool,
    /// A link a scan never follows.
    pub link: bool,
    /// Size in bytes, for files only.
    pub size: Option<u64>,
}

/// Where the highlight is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Highlight {
    /// The pinned "Scan this folder" row above a folder's list.
    Scan,
    /// A row of [`Picker::entries`].
    Row(usize),
}

/// A recursive file count: how many files a scan would cover, and whether
/// more may follow (the count is still running, or it stopped short).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Count {
    pub files: u64,
    pub more: bool,
}

/// How a [`Message`] reads: a nudge, a caution, or a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    Hint,
    Warn,
    Error,
}

/// Feedback under the list.
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
    /// Show the picker's key sheet.
    Help,
    /// Close a reopened picker and return to the main view unchanged.
    Back,
    /// Leave the app.
    Quit,
}

/// A read the picker needs. The runtime carries each out off the input
/// thread and answers through the matching `on_` method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// List this folder; answered by [`Picker::on_listing`].
    List(PathBuf),
    /// Find out what this path is; answered by [`Picker::on_stat`].
    Stat(PathBuf),
    /// Count the files a scan of this folder would cover, replacing any
    /// count still running; answered by [`Picker::on_count`].
    Count(PathBuf),
    /// Stop the running count: nothing shows it any more.
    StopCount,
}

/// What a path turned out to be, from its metadata alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Found {
    /// Nothing is there, or it cannot be looked up.
    Missing,
    Folder,
    /// A file: its size, and whether it is a cloud placeholder whose content
    /// is not on disk.
    File {
        size: u64,
        cloud: bool,
    },
}

/// The picker's state.
#[derive(Debug, Clone)]
pub struct Picker {
    /// What the list shows.
    view: View,
    /// Recent picks then places, each found, gone, or still being looked up.
    places: Vec<Place>,
    /// The latest folder listing to arrive.
    folder: Option<Folder>,
    /// The rows on show: the view, narrowed by the filter.
    rows: Vec<Entry>,
    highlight: Option<Highlight>,
    /// The highlight was placed on purpose (a move, or a remembered one), so
    /// rows arriving later keep it instead of the default first entry.
    touched: bool,
    /// The filter kept after the prompt closed with enter.
    filter: String,
    /// The prompt, while it is open.
    prompt: Option<Prompt>,
    /// A transient message, cleared by the next move.
    message: Option<Message>,
    /// A large root waiting for a second press.
    confirm: Option<Confirm>,
    /// The running count: its folder and the totals so far.
    counts: Option<(PathBuf, Totals)>,
    /// Each folder's highlight, kept when leaving it.
    marks: HashMap<PathBuf, Mark>,
    /// The places list's highlight, kept while a folder is shown.
    places_mark: Option<Mark>,
    /// A pasted or reopened path waiting for its lookup.
    jump: Option<PathBuf>,
    /// Reads not yet handed to the runtime.
    requests: Vec<Request>,
    home: Option<PathBuf>,
    cwd: Option<PathBuf>,
    /// Opened from the main view: the last esc returns Back, not Quit.
    reopened: bool,
    /// Rows a page key moves, set by the renderer.
    page: usize,
}

impl Picker {
    // ---- building ---------------------------------------------------------

    /// The real picker: recent picks, the user's known folders, the current
    /// folder, home and the drives. Nothing is read here; every place but
    /// home is looked up through [`Request::Stat`] before it shows.
    pub fn new(cwd: Option<PathBuf>, recent: Vec<PathBuf>) -> Self {
        let dirs = directories::UserDirs::new();
        let home = dirs.as_ref().map(|d| d.home_dir().to_path_buf());
        let mut known = Vec::new();
        if let Some(d) = &dirs {
            let folders = [
                ("Downloads", d.download_dir()),
                ("Desktop", d.desktop_dir()),
                ("Documents", d.document_dir()),
                ("Pictures", d.picture_dir()),
                ("Videos", d.video_dir()),
                ("Music", d.audio_dir()),
            ];
            for (label, path) in folders {
                if let Some(path) = path {
                    known.push((label.to_string(), path.to_path_buf()));
                }
            }
        }
        Self::probing(known, cwd, home, drive_roots(), recent)
    }

    /// The real picker's places, given. Known folders, the current folder
    /// and the drives are looked up before they show; home shows at once,
    /// and the drives go after it, so a slow drive never moves a row above.
    fn probing(
        known: Vec<(String, PathBuf)>,
        cwd: Option<PathBuf>,
        home: Option<PathBuf>,
        drives: Vec<PathBuf>,
        recent: Vec<PathBuf>,
    ) -> Self {
        let mut places = Vec::new();
        for (label, path) in known {
            push_place(&mut places, &label, path, EntryKind::Place, Probe::Pending);
        }
        if let Some(cwd) = &cwd
            && !is_large_root(cwd, home.as_deref())
        {
            let probe = Probe::Pending;
            push_place(
                &mut places,
                "Current folder",
                cwd.clone(),
                EntryKind::Place,
                probe,
            );
        }
        if let Some(home) = &home {
            let found = Probe::Found(Found::Folder);
            push_place(&mut places, "Home", home.clone(), EntryKind::Place, found);
        }
        for root in drives {
            let label = root.display().to_string();
            push_place(&mut places, &label, root, EntryKind::Drive, Probe::Pending);
        }
        Self::build(places, recent, home, cwd)
    }

    /// Fixed places, listed with no lookups (for previews and tests). Recent
    /// picks are still looked up before they show.
    pub fn with_suggestions(places: Vec<Suggestion>, recent: Vec<PathBuf>) -> Self {
        let home = directories::BaseDirs::new().map(|d| d.home_dir().to_path_buf());
        let mut list = Vec::new();
        for s in places {
            let kind = if is_root(&s.path) {
                EntryKind::Drive
            } else {
                EntryKind::Place
            };
            push_place(
                &mut list,
                &s.label,
                s.path,
                kind,
                Probe::Found(Found::Folder),
            );
        }
        Self::build(list, recent, home, None)
    }

    /// Reopened from the main view on `target`: see [`Picker::reopened_at`].
    pub fn reopen(cwd: Option<PathBuf>, recent: Vec<PathBuf>, target: &Path) -> Self {
        Self::new(cwd, recent).reopened_at(target)
    }

    /// This picker opened from the main view on `target`: it starts in that
    /// folder (a file's own folder, with the file highlighted), and the last
    /// esc returns Back instead of Quit.
    pub fn reopened_at(mut self, target: &Path) -> Self {
        self.reopened = true;
        self.jump_to(target.to_path_buf(), true);
        self
    }

    /// Use `home` for `~` and the large-root checks instead of the user's.
    pub fn with_home(mut self, home: Option<PathBuf>) -> Self {
        self.home = home;
        self
    }

    fn build(
        places: Vec<Place>,
        recent: Vec<PathBuf>,
        home: Option<PathBuf>,
        cwd: Option<PathBuf>,
    ) -> Self {
        let mut list = recent_places(recent);
        list.extend(places);
        let requests = list
            .iter()
            .filter(|p| p.probe == Probe::Pending)
            .map(|p| Request::Stat(p.path.clone()))
            .collect();
        let mut picker = Self {
            view: View::Places,
            places: list,
            folder: None,
            rows: Vec::new(),
            highlight: None,
            touched: false,
            filter: String::new(),
            prompt: None,
            message: None,
            confirm: None,
            counts: None,
            marks: HashMap::new(),
            places_mark: None,
            jump: None,
            requests,
            home,
            cwd,
            reopened: false,
            page: 10,
        };
        picker.rebuild(None);
        picker
    }

    // ---- input ------------------------------------------------------------

    /// Handle one key. Release events are ignored.
    pub fn on_key(&mut self, ev: KeyEvent) -> PickOutcome {
        if ev.kind == KeyEventKind::Release {
            return PickOutcome::Stay;
        }
        let ctrl = ev.modifiers.contains(KeyModifiers::CONTROL);
        // AltGr arrives as Ctrl+Alt, and some layouts type `\` or `~` with it.
        let altgr = ctrl && ev.modifiers.contains(KeyModifiers::ALT);
        if ev.code == KeyCode::Char('c') && ctrl && !altgr {
            return PickOutcome::Quit;
        }
        let typed = match ev.code {
            KeyCode::Char(c) if (!ctrl || altgr) && !c.is_control() => Some(c),
            _ => None,
        };
        if self.prompt.is_some() {
            self.prompt_key(ev.code, ctrl && !altgr, typed);
            return PickOutcome::Stay;
        }
        let outcome = self.browse_key(ev.code, typed);
        // A place's count only serves its confirm.
        if self.view == View::Places && self.confirm.is_none() && self.counts.take().is_some() {
            self.requests.push(Request::StopCount);
        }
        outcome
    }

    /// A bracketed paste: in the prompt it is text (an absolute path
    /// replaces what was typed); otherwise it jumps to the path it names, a
    /// folder opening and a file showing in its folder, highlighted.
    pub fn on_paste(&mut self, text: &str) {
        let text = clean_paste(text);
        if text.is_empty() {
            return;
        }
        if self.prompt.is_some() {
            self.paste_into_prompt(&text);
            return;
        }
        self.message = None;
        self.confirm = None;
        let view = self.view.clone();
        let path = self.resolve(&text, &view);
        self.jump_to(path, false);
    }

    /// Keys that arrived too fast to be typed by hand: a paste on a terminal
    /// without bracketed paste. They become prompt text, never commands.
    pub fn on_burst(&mut self, text: &str) {
        let text: String = text.chars().filter(|c| !c.is_control()).collect();
        if text.is_empty() {
            return;
        }
        if self.prompt.is_none() {
            self.confirm = None;
            self.open_prompt(String::new());
        }
        self.paste_into_prompt(&text);
    }

    // ---- the runtime's side ----------------------------------------------

    /// The reads asked for since the last call, oldest first.
    pub fn take_requests(&mut self) -> Vec<Request> {
        std::mem::take(&mut self.requests)
    }

    /// Whether reads wait to be taken.
    pub fn has_requests(&self) -> bool {
        !self.requests.is_empty()
    }

    /// A folder listing arrived. Only the folder on show takes it.
    pub fn on_listing(&mut self, listing: Listing) {
        let View::Folder(dir) = &self.view else {
            return;
        };
        if listing.location != *dir {
            return;
        }
        let remembered = self.marks.get(&path_key(dir)).cloned();
        let mark = self.current_mark().or(remembered);
        self.folder = Some(Folder::new(listing));
        self.rebuild(mark);
    }

    /// A lookup arrived: a place shows or goes, and a pasted or reopened
    /// path opens.
    pub fn on_stat(&mut self, path: &Path, found: Found) {
        let mut changed = false;
        for p in &mut self.places {
            if p.probe == Probe::Pending && p.path == path {
                p.probe = settle_probe(p.kind, found);
                changed = true;
            }
        }
        if changed && self.view == View::Places {
            self.refresh();
        }
        if self.jump.as_deref() == Some(path) {
            self.jump = None;
            self.land(path.to_path_buf(), found);
        }
    }

    /// More of a count arrived for the folder counted at `root`.
    pub fn on_count(&mut self, root: &Path, delta: &CountDelta) {
        if let Some((counted, totals)) = &mut self.counts
            && counted == root
        {
            totals.apply(delta);
        }
    }

    /// The list on show waits on a read: a listing, a jump's lookup, or (at
    /// the top level) a place other than a drive. The runtime gives such a
    /// read a moment to land, so a fast folder never flashes empty.
    pub fn waiting(&self) -> bool {
        self.jump.is_some()
            || matches!(&self.view, View::Folder(dir) if !self.listed(dir))
            || (self.view == View::Places
                && self
                    .places
                    .iter()
                    .any(|p| p.probe == Probe::Pending && p.kind != EntryKind::Drive))
    }

    /// Something on show is still being read, drives included: the view
    /// shows a thin gauge.
    pub fn loading(&self) -> bool {
        self.waiting()
            || (self.view == View::Places && self.places.iter().any(|p| p.probe == Probe::Pending))
    }

    // ---- what the view draws ----------------------------------------------

    /// The folder being shown; `None` at the top level.
    pub fn location(&self) -> Option<&Path> {
        match &self.view {
            View::Folder(dir) => Some(dir),
            View::Places => None,
        }
    }

    pub fn entries(&self) -> &[Entry] {
        &self.rows
    }

    pub fn highlight(&self) -> Option<Highlight> {
        self.highlight
    }

    /// The highlighted row of [`Picker::entries`], if any.
    pub fn selected(&self) -> Option<usize> {
        match self.highlight {
            Some(Highlight::Row(i)) => Some(i),
            _ => None,
        }
    }

    /// The prompt's text while it is open.
    pub fn prompt(&self) -> Option<&str> {
        self.prompt.as_ref().map(|p| p.text.as_str())
    }

    /// What narrows the list: the prompt's last segment, or the kept filter.
    pub fn filter(&self) -> &str {
        match &self.prompt {
            Some(p) => &p.filter,
            None => &self.filter,
        }
    }

    /// The pinned scan row shows: a folder, with the prompt closed.
    pub fn scan_row(&self) -> bool {
        self.prompt.is_none() && matches!(self.view, View::Folder(_))
    }

    /// The message under the list: a pending confirm, else the latest
    /// message, else the folder's own note (why it could not be read).
    pub fn message(&self) -> Option<Message> {
        if let Some(c) = &self.confirm {
            return Some(Message {
                text: self.confirm_text(c),
                kind: MessageKind::Warn,
            });
        }
        if let Some(m) = &self.message {
            return Some(m.clone());
        }
        self.shown_folder().and_then(Folder::note)
    }

    /// A very large folder awaits a second press.
    pub fn confirming(&self) -> bool {
        self.confirm.is_some()
    }

    /// The folder on show was read and could not be listed.
    pub fn listing_failed(&self) -> bool {
        self.shown_folder()
            .is_some_and(|f| f.listing.error.is_some())
    }

    /// How many files a scan of the folder on show would cover so far;
    /// `None` before the first count arrives.
    pub fn here_count(&self) -> Option<Count> {
        let View::Folder(dir) = &self.view else {
            return None;
        };
        let (root, totals) = self.counts.as_ref()?;
        if root != dir || (totals.total() == 0 && !totals.is_done()) {
            return None;
        }
        Some(Count {
            files: totals.total(),
            more: !totals.is_done() || totals.was_stopped(),
        })
    }

    /// The count of `dir`, a folder inside the one on show; `None` until the
    /// count reaches it.
    pub fn count_of(&self, dir: &Path) -> Option<Count> {
        let (_, totals) = self.counts.as_ref()?;
        let fin = totals.is_final(dir);
        let more = !fin || totals.was_stopped();
        match totals.get(dir) {
            Some(files) => Some(Count { files, more }),
            None if fin && !totals.was_stopped() => Some(Count {
                files: 0,
                more: false,
            }),
            None => None,
        }
    }

    /// What esc does now: cancel, clear, back or quit.
    pub fn esc_word(&self) -> &'static str {
        if self.prompt.is_some() || self.confirm.is_some() {
            "cancel"
        } else if !self.filter.is_empty() {
            "clear"
        } else if self.reopened {
            "back"
        } else {
            "quit"
        }
    }

    /// The rows a page key moves: the list's height on screen.
    pub fn set_page(&mut self, rows: usize) {
        self.page = rows.max(1);
    }

    // ---- keys -------------------------------------------------------------

    fn browse_key(&mut self, code: KeyCode, typed: Option<char>) -> PickOutcome {
        // A pending confirm holds only for the key that answers it.
        let armed = self.confirm.take();
        match (code, typed) {
            (KeyCode::Up, _) | (_, Some('k')) => self.step(-1),
            (KeyCode::Down, _) | (_, Some('j')) => self.step(1),
            (KeyCode::PageUp, _) => self.page_by(-1),
            (KeyCode::PageDown, _) => self.page_by(1),
            (KeyCode::Home, _) | (_, Some('g')) => self.jump_end(false),
            (KeyCode::End, _) | (_, Some('G')) => self.jump_end(true),
            (KeyCode::Enter | KeyCode::Right, _) | (_, Some('l')) => return self.open(armed),
            (KeyCode::Left | KeyCode::Backspace, _) | (_, Some('h')) => self.up(),
            (KeyCode::Esc, _) => return self.escape(armed),
            (_, Some('s')) => return self.scan_here(armed),
            (_, Some('/')) => {
                let text = self.filter.clone();
                self.open_prompt(text);
            }
            (_, Some('?')) => return PickOutcome::Help,
            (_, Some('~')) => self.go_home(),
            (_, Some(_)) => self.hint(KEYS_HINT),
            _ => {}
        }
        PickOutcome::Stay
    }

    fn prompt_key(&mut self, code: KeyCode, ctrl: bool, typed: Option<char>) {
        match code {
            KeyCode::Enter => self.keep_prompt(),
            KeyCode::Esc => self.cancel_prompt(),
            KeyCode::Tab => self.complete(),
            KeyCode::Up => self.step(-1),
            KeyCode::Down => self.step(1),
            KeyCode::PageUp => self.page_by(-1),
            KeyCode::PageDown => self.page_by(1),
            KeyCode::Home => self.jump_end(false),
            KeyCode::End => self.jump_end(true),
            KeyCode::Backspace => self.edit(|t| {
                t.pop();
            }),
            KeyCode::Char('u') if ctrl => self.edit(String::clear),
            KeyCode::Char('w') if ctrl => self.edit(erase_segment),
            _ => {
                if let Some(c) = typed {
                    self.edit(|t| t.push(c));
                }
            }
        }
    }

    /// Move by `delta` rows, stopping at the ends. Up from the first entry
    /// reaches the scan row.
    fn step(&mut self, delta: isize) {
        self.message = None;
        let lo: isize = if self.scan_row() { -1 } else { 0 };
        let hi = self.rows.len() as isize - 1;
        if hi < lo {
            return;
        }
        let at = match self.highlight {
            Some(Highlight::Scan) => -1,
            Some(Highlight::Row(i)) => i as isize,
            None => {
                self.place_at(if delta > 0 && hi >= 0 { 0 } else { lo });
                return;
            }
        };
        self.place_at((at + delta).clamp(lo, hi));
    }

    /// Page by the list's height, stopping at the first and last entry.
    fn page_by(&mut self, dir: isize) {
        self.message = None;
        let hi = self.rows.len() as isize - 1;
        if hi < 0 {
            return;
        }
        let at = match self.highlight {
            Some(Highlight::Row(i)) => i as isize,
            _ => -1,
        };
        if at < 0 && dir < 0 {
            return;
        }
        self.place_at((at + dir * self.page as isize).clamp(0, hi));
    }

    fn jump_end(&mut self, last: bool) {
        self.message = None;
        if !self.rows.is_empty() {
            let i = if last { self.rows.len() - 1 } else { 0 };
            self.place_at(i as isize);
        }
    }

    /// Highlight position `at`: -1 is the scan row.
    fn place_at(&mut self, at: isize) {
        self.touched = true;
        self.highlight = Some(if at < 0 {
            Highlight::Scan
        } else {
            Highlight::Row(at as usize)
        });
    }

    fn selected_entry(&self) -> Option<&Entry> {
        self.selected().and_then(|i| self.rows.get(i))
    }

    /// Enter, Right or `l`: open a folder or place, scan a file, or scan
    /// the folder from its scan row.
    fn open(&mut self, armed: Option<Confirm>) -> PickOutcome {
        self.message = None;
        match self.highlight {
            Some(Highlight::Scan) => self.scan_here_with("enter", armed),
            Some(Highlight::Row(_)) => {
                let Some(entry) = self.selected_entry().cloned() else {
                    return PickOutcome::Stay;
                };
                if entry.dir {
                    self.open_folder(entry.path, None);
                    PickOutcome::Stay
                } else if entry.cloud {
                    self.warn(CLOUD_WARNING);
                    PickOutcome::Stay
                } else {
                    self.scan_request(entry.path, "enter", armed)
                }
            }
            None => PickOutcome::Stay,
        }
    }

    /// `s`: scan the folder on show, or at the top level the highlighted place.
    fn scan_here(&mut self, armed: Option<Confirm>) -> PickOutcome {
        self.message = None;
        if self.view == View::Places {
            let Some(entry) = self.selected_entry().cloned() else {
                return PickOutcome::Stay;
            };
            if entry.cloud {
                self.warn(CLOUD_WARNING);
                return PickOutcome::Stay;
            }
            return self.scan_request(entry.path, "s", armed);
        }
        self.scan_here_with("s", armed)
    }

    fn scan_here_with(&mut self, key: &'static str, armed: Option<Confirm>) -> PickOutcome {
        let View::Folder(dir) = &self.view else {
            return PickOutcome::Stay;
        };
        let dir = dir.clone();
        if self.listing_failed() {
            self.message = Some(Message {
                text: UNREADABLE.to_string(),
                kind: MessageKind::Error,
            });
            return PickOutcome::Stay;
        }
        self.scan_request(dir, key, armed)
    }

    /// Scan `path`, unless it is a large root seen for the first time: then
    /// warn, quoting its count, and wait for the same press again.
    fn scan_request(
        &mut self,
        path: PathBuf,
        key: &'static str,
        armed: Option<Confirm>,
    ) -> PickOutcome {
        let target = normalize(&path);
        let Some(kind) = large_root_kind(&target, self.home.as_deref()) else {
            return PickOutcome::Scan(target);
        };
        if armed.is_some_and(|c| same_path(&c.path, &target)) {
            return PickOutcome::Scan(target);
        }
        let counted = if self.counting(&path) {
            path
        } else if self.counting(&target) {
            target.clone()
        } else {
            self.start_count(target.clone());
            target.clone()
        };
        self.confirm = Some(Confirm {
            path: target,
            counted,
            kind,
            key,
        });
        PickOutcome::Stay
    }

    /// Left, `h` or Backspace: up a folder, highlighting the one we left. At
    /// a drive root, the top level with that drive highlighted.
    fn up(&mut self) {
        self.message = None;
        let View::Folder(dir) = &self.view else {
            return;
        };
        let dir = dir.clone();
        match dir.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => {
                self.open_folder(parent.to_path_buf(), Some(Mark::Path(dir)));
            }
            _ => self.show_places(Some(Mark::Path(dir))),
        }
    }

    fn go_home(&mut self) {
        self.message = None;
        match self.home.clone() {
            Some(home) => self.open_folder(home, None),
            None => self.hint("No home folder is known here."),
        }
    }

    /// Esc: cancel a confirm, else clear the filter, else leave.
    fn escape(&mut self, armed: Option<Confirm>) -> PickOutcome {
        self.message = None;
        if armed.is_some() {
            return PickOutcome::Stay;
        }
        if !self.filter.is_empty() {
            let keep = self.current_mark();
            self.filter.clear();
            self.rebuild(keep);
            return PickOutcome::Stay;
        }
        if self.reopened {
            PickOutcome::Back
        } else {
            PickOutcome::Quit
        }
    }

    // ---- the prompt -------------------------------------------------------

    fn open_prompt(&mut self, text: String) {
        self.message = None;
        let before = (self.view.clone(), self.filter.clone(), self.current_mark());
        self.prompt = Some(Prompt {
            text,
            filter: String::new(),
            before,
        });
        self.apply_prompt();
    }

    fn edit(&mut self, change: impl FnOnce(&mut String)) {
        if let Some(p) = &mut self.prompt {
            change(&mut p.text);
        }
        self.message = None;
        self.apply_prompt();
    }

    fn paste_into_prompt(&mut self, text: &str) {
        let replaces = is_absolute_text(text.trim().trim_matches('"'));
        self.edit(|t| {
            if replaces {
                *t = text.to_string();
            } else {
                t.push_str(text);
            }
        });
    }

    /// Follow the prompt's text: list the folder it names and narrow the
    /// list by its last segment. A name typed in full is highlighted, else
    /// the highlight stays if it still matches, else the first match.
    fn apply_prompt(&mut self) {
        let Some(prompt) = &self.prompt else {
            return;
        };
        let (view, filter) = self.parse(&prompt.text, &prompt.before.0);
        let keep = self.current_mark();
        if view != self.view {
            self.set_view(view);
        }
        if let Some(p) = &mut self.prompt {
            p.filter = filter.clone();
        }
        self.rows = self.compute_rows();
        let exact = self.exact(&filter);
        let kept = self.find(keep.as_ref());
        self.touched = exact.is_some() || kept.is_some();
        self.highlight = exact.or(kept).or(self.first());
    }

    /// Enter: close the prompt, keeping its folder and filter. Never scans.
    fn keep_prompt(&mut self) {
        if let Some(p) = self.prompt.take() {
            self.filter = p.filter;
        }
    }

    /// Esc: close the prompt and put back the folder, filter and highlight
    /// from before `/`.
    fn cancel_prompt(&mut self) {
        let Some(p) = self.prompt.take() else {
            return;
        };
        let (view, filter, mark) = p.before;
        self.filter = filter;
        if view != self.view {
            self.set_view(view);
        }
        match (&self.view, &mark) {
            (View::Folder(dir), Some(m)) => {
                self.marks.insert(path_key(dir), m.clone());
            }
            (View::Places, _) => self.places_mark = mark.clone(),
            _ => {}
        }
        self.rebuild(mark);
    }

    /// Tab: complete the highlighted name. A folder gains a separator, which
    /// lists it.
    fn complete(&mut self) {
        let Some(entry) = self.selected_entry().cloned() else {
            self.hint("No match");
            return;
        };
        let places = self.view == View::Places;
        let Some(p) = &mut self.prompt else {
            return;
        };
        let sep = p
            .text
            .chars()
            .rev()
            .find(|c| matches!(c, '/' | '\\'))
            .unwrap_or(MAIN_SEPARATOR);
        let head = match p.text.rfind(['/', '\\']) {
            Some(i) => p.text[..=i].to_string(),
            None => String::new(),
        };
        let mut text = if places {
            entry.path.display().to_string()
        } else {
            format!("{head}{}", entry_name(&entry))
        };
        if entry.dir && !text.ends_with(['/', '\\']) {
            text.push(sep);
        }
        p.text = text;
        self.apply_prompt();
    }

    // ---- views and rows ---------------------------------------------------

    /// Show `dir`. Its listing and count are asked for unless already here.
    /// `mark` is highlighted once it shows, else what the folder last had
    /// highlighted, else its first entry.
    fn open_folder(&mut self, dir: PathBuf, mark: Option<Mark>) {
        self.keep_mark();
        if let Some(mark) = mark {
            self.marks.insert(path_key(&dir), mark);
        }
        self.filter.clear();
        self.confirm = None;
        self.set_view(View::Folder(dir));
        self.restore();
    }

    /// The top level, with `mark` highlighted if given.
    fn show_places(&mut self, mark: Option<Mark>) {
        self.keep_mark();
        if mark.is_some() {
            self.places_mark = mark;
        }
        self.filter.clear();
        self.confirm = None;
        self.set_view(View::Places);
        self.restore();
    }

    /// Switch the list to `view`, asking for what it needs. The rows are
    /// rebuilt by the caller.
    fn set_view(&mut self, view: View) {
        match &view {
            View::Folder(dir) => {
                if !self.listed(dir) {
                    self.requests.push(Request::List(dir.clone()));
                }
                if !self.counting(dir) {
                    self.start_count(dir.clone());
                }
            }
            View::Places => {
                if self.counts.take().is_some() {
                    self.requests.push(Request::StopCount);
                }
            }
        }
        self.view = view;
        self.rows.clear();
        self.highlight = None;
    }

    /// Go to `path` once it is looked up. With `show_now` the list shows it
    /// as a folder meanwhile (a reopened picker has nothing else to show).
    fn jump_to(&mut self, path: PathBuf, show_now: bool) {
        if show_now {
            self.view = View::Folder(path.clone());
            self.rows.clear();
            self.highlight = None;
        }
        self.jump = Some(path.clone());
        self.requests.push(Request::Stat(path));
    }

    /// A jump's path turned out to be `found`.
    fn land(&mut self, path: PathBuf, found: Found) {
        match found {
            Found::Folder => self.open_folder(path, None),
            Found::File { .. } => match path.parent() {
                Some(parent) if !parent.as_os_str().is_empty() => {
                    self.open_folder(parent.to_path_buf(), Some(Mark::Path(path)));
                }
                _ => {}
            },
            Found::Missing => {
                if self.view == View::Folder(path.clone()) && !self.listed(&path) {
                    self.show_places(None);
                }
                self.message = Some(Message {
                    text: format!("No such file or folder: {}", path.display()),
                    kind: MessageKind::Error,
                });
            }
        }
    }

    /// Keep the current highlight for the view being left.
    fn keep_mark(&mut self) {
        let mark = self.current_mark();
        match &self.view {
            View::Places => self.places_mark = mark,
            View::Folder(dir) => {
                if let Some(m) = mark {
                    self.marks.insert(path_key(dir), m);
                }
            }
        }
    }

    fn current_mark(&self) -> Option<Mark> {
        match self.highlight? {
            Highlight::Scan => Some(Mark::Scan),
            Highlight::Row(i) => self.rows.get(i).map(|e| Mark::Path(e.path.clone())),
        }
    }

    /// Rebuild the rows with the view's remembered highlight.
    fn restore(&mut self) {
        let mark = match &self.view {
            View::Places => self.places_mark.clone(),
            View::Folder(dir) => self.marks.get(&path_key(dir)).cloned(),
        };
        self.rebuild(mark);
    }

    /// Rebuild the rows, highlighting `mark` if it shows, else the first.
    fn rebuild(&mut self, mark: Option<Mark>) {
        self.rows = self.compute_rows();
        let found = self.find(mark.as_ref());
        self.touched = found.is_some();
        self.highlight = found.or(self.first());
    }

    /// Rebuild after rows arrived, keeping a highlight placed on purpose; an
    /// untouched list keeps its default, the first entry.
    fn refresh(&mut self) {
        let keep = if self.touched {
            self.current_mark()
        } else {
            None
        };
        let touched = self.touched;
        self.rebuild(keep);
        self.touched |= touched && self.highlight.is_some();
    }

    fn first(&self) -> Option<Highlight> {
        (!self.rows.is_empty()).then_some(Highlight::Row(0))
    }

    fn find(&self, mark: Option<&Mark>) -> Option<Highlight> {
        match mark? {
            Mark::Scan => self.scan_row().then_some(Highlight::Scan),
            Mark::Path(p) => self
                .rows
                .iter()
                .position(|e| same_path(&e.path, p))
                .map(Highlight::Row),
        }
    }

    /// The row named exactly `filter`, matching case first.
    fn exact(&self, filter: &str) -> Option<Highlight> {
        if filter.is_empty() {
            return None;
        }
        let lower = filter.to_lowercase();
        self.rows
            .iter()
            .position(|e| entry_name(e) == filter)
            .or_else(|| {
                self.rows
                    .iter()
                    .position(|e| entry_name(e).to_lowercase() == lower)
            })
            .map(Highlight::Row)
    }

    fn compute_rows(&self) -> Vec<Entry> {
        let filter = self.filter().to_lowercase();
        match &self.view {
            View::Places => place_rows(&self.places, &filter),
            View::Folder(_) => self
                .shown_folder()
                .map(|f| f.rows(&filter))
                .unwrap_or_default(),
        }
    }

    /// The folder on show, once its listing arrived.
    fn shown_folder(&self) -> Option<&Folder> {
        let View::Folder(dir) = &self.view else {
            return None;
        };
        self.folder.as_ref().filter(|f| f.listing.location == *dir)
    }

    fn listed(&self, dir: &Path) -> bool {
        self.folder
            .as_ref()
            .is_some_and(|f| f.listing.location == dir)
    }

    fn counting(&self, dir: &Path) -> bool {
        self.counts
            .as_ref()
            .is_some_and(|(root, _)| same_path(root, dir))
    }

    fn start_count(&mut self, dir: PathBuf) {
        self.counts = Some((dir.clone(), Totals::new(&dir, Some(1))));
        self.requests.push(Request::Count(dir));
    }

    /// Split prompt text into the view to list and the filter. Plain text
    /// filters `base`; text with a separator, a lone `~` or a drive is a
    /// path, listed up to its last segment, which filters it.
    fn parse(&self, text: &str, base: &View) -> (View, String) {
        let typed = text.trim().trim_matches('"');
        if !is_path_text(typed) {
            return (base.clone(), typed.to_string());
        }
        if typed == "~"
            && let Some(home) = &self.home
        {
            let home = normalize(home);
            let name = home
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let parent = home.parent().map(Path::to_path_buf).unwrap_or(home);
            return (View::Folder(parent), name);
        }
        if is_drive_letter(typed) {
            let root = PathBuf::from(format!("{typed}{MAIN_SEPARATOR}"));
            return (View::Folder(root), String::new());
        }
        let (dir, filter) = match typed.rfind(['/', '\\']) {
            Some(i) => (&typed[..=i], &typed[i + 1..]),
            None => ("", typed),
        };
        (View::Folder(self.resolve(dir, base)), filter.to_string())
    }

    /// An absolute path for typed or pasted text: `~` expanded, relative to
    /// `base` (else the current folder, else home), `.` and `..` resolved.
    fn resolve(&self, typed: &str, base: &View) -> PathBuf {
        let typed = if cfg!(windows) {
            typed.to_string()
        } else {
            typed.replace('\\', "/")
        };
        let path = expand_tilde(&typed, self.home.as_deref());
        let path = if path.is_relative() {
            let from = match base {
                View::Folder(dir) => Some(dir.clone()),
                View::Places => self.cwd.clone().or_else(|| self.home.clone()),
            };
            match from {
                Some(from) => from.join(path),
                None => path,
            }
        } else {
            path
        };
        normalize(&path)
    }

    /// The large-root warning, with the count so far.
    fn confirm_text(&self, c: &Confirm) -> String {
        let count = match &self.counts {
            Some((root, t)) if *root == c.counted && (t.total() > 0 || t.is_done()) => {
                let n = Count {
                    files: t.total(),
                    more: !t.is_done() || t.was_stopped(),
                };
                let so_far = if t.is_done() { "" } else { " so far" };
                format!(": {}{so_far}", count_text(n))
            }
            _ => String::new(),
        };
        format!(
            "{}{count}. Press {} again to scan it.",
            c.kind.what(),
            c.key
        )
    }

    fn hint(&mut self, text: &str) {
        self.message = Some(Message {
            text: text.to_string(),
            kind: MessageKind::Hint,
        });
    }

    fn warn(&mut self, text: &str) {
        self.message = Some(Message {
            text: text.to_string(),
            kind: MessageKind::Warn,
        });
    }
}

/// What the list shows.
#[derive(Debug, Clone, PartialEq, Eq)]
enum View {
    /// Recent picks and places.
    Places,
    /// One folder's contents.
    Folder(PathBuf),
}

/// A highlight to come back to: the scan row, or an entry by path.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Mark {
    Scan,
    Path(PathBuf),
}

/// The prompt `/` opened.
#[derive(Debug, Clone)]
struct Prompt {
    text: String,
    /// What narrows the list: a path's last segment, or all of plain text.
    filter: String,
    /// The view, filter and highlight from before `/`, for esc.
    before: (View, String, Option<Mark>),
}

/// One place the top level can list.
#[derive(Debug, Clone)]
struct Place {
    label: String,
    path: PathBuf,
    kind: EntryKind,
    probe: Probe,
}

/// Where a place's lookup stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Probe {
    Pending,
    /// Shown.
    Found(Found),
    /// Missing, or not a folder where one was wanted: never shown.
    Gone,
}

/// A large root waiting for a second press.
#[derive(Debug, Clone)]
struct Confirm {
    /// What a second press scans.
    path: PathBuf,
    /// The folder whose count the warning quotes.
    counted: PathBuf,
    kind: LargeRoot,
    /// The key that armed it, named in the warning.
    key: &'static str,
}

/// A folder's listing with every name lowercased once, so filtering on each
/// key never lowercases the whole folder again.
#[derive(Debug, Clone)]
struct Folder {
    listing: Listing,
    lower: Vec<String>,
}

impl Folder {
    fn new(listing: Listing) -> Self {
        let lower = listing
            .items
            .iter()
            .map(|item| item.name.to_lowercase())
            .collect();
        Self { listing, lower }
    }

    fn note(&self) -> Option<Message> {
        if let Some(text) = &self.listing.error {
            return Some(Message {
                text: text.clone(),
                kind: MessageKind::Error,
            });
        }
        self.listing.truncated.then(|| Message {
            text: format!(
                "Only the first {} items in this folder are listed.",
                thousands(MAX_READ)
            ),
            kind: MessageKind::Hint,
        })
    }

    /// The rows matching `filter` (lowercase): prefix matches before the
    /// rest, hidden entries after shown ones, folders before files, each
    /// group in the listing's natural order.
    fn rows(&self, filter: &str) -> Vec<Entry> {
        let mut matched: Vec<(u8, &Item)> = self
            .listing
            .items
            .iter()
            .zip(&self.lower)
            .filter_map(|(item, lower)| {
                let rank = if lower.starts_with(filter) {
                    0
                } else if lower.contains(filter) {
                    1
                } else {
                    return None;
                };
                let group = (rank << 2) | (u8::from(item.hidden) << 1) | u8::from(!item.dir);
                Some((group, item))
            })
            .collect();
        matched.sort_by_key(|&(group, _)| group);
        matched
            .into_iter()
            .map(|(_, item)| item_entry(item))
            .collect()
    }
}

/// The row for a listed file or folder.
fn item_entry(item: &Item) -> Entry {
    let label = if item.dir {
        format!("{}{MAIN_SEPARATOR}", item.name)
    } else {
        item.name.clone()
    };
    Entry {
        label,
        path: item.path.clone(),
        kind: if item.dir {
            EntryKind::Dir
        } else {
            EntryKind::File
        },
        dir: item.dir,
        cloud: item.cloud,
        hidden: item.hidden,
        link: item.link,
        size: item.size,
    }
}

/// The name Tab completes and an exact filter matches.
fn entry_name(e: &Entry) -> &str {
    match e.kind {
        EntryKind::Dir => e.label.trim_end_matches(MAIN_SEPARATOR),
        _ => &e.label,
    }
}

/// The places that show, at most five recent picks first, narrowed by
/// `filter` (lowercase) on label or path, label prefixes first.
fn place_rows(places: &[Place], filter: &str) -> Vec<Entry> {
    let mut recents = 0;
    let mut out: Vec<(u8, Entry)> = Vec::new();
    for p in places {
        let Probe::Found(found) = p.probe else {
            continue;
        };
        if p.kind == EntryKind::Recent {
            if recents == MAX_RECENT {
                continue;
            }
            recents += 1;
        }
        let dir = found == Found::Folder;
        let mut label = p.label.clone();
        if p.kind == EntryKind::Recent && dir && !label.ends_with(['/', '\\']) {
            label.push(MAIN_SEPARATOR);
        }
        let rank = if filter.is_empty() {
            0
        } else {
            let l = label.to_lowercase();
            if l.starts_with(filter) {
                0
            } else if l.contains(filter) || p.path.to_string_lossy().to_lowercase().contains(filter)
            {
                1
            } else {
                continue;
            }
        };
        let (size, cloud) = match found {
            Found::File { size, cloud } => (Some(size), cloud),
            _ => (None, false),
        };
        out.push((
            rank,
            Entry {
                label,
                path: p.path.clone(),
                kind: p.kind,
                dir,
                cloud,
                hidden: false,
                link: false,
                size,
            },
        ));
    }
    out.sort_by_key(|&(rank, _)| rank);
    out.into_iter().map(|(_, e)| e).collect()
}

/// Recent picks, deduplicated, each waiting for its lookup.
fn recent_places(recent: Vec<PathBuf>) -> Vec<Place> {
    let mut out: Vec<Place> = Vec::new();
    for path in recent {
        if out.iter().any(|p| same_path(&p.path, &path)) {
            continue;
        }
        out.push(Place {
            label: path.display().to_string(),
            path,
            kind: EntryKind::Recent,
            probe: Probe::Pending,
        });
    }
    out
}

fn push_place(places: &mut Vec<Place>, label: &str, path: PathBuf, kind: EntryKind, probe: Probe) {
    if places.iter().any(|p| same_path(&p.path, &path)) {
        return;
    }
    places.push(Place {
        label: label.to_string(),
        path,
        kind,
        probe,
    });
}

/// A place's lookup result: a recent pick may be a file; any other place
/// must be a folder.
fn settle_probe(kind: EntryKind, found: Found) -> Probe {
    match (kind, found) {
        (_, Found::Missing) => Probe::Gone,
        (EntryKind::Recent, f) | (_, f @ Found::Folder) => Probe::Found(f),
        _ => Probe::Gone,
    }
}

/// A count as the picker shows it: "1,204 files", "1 file", or
/// "1,204+ files" while more may follow.
pub fn count_text(c: Count) -> String {
    let n = usize::try_from(c.files).unwrap_or(usize::MAX);
    if c.more {
        format!("{}+ files", thousands(n))
    } else {
        format!("{} {}", thousands(n), plural(n, "file", "files"))
    }
}

/// Look `path` up from its metadata alone. The runtime runs this on a
/// worker for [`Request::Stat`]; nothing in [`Picker`] calls it. A cloud
/// placeholder is described from its attributes and never opened.
pub fn stat(path: &Path) -> Found {
    if path_cloud_only(path) {
        let size = std::fs::symlink_metadata(path).map_or(0, |m| m.len());
        return Found::File { size, cloud: true };
    }
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_dir() => Found::Folder,
        Ok(meta) => Found::File {
            size: meta.len(),
            cloud: false,
        },
        Err(_) => Found::Missing,
    }
}

/// The drive roots to look for: `C:\` to `Z:\` on Windows (A: and B: are
/// skipped), or `/`.
fn drive_roots() -> Vec<PathBuf> {
    if cfg!(windows) {
        ('C'..='Z')
            .map(|d| PathBuf::from(format!("{d}:\\")))
            .collect()
    } else {
        vec![PathBuf::from("/")]
    }
}

/// A root with nothing above it, such as `C:\` or `/`.
fn is_root(path: &Path) -> bool {
    path.has_root() && path.parent().is_none()
}

/// `C:` style input on Windows: the drive's root.
fn is_drive_letter(typed: &str) -> bool {
    let b = typed.as_bytes();
    cfg!(windows) && b.len() == 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
}

/// Prompt text that names a path rather than filtering.
fn is_path_text(typed: &str) -> bool {
    typed.contains(['/', '\\']) || typed == "~" || is_drive_letter(typed)
}

/// Pasted text that stands on its own as a path, replacing what was typed.
fn is_absolute_text(text: &str) -> bool {
    let p = Path::new(text);
    p.is_absolute()
        || p.has_root()
        || text == "~"
        || text.starts_with("~/")
        || text.starts_with("~\\")
        || text.get(..2).is_some_and(is_drive_letter)
}

/// Paste text as a path: line breaks and other control characters dropped,
/// and the quotes Windows adds when copying a path stripped.
fn clean_paste(text: &str) -> String {
    let kept: String = text.chars().filter(|c| !c.is_control()).collect();
    kept.trim().trim_matches('"').trim().to_string()
}

/// Ctrl+W: erase the last path segment, or the filter.
fn erase_segment(text: &mut String) {
    let kept = text.trim_end_matches(['/', '\\']).len();
    text.truncate(kept);
    match text.rfind(['/', '\\']) {
        Some(i) => text.truncate(i + 1),
        None => text.clear(),
    }
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
    /// What the root is: the start of its warning.
    fn what(self) -> &'static str {
        match self {
            LargeRoot::Drive { filesystem: true } => "That is the whole filesystem",
            LargeRoot::Drive { filesystem: false } => "That is a whole drive",
            LargeRoot::Home => "That is your whole home folder",
            LargeRoot::Users => "That holds every user's home folder",
        }
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
pub(crate) fn same_path(a: &Path, b: &Path) -> bool {
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

/// A map key for a folder: case-folded on Windows, where case never tells
/// two folders apart.
fn path_key(path: &Path) -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(path.to_string_lossy().to_lowercase())
    } else {
        path.to_path_buf()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEP: char = MAIN_SEPARATOR;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::from(code)
    }

    fn ch(c: char) -> KeyEvent {
        KeyEvent::from(KeyCode::Char(c))
    }

    fn ctrl(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    fn press(p: &mut Picker, code: KeyCode) -> PickOutcome {
        p.on_key(key(code))
    }

    fn type_str(p: &mut Picker, s: &str) {
        for c in s.chars() {
            assert_eq!(p.on_key(ch(c)), PickOutcome::Stay, "{c}");
        }
    }

    /// Answer every listing and lookup the way the runtime does, but
    /// synchronously. Counts are left to the tests that feed them.
    fn serve(p: &mut Picker) {
        for _ in 0..16 {
            let reqs = p.take_requests();
            if reqs.is_empty() {
                return;
            }
            for r in reqs {
                match r {
                    Request::List(dir) => p.on_listing(Listing::read(&dir, MAX_READ)),
                    Request::Stat(path) => {
                        let found = stat(&path);
                        p.on_stat(&path, found);
                    }
                    Request::Count(_) | Request::StopCount => {}
                }
            }
        }
    }

    /// A picker with no places and no recents, homed at `home`.
    fn bare(home: Option<PathBuf>) -> Picker {
        Picker::with_suggestions(Vec::new(), Vec::new()).with_home(home)
    }

    /// `bare`, showing `dir` (listed).
    fn at(dir: &Path) -> Picker {
        let mut p = bare(None);
        p.on_paste(&dir.display().to_string());
        serve(&mut p);
        assert_eq!(p.location(), Some(dir));
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
    fn tree() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("alpha").join("inner")).unwrap();
        std::fs::write(root.join("alpha").join("a.txt"), b"a").unwrap();
        std::fs::create_dir(root.join("beta")).unwrap();
        std::fs::write(root.join("notes.txt"), b"hello").unwrap();
        tmp
    }

    fn delta(dirs: &[(&Path, u32)], frontier: Option<&Path>, done: bool) -> CountDelta {
        CountDelta {
            dirs: dirs.iter().map(|(d, n)| (d.to_path_buf(), *n)).collect(),
            frontier: frontier.map(Path::to_path_buf),
            done,
            stopped: false,
        }
    }

    #[test]
    fn places_show_at_once_with_the_first_highlighted() {
        let tmp = tree();
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
        let mut p = Picker::with_suggestions(places, Vec::new());
        assert!(p.take_requests().is_empty(), "suggestions need no lookups");
        assert_eq!(p.location(), None);
        assert_eq!(labels(&p), ["Downloads", "Home"]);
        assert!(
            p.entries()
                .iter()
                .all(|e| e.kind == EntryKind::Place && e.dir)
        );
        assert_eq!(p.highlight(), Some(Highlight::Row(0)));
        assert!(!p.scan_row(), "the top level has no scan row");
        assert!(p.message().is_none());
        assert_eq!(p.esc_word(), "quit");
    }

    #[test]
    fn places_and_drives_arrive_later_and_rows_above_never_move() {
        let tmp = tree();
        let alpha = tmp.path().join("alpha");
        let beta = tmp.path().join("beta");
        let home = tmp.path().to_path_buf();
        let (d1, d2) = (tmp.path().join("d1"), tmp.path().join("d2"));
        let mut p = Picker::probing(
            vec![
                ("Downloads".into(), alpha.clone()),
                ("Videos".into(), tmp.path().join("missing")),
            ],
            Some(beta.clone()),
            Some(home.clone()),
            vec![d1.clone(), d2.clone()],
            Vec::new(),
        );
        // Nothing has been looked up yet: only home shows.
        assert_eq!(labels(&p), ["Home"]);
        assert!(p.waiting() && p.loading());
        let reqs = p.take_requests();
        assert_eq!(reqs.len(), 5, "{reqs:?}");
        p.on_stat(&alpha, Found::Folder);
        p.on_stat(&tmp.path().join("missing"), Found::Missing);
        p.on_stat(&beta, Found::Folder);
        assert_eq!(labels(&p), ["Downloads", "Current folder", "Home"]);
        assert_eq!(p.selected(), Some(0), "untouched: the first entry");
        assert!(!p.waiting(), "only drives are left");
        assert!(p.loading(), "the drives still show a gauge");

        // The user moves; a drive arriving appends below without moving them.
        press(&mut p, KeyCode::Down);
        p.on_stat(&d2, Found::Folder);
        p.on_stat(&d1, Found::Missing);
        assert_eq!(p.entries().len(), 4);
        assert_eq!(p.entries()[3].kind, EntryKind::Drive);
        assert_eq!(highlighted(&p).label, "Current folder");
        assert!(!p.loading());
    }

    #[test]
    fn recents_come_first_and_missing_ones_are_skipped() {
        let tmp = tree();
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
        let mut p = Picker::with_suggestions(places, recent);
        assert_eq!(labels(&p), ["Desktop"], "recents wait for their lookups");
        serve(&mut p);
        let kinds: Vec<_> = p.entries().iter().map(|e| e.kind).collect();
        assert_eq!(
            kinds,
            [EntryKind::Recent, EntryKind::Recent, EntryKind::Place]
        );
        assert_eq!(p.entries()[0].label, file.display().to_string());
        assert_eq!(p.entries()[0].size, Some(5));
        assert!(!p.entries()[0].dir);
        assert_eq!(p.entries()[1].path, alpha);
        assert_eq!(p.entries()[1].label, format!("{}{SEP}", alpha.display()));
        assert_eq!(p.selected(), Some(0), "the newest recent");

        let many: Vec<PathBuf> = (0..7)
            .map(|i| {
                let d = tmp.path().join(format!("r{i}"));
                std::fs::create_dir(&d).unwrap();
                d
            })
            .collect();
        let mut p = Picker::with_suggestions(Vec::new(), many);
        serve(&mut p);
        assert_eq!(p.entries().len(), MAX_RECENT);
    }

    #[test]
    fn enter_opens_a_recent_folder_and_scans_a_recent_file() {
        let tmp = tree();
        let file = tmp.path().join("notes.txt");
        let alpha = tmp.path().join("alpha");
        let mut p = Picker::with_suggestions(Vec::new(), vec![file.clone(), alpha.clone()]);
        serve(&mut p);
        assert_eq!(press(&mut p, KeyCode::Enter), PickOutcome::Scan(file));
        press(&mut p, KeyCode::Down);
        assert_eq!(press(&mut p, KeyCode::Right), PickOutcome::Stay);
        serve(&mut p);
        assert_eq!(p.location(), Some(alpha.as_path()));
    }

    #[test]
    fn a_folder_lists_folders_then_files_with_the_first_highlighted() {
        let tmp = tree();
        let p = at(tmp.path());
        let (alpha, beta) = (dir_label("alpha"), dir_label("beta"));
        assert_eq!(labels(&p), [alpha.as_str(), beta.as_str(), "notes.txt"]);
        assert_eq!(p.entries()[2].kind, EntryKind::File);
        assert_eq!(p.entries()[2].size, Some(5));
        assert!(p.scan_row());
        assert_eq!(
            p.highlight(),
            Some(Highlight::Row(0)),
            "the first entry, never the scan row"
        );
    }

    #[test]
    fn moving_stops_at_the_ends_and_up_reaches_the_scan_row() {
        let tmp = tempfile::tempdir().unwrap();
        for i in 0..30 {
            std::fs::create_dir(tmp.path().join(format!("d{i:02}"))).unwrap();
        }
        let mut p = at(tmp.path());
        let n = p.entries().len();
        assert_eq!(n, 30);
        press(&mut p, KeyCode::Up);
        assert_eq!(p.highlight(), Some(Highlight::Scan));
        press(&mut p, KeyCode::Up);
        assert_eq!(p.highlight(), Some(Highlight::Scan), "no wrap");
        press(&mut p, KeyCode::Down);
        assert_eq!(p.selected(), Some(0));
        p.set_page(7);
        press(&mut p, KeyCode::PageDown);
        assert_eq!(p.selected(), Some(7));
        press(&mut p, KeyCode::PageUp);
        press(&mut p, KeyCode::PageUp);
        assert_eq!(p.selected(), Some(0), "pages stop at the first entry");
        p.on_key(ch('G'));
        assert_eq!(p.selected(), Some(n - 1));
        p.on_key(ch('j'));
        press(&mut p, KeyCode::Down);
        assert_eq!(p.selected(), Some(n - 1), "no wrap at the end");
        p.on_key(ch('g'));
        assert_eq!(p.selected(), Some(0));
        press(&mut p, KeyCode::End);
        p.on_key(ch('k'));
        assert_eq!(p.selected(), Some(n - 2));
        press(&mut p, KeyCode::Home);
        assert_eq!(p.selected(), Some(0));

        // At the top level up never leaves the list.
        let mut places = Picker::with_suggestions(
            vec![Suggestion {
                label: "Here".into(),
                path: tmp.path().to_path_buf(),
            }],
            Vec::new(),
        );
        press(&mut places, KeyCode::Up);
        assert_eq!(places.selected(), Some(0));
    }

    #[test]
    fn left_goes_up_and_highlights_the_folder_we_left() {
        let tmp = tree();
        let mut p = at(tmp.path());
        press(&mut p, KeyCode::Down);
        assert_eq!(highlighted(&p).label, dir_label("beta"));
        p.on_key(ch('l'));
        serve(&mut p);
        assert_eq!(p.location(), Some(tmp.path().join("beta").as_path()));
        p.on_key(ch('h'));
        serve(&mut p);
        assert_eq!(p.location(), Some(tmp.path()));
        assert_eq!(highlighted(&p).path, tmp.path().join("beta"));

        // Into alpha, then Backspace back out: alpha is highlighted.
        press(&mut p, KeyCode::Up);
        press(&mut p, KeyCode::Enter);
        serve(&mut p);
        assert_eq!(p.location(), Some(tmp.path().join("alpha").as_path()));
        press(&mut p, KeyCode::Backspace);
        serve(&mut p);
        assert_eq!(highlighted(&p).path, tmp.path().join("alpha"));
    }

    #[test]
    fn each_folder_remembers_its_highlight() {
        let tmp = tree();
        let mut p = at(tmp.path());
        p.home = Some(tmp.path().join("beta"));
        press(&mut p, KeyCode::End);
        assert_eq!(highlighted(&p).label, "notes.txt");
        p.on_key(ch('~'));
        serve(&mut p);
        assert_eq!(p.location(), Some(tmp.path().join("beta").as_path()));
        p.on_paste(&tmp.path().display().to_string());
        serve(&mut p);
        assert_eq!(p.location(), Some(tmp.path()));
        assert_eq!(highlighted(&p).label, "notes.txt", "restored");

        // The scan row is remembered too.
        press(&mut p, KeyCode::Home);
        press(&mut p, KeyCode::Up);
        p.on_key(ch('~'));
        serve(&mut p);
        p.on_paste(&tmp.path().display().to_string());
        serve(&mut p);
        assert_eq!(p.highlight(), Some(Highlight::Scan));
    }

    #[test]
    fn at_a_drive_root_left_goes_to_places_with_the_drive_highlighted() {
        let root = if cfg!(windows) {
            PathBuf::from("C:\\")
        } else {
            PathBuf::from("/")
        };
        let places = vec![
            Suggestion {
                label: "Elsewhere".into(),
                path: PathBuf::from("elsewhere"),
            },
            Suggestion {
                label: "Root".into(),
                path: root.clone(),
            },
        ];
        let mut p = Picker::with_suggestions(places, Vec::new());
        press(&mut p, KeyCode::Down);
        press(&mut p, KeyCode::Enter);
        assert_eq!(p.location(), Some(root.as_path()));
        // The listing is never served: going up needs none.
        press(&mut p, KeyCode::Left);
        assert_eq!(p.location(), None);
        assert_eq!(highlighted(&p).path, root);
        assert!(
            p.take_requests().contains(&Request::StopCount),
            "the count stops"
        );
        press(&mut p, KeyCode::Left);
        assert_eq!(p.location(), None, "the top level is the top");
    }

    #[test]
    fn hidden_entries_go_last_in_natural_order() {
        let tmp = tempfile::tempdir().unwrap();
        for d in ["v10", "v9", "V1", ".cache"] {
            std::fs::create_dir(tmp.path().join(d)).unwrap();
        }
        for f in ["page10.txt", "page2.txt", "Page1.txt", ".env"] {
            std::fs::write(tmp.path().join(f), b"x").unwrap();
        }
        let p = at(tmp.path());
        let (v1, v9, v10, cache) = (
            dir_label("V1"),
            dir_label("v9"),
            dir_label("v10"),
            dir_label(".cache"),
        );
        assert_eq!(
            labels(&p),
            [
                v1.as_str(),
                v9.as_str(),
                v10.as_str(),
                "Page1.txt",
                "page2.txt",
                "page10.txt",
                cache.as_str(),
                ".env",
            ]
        );
        assert!(p.entries()[6].hidden && p.entries()[7].hidden);
        assert!(!p.entries()[0].hidden);
    }

    #[test]
    fn the_prompt_filters_prefix_first_and_enter_keeps_it() {
        let tmp = tempfile::tempdir().unwrap();
        for d in ["keynotes", "Notes2", "note", "other"] {
            std::fs::create_dir(tmp.path().join(d)).unwrap();
        }
        for f in ["footnotes.md", "notes.txt", "zzz.txt"] {
            std::fs::write(tmp.path().join(f), b"x").unwrap();
        }
        let mut p = at(tmp.path());
        p.on_key(ch('/'));
        assert_eq!(p.prompt(), Some(""));
        assert!(!p.scan_row(), "the prompt takes the scan row's place");
        type_str(&mut p, "NOTE");
        let (note, notes2, keynotes) = (
            dir_label("note"),
            dir_label("Notes2"),
            dir_label("keynotes"),
        );
        assert_eq!(
            labels(&p),
            [
                note.as_str(),
                notes2.as_str(),
                "notes.txt",
                keynotes.as_str(),
                "footnotes.md",
            ]
        );
        assert_eq!(highlighted(&p).label, note, "a name typed in full wins");
        type_str(&mut p, "s");
        assert_eq!(highlighted(&p).label, notes2, "else the first match");
        press(&mut p, KeyCode::Down);
        assert_eq!(highlighted(&p).label, "notes.txt");
        type_str(&mut p, "."); // still matches: the highlight stays
        assert_eq!(highlighted(&p).label, "notes.txt");
        // Letters type in the prompt, never act.
        type_str(&mut p, "sql");
        assert_eq!(p.prompt(), Some("NOTEs.sql"));
        assert!(p.entries().is_empty());
        press(&mut p, KeyCode::Tab);
        assert_eq!(p.message().map(|m| m.text), Some("No match".to_string()));
        p.on_key(ctrl('w'));
        type_str(&mut p, "no");
        assert_eq!(
            press(&mut p, KeyCode::Enter),
            PickOutcome::Stay,
            "enter never scans"
        );
        assert_eq!(p.prompt(), None);
        assert_eq!(p.filter(), "no");
        assert_eq!(p.esc_word(), "clear");
        let kept = highlighted(&p).path.clone();
        assert_eq!(press(&mut p, KeyCode::Esc), PickOutcome::Stay);
        assert_eq!(p.filter(), "");
        assert_eq!(p.entries().len(), 7);
        assert_eq!(highlighted(&p).path, kept, "clearing keeps the highlight");
    }

    #[test]
    fn prompt_paths_list_their_folder_and_esc_restores_the_state_before() {
        let tmp = tree();
        let mut p = at(tmp.path());
        press(&mut p, KeyCode::End);
        let before = highlighted(&p).path.clone();
        p.on_key(ch('/'));
        // A relative path lists inside the folder shown before `/`.
        type_str(&mut p, &format!("alpha{SEP}"));
        serve(&mut p);
        assert_eq!(p.location(), Some(tmp.path().join("alpha").as_path()));
        assert_eq!(p.filter(), "");
        type_str(&mut p, "in");
        assert_eq!(highlighted(&p).label, dir_label("inner"));
        // Tab completes the name; a folder gains a separator and lists.
        press(&mut p, KeyCode::Tab);
        serve(&mut p);
        assert_eq!(p.prompt(), Some(format!("alpha{SEP}inner{SEP}").as_str()));
        assert_eq!(
            p.location(),
            Some(tmp.path().join("alpha").join("inner").as_path())
        );
        // Ctrl+W erases a segment, ctrl+u everything.
        p.on_key(ctrl('w'));
        serve(&mut p);
        assert_eq!(p.prompt(), Some(format!("alpha{SEP}").as_str()));
        p.on_key(ctrl('u'));
        serve(&mut p);
        assert_eq!(p.location(), Some(tmp.path()));
        // An absolute path, typed with forward slashes.
        let abs = format!("{}/al", tmp.path().display());
        type_str(&mut p, &abs);
        serve(&mut p);
        assert_eq!(p.location(), Some(tmp.path()));
        assert_eq!(highlighted(&p).label, dir_label("alpha"));
        press(&mut p, KeyCode::Tab);
        assert_eq!(
            p.prompt(),
            Some(format!("{}/alpha/", tmp.path().display()).as_str())
        );
        serve(&mut p);
        assert_eq!(p.location(), Some(tmp.path().join("alpha").as_path()));
        // Esc puts back the folder, the filter and the highlight.
        press(&mut p, KeyCode::Esc);
        serve(&mut p);
        assert_eq!(p.prompt(), None);
        assert_eq!(p.location(), Some(tmp.path()));
        assert_eq!(p.filter(), "");
        assert_eq!(highlighted(&p).path, before);
    }

    #[test]
    fn tilde_and_drives_in_the_prompt() {
        let tmp = tree();
        let mut p = bare(Some(tmp.path().join("alpha")));
        p.on_key(ch('/'));
        type_str(&mut p, "~");
        assert_eq!(p.location(), Some(tmp.path()));
        assert_eq!(p.filter(), "alpha");
        p.on_key(ctrl('u'));
        type_str(&mut p, "~/in");
        assert_eq!(p.location(), Some(tmp.path().join("alpha").as_path()));
        assert_eq!(p.filter(), "in");
        if cfg!(windows) {
            p.on_key(ctrl('u'));
            type_str(&mut p, "C:");
            assert_eq!(p.location(), Some(Path::new("C:\\")));
        }
        assert_eq!(expand_tilde("~\\a", Some(tmp.path())), tmp.path().join("a"));
        assert_eq!(expand_tilde("~a", Some(tmp.path())), PathBuf::from("~a"));
        assert_eq!(expand_tilde("~/a", None), PathBuf::from("~/a"));
    }

    #[test]
    fn a_paste_jumps_to_its_path() {
        let tmp = tree();
        let mut p = bare(None);
        // A file: its folder, with it highlighted. Quotes and the line
        // break a Windows copy adds are dropped.
        let file = tmp.path().join("notes.txt");
        p.on_paste(&format!("\"{}\"\r\n", file.display()));
        assert!(p.waiting());
        serve(&mut p);
        assert_eq!(p.location(), Some(tmp.path()));
        assert_eq!(highlighted(&p).path, file);
        // A relative path, from the folder shown.
        p.on_paste("alpha");
        serve(&mut p);
        assert_eq!(p.location(), Some(tmp.path().join("alpha").as_path()));
        // Nothing there: the view stays, with a message.
        p.on_paste("nowhere");
        serve(&mut p);
        assert_eq!(p.location(), Some(tmp.path().join("alpha").as_path()));
        let msg = p.message().unwrap();
        assert_eq!(msg.kind, MessageKind::Error);
        assert!(
            msg.text.starts_with("No such file or folder"),
            "{}",
            msg.text
        );
        // In the prompt an absolute path replaces the text; other text adds.
        p.on_key(ch('/'));
        type_str(&mut p, "zz");
        p.on_paste(&tmp.path().join("al").display().to_string());
        assert_eq!(
            p.prompt(),
            Some(tmp.path().join("al").display().to_string().as_str())
        );
        p.on_paste("pha");
        assert!(p.prompt().unwrap().ends_with("alpha"));
    }

    #[test]
    fn a_burst_of_keys_becomes_prompt_text() {
        let tmp = tree();
        let mut p = at(tmp.path());
        // Would scan, open and go up as keys; as a burst it is only text.
        p.on_burst("shl");
        assert_eq!(p.prompt(), Some("shl"));
        assert_eq!(p.location(), Some(tmp.path()));
        p.on_burst(&tmp.path().join("beta").display().to_string());
        assert_eq!(
            p.prompt(),
            Some(tmp.path().join("beta").display().to_string().as_str()),
            "an absolute path replaces"
        );
        serve(&mut p);
        assert_eq!(highlighted(&p).label, dir_label("beta"));
        // The enter a paste ends with keeps the result and never scans.
        assert_eq!(press(&mut p, KeyCode::Enter), PickOutcome::Stay);
        assert_eq!(p.filter(), "beta");
    }

    #[test]
    fn unbound_letters_point_at_the_prompt_and_q_never_quits() {
        let tmp = tree();
        let mut p = at(tmp.path());
        for c in ['q', 'x', 'Q', '1'] {
            assert_eq!(p.on_key(ch(c)), PickOutcome::Stay);
            assert_eq!(p.message().unwrap().text, KEYS_HINT);
        }
        let mut release = ch('s');
        release.kind = KeyEventKind::Release;
        assert_eq!(p.on_key(release), PickOutcome::Stay);
        assert_eq!(p.on_key(ctrl('c')), PickOutcome::Quit);
    }

    #[test]
    fn counts_show_a_plus_while_counting() {
        let tmp = tree();
        let mut p = at(tmp.path());
        let root = tmp.path().to_path_buf();
        let (alpha, beta) = (root.join("alpha"), root.join("beta"));
        assert_eq!(p.here_count(), None, "nothing counted yet");
        assert_eq!(p.count_of(&alpha), None);
        let inner = alpha.join("inner");
        p.on_count(
            &root,
            &delta(&[(&root, 1), (&inner, 300)], Some(&inner), false),
        );
        let c = p.here_count().unwrap();
        assert_eq!((c.files, c.more), (301, true));
        assert_eq!(count_text(c), "301+ files");
        assert_eq!(count_text(p.count_of(&alpha).unwrap()), "300+ files");
        assert_eq!(p.count_of(&beta), None, "not reached yet");
        // The walk moves past alpha: its count is final.
        p.on_count(&root, &delta(&[(&alpha, 1)], Some(&root.join("b")), false));
        assert_eq!(count_text(p.count_of(&alpha).unwrap()), "301 files");
        // A count for another folder is ignored.
        p.on_count(&alpha, &delta(&[(&alpha, 99)], None, false));
        assert_eq!(p.here_count().unwrap().files, 302);
        p.on_count(&root, &delta(&[], None, true));
        assert_eq!(count_text(p.here_count().unwrap()), "302 files");
        assert_eq!(count_text(p.count_of(&beta).unwrap()), "0 files");
        assert_eq!(
            count_text(Count {
                files: 1,
                more: false
            }),
            "1 file"
        );
        assert_eq!(
            count_text(Count {
                files: 1,
                more: true
            }),
            "1+ files"
        );
    }

    #[test]
    fn opening_a_folder_asks_for_its_listing_and_count() {
        let tmp = tree();
        let mut p = bare(None);
        p.on_paste(&tmp.path().display().to_string());
        assert_eq!(p.take_requests(), [Request::Stat(tmp.path().to_path_buf())]);
        p.on_stat(tmp.path(), Found::Folder);
        assert_eq!(
            p.take_requests(),
            [
                Request::List(tmp.path().to_path_buf()),
                Request::Count(tmp.path().to_path_buf())
            ]
        );
        assert!(p.waiting() && p.loading());
        assert!(p.entries().is_empty());
        // A listing for another folder is ignored.
        p.on_listing(Listing::read(&tmp.path().join("alpha"), MAX_READ));
        assert!(p.entries().is_empty());
        p.on_listing(Listing::read(tmp.path(), MAX_READ));
        assert!(!p.waiting());
        assert_eq!(p.entries().len(), 3);
    }

    #[test]
    fn large_roots_need_a_second_press_that_quotes_the_count() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("me");
        std::fs::create_dir_all(home.join("docs")).unwrap();
        let mut p = bare(Some(home.clone()));
        p.on_key(ch('~'));
        serve(&mut p);
        assert_eq!(p.location(), Some(home.as_path()));
        assert_eq!(p.on_key(ch('s')), PickOutcome::Stay);
        assert!(p.confirming());
        assert_eq!(p.esc_word(), "cancel");
        let msg = p.message().unwrap();
        assert_eq!(msg.kind, MessageKind::Warn);
        assert_eq!(
            msg.text,
            "That is your whole home folder. Press s again to scan it."
        );
        // The running count shows up in the warning as it grows.
        let docs = home.join("docs");
        p.on_count(&home, &delta(&[(&docs, 1_204_331)], Some(&docs), false));
        assert_eq!(
            p.message().unwrap().text,
            "That is your whole home folder: 1,204,331+ files so far. \
             Press s again to scan it."
        );
        assert_eq!(p.on_key(ch('s')), PickOutcome::Scan(normalize(&home)));

        // Esc cancels a pending confirm; a move does too.
        p.on_key(ch('s'));
        assert_eq!(press(&mut p, KeyCode::Esc), PickOutcome::Stay);
        assert!(!p.confirming());
        assert!(p.message().is_none());
        p.on_key(ch('s'));
        press(&mut p, KeyCode::Down);
        assert!(!p.confirming());

        // Enter on the scan row names enter, and the count's end.
        press(&mut p, KeyCode::Up);
        press(&mut p, KeyCode::Up);
        assert_eq!(p.highlight(), Some(Highlight::Scan));
        p.on_count(&home, &delta(&[], None, true));
        assert_eq!(press(&mut p, KeyCode::Enter), PickOutcome::Stay);
        assert_eq!(
            p.message().unwrap().text,
            "That is your whole home folder: 1,204,331 files. Press enter again to scan it."
        );
        assert_eq!(
            press(&mut p, KeyCode::Enter),
            PickOutcome::Scan(normalize(&home))
        );

        // The folder above home holds every home.
        press(&mut p, KeyCode::Left);
        serve(&mut p);
        p.on_key(ch('s'));
        assert!(
            p.message()
                .unwrap()
                .text
                .starts_with("That holds every user's home folder")
        );
    }

    #[test]
    fn s_at_the_top_level_scans_the_highlighted_place() {
        let tmp = tree();
        let home = tmp.path().join("alpha");
        let places = vec![
            Suggestion {
                label: "Beta".into(),
                path: tmp.path().join("beta"),
            },
            Suggestion {
                label: "Home".into(),
                path: home.clone(),
            },
        ];
        let mut p = Picker::with_suggestions(places, Vec::new()).with_home(Some(home.clone()));
        assert_eq!(
            p.on_key(ch('s')),
            PickOutcome::Scan(normalize(&tmp.path().join("beta")))
        );
        press(&mut p, KeyCode::Down);
        assert_eq!(p.on_key(ch('s')), PickOutcome::Stay);
        assert!(p.confirming());
        assert_eq!(p.take_requests(), [Request::Count(normalize(&home))]);
        press(&mut p, KeyCode::Up);
        assert!(!p.confirming());
        assert_eq!(
            p.take_requests(),
            [Request::StopCount],
            "nothing needs the count now"
        );
    }

    #[test]
    fn cloud_only_files_are_never_scanned() {
        let tmp = tree();
        let mut p = at(tmp.path());
        if let Some(folder) = &mut p.folder {
            for item in &mut folder.listing.items {
                item.cloud = !item.dir;
            }
        }
        p.rebuild(None);
        press(&mut p, KeyCode::End);
        let entry = highlighted(&p);
        assert!(entry.cloud);
        assert_eq!(press(&mut p, KeyCode::Enter), PickOutcome::Stay);
        let msg = p.message().unwrap();
        assert_eq!(msg.kind, MessageKind::Warn);
        assert_eq!(msg.text, CLOUD_WARNING);
    }

    #[test]
    fn a_folder_that_cannot_be_listed_shows_why_and_cannot_be_scanned() {
        let tmp = tree();
        let mut p = bare(None);
        let missing = tmp.path().join("missing");
        p.on_key(ch('/'));
        type_str(&mut p, &format!("{}{SEP}", missing.display()));
        serve(&mut p);
        press(&mut p, KeyCode::Enter);
        assert_eq!(p.location(), Some(missing.as_path()));
        assert!(p.listing_failed());
        let msg = p.message().unwrap();
        assert_eq!(msg.kind, MessageKind::Error);
        assert!(msg.text.starts_with("No such folder"), "{}", msg.text);
        assert_eq!(p.on_key(ch('s')), PickOutcome::Stay);
        assert_eq!(p.message().unwrap().text, UNREADABLE);
        press(&mut p, KeyCode::Left);
        serve(&mut p);
        assert_eq!(highlighted(&p).path, tmp.path().join("alpha"));
    }

    #[test]
    fn esc_quits_at_once_and_a_reopened_picker_goes_back() {
        let tmp = tree();
        let mut p = at(tmp.path());
        assert_eq!(press(&mut p, KeyCode::Esc), PickOutcome::Quit);

        let current = tmp.path().join("alpha").join("a.txt");
        let mut p = bare(None).reopened_at(&current);
        assert_eq!(p.location(), Some(current.as_path()), "shown meanwhile");
        serve(&mut p);
        assert_eq!(p.location(), Some(tmp.path().join("alpha").as_path()));
        assert_eq!(highlighted(&p).path, current);
        assert_eq!(p.esc_word(), "back");
        assert_eq!(press(&mut p, KeyCode::Esc), PickOutcome::Back);
        assert_eq!(p.on_key(ctrl('c')), PickOutcome::Quit);

        let folder = tmp.path().join("beta");
        let mut p = bare(None).reopened_at(&folder);
        serve(&mut p);
        assert_eq!(p.location(), Some(folder.as_path()));

        let mut p = bare(None).reopened_at(&tmp.path().join("gone"));
        serve(&mut p);
        assert_eq!(p.location(), None, "a missing target falls back to places");
        assert_eq!(p.message().unwrap().kind, MessageKind::Error);
        assert_eq!(p.on_key(ch('?')), PickOutcome::Help);
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
                large_root_kind(Path::new("C:\\"), None),
                Some(LargeRoot::Drive { filesystem: false })
            );
        } else {
            assert_eq!(
                large_root_kind(Path::new("/"), None),
                Some(LargeRoot::Drive { filesystem: true })
            );
        }
    }

    #[test]
    fn stat_tells_folders_files_and_nothing_apart() {
        let tmp = tree();
        assert_eq!(stat(tmp.path()), Found::Folder);
        assert_eq!(
            stat(&tmp.path().join("notes.txt")),
            Found::File {
                size: 5,
                cloud: false
            }
        );
        assert_eq!(stat(&tmp.path().join("gone")), Found::Missing);
    }

    #[test]
    fn no_dashes_in_messages() {
        let kinds = [
            LargeRoot::Drive { filesystem: true },
            LargeRoot::Drive { filesystem: false },
            LargeRoot::Home,
            LargeRoot::Users,
        ];
        let mut texts: Vec<String> = kinds.iter().map(|k| k.what().to_string()).collect();
        texts.extend([CLOUD_WARNING, KEYS_HINT, UNREADABLE, HERE_LABEL].map(String::from));
        for text in texts {
            assert!(!text.contains(['\u{2013}', '\u{2014}']), "{text}");
        }
    }
}
