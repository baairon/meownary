//! One source of truth for keys: the [`Key`] set the app dispatches on, the
//! `?` cheatsheet groups, and the contextual footer hints. Every key the app
//! handles is a [`Key`] variant, and a test checks that each variant's names
//! appear in [`HELP_GROUPS`] (and nothing else does), so the footer and the
//! help overlay can never drift from what the app actually handles. The
//! picker reads raw keys, so its own sheet, [`PICKER_HELP`], names keys
//! rather than [`Key`]s; [`help_groups`] picks the sheet for a context.
//!
//! Key names in hints are plain words: `up/dn j/k` lists four names. A hint
//! key is split on spaces and `/`, except the lone `/` (the filter key).

#![cfg(feature = "tui")]

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// A single key and what it does.
#[derive(Debug, Clone, Copy)]
pub struct Hint {
    pub key: &'static str,
    pub label: &'static str,
}

const fn h(key: &'static str, label: &'static str) -> Hint {
    Hint { key, label }
}

/// Every key the view reacts to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Key {
    Up,
    Down,
    Left,
    Right,
    PageUp,
    PageDown,
    Home,
    End,
    Tab,
    Enter,
    Esc,
    Space,
    Scrub,
    Deattribute,
    DeepDeattribute,
    Delete,
    Editor,
    Buckets,
    Filter,
    Undo,
    Open,
    Help,
    Quit,
    Interrupt,
    Yes,
    No,
    Backspace,
}

impl Key {
    pub const ALL: [Key; 27] = [
        Key::Up,
        Key::Down,
        Key::Left,
        Key::Right,
        Key::PageUp,
        Key::PageDown,
        Key::Home,
        Key::End,
        Key::Tab,
        Key::Enter,
        Key::Esc,
        Key::Space,
        Key::Scrub,
        Key::Deattribute,
        Key::DeepDeattribute,
        Key::Delete,
        Key::Editor,
        Key::Buckets,
        Key::Filter,
        Key::Undo,
        Key::Open,
        Key::Help,
        Key::Quit,
        Key::Interrupt,
        Key::Yes,
        Key::No,
        Key::Backspace,
    ];

    /// The names this key goes by in the hints.
    pub fn names(self) -> &'static [&'static str] {
        match self {
            Key::Up => &["up", "k"],
            Key::Down => &["dn", "j"],
            Key::Left => &["left", "h"],
            Key::Right => &["right", "l"],
            Key::PageUp => &["pgup"],
            Key::PageDown => &["pgdn"],
            Key::Home => &["home", "g"],
            Key::End => &["end", "G"],
            Key::Tab => &["tab"],
            Key::Enter => &["enter"],
            Key::Esc => &["esc"],
            Key::Space => &["space"],
            Key::Scrub => &["d"],
            Key::Deattribute => &["a"],
            Key::DeepDeattribute => &["A"],
            Key::Delete => &["D", "x"],
            Key::Editor => &["e"],
            Key::Buckets => &["b"],
            Key::Filter => &["/"],
            Key::Undo => &["u"],
            Key::Open => &["o"],
            Key::Help => &["?"],
            Key::Quit => &["q"],
            Key::Interrupt => &["ctrl+c"],
            Key::Yes => &["y"],
            Key::No => &["n"],
            Key::Backspace => &["backspace"],
        }
    }

    /// Map a terminal key event to a [`Key`].
    pub fn from_event(ev: &KeyEvent) -> Option<Key> {
        let ctrl = ev.modifiers.contains(KeyModifiers::CONTROL);
        Some(match ev.code {
            KeyCode::Char('c') if ctrl => Key::Interrupt,
            _ if ctrl => return None,
            KeyCode::Up | KeyCode::Char('k') => Key::Up,
            KeyCode::Down | KeyCode::Char('j') => Key::Down,
            KeyCode::Left | KeyCode::Char('h') => Key::Left,
            KeyCode::Right | KeyCode::Char('l') => Key::Right,
            KeyCode::PageUp => Key::PageUp,
            KeyCode::PageDown => Key::PageDown,
            KeyCode::Home | KeyCode::Char('g') => Key::Home,
            KeyCode::End | KeyCode::Char('G') => Key::End,
            KeyCode::Tab | KeyCode::BackTab => Key::Tab,
            KeyCode::Enter => Key::Enter,
            KeyCode::Esc => Key::Esc,
            KeyCode::Char(' ') => Key::Space,
            KeyCode::Char('d') => Key::Scrub,
            KeyCode::Char('a') => Key::Deattribute,
            KeyCode::Char('A') => Key::DeepDeattribute,
            KeyCode::Char('D') | KeyCode::Char('x') => Key::Delete,
            KeyCode::Char('e') => Key::Editor,
            KeyCode::Char('b') => Key::Buckets,
            KeyCode::Char('/') => Key::Filter,
            KeyCode::Char('u') => Key::Undo,
            KeyCode::Char('o') => Key::Open,
            KeyCode::Char('?') => Key::Help,
            KeyCode::Char('q') => Key::Quit,
            KeyCode::Char('y') => Key::Yes,
            KeyCode::Char('n') => Key::No,
            KeyCode::Backspace => Key::Backspace,
            _ => return None,
        })
    }
}

/// The main view's `?` cheatsheet, grouped. It is exactly as tall as an
/// 80x24 terminal allows in two columns, so a new hint means another one
/// goes, or the group it joins gets shorter.
pub const HELP_GROUPS: &[(&str, &[Hint])] = &[
    (
        "move",
        &[
            h("up/dn j/k", "move"),
            h("pgup/pgdn", "page"),
            h("home/end g/G", "top / bottom"),
            h("enter right/l", "open"),
            h("left/h backspace", "up a folder"),
            h("tab", "switch pane"),
            h("esc", "back"),
        ],
    ),
    (
        "act",
        &[
            h("space", "select"),
            h("d", "scrub markers"),
            h("a", "deattribute"),
            h("A", "deep deattribute"),
            h("D / x", "delete file"),
            h("e", "open in editor"),
            h("u", "undo last"),
        ],
    ),
    (
        "view",
        &[
            h("o", "open file or folder"),
            h("b", "buckets"),
            h("/", "filter"),
            h("?", "keys"),
            h("q / ctrl+c", "quit"),
        ],
    ),
    (
        "prompts",
        &[
            h("y", "confirm"),
            h("n / esc", "cancel or clear"),
            h("enter", "keep the filter"),
            h("backspace", "erase"),
        ],
    ),
];

/// The picker's `?` cheatsheet. The picker reads raw keys, so these name
/// keys from [`PICKER_KEYS`] rather than [`Key`]s.
pub const PICKER_HELP: &[(&str, &[Hint])] = &[
    (
        "move",
        &[
            h("up/dn j/k", "move"),
            h("pgup/pgdn", "page"),
            h("home/end g/G", "first / last"),
        ],
    ),
    (
        "open",
        &[
            h("enter right l", "open or scan"),
            h("left h backspace", "up a folder"),
            h("s", "scan this folder"),
            h("~", "home folder"),
        ],
    ),
    (
        "type",
        &[
            h("/", "filter or path"),
            h("tab", "complete"),
            h("ctrl+u ctrl+w", "erase"),
            h("enter", "keep"),
        ],
    ),
    (
        "leave",
        &[
            h("esc", "cancel or leave"),
            h("ctrl+c", "quit"),
            h("?", "keys"),
        ],
    ),
];

/// Every key name the picker handles. Its footers and its sheet name only
/// these, and its sheet names every one.
pub const PICKER_KEYS: &[&str] = &[
    "up",
    "dn",
    "j",
    "k",
    "pgup",
    "pgdn",
    "home",
    "end",
    "g",
    "G",
    "enter",
    "right",
    "l",
    "left",
    "h",
    "backspace",
    "s",
    "~",
    "/",
    "tab",
    "ctrl+u",
    "ctrl+w",
    "esc",
    "ctrl+c",
    "?",
];

/// The picker's footer while it browses a folder. The view swaps the esc
/// label for the state: quit, back, clear or cancel.
pub const PICKER_FOLDER_HINTS: &[Hint] = &[
    h("up/dn", "move"),
    h("enter", "open"),
    h("left", "up"),
    h("s", "scan here"),
    h("/", "filter"),
    h("?", "keys"),
    h("esc", "quit"),
];

/// The picker's footer at the top level, among recent picks and places.
pub const PICKER_PLACES_HINTS: &[Hint] = &[
    h("up/dn", "move"),
    h("enter", "open"),
    h("/", "path"),
    h("?", "keys"),
    h("esc", "quit"),
];

/// The picker's footer while its prompt is open.
pub const PICKER_PROMPT_HINTS: &[Hint] =
    &[h("enter", "keep"), h("tab", "complete"), h("esc", "cancel")];

/// The `?` cheatsheet for a context: the picker's own, or the main view's.
pub fn help_groups(ctx: &str) -> &'static [(&'static str, &'static [Hint])] {
    if ctx == "picker" {
        PICKER_HELP
    } else {
        HELP_GROUPS
    }
}

/// The key names a hint lists.
pub fn hint_names(key: &'static str) -> Vec<&'static str> {
    if key == "/" {
        return vec!["/"];
    }
    key.split([' ', '/']).filter(|s| !s.is_empty()).collect()
}

/// The contextual footer for a view: `files` (or `scan`), `findings`,
/// `detail`, `buckets`, `confirm`, `help`, `filter`, `picker`. Kept short:
/// rare keys, such as `A` (deep deattribute, which may stop a copy loading),
/// belong in the cheatsheet only. The picker reads raw events
/// itself, like the filter, so its footer names keys rather than actions.
pub fn footer_hints(view: &str) -> &'static [Hint] {
    const FILES: &[Hint] = &[
        h("enter", "open"),
        h("space", "select"),
        h("d", "scrub"),
        h("a", "deattribute"),
        h("D", "delete"),
        h("b", "buckets"),
        h("/", "filter"),
        h("o", "open"),
        h("?", "keys"),
    ];
    const FINDINGS: &[Hint] = &[
        h("enter", "detail"),
        h("space", "select"),
        h("d", "scrub"),
        h("a", "deattribute"),
        h("e", "editor"),
        h("u", "undo"),
        h("tab", "files"),
        h("?", "keys"),
    ];
    const DETAIL: &[Hint] = &[
        h("up/dn", "scroll"),
        h("d", "scrub"),
        h("a", "deattribute"),
        h("e", "editor"),
        h("u", "undo"),
        h("esc", "back"),
        h("?", "keys"),
    ];
    const BUCKETS: &[Hint] = &[
        h("enter", "show"),
        h("b", "regroup"),
        h("d", "scrub all"),
        h("a", "deattribute"),
        h("esc", "back"),
        h("?", "keys"),
    ];
    const CONFIRM: &[Hint] = &[h("y", "confirm"), h("n", "cancel"), h("up/dn", "scroll")];
    const HELP: &[Hint] = &[h("esc", "close")];
    const FILTER: &[Hint] = &[h("enter", "keep"), h("esc", "clear")];
    match view {
        "findings" => FINDINGS,
        "detail" => DETAIL,
        "buckets" => BUCKETS,
        "confirm" => CONFIRM,
        "help" => HELP,
        "filter" => FILTER,
        "picker" => PICKER_FOLDER_HINTS,
        _ => FILES,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn help_names() -> BTreeSet<&'static str> {
        HELP_GROUPS
            .iter()
            .flat_map(|(_, hints)| hints.iter())
            .flat_map(|hint| hint_names(hint.key))
            .collect()
    }

    fn key_names() -> BTreeSet<&'static str> {
        Key::ALL
            .iter()
            .flat_map(|k| k.names().iter().copied())
            .collect()
    }

    #[test]
    fn help_covers_every_handled_key_and_nothing_else() {
        let help = help_names();
        let keys = key_names();
        let missing: Vec<_> = keys.difference(&help).collect();
        let extra: Vec<_> = help.difference(&keys).collect();
        assert!(missing.is_empty(), "keys missing from help: {missing:?}");
        assert!(extra.is_empty(), "help lists unhandled keys: {extra:?}");
    }

    #[test]
    fn footers_only_name_real_keys() {
        let keys = key_names();
        for view in [
            "files", "findings", "detail", "buckets", "confirm", "help", "filter",
        ] {
            for hint in footer_hints(view) {
                for n in hint_names(hint.key) {
                    assert!(keys.contains(n), "{view} footer names unknown key {n}");
                }
            }
        }
        // The picker reads raw keys: its footers name its own keys.
        let picker = [
            footer_hints("picker"),
            PICKER_FOLDER_HINTS,
            PICKER_PLACES_HINTS,
            PICKER_PROMPT_HINTS,
        ];
        for hint in picker.iter().flat_map(|hints| hints.iter()) {
            for n in hint_names(hint.key) {
                assert!(PICKER_KEYS.contains(&n), "picker footer names {n}");
            }
        }
    }

    #[test]
    fn picker_help_covers_every_picker_key_and_nothing_else() {
        let help: BTreeSet<&str> = PICKER_HELP
            .iter()
            .flat_map(|(_, hints)| hints.iter())
            .flat_map(|hint| hint_names(hint.key))
            .collect();
        let keys: BTreeSet<&str> = PICKER_KEYS.iter().copied().collect();
        let missing: Vec<_> = keys.difference(&help).collect();
        let extra: Vec<_> = help.difference(&keys).collect();
        assert!(
            missing.is_empty(),
            "picker keys missing from help: {missing:?}"
        );
        assert!(
            extra.is_empty(),
            "picker help lists unhandled keys: {extra:?}"
        );
        assert!(!keys.contains("q"), "q is never a picker key");
    }

    #[test]
    fn picker_footer_lists_its_keys_in_order() {
        let keys: Vec<&str> = footer_hints("picker").iter().map(|h| h.key).collect();
        assert_eq!(keys, ["up/dn", "enter", "left", "s", "/", "?", "esc"]);
        let keys: Vec<&str> = PICKER_PLACES_HINTS.iter().map(|h| h.key).collect();
        assert_eq!(keys, ["up/dn", "enter", "/", "?", "esc"]);
        let keys: Vec<&str> = PICKER_PROMPT_HINTS.iter().map(|h| h.key).collect();
        assert_eq!(keys, ["enter", "tab", "esc"]);
        assert!(footer_hints("files").iter().any(|h| h.key == "o"));
    }

    #[test]
    fn every_name_maps_back_to_its_key() {
        for k in Key::ALL {
            for name in k.names() {
                let ev = match *name {
                    "up" => KeyEvent::from(KeyCode::Up),
                    "dn" => KeyEvent::from(KeyCode::Down),
                    "left" => KeyEvent::from(KeyCode::Left),
                    "right" => KeyEvent::from(KeyCode::Right),
                    "pgup" => KeyEvent::from(KeyCode::PageUp),
                    "pgdn" => KeyEvent::from(KeyCode::PageDown),
                    "home" => KeyEvent::from(KeyCode::Home),
                    "end" => KeyEvent::from(KeyCode::End),
                    "tab" => KeyEvent::from(KeyCode::Tab),
                    "enter" => KeyEvent::from(KeyCode::Enter),
                    "esc" => KeyEvent::from(KeyCode::Esc),
                    "space" => KeyEvent::from(KeyCode::Char(' ')),
                    "backspace" => KeyEvent::from(KeyCode::Backspace),
                    "ctrl+c" => KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
                    one => {
                        let c = one.chars().next().unwrap();
                        assert_eq!(one.chars().count(), 1, "{one}");
                        KeyEvent::from(KeyCode::Char(c))
                    }
                };
                assert_eq!(Key::from_event(&ev), Some(k), "{name}");
            }
        }
    }

    #[test]
    fn hints_are_ascii() {
        let footers = [
            PICKER_FOLDER_HINTS,
            PICKER_PLACES_HINTS,
            PICKER_PROMPT_HINTS,
        ];
        for hint in footers.iter().flat_map(|f| f.iter()) {
            assert!(hint.key.is_ascii() && hint.label.is_ascii(), "{}", hint.key);
        }
        for (title, hints) in HELP_GROUPS.iter().chain(PICKER_HELP) {
            assert!(title.is_ascii());
            for hint in *hints {
                assert!(hint.key.is_ascii() && hint.label.is_ascii(), "{}", hint.key);
            }
        }
    }
}
