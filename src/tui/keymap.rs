//! One source of truth for keys: the [`Key`] set the app dispatches on, the
//! `?` cheatsheet groups, and the contextual footer hints. Every key the app
//! handles is a [`Key`] variant, and a test checks that each variant's names
//! appear in [`HELP_GROUPS`] (and nothing else does), so the footer and the
//! help overlay can never drift from what the app actually handles.
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
    pub const ALL: [Key; 26] = [
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

/// The full `?` cheatsheet, grouped.
pub const HELP_GROUPS: &[(&str, &[Hint])] = &[
    (
        "move",
        &[
            h("up/dn j/k", "move"),
            h("pgup/pgdn", "page"),
            h("home/end g/G", "top / bottom"),
            h("tab left/right h/l", "switch pane"),
            h("enter", "open"),
            h("esc", "back"),
        ],
    ),
    (
        "act",
        &[
            h("space", "select"),
            h("d", "scrub markers"),
            h("a", "deattribute"),
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
    ("confirm", &[h("y", "confirm"), h("n / esc", "cancel")]),
    (
        "filter",
        &[
            h("backspace", "erase"),
            h("enter", "keep"),
            h("esc", "clear"),
        ],
    ),
];

/// The key names a hint lists.
pub fn hint_names(key: &'static str) -> Vec<&'static str> {
    if key == "/" {
        return vec!["/"];
    }
    key.split([' ', '/']).filter(|s| !s.is_empty()).collect()
}

/// The contextual footer for a view: `files` (or `scan`), `findings`,
/// `detail`, `buckets`, `confirm`, `help`, `filter`, `picker`. Kept short;
/// the rare keys live only in the cheatsheet. The picker reads raw events
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
    const PICKER: &[Hint] = &[
        h("up/dn", "move"),
        h("right", "open"),
        h("left", "back"),
        h("enter", "scan"),
        h("tab", "complete"),
        h("esc", "quit"),
    ];
    match view {
        "findings" => FINDINGS,
        "detail" => DETAIL,
        "buckets" => BUCKETS,
        "confirm" => CONFIRM,
        "help" => HELP,
        "filter" => FILTER,
        "picker" => PICKER,
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
            "files", "findings", "detail", "buckets", "confirm", "help", "filter", "picker",
        ] {
            for hint in footer_hints(view) {
                for n in hint_names(hint.key) {
                    assert!(keys.contains(n), "{view} footer names unknown key {n}");
                }
            }
        }
    }

    #[test]
    fn picker_footer_lists_its_keys_in_order() {
        let keys: Vec<&str> = footer_hints("picker").iter().map(|h| h.key).collect();
        assert_eq!(keys, ["up/dn", "right", "left", "enter", "tab", "esc"]);
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
        for (title, hints) in HELP_GROUPS {
            assert!(title.is_ascii());
            for hint in *hints {
                assert!(hint.key.is_ascii() && hint.label.is_ascii(), "{}", hint.key);
            }
        }
    }
}
