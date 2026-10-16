//! One source of truth for keys: the `?` cheatsheet groups and the contextual
//! footer hints. New keys are added here so the footer and the help overlay can
//! never drift from what the app actually handles.

#![cfg(feature = "tui")]

/// A single key and what it does.
#[derive(Debug, Clone, Copy)]
pub struct Hint {
    pub key: &'static str,
    pub label: &'static str,
}

const fn h(key: &'static str, label: &'static str) -> Hint {
    Hint { key, label }
}

/// The full `?` cheatsheet, grouped.
pub const HELP_GROUPS: &[(&str, &[Hint])] = &[
    (
        "move",
        &[
            h("↑↓ / j k", "up / down"),
            h("tab", "switch pane"),
            h("enter", "open detail"),
            h("esc", "back"),
        ],
    ),
    (
        "act",
        &[
            h("d", "scrub marker"),
            h("D / x", "delete file"),
            h("e", "open in editor"),
            h("space", "select"),
            h("u", "undo last"),
        ],
    ),
    (
        "view",
        &[
            h("b", "buckets"),
            h("/", "filter"),
            h("?", "help"),
            h("q", "quit"),
        ],
    ),
];

/// The contextual footer for a view (`scan`, `detail`, `buckets`). Kept short;
/// the rare keys live only in the cheatsheet.
pub fn footer_hints(view: &str) -> &'static [Hint] {
    const DETAIL: &[Hint] = &[
        h("d", "scrub"),
        h("e", "editor"),
        h("esc", "back"),
        h("?", "keys"),
    ];
    const BUCKETS: &[Hint] = &[
        h("enter", "open"),
        h("d", "clean all"),
        h("esc", "back"),
        h("?", "keys"),
    ];
    const SCAN: &[Hint] = &[
        h("enter", "detail"),
        h("d", "scrub"),
        h("b", "buckets"),
        h("u", "undo"),
        h("?", "keys"),
    ];
    match view {
        "detail" => DETAIL,
        "buckets" => BUCKETS,
        _ => SCAN,
    }
}
