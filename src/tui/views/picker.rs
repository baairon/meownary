//! The picker screen: a calm centered card with the wordmark and tagline,
//! where the list is, the pinned "Scan this folder" row (or the prompt),
//! the list, and the picker's message.
//!
//! The card's size comes from the terminal alone, never from the list or
//! the message, so the location line and the list hold their rows while
//! listings of any size come and go. Only the rows in view are drawn,
//! however long the list.

#![cfg(feature = "tui")]

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Widget};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::util::fmt::human_size;

use crate::tui::app::{self, App, Overlay};
use crate::tui::keymap::{self, Hint};
use crate::tui::logo;
use crate::tui::picker::{self, Entry, EntryKind, HERE_LABEL, Highlight, MessageKind, Picker};
use crate::tui::theme::{Look, Tone};
use crate::tui::ui::{pad, put, scroll_offset, truncate, truncate_left, width_of, wordmark};
use crate::tui::widgets::Gauge;

/// The line under the wordmark on the picker.
pub const PICKER_TAGLINE: [&str; 2] = [
    "Pick a file or folder to scan.",
    "Nothing is changed until you confirm an action.",
];

/// The widest the picker card gets.
const PICKER_MAX_W: u16 = 88;
/// The tallest the card gets; on a taller terminal it floats a little
/// above center.
const PICKER_MAX_H: u16 = 32;
/// Fewest list rows kept before a part of the card gives way.
const MIN_LIST: u16 = 3;
/// Most lines a message wraps to.
const MESSAGE_LINES: u16 = 3;
/// Width of the picker's kind column.
const KIND_W: usize = 6;
/// Widest a place or recent label column gets before its path.
const PLACE_LABEL_W: usize = 18;

/// Which optional parts of the picker card are drawn. They depend on the
/// terminal's size alone, and drop away, least important first, when it is
/// short.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Parts {
    card: bool,
    gap: bool,
    tagline: u16,
    logo: bool,
    slot: bool,
    message: u16,
}

impl Parts {
    /// Rows everything but the list takes.
    fn rows(&self) -> u16 {
        let b = |on: bool, n: u16| if on { n } else { 0 };
        // The card: two borders and a blank row at the top. The location
        // line always shows.
        b(self.card, 3)
            + b(self.logo, 1)
            + self.tagline
            + b(self.gap, 1)
            + 1
            + b(self.slot, 1)
            + self.message
    }

    /// Drop the next part. False when nothing is left to drop.
    fn shed(&mut self) -> bool {
        if self.card {
            self.card = false;
        } else if self.gap {
            self.gap = false;
        } else if self.message > 2 {
            self.message = 2;
        } else if self.tagline > 0 {
            self.tagline = 0;
        } else if self.message > 1 {
            self.message = 1;
        } else if self.logo {
            self.logo = false;
        } else if self.slot {
            self.slot = false;
        } else if self.message > 0 {
            self.message = 0;
        } else {
            return false;
        }
        true
    }
}

/// Where each part of the picker goes, worked out from the area alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PickerLayout {
    /// The card, borders included when it has them.
    pub card: Rect,
    pub bordered: bool,
    pub logo: Option<Rect>,
    /// The tagline's rows, one or two.
    pub tagline: Rect,
    pub location: Rect,
    /// The scan row, or the prompt while it is open.
    pub slot: Option<Rect>,
    pub list: Rect,
    pub message: Rect,
}

/// Lay the picker out in `area`.
pub(crate) fn picker_layout(area: Rect) -> PickerLayout {
    let margin = if area.width >= 40 { 4 } else { 0 };
    let card_w = area.width.saturating_sub(margin).min(PICKER_MAX_W);
    let content_w = |card: bool| -> usize {
        if card {
            card_w.saturating_sub(6) as usize
        } else {
            card_w as usize
        }
    };
    let one_line = PICKER_TAGLINE.join(" ");
    let tag_h = |w: usize| if one_line.width() <= w { 1 } else { 2 };
    // A tall terminal leaves a row of air above and below the card.
    let height = |card: bool| -> u16 {
        let h = if card && area.height >= 26 {
            area.height - 2
        } else {
            area.height
        };
        h.min(PICKER_MAX_H)
    };
    let card = area.width >= 40 && area.height >= 18;
    let mut parts = Parts {
        card,
        gap: true,
        tagline: tag_h(content_w(card)),
        logo: true,
        slot: true,
        message: MESSAGE_LINES,
    };
    while parts.rows() + MIN_LIST > height(parts.card) && parts.shed() {}
    if parts.tagline > 0 {
        parts.tagline = tag_h(content_w(parts.card));
    }
    let h = height(parts.card);

    // A little above center reads as calmer.
    let x = area.x + (area.width - card_w) / 2;
    let y = area.y + (area.height - h + 1) * 2 / 5;
    let card_rect = Rect::new(x, y, card_w, h);
    let inner = if parts.card {
        let inner = Block::bordered().inner(card_rect);
        Rect {
            x: inner.x + 2,
            y: inner.y + 1,
            width: inner.width.saturating_sub(4),
            height: inner.height.saturating_sub(1),
        }
    } else {
        card_rect
    };
    let bottom = inner.bottom();
    let mut cy = inner.y;
    let mut take = |n: u16| -> Rect {
        let top = cy.min(bottom);
        let rows = n.min(bottom - top);
        cy = top + rows;
        Rect::new(inner.x, top, inner.width, rows)
    };
    let logo = parts.logo.then(|| take(1));
    let tagline = take(parts.tagline);
    if parts.gap {
        take(1);
    }
    let location = take(1);
    let slot = parts.slot.then(|| take(1));
    let list_h = h.saturating_sub(parts.rows());
    let list = take(list_h);
    let message = take(parts.message);
    PickerLayout {
        card: card_rect,
        bordered: parts.card,
        logo,
        tagline,
        location,
        slot,
        list,
        message,
    }
}

/// The picker screen.
pub(crate) fn draw_picker(buf: &mut Buffer, area: Rect, app: &mut App, look: &Look) {
    if app.picker.is_none() {
        return;
    }
    let lay = picker_layout(area);
    if lay.bordered {
        Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(look.border(false))
            .render(lay.card, buf);
    }
    if let Some(r) = lay.logo
        && r.height > 0
    {
        let lx = r.x + r.width.saturating_sub(logo::WORDMARK.len() as u16) / 2;
        let lw = r.right().saturating_sub(lx);
        let spans = wordmark(app, look, lx, r.y, lw);
        put(buf, Rect::new(lx, r.y, lw, 1), &Line::from(spans));
    }
    draw_tagline(buf, lay.tagline, look);

    // The list window, kept around the highlight.
    let rows = lay.list.height as usize;
    let Some(picker) = app.picker.as_mut() else {
        return;
    };
    picker.set_page(rows);
    let n = picker.entries().len();
    let selected = picker.selected();
    app.picker_offset = match selected {
        Some(sel) => scroll_offset(sel, app.picker_offset, rows, n),
        None => app.picker_offset.min(n.saturating_sub(rows)),
    };
    let offset = app.picker_offset;
    let anim = app.anim_ms;
    let Some(picker) = app.picker.as_ref() else {
        return;
    };
    draw_location(buf, lay.location, picker, look, anim, rows);
    if let Some(slot) = lay.slot {
        draw_slot(buf, slot, picker, look);
    }
    draw_list(buf, lay.list, picker, look, offset);
    draw_message(buf, lay.message, picker, look);
}

fn draw_tagline(buf: &mut Buffer, rect: Rect, look: &Look) {
    let w = rect.width as usize;
    let lines: Vec<String> = if rect.height == 1 {
        vec![truncate(&PICKER_TAGLINE.join(" "), w)]
    } else {
        PICKER_TAGLINE.iter().map(|s| truncate(s, w)).collect()
    };
    for (i, l) in lines.into_iter().take(rect.height as usize).enumerate() {
        let r = Rect::new(rect.x, rect.y + i as u16, rect.width, 1);
        put(buf, r, &Line::from(Span::styled(l, look.dim())).centered());
    }
}

/// Where the list is, with a rule that turns into a thin gauge while a
/// read is in flight, the kept filter, and the position once it scrolls.
fn draw_location(buf: &mut Buffer, rect: Rect, p: &Picker, look: &Look, anim: u64, rows: usize) {
    if rect.height == 0 {
        return;
    }
    let w = rect.width as usize;
    let mut right: Vec<Span> = Vec::new();
    if p.prompt().is_none() && !p.filter().is_empty() {
        right.push(Span::styled(
            format!(" / {} ", truncate(p.filter(), 16)),
            look.chip(Tone::Good),
        ));
        right.push(Span::raw(" "));
    }
    let n = p.entries().len();
    if n > rows
        && let Some(sel) = p.selected()
    {
        right.push(Span::styled(
            format!("{} of {} ", app::thousands(sel + 1), app::thousands(n)),
            look.faint(),
        ));
    }
    let right_w = width_of(&right);
    let room = w.saturating_sub(right_w + 4);
    let mut spans = vec![Span::raw(" ")];
    match p.location() {
        None => spans.push(Span::styled(truncate("places", room), look.label())),
        Some(dir) => spans.extend(crumb(&dir.display().to_string(), room, look)),
    }
    spans.push(Span::raw(" "));
    let used = width_of(&spans).min(w);
    put(buf, rect, &Line::from(spans));
    let rule_w = w.saturating_sub(used + right_w + usize::from(right_w > 0));
    let rule = Rect::new(rect.x + used as u16, rect.y, rule_w as u16, 1);
    if p.loading() {
        Gauge::new(0.0)
            .inflight(0.0, 1.0)
            .live(true)
            .render(buf, rule, look, anim);
    } else {
        put(
            buf,
            rule,
            &Line::from(Span::styled("─".repeat(rule_w), look.rule())),
        );
    }
    if !right.is_empty() {
        put(buf, rect, &Line::from(right).right_aligned());
    }
}

/// A folder's path with its last segment standing out.
fn crumb(path: &str, room: usize, look: &Look) -> Vec<Span<'static>> {
    let shown = truncate_left(path, room);
    let name_at = shown
        .trim_end_matches(['/', '\\'])
        .rfind(['/', '\\'])
        .map(|i| i + 1)
        .unwrap_or(0);
    let (head, name) = shown.split_at(name_at);
    vec![
        Span::styled(head.to_string(), look.dim()),
        Span::styled(name.to_string(), look.bright()),
    ]
}

/// The pinned row: "Scan this folder" with its count, or the prompt.
fn draw_slot(buf: &mut Buffer, rect: Rect, p: &Picker, look: &Look) {
    if rect.height == 0 {
        return;
    }
    let w = rect.width as usize;
    if let Some(text) = p.prompt() {
        let room = w.saturating_sub(6);
        let line = Line::from(vec![
            Span::raw(" "),
            Span::styled(" / ", look.chip(Tone::Info)),
            Span::raw(" "),
            Span::styled(truncate_left(text, room), look.strong()),
            Span::styled("_", look.bright()),
        ]);
        put(buf, rect, &line);
        return;
    }
    if !p.scan_row() {
        return;
    }
    let on = p.highlight() == Some(Highlight::Scan);
    if on {
        buf.set_style(rect, look.cursor_row(true));
    }
    let label_style = if p.confirming() {
        look.tone(Tone::Warn)
    } else {
        look.bright()
    };
    let count = p.here_count();
    let right = count.map(picker::count_text).unwrap_or_default();
    let right_style = match count {
        Some(c) if c.more => look.faint(),
        _ => look.dim(),
    };
    let mut spans = vec![
        Span::raw(" "),
        Span::styled(format!("{:<KIND_W$}", "scan"), look.pink()),
        Span::raw("  "),
    ];
    let room = w.saturating_sub(1 + KIND_W + 2 + right.width() + 1);
    let label = truncate(HERE_LABEL, room);
    let used = label.width();
    spans.push(Span::styled(label, label_style));
    if !right.is_empty() {
        spans.push(Span::raw(" ".repeat(room.saturating_sub(used) + 1)));
        spans.push(Span::styled(right, right_style));
    }
    put(buf, rect, &Line::from(spans));
}

fn draw_list(buf: &mut Buffer, rect: Rect, p: &Picker, look: &Look, offset: usize) {
    if rect.height == 0 {
        return;
    }
    let entries = p.entries();
    let w = rect.width as usize;
    let rows = rect.height as usize;
    if entries.is_empty() {
        if let Some(text) = empty_note(p) {
            put(
                buf,
                Rect::new(rect.x, rect.y, rect.width, 1),
                &Line::from(Span::styled(
                    format!(" {}", truncate(text, w.saturating_sub(1))),
                    look.dim(),
                )),
            );
        }
        return;
    }
    let window = entries.iter().enumerate().skip(offset).take(rows);
    let label_w = entries
        .iter()
        .skip(offset)
        .take(rows)
        .filter(|e| {
            matches!(
                e.kind,
                EntryKind::Place | EntryKind::Recent | EntryKind::Drive
            )
        })
        .map(|e| e.label.width())
        .max()
        .unwrap_or(0)
        .min(PLACE_LABEL_W);
    for (k, (i, e)) in window.enumerate() {
        let r = Rect::new(rect.x, rect.y + k as u16, rect.width, 1);
        let on = p.selected() == Some(i);
        if on {
            buf.set_style(r, look.cursor_row(true));
        }
        let (right, right_style) = right_text(p, e, look);
        put(
            buf,
            r,
            &Line::from(entry_spans(e, w, label_w, on, right, right_style, look)),
        );
    }
}

/// What the list says when it has no rows: nothing while it is read or when
/// it could not be (the message says why).
fn empty_note(p: &Picker) -> Option<&'static str> {
    if p.loading() || p.listing_failed() {
        return None;
    }
    Some(if !p.filter().is_empty() {
        if p.prompt().is_some() {
            "Nothing matches."
        } else {
            "Nothing matches. Esc clears the filter."
        }
    } else if p.location().is_some() {
        "This folder is empty."
    } else {
        "Nothing to show here."
    })
}

/// The right-hand column: a file's size, or a folder's count.
fn right_text(p: &Picker, e: &Entry, look: &Look) -> (String, Style) {
    match e.kind {
        EntryKind::File | EntryKind::Recent if !e.dir => {
            let style = if e.cloud { look.faint() } else { look.dim() };
            let text = e
                .size
                .map(human_size)
                .unwrap_or_else(|| "online".to_string());
            (text, style)
        }
        EntryKind::Dir if !e.link => match p.count_of(&e.path) {
            Some(c) => {
                let style = if c.more { look.faint() } else { look.dim() };
                (picker::count_text(c), style)
            }
            None => (String::new(), look.dim()),
        },
        _ => (String::new(), look.dim()),
    }
}

/// One row: a kind column, the name (folders in the accent color, hidden
/// entries faint), a dim path for places and recent picks, and the right
/// column.
fn entry_spans(
    e: &Entry,
    w: usize,
    label_w: usize,
    on: bool,
    right: String,
    right_style: Style,
    look: &Look,
) -> Vec<Span<'static>> {
    let (kind, kind_style, name_style) = match e.kind {
        EntryKind::Recent => ("recent", look.dim(), look.text()),
        EntryKind::Place => ("place", look.dim(), look.text()),
        EntryKind::Drive => ("drive", look.dim(), look.text()),
        EntryKind::Dir if e.link => ("link", look.faint(), look.faint()),
        EntryKind::Dir => ("folder", look.faint(), look.accent()),
        EntryKind::File if e.cloud => ("cloud", look.faint(), look.faint()),
        EntryKind::File => ("file", look.faint(), look.text()),
    };
    let name_style = if e.hidden { look.faint() } else { name_style };
    let name_style = if on && !e.cloud && !e.hidden {
        name_style.add_modifier(Modifier::BOLD)
    } else {
        name_style
    };
    let right_w = if right.is_empty() {
        0
    } else {
        right.width() + 1
    };
    let room = w.saturating_sub(1 + KIND_W + 2 + right_w + 1);
    let mut spans = vec![
        Span::raw(" "),
        Span::styled(format!("{kind:<KIND_W$}"), kind_style),
        Span::raw("  "),
    ];
    let path = e.path.display().to_string();
    let with_path = matches!(e.kind, EntryKind::Place | EntryKind::Drive)
        && path != e.label
        && room > label_w + 8;
    let used = if with_path {
        let label = pad(&e.label, label_w);
        let shown = truncate_left(&path, room - label_w - 2);
        let used = label_w + 2 + shown.width();
        spans.push(Span::styled(label, name_style));
        spans.push(Span::raw("  "));
        spans.push(Span::styled(shown, look.faint()));
        used
    } else {
        let label = if e.kind == EntryKind::Recent {
            truncate_left(&e.label, room)
        } else {
            truncate(&e.label, room)
        };
        let used = label.width();
        spans.push(Span::styled(label, name_style));
        used
    };
    if right_w > 0 {
        spans.push(Span::raw(" ".repeat(room.saturating_sub(used) + 1)));
        spans.push(Span::styled(right, right_style));
    }
    spans
}

/// The message, wrapped to at most the message rows and sitting on the
/// last of them.
fn draw_message(buf: &mut Buffer, rect: Rect, p: &Picker, look: &Look) {
    if rect.height == 0 {
        return;
    }
    let Some(m) = p.message() else {
        return;
    };
    let tone = match m.kind {
        MessageKind::Hint => Tone::Info,
        MessageKind::Warn => Tone::Warn,
        MessageKind::Error => Tone::Bad,
    };
    let lines = wrap(
        &m.text,
        (rect.width as usize).saturating_sub(1),
        rect.height as usize,
    );
    let top = rect.bottom() - lines.len() as u16;
    for (i, l) in lines.into_iter().enumerate() {
        let r = Rect::new(rect.x, top + i as u16, rect.width, 1);
        put(
            buf,
            r,
            &Line::from(Span::styled(format!(" {l}"), look.tone(tone))),
        );
    }
}

/// `text` wrapped at spaces to `w` columns, at most `max` lines. A word
/// wider than a line is cut where the line ends, and text left over ends
/// the last line with `...`.
pub(crate) fn wrap(text: &str, w: usize, max: usize) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    if w == 0 || max == 0 {
        return lines;
    }
    let mut cur = String::new();
    let mut words = text.split_whitespace();
    let mut pending: Option<String> = None;
    while let Some(word) = pending.take().or_else(|| words.next().map(str::to_string)) {
        let need = if cur.is_empty() {
            word.width()
        } else {
            cur.width() + 1 + word.width()
        };
        if need <= w {
            if !cur.is_empty() {
                cur.push(' ');
            }
            cur.push_str(&word);
            continue;
        }
        if cur.is_empty() {
            let (head, rest) = split_cols(&word, w);
            lines.push(head);
            pending = Some(rest);
        } else {
            lines.push(std::mem::take(&mut cur));
            pending = Some(word);
        }
        if lines.len() == max {
            let mut last = lines.pop().unwrap_or_default();
            while last.width() + 3 > w && last.pop().is_some() {}
            last.push_str("...");
            lines.push(last);
            return lines;
        }
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    lines
}

/// `s` split after its first `w` columns (at least one character).
fn split_cols(s: &str, w: usize) -> (String, String) {
    let mut used = 0;
    let mut at = 0;
    for (i, c) in s.char_indices() {
        let cw = c.width().unwrap_or(0);
        if used + cw > w && i > 0 {
            break;
        }
        used += cw;
        at = i + c.len_utf8();
    }
    (s[..at].to_string(), s[at..].to_string())
}

/// The footer while the picker is up: its keys for the state, with esc
/// saying what it does now.
pub(crate) fn picker_hints(app: &App) -> Vec<Hint> {
    if matches!(app.overlay, Some(Overlay::Help)) {
        return vec![Hint {
            key: "esc",
            label: "close",
        }];
    }
    let Some(p) = app.picker.as_ref() else {
        return keymap::footer_hints("picker").to_vec();
    };
    let base = if p.prompt().is_some() {
        keymap::PICKER_PROMPT_HINTS
    } else if p.location().is_none() {
        keymap::PICKER_PLACES_HINTS
    } else {
        keymap::PICKER_FOLDER_HINTS
    };
    let esc = p.esc_word();
    base.iter()
        .map(|h| {
            if h.key == "esc" {
                Hint {
                    key: "esc",
                    label: esc,
                }
            } else {
                *h
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_wrap_to_three_lines_at_most() {
        let text = "That is a whole drive: 1,204,331+ files so far. Press s again to scan it.";
        assert_eq!(wrap(text, 80, 3), [text]);
        let lines = wrap(text, 30, 3);
        assert_eq!(
            lines,
            [
                "That is a whole drive:",
                "1,204,331+ files so far. Press",
                "s again to scan it."
            ]
        );
        let cut = wrap(text, 20, 3);
        assert_eq!(cut.len(), 3);
        assert!(cut[2].ends_with("..."), "{cut:?}");
        assert!(cut.iter().all(|l| l.width() <= 20), "{cut:?}");
        // A long path breaks where the line ends.
        let path = wrap("Cannot open C:\\a\\very\\long\\path\\here", 12, 3);
        assert!(path.iter().all(|l| l.width() <= 12), "{path:?}");
        assert!(wrap("x", 0, 3).is_empty());
        assert!(wrap("x", 5, 0).is_empty());
    }

    #[test]
    fn the_layout_depends_on_the_area_alone() {
        for (w, h) in [(100, 29), (80, 23), (60, 23), (50, 19), (34, 19), (24, 7)] {
            let lay = picker_layout(Rect::new(0, 0, w, h));
            assert!(lay.list.height >= MIN_LIST, "{w}x{h}: {lay:?}");
            assert!(lay.card.bottom() <= h);
            assert!(lay.list.y > lay.location.y);
            assert!(lay.message.y >= lay.list.bottom());
        }
        let big = picker_layout(Rect::new(0, 0, 100, 29));
        assert!(big.bordered && big.logo.is_some() && big.slot.is_some());
        assert_eq!(big.message.height, MESSAGE_LINES);
        let tiny = picker_layout(Rect::new(0, 0, 10, 3));
        assert_eq!(tiny.location.height, 1);
    }
}
