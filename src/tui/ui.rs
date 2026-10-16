//! Drawing. Everything the view shows is painted here from [`App`] state and a
//! [`Look`], straight into a ratatui [`Buffer`], so the live terminal and the
//! README previews (see `preview`) run exactly the same code.
//!
//! The renderer writes a few facts back into the app (pane height for paging,
//! scroll offsets, whether the layout is narrow, where the rainbow letters
//! landed); the state machine reads them on the next key.

#![cfg(feature = "tui")]

use std::path::Path;

use ratatui::Frame;
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Clear, Widget};
use serde::Serialize;

use crate::edit::{self, Risk};
use crate::model::{Category, Confidence, FileReport, Finding, Marker, RemovalStrategy, Severity};
use crate::util::fmt::{hex_dump, human_size};

use super::app::{self, App, Overlay, Pane, Plan, Screen};
use super::keymap::{self, Hint};
use super::logo;
use super::picker::{Entry, EntryKind, MessageKind};
use super::theme::{Look, Tone};

/// Narrower than this, one pane shows at a time and `tab` switches.
pub const NARROW: u16 = 60;

/// The smallest area the view draws into; below it a short note shows.
pub const MIN_W: u16 = 24;
pub const MIN_H: u16 = 8;

/// Draw one frame.
pub fn draw(frame: &mut Frame, app: &mut App, look: &Look) {
    let area = frame.area();
    draw_into(frame.buffer_mut(), area, app, look);
}

/// Draw one frame into `buf` over `area`.
pub fn draw_into(buf: &mut Buffer, area: Rect, app: &mut App, look: &Look) {
    app.rainbow_cells.clear();
    buf.set_style(area, look.base());
    if area.width < MIN_W || area.height < MIN_H {
        let msg = Line::from(Span::styled(
            "Enlarge the terminal to use meownary.",
            look.dim(),
        ));
        let y = area.y + area.height / 2;
        put(buf, Rect::new(area.x, y, area.width, 1), &msg.centered());
        return;
    }
    app.narrow = area.width < NARROW;
    if app.is_picking() {
        let [body, footer] =
            Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).areas(area);
        draw_picker(buf, body, app, look);
        draw_footer(buf, footer, app, look);
        return;
    }
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .areas(area);

    draw_header(buf, header, app, look);
    match app.screen {
        Screen::Main => draw_main(buf, body, app, look),
        Screen::Detail => draw_detail(buf, body, app, look),
        Screen::Buckets => draw_buckets(buf, body, app, look),
    }
    draw_footer(buf, footer, app, look);

    match app.overlay {
        Some(Overlay::Help) => {
            backdrop(buf, area, look);
            app.rainbow_cells.clear();
            draw_help(buf, area, app, look);
        }
        Some(Overlay::Confirm(_)) => {
            backdrop(buf, area, look);
            app.rainbow_cells.clear();
            draw_confirm(buf, body, app, look);
            app.confirm_drawn = true;
        }
        Some(Overlay::Filter) | None => {}
    }
}

// ---- small helpers ------------------------------------------------------

/// Render `line` into a one-row `rect`.
fn put(buf: &mut Buffer, rect: Rect, line: &Line) {
    if rect.width == 0 || rect.height == 0 {
        return;
    }
    line.render(Rect { height: 1, ..rect }, buf);
}

fn row(area: Rect, dy: u16) -> Rect {
    Rect::new(area.x, area.y + dy, area.width, 1)
}

fn width_of(spans: &[Span]) -> usize {
    spans.iter().map(|s| s.content.chars().count()).sum()
}

/// Cut `s` to `w` columns, ending in `...` when it was longer.
pub fn truncate(s: &str, w: usize) -> String {
    let n = s.chars().count();
    if n <= w {
        return s.to_string();
    }
    if w <= 3 {
        return s.chars().take(w).collect();
    }
    let mut out: String = s.chars().take(w - 3).collect();
    out.push_str("...");
    out
}

/// Cut `s` to `w` columns from the left, keeping its end (the file name).
pub fn truncate_left(s: &str, w: usize) -> String {
    let n = s.chars().count();
    if n <= w {
        return s.to_string();
    }
    if w <= 3 {
        return s.chars().skip(n - w).collect();
    }
    let mut out = String::from("...");
    out.extend(s.chars().skip(n - (w - 3)));
    out
}

fn pad(s: &str, w: usize) -> String {
    let mut out = truncate(s, w);
    let n = out.chars().count();
    out.extend(std::iter::repeat_n(' ', w.saturating_sub(n)));
    out
}

/// Keep `cursor` inside a window of `rows` starting at `offset`.
pub fn scroll_offset(cursor: usize, offset: usize, rows: usize, len: usize) -> usize {
    if rows == 0 || len <= rows {
        return 0;
    }
    let max = len - rows;
    let mut off = offset.min(max);
    if cursor < off {
        off = cursor;
    } else if cursor >= off + rows {
        off = cursor + 1 - rows;
    }
    off.min(max)
}

/// A centered rect of at most `w` by `h` inside `area`.
fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    )
}

/// A rounded pane with a title chip and an optional dim right-hand note.
fn pane(title: &str, note: &str, focused: bool, look: &Look) -> Block<'static> {
    let mut block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(look.border(focused))
        .title_top(Line::from(vec![
            Span::raw(" "),
            Span::styled(format!(" {title} "), look.title(focused)),
            Span::raw(" "),
        ]));
    if !note.is_empty() {
        block = block.title_top(
            Line::from(vec![
                Span::styled(format!(" {note} "), look.dim()),
                Span::raw(" "),
            ])
            .right_aligned(),
        );
    }
    block
}

/// Dim everything already drawn, so a modal stands out.
fn backdrop(buf: &mut Buffer, area: Rect, look: &Look) {
    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            if let Some(c) = buf.cell_mut((x, y)) {
                if look.mono {
                    c.modifier.insert(Modifier::DIM);
                } else {
                    c.fg = look.fade(c.fg);
                    c.bg = look.fade(c.bg);
                    c.modifier.remove(Modifier::BOLD);
                }
            }
        }
    }
}

fn severity_name(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Notice => "notice",
        Severity::Warn => "warn",
        Severity::Alert => "alert",
    }
}

fn confidence_name(c: Confidence) -> &'static str {
    match c {
        Confidence::Strong => "strong",
        Confidence::Moderate => "moderate",
        Confidence::Weak => "weak",
    }
}

/// Width of a severity chip.
const CHIP_W: usize = 9;

/// A severity chip, [`CHIP_W`] columns wide.
fn sev_chip(s: Severity, look: &Look) -> Span<'static> {
    Span::styled(format!(" {:<6}  ", severity_name(s)), look.severity_chip(s))
}

/// The key-chip and label pair used by the footer, the help and modals.
/// The chip is padded to `key_w`, so a stacked column of chips forms one even
/// block and the labels line up; callers that pass the key's own length get a
/// chip that hugs the key.
fn hint_spans(key: &str, label: &str, key_w: usize, look: &Look) -> Vec<Span<'static>> {
    vec![
        Span::styled(format!(" {key:<key_w$} "), look.key_chip()),
        Span::styled(format!(" {label}"), look.dim()),
    ]
}

/// "meownary": "meow" in the rainbow, "nary" in the pastel gradient. Records
/// the rainbow cells when the wordmark starts at `(x, y)` and fits `max_w`.
fn wordmark(app: &mut App, look: &Look, x: u16, y: u16, max_w: u16) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    let rest = logo::WORDMARK.chars().count() - logo::RAINBOW_LEN;
    for (i, c) in logo::WORDMARK.chars().enumerate() {
        let style = if i < logo::RAINBOW_LEN {
            if (i as u16) < max_w && !look.mono {
                app.rainbow_cells.push((x + i as u16, y, i));
            }
            look.rainbow(i, app.anim_ms)
        } else {
            look.gradient(i - logo::RAINBOW_LEN, rest)
        };
        spans.push(Span::styled(c.to_string(), style));
    }
    spans
}

// ---- picker -------------------------------------------------------------

/// The line under the wordmark on the picker.
pub const PICKER_TAGLINE: [&str; 2] = [
    "Pick a file or folder to scan.",
    "Nothing is changed until you confirm an action.",
];

/// The widest the picker card gets.
const PICKER_MAX_W: u16 = 88;
/// Width of the picker's kind column.
const KIND_W: usize = 6;
/// Width of the picker's size column.
const SIZE_W: usize = 9;
/// Widest a place or recent label column gets before its path.
const PLACE_LABEL_W: usize = 18;

/// Which optional parts of the picker card are drawn. Parts drop away, in
/// reverse order of importance, when the terminal is short.
#[derive(Debug, Clone, Copy)]
struct PickerParts {
    card: bool,
    gaps: bool,
    tagline: u16,
    logo: bool,
    location: bool,
    message: bool,
}

impl PickerParts {
    /// Rows everything but the list takes.
    fn fixed(&self) -> u16 {
        let b = |on: bool, n: u16| if on { n } else { 0 };
        // The card: two borders and a blank row at the top.
        b(self.card, 3)
            + b(self.gaps, 2)
            + self.tagline
            + b(self.logo, 1)
            + 3
            + b(self.location, 1)
            + b(self.message, 1)
    }

    /// Drop the next part. False when nothing is left to drop.
    fn shed(&mut self) -> bool {
        if self.card {
            self.card = false;
        } else if self.gaps {
            self.gaps = false;
        } else if self.tagline > 0 {
            self.tagline = 0;
        } else if self.logo {
            self.logo = false;
        } else if self.location {
            self.location = false;
        } else if self.message {
            self.message = false;
        } else {
            return false;
        }
        true
    }
}

/// The picker screen: a calm centered card with the wordmark, one line on
/// what happens next, the path box, where the list is, the list, and the
/// picker's message.
fn draw_picker(buf: &mut Buffer, area: Rect, app: &mut App, look: &Look) {
    let Some(picker) = app.picker.as_ref() else {
        return;
    };
    let n = picker.entries().len();
    let hidden = picker.hidden();
    let selected = picker.selected();
    let confirming = picker.confirming();
    let input = picker.input().to_string();
    let location = picker.location().map(|p| p.display().to_string());
    let message = picker
        .message()
        .map(|m| (m.text.clone(), message_tone(&m.kind)));

    // Width first: the card, its content column, and the tagline's shape.
    let margin = if area.width >= 40 { 4 } else { 0 };
    let card_w = area.width.saturating_sub(margin).min(PICKER_MAX_W);
    let mut parts = PickerParts {
        card: area.width >= 40 && area.height >= 18,
        gaps: true,
        tagline: 0,
        logo: true,
        location: true,
        message: true,
    };
    let content_w = |card: bool| -> usize {
        let w = if card {
            card_w.saturating_sub(6)
        } else {
            card_w
        };
        w as usize
    };
    let one_line = PICKER_TAGLINE.join(" ");
    let tag_h = |w: usize| if one_line.chars().count() <= w { 1 } else { 2 };
    parts.tagline = tag_h(content_w(parts.card));

    // Then height: the list wants every row, needs a few, and the optional
    // parts give way until those few fit.
    let more = u16::from(hidden > 0);
    let want = (n.max(1) as u16).saturating_add(more);
    let need = want.min(3);
    while parts.fixed() + need > area.height && parts.shed() {}
    if parts.tagline > 0 {
        parts.tagline = tag_h(content_w(parts.card));
    }
    let list_h = want.min(area.height.saturating_sub(parts.fixed()));
    let total_h = (parts.fixed() + list_h).min(area.height);

    // Place the card a little above center: it reads as calmer.
    let x = area.x + (area.width - card_w) / 2;
    let y = area.y + (area.height - total_h) * 2 / 5;
    let card = Rect::new(x, y, card_w, total_h);
    let inner = if parts.card {
        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(look.border(false));
        let inner = block.inner(card);
        block.render(card, buf);
        Rect {
            x: inner.x + 2,
            y: inner.y + 1,
            width: inner.width.saturating_sub(4),
            height: inner.height.saturating_sub(1),
        }
    } else {
        card
    };
    let w = inner.width as usize;
    let mut cy = inner.y;
    let bottom = inner.bottom();
    let line_at = |cy: u16| Rect::new(inner.x, cy, inner.width, 1);

    if parts.logo && cy < bottom {
        let lx = inner.x + inner.width.saturating_sub(logo::WORDMARK.len() as u16) / 2;
        let lw = inner.right().saturating_sub(lx);
        let spans = wordmark(app, look, lx, cy, lw);
        put(buf, Rect::new(lx, cy, lw, 1), &Line::from(spans));
        cy += 1;
    }
    if parts.tagline > 0 {
        let lines: Vec<String> = if parts.tagline == 1 {
            vec![one_line.clone()]
        } else {
            PICKER_TAGLINE.iter().map(|s| truncate(s, w)).collect()
        };
        for l in lines {
            if cy < bottom {
                put(
                    buf,
                    line_at(cy),
                    &Line::from(Span::styled(l, look.dim())).centered(),
                );
                cy += 1;
            }
        }
    }
    if parts.gaps {
        cy += 1;
    }

    // The path box. It turns to the warning color while a confirm is up.
    if cy + 3 <= bottom {
        let rect = Rect::new(inner.x, cy, inner.width, 3);
        let (border, title) = if confirming {
            (look.tone(Tone::Warn), look.chip(Tone::Warn))
        } else {
            (look.border(true), look.title(true))
        };
        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(border)
            .title_top(Line::from(vec![
                Span::raw(" "),
                Span::styled(" path ", title),
                Span::raw(" "),
            ]));
        let field = block.inner(rect);
        block.render(rect, buf);
        let room = (field.width as usize).saturating_sub(3);
        let mut spans = vec![Span::raw(" ")];
        if input.is_empty() {
            spans.push(Span::styled(" ", look.key_chip()));
            spans.push(Span::styled(
                truncate(" Type a path, or choose below.", room),
                look.faint(),
            ));
        } else {
            spans.push(Span::styled(truncate_left(&input, room), look.strong()));
            spans.push(Span::styled(" ", look.key_chip()));
        }
        put(buf, field, &Line::from(spans));
        cy += 3;
    }

    // Where the list is, with a rule, and the position once it scrolls.
    let rows = list_h.saturating_sub(if list_h >= 2 { more } else { 0 }) as usize;
    if parts.location && cy < bottom {
        let mut right: Vec<Span> = Vec::new();
        if n > rows
            && let Some(sel) = selected
        {
            right.push(Span::styled(
                format!(" {} of {}", app::thousands(sel + 1), app::thousands(n)),
                look.faint(),
            ));
        }
        let where_ = location.as_deref().unwrap_or("places");
        let room = w.saturating_sub(width_of(&right) + 4);
        let shown = truncate_left(where_, room);
        let rule = w.saturating_sub(shown.chars().count() + 2 + width_of(&right));
        let mut spans = vec![
            Span::raw(" "),
            Span::styled(shown, look.label()),
            Span::raw(" "),
            Span::styled("─".repeat(rule), look.rule()),
        ];
        spans.extend(right);
        put(buf, line_at(cy), &Line::from(spans));
        cy += 1;
    }

    // The list, scrolled so the highlight stays in view.
    app.picker_offset = match selected {
        Some(sel) => scroll_offset(sel, app.picker_offset, rows, n),
        // Nothing highlighted (a listing error): hold the window still.
        None => app.picker_offset.min(n.saturating_sub(rows)),
    };
    let offset = app.picker_offset;
    let Some(picker) = app.picker.as_ref() else {
        return;
    };
    let entries = picker.entries();
    let label_w = entries
        .iter()
        .filter(|e| matches!(e.kind, EntryKind::Place | EntryKind::Recent))
        .map(|e| e.label.chars().count())
        .max()
        .unwrap_or(0)
        .min(PLACE_LABEL_W);
    if n == 0 && rows > 0 && cy < bottom {
        let msg = if input.is_empty() {
            "Nothing to show here."
        } else {
            "Nothing matches. Backspace widens the list."
        };
        put(
            buf,
            line_at(cy),
            &Line::from(Span::styled(format!(" {msg}"), look.dim())),
        );
    }
    for (k, e) in entries.iter().skip(offset).take(rows).enumerate() {
        let ry = cy + k as u16;
        if ry >= bottom {
            break;
        }
        let rect = line_at(ry);
        let on = selected == Some(offset + k);
        if on {
            buf.set_style(rect, look.cursor_row(true));
        }
        put(buf, rect, &Line::from(entry_spans(e, w, label_w, on, look)));
    }
    cy += rows as u16;
    if hidden > 0 && list_h >= 2 && cy < bottom {
        put(
            buf,
            line_at(cy),
            &Line::from(Span::styled(
                format!(" +{} more, type to narrow", app::thousands(hidden)),
                look.faint(),
            )),
        );
    }

    // The message sits at the foot of the card.
    if parts.message
        && let Some((text, tone)) = message
    {
        let my = (card.bottom())
            .saturating_sub(1 + u16::from(parts.card))
            .max(inner.y);
        if my < area.bottom() {
            put(
                buf,
                line_at(my),
                &Line::from(Span::styled(
                    format!(" {}", truncate(&text, w.saturating_sub(1))),
                    look.tone(tone),
                )),
            );
        }
    }
}

fn message_tone(kind: &MessageKind) -> Tone {
    match kind {
        MessageKind::Hint => Tone::Info,
        MessageKind::Warn => Tone::Warn,
        MessageKind::Error => Tone::Bad,
    }
}

/// One picker row: a kind column, the name (folders in the accent color,
/// the scan row as an action), a dim path for places and recent picks, and
/// a right-aligned size for files.
fn entry_spans(e: &Entry, w: usize, label_w: usize, on: bool, look: &Look) -> Vec<Span<'static>> {
    let (kind, kind_style, name_style) = match e.kind {
        EntryKind::Here => ("scan", look.pink(), look.bright()),
        EntryKind::Parent => ("up", look.faint(), look.dim()),
        EntryKind::Recent => ("recent", look.dim(), look.text()),
        EntryKind::Place => ("place", look.dim(), look.text()),
        EntryKind::Dir => ("folder", look.faint(), look.accent()),
        EntryKind::File => ("file", look.faint(), look.text()),
        EntryKind::CloudFile => ("cloud", look.faint(), look.faint()),
    };
    let cloud = matches!(e.kind, EntryKind::CloudFile);
    let name_style = if on && !cloud {
        name_style.add_modifier(Modifier::BOLD)
    } else {
        name_style
    };
    let size = match (&e.kind, e.size) {
        (EntryKind::File | EntryKind::CloudFile | EntryKind::Recent, Some(s)) => human_size(s),
        (EntryKind::CloudFile, None) => "online".to_string(),
        _ => String::new(),
    };
    let size_w = if size.is_empty() {
        0
    } else {
        SIZE_W.max(size.len()) + 1
    };
    let room = w.saturating_sub(1 + KIND_W + 2 + size_w);
    let mut spans = vec![
        Span::raw(" "),
        Span::styled(format!("{kind:<KIND_W$}"), kind_style),
        Span::raw("  "),
    ];
    let path = e.path.display().to_string();
    let with_path = matches!(e.kind, EntryKind::Place | EntryKind::Recent)
        && path != e.label
        && room > label_w + 8;
    let used = if with_path {
        let label = pad(&e.label, label_w);
        let path_w = room - label_w - 2;
        let shown = truncate_left(&path, path_w);
        let used = label_w + 2 + shown.chars().count();
        spans.push(Span::styled(label, name_style));
        spans.push(Span::raw("  "));
        spans.push(Span::styled(shown, look.faint()));
        used
    } else {
        let label = if matches!(e.kind, EntryKind::Recent) {
            truncate_left(&e.label, room)
        } else {
            truncate(&e.label, room)
        };
        let used = label.chars().count();
        spans.push(Span::styled(label, name_style));
        used
    };
    if size_w > 0 {
        spans.push(Span::raw(" ".repeat(room.saturating_sub(used))));
        let style = if cloud { look.faint() } else { look.dim() };
        spans.push(Span::styled(format!(" {size:>SIZE_W$}"), style));
    }
    spans
}

// ---- header -------------------------------------------------------------

fn draw_header(buf: &mut Buffer, area: Rect, app: &mut App, look: &Look) {
    let x = area.x + 1;
    if x >= area.right() {
        return;
    }
    let w = area.right() - x;
    let line0 = Rect::new(x, area.y, w, 1);

    // Row 0: the wordmark, the tagline, and an alert count on the right.
    let spans = wordmark(app, look, x, area.y, w);
    let stats = app.stats();
    let mut right: Vec<Span> = Vec::new();
    if stats.alerts > 0 {
        right.push(Span::styled(
            format!(
                " {} {} ",
                app::thousands(stats.alerts),
                app::plural(stats.alerts, "alert", "alerts")
            ),
            look.chip(Tone::Bad),
        ));
        right.push(Span::raw(" "));
    }
    put(buf, line0, &Line::from(spans));
    if !right.is_empty() {
        put(buf, line0, &Line::from(right).right_aligned());
    }

    // Row 1: scan progress or the summary.
    let scan = app.scan_line();
    let mut spans = vec![Span::styled(
        scan.clone(),
        if app.scanning {
            look.accent()
        } else {
            look.text()
        },
    )];
    if let (true, Some(total)) = (app.scanning, app.total) {
        let bar_w = 24usize.min((w as usize).saturating_sub(scan.len() + 8));
        if bar_w >= 6 && total > 0 {
            let done = app.reports().len().min(total);
            let filled = done * bar_w / total;
            spans.push(Span::raw("  "));
            spans.push(Span::styled("━".repeat(filled), look.bright()));
            spans.push(Span::styled("─".repeat(bar_w - filled), look.rule()));
            spans.push(Span::styled(
                format!(" {}%", done * 100 / total),
                look.dim(),
            ));
        }
    }
    put(buf, row(line0, 1), &Line::from(spans));

    // Row 2: the latest message, or a gentle pointer at the keys.
    let line = match &app.status {
        Some(s) => Line::from(Span::styled(s.text.clone(), look.tone(s.tone))),
        None => Line::from(vec![
            Span::styled("Press ", look.faint()),
            Span::styled("?", look.accent()),
            Span::styled(" for keys, ", look.faint()),
            Span::styled("q", look.accent()),
            Span::styled(" to quit.", look.faint()),
        ]),
    };
    put(buf, row(line0, 2), &line);
}

// ---- main screen ----------------------------------------------------------

fn draw_main(buf: &mut Buffer, area: Rect, app: &mut App, look: &Look) {
    if app.narrow {
        match app.pane {
            Pane::Files => draw_files(buf, area, app, look, true),
            Pane::Findings => draw_findings(buf, area, app, look, true),
        }
        return;
    }
    let [left, right] =
        Layout::horizontal([Constraint::Percentage(44), Constraint::Percentage(56)]).areas(area);
    let files_focus = app.pane == Pane::Files;
    draw_files(buf, left, app, look, files_focus);
    draw_findings(buf, right, app, look, !files_focus);
}

fn draw_files(buf: &mut Buffer, area: Rect, app: &mut App, look: &Look, focused: bool) {
    let total = app.reports().len();
    let shown = app.visible().len();
    let note = if app.filter.is_active() {
        format!("{} of {}", app::thousands(shown), app::thousands(total))
    } else {
        app::thousands(total)
    };
    let block = pane("files", &note, focused, look);
    let inner = block.inner(area);
    block.render(area, buf);
    if inner.height == 0 || inner.width < 8 {
        return;
    }
    let rows = inner.height as usize;
    if focused {
        app.page = rows;
    }
    app.file_offset = scroll_offset(app.file_cursor, app.file_offset, rows, shown);

    if shown == 0 {
        let msg = if app.scanning {
            "Scanning...".to_string()
        } else if app.filter.is_active() {
            "No files match the filter.".to_string()
        } else {
            "No files to scan.".to_string()
        };
        put(
            buf,
            row(inner, 1),
            &Line::from(Span::styled(msg, look.dim())).centered(),
        );
        return;
    }

    let window: Vec<usize> = app
        .visible()
        .iter()
        .skip(app.file_offset)
        .take(rows)
        .copied()
        .collect();
    let fmt_w = window
        .iter()
        .map(|&i| app.reports()[i].format.as_deref().unwrap_or("?").len())
        .max()
        .unwrap_or(1)
        .min(8);
    let count_w = window
        .iter()
        .map(|&i| app.reports()[i].findings.len().to_string().len())
        .max()
        .unwrap_or(1);

    for (k, &ri) in window.iter().enumerate() {
        let r = &app.reports()[ri];
        let rect = row(inner, k as u16);
        if app.file_offset + k == app.file_cursor {
            buf.set_style(rect, look.cursor_row(focused));
        }
        let line = file_row(app, r, inner.width as usize, fmt_w, count_w, look);
        put(buf, rect, &line);
    }
}

fn file_row(
    app: &App,
    r: &FileReport,
    width: usize,
    fmt_w: usize,
    count_w: usize,
    look: &Look,
) -> Line<'static> {
    let mark = if app.is_file_picked(&r.path) {
        Span::styled("+", look.pink())
    } else {
        Span::raw(" ")
    };
    let dot = match r.max_severity() {
        Some(s) => Span::styled("●", look.severity(s).add_modifier(Modifier::BOLD)),
        None => Span::styled("·", look.faint()),
    };
    let n = r.findings.len();
    let count = if n == 0 {
        Span::styled(format!("{:>count_w$}", "-"), look.faint())
    } else {
        let sev = r.max_severity().unwrap_or(Severity::Info);
        Span::styled(
            format!("{n:>count_w$}"),
            look.severity(sev).add_modifier(Modifier::BOLD),
        )
    };
    let fmt = r.format.as_deref().unwrap_or("?");
    let fixed = 1 + 1 + 1 + 1 + fmt_w + 2 + count_w + 1;
    let name_w = width.saturating_sub(fixed);
    // A saved file carries a chip after its name; it shrinks to a check
    // mark when the name would be squeezed, so the columns never move.
    let chip = saved_chip(app, &r.path, look).map(|(word, style)| {
        let full = format!(" {word} ");
        if name_w >= full.chars().count() + 1 + 6 {
            Span::styled(full, style)
        } else {
            Span::styled(" ✓ ", style)
        }
    });
    let chip_w = chip
        .as_ref()
        .filter(|c| name_w >= c.content.chars().count() + 3)
        .map(|c| c.content.chars().count() + 1)
        .unwrap_or(0);
    let text_w = name_w - chip_w;
    let mut name = truncate_left(&app.display_path(&r.path), text_w);
    let partial = r.partial && name.chars().count() + 2 <= text_w;
    if partial {
        name.push_str(" ~");
    }
    let name_len = name.chars().count();
    let name_style = if n == 0 { look.dim() } else { look.text() };
    let mut spans = vec![mark, dot, Span::raw(" "), Span::styled(name, name_style)];
    if chip_w > 0
        && let Some(chip) = chip
    {
        spans.push(Span::raw(" "));
        spans.push(chip);
    }
    spans.push(Span::raw(
        " ".repeat(name_w.saturating_sub(name_len + chip_w) + 1),
    ));
    spans.push(Span::styled(
        format!("{:>fmt_w$}", truncate(fmt, fmt_w)),
        look.dim(),
    ));
    spans.push(Span::raw("  "));
    spans.push(count);
    Line::from(spans)
}

/// The chip word and style for a saved file or an output copy: a calm
/// success tone for what was saved, the info tone for a copy.
fn saved_chip(app: &App, path: &Path, look: &Look) -> Option<(&'static str, Style)> {
    let soft = |fg: Color, bg: Color| {
        if look.mono {
            Style::new().add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
        } else {
            Style::new().fg(fg).bg(bg).add_modifier(Modifier::BOLD)
        }
    };
    if app.is_copy(path) {
        return Some(("copy", soft(look.p.info, Color::Rgb(0x1f, 0x2b, 0x45))));
    }
    app.saved(path).map(|s| {
        (
            s.kind.word(),
            soft(look.p.good, Color::Rgb(0x1a, 0x33, 0x27)),
        )
    })
}

/// The "saved" or "copy of" field for the detail view and the peek.
fn saved_field(app: &App, path: &Path, width: usize, look: &Look) -> Option<Vec<Span<'static>>> {
    if let Some(original) = app.copy_of(path) {
        let shown = truncate_left(&original.display().to_string(), width.saturating_sub(9));
        return Some(vec![
            Span::styled("copy of ", look.good()),
            Span::styled(shown, look.text()),
        ]);
    }
    let s = app.saved(path)?;
    let word = s.kind.word();
    let shown = truncate_left(
        &s.output.display().to_string(),
        width.saturating_sub(word.len() + 2),
    );
    Some(vec![
        Span::styled(
            format!("{word}  "),
            look.good().add_modifier(Modifier::BOLD),
        ),
        Span::styled(shown, look.text()),
    ])
}

fn draw_findings(buf: &mut Buffer, area: Rect, app: &mut App, look: &Look, focused: bool) {
    let idxs = app.current_findings();
    let note = match app.current_file() {
        Some(r) => {
            let room = (area.width as usize).saturating_sub(18);
            truncate_left(&app.display_path(&r.path), room)
        }
        None => String::new(),
    };
    let block = pane("findings", &note, focused, look);
    let inner = block.inner(area);
    block.render(area, buf);
    if inner.height == 0 || inner.width < 12 {
        return;
    }
    // Tall enough: keep the bottom for a short peek at the highlighted finding.
    let peek = inner.height >= PEEK_MIN_H && !idxs.is_empty();
    let list_h = if peek {
        inner.height - PEEK_H
    } else {
        inner.height
    };
    let rows = (list_h as usize / 2).max(1);
    if focused {
        app.page = rows;
    }
    app.finding_offset = scroll_offset(app.finding_cursor, app.finding_offset, rows, idxs.len());

    let Some(r) = app.current_file() else {
        let msg = if app.scanning {
            "Findings appear here as files are scanned."
        } else {
            "Select a file on the left."
        };
        put(
            buf,
            row(inner, 1),
            &Line::from(Span::styled(msg, look.dim())).centered(),
        );
        return;
    };
    if idxs.is_empty() {
        let (msg, style) = if r.findings.is_empty() {
            ("This file has no findings.", look.good())
        } else {
            ("No findings match the filter.", look.dim())
        };
        put(
            buf,
            row(inner, 1),
            &Line::from(Span::styled(msg, style)).centered(),
        );
        if r.partial {
            put(
                buf,
                row(inner, 2),
                &Line::from(Span::styled(
                    "This file could only be partly read.",
                    look.tone(Tone::Warn),
                ))
                .centered(),
            );
        }
        return;
    }

    let w = inner.width as usize;
    for k in 0..rows {
        let pos = app.finding_offset + k;
        let Some(&fi) = idxs.get(pos) else { break };
        let Some(f) = r.findings.get(fi) else { break };
        let y = (k * 2) as u16;
        if y >= list_h {
            break;
        }
        let top = row(inner, y);
        if pos == app.finding_cursor {
            let h = if y + 1 < list_h { 2 } else { 1 };
            buf.set_style(Rect { height: h, ..top }, look.cursor_row(focused));
        }
        let (first, second) = finding_rows(app, r, fi, f, w, look);
        put(buf, top, &first);
        if y + 1 < list_h {
            put(buf, row(inner, y + 1), &second);
        }
    }

    if peek && let Some((r, _, f)) = app.current_finding() {
        let area = Rect {
            y: inner.y + list_h,
            height: PEEK_H,
            ..inner
        };
        let saved = saved_field(app, &r.path, (area.width as usize).saturating_sub(11), look);
        draw_peek(buf, area, r, f, saved, look);
    }
}

/// Rows the peek under the findings list takes.
const PEEK_H: u16 = 6;
/// The findings pane shows the peek from this inner height up.
const PEEK_MIN_H: u16 = 17;

/// A few facts about the highlighted finding, so the common questions (what
/// is it, what would `d` do, is that safe) need no trip to the detail view.
fn draw_peek(
    buf: &mut Buffer,
    area: Rect,
    r: &FileReport,
    f: &Finding,
    saved: Option<Vec<Span<'static>>>,
    look: &Look,
) {
    let w = area.width as usize;
    let rule = w.saturating_sub(7);
    put(
        buf,
        row(area, 0),
        &Line::from(vec![
            Span::raw(" "),
            Span::styled("peek", look.label()),
            Span::raw(" "),
            Span::styled("─".repeat(rule), look.rule()),
        ]),
    );
    let field = |name: &str, value: Vec<Span<'static>>| {
        let mut spans = vec![Span::styled(format!(" {name:<9}"), look.label())];
        spans.extend(value);
        Line::from(spans)
    };
    let val_w = w.saturating_sub(11);
    let mut lines = vec![field(
        "kind",
        vec![Span::styled(
            truncate(&category_text(&f.category), val_w),
            look.text(),
        )],
    )];
    let note = f
        .evidence
        .note
        .clone()
        .unwrap_or_else(|| format!("at 0x{:x}", f.evidence.offset));
    lines.push(field(
        "note",
        vec![Span::styled(truncate_left(&note, val_w), look.text())],
    ));
    match &f.marker {
        Some(m) => {
            lines.push(field(
                "action",
                vec![Span::styled(truncate(&marker_text(m), val_w), look.text())],
            ));
            let risk = edit::assess(r.format.as_deref(), r.size, m);
            let mut v = verdict_spans(&risk, look);
            // The reason is exact, so it wraps onto the spare row rather than
            // being cut short.
            let chip_w = v.first().map(|c| c.content.chars().count()).unwrap_or(0);
            let reason = v.pop().map(|s| (s.content.trim().to_string(), s.style));
            let mut first = v;
            let mut rest = None;
            if let Some((text, style)) = reason {
                let room = val_w.saturating_sub(chip_w + 2);
                let (a, b) = wrap_once(&text, room);
                first.push(Span::styled(format!("  {a}"), style));
                if !b.is_empty() {
                    rest = Some(Span::styled(truncate(&b, val_w), style));
                }
            }
            lines.push(field("verdict", first));
            if let Some(span) = rest {
                lines.push(field("", vec![span]));
            }
        }
        None => {
            lines.push(field(
                "action",
                vec![Span::styled(
                    truncate("Nothing. This finding has no removable marker.", val_w),
                    look.dim(),
                )],
            ));
        }
    }
    // A saved file says so right under the kind; the note gives way when
    // the rows run out.
    if let Some(value) = saved {
        lines.insert(1, field("saved", value));
        if lines.len() > (area.height as usize).saturating_sub(1) {
            lines.remove(2);
        }
    }
    for (k, line) in lines
        .iter()
        .take((area.height as usize).saturating_sub(1))
        .enumerate()
    {
        put(buf, row(area, 1 + k as u16), line);
    }
}

/// Split `s` at the last space that keeps the first part within `w` columns.
fn wrap_once(s: &str, w: usize) -> (String, String) {
    if s.chars().count() <= w {
        return (s.to_string(), String::new());
    }
    let head: String = s.chars().take(w + 1).collect();
    match head.rfind(' ') {
        Some(cut) if cut > 0 => (s[..cut].to_string(), s[cut + 1..].to_string()),
        _ => (truncate(s, w), String::new()),
    }
}

fn finding_rows(
    app: &App,
    r: &FileReport,
    fi: usize,
    f: &Finding,
    w: usize,
    look: &Look,
) -> (Line<'static>, Line<'static>) {
    let weak = f.confidence == Confidence::Weak;
    let mark = if app.is_finding_picked(&r.path, fi) {
        Span::styled("+", look.pink())
    } else {
        Span::raw(" ")
    };
    let title_w = w.saturating_sub(2 + CHIP_W + 1 + 1);
    let title_style = if weak { look.dim() } else { look.strong() };
    let first = Line::from(vec![
        mark,
        Span::raw(" "),
        sev_chip(f.severity, look),
        Span::raw(" "),
        Span::styled(truncate(&f.title, title_w), title_style),
    ]);

    // The confidence sits under the chip's text, the signature under the title.
    let tag = if f.is_removable() { "removable" } else { "" };
    let sig_w = w.saturating_sub(3 + 8 + 1 + tag.len() + 2);
    let sig = truncate(&f.signature_id, sig_w);
    let mut spans = vec![
        Span::raw("   "),
        Span::styled(
            format!("{:<8}", confidence_name(f.confidence)),
            look.confidence(f.confidence),
        ),
        Span::raw(" "),
        Span::styled(sig, if weak { look.faint() } else { look.accent() }),
    ];
    let used = width_of(&spans);
    if !tag.is_empty() && w > used + tag.len() + 1 {
        spans.push(Span::raw(" ".repeat(w - used - tag.len() - 1)));
        spans.push(Span::styled(tag, look.pink()));
    }
    (first, Line::from(spans))
}

// ---- detail ---------------------------------------------------------------

fn draw_detail(buf: &mut Buffer, area: Rect, app: &mut App, look: &Look) {
    let block = pane("finding", "esc: back", true, look);
    let mut inner = block.inner(area);
    block.render(area, buf);
    if inner.width >= 78 {
        inner = Rect {
            x: inner.x + 1,
            width: inner.width - 2,
            ..inner
        };
    }
    let lines = detail_lines(app, look, inner.width as usize);
    let h = inner.height as usize;
    app.detail_lines = lines.len();
    app.page = h.max(1);
    let max = lines.len().saturating_sub(h);
    app.detail_scroll = app.detail_scroll.min(max);
    for (k, line) in lines.iter().skip(app.detail_scroll).take(h).enumerate() {
        put(buf, row(inner, k as u16), line);
    }
    if max > 0 {
        let note = format!(
            " {}/{} ",
            app.detail_scroll + h.min(lines.len()),
            lines.len()
        );
        let r = Rect::new(area.x, area.bottom() - 1, area.width.saturating_sub(2), 1);
        put(
            buf,
            r,
            &Line::from(Span::styled(note, look.dim())).right_aligned(),
        );
    }
}

/// The text the detail view shows for the highlighted finding.
pub fn detail_lines(app: &App, look: &Look, width: usize) -> Vec<Line<'static>> {
    let Some((r, _, f)) = app.current_finding() else {
        return vec![Line::from(Span::styled("Nothing selected.", look.dim()))];
    };
    let mut out = Vec::new();
    out.push(Line::from(Span::styled(
        truncate(&f.title, width),
        look.strong(),
    )));
    out.push(Line::from(""));

    let field = |name: &str, value: Vec<Span<'static>>| {
        let mut spans = vec![Span::styled(format!("{name:<11}"), look.label())];
        spans.extend(value);
        Line::from(spans)
    };
    let text = |s: String| Span::styled(s, look.text());

    out.push(field("file", {
        let mut v = vec![text(truncate_left(
            &app.display_path(&r.path),
            width.saturating_sub(32),
        ))];
        v.push(Span::styled(
            format!(
                "  {}, {}",
                r.format.as_deref().unwrap_or("unknown format"),
                human_size(r.size)
            ),
            look.dim(),
        ));
        v
    }));
    if let Some(value) = saved_field(app, &r.path, width.saturating_sub(11), look) {
        out.push(field("saved", value));
    }
    out.push(field("kind", vec![text(category_text(&f.category))]));
    let mut rating = vec![
        sev_chip(f.severity, look),
        Span::raw("  "),
        Span::styled(
            format!("{} confidence", confidence_name(f.confidence)),
            look.confidence(f.confidence),
        ),
    ];
    if f.confidence == Confidence::Weak {
        rating.push(Span::styled(
            "  (weak: excluded from bulk actions)",
            look.dim(),
        ));
    }
    out.push(field("rating", rating));
    out.push(field(
        "signature",
        vec![Span::styled(f.signature_id.clone(), look.accent())],
    ));
    if let Some(c) = &f.evidence.catalog_ref {
        out.push(field("catalog", vec![text(c.clone())]));
    }
    out.push(field(
        "note",
        vec![text(truncate(
            f.evidence.note.as_deref().unwrap_or("-"),
            width.saturating_sub(11),
        ))],
    ));
    out.push(field(
        "offset",
        vec![text(format!(
            "0x{:x} ({} bytes in)",
            f.evidence.offset, f.evidence.offset
        ))],
    ));
    match &f.marker {
        Some(m) => {
            out.push(field(
                "marker",
                vec![
                    text(marker_text(m)),
                    Span::styled(
                        format!("  in {}", app::container_slug(m.container)),
                        look.dim(),
                    ),
                ],
            ));
            let risk = edit::assess(r.format.as_deref(), r.size, m);
            out.push(field("verdict", verdict_spans(&risk, look)));
        }
        None => out.push(field(
            "marker",
            vec![Span::styled("None. Nothing to scrub.", look.dim())],
        )),
    }
    out.push(Line::from(""));

    let base = app::hex_base(f.evidence.offset);
    out.push(Line::from(vec![
        Span::styled("bytes ", look.label()),
        Span::styled(
            format!("0x{:x}..0x{:x}", base, base + app::HEX_WINDOW),
            look.dim(),
        ),
        Span::styled("   marker ", look.label()),
        Span::styled("  ", look.hex_marker()),
        Span::styled("   evidence ", look.label()),
        Span::styled("ab", look.hex_evidence()),
    ]));
    match &app.hex {
        Some(h) if h.path == r.path && h.base == base => match &h.error {
            Some(e) => out.push(Line::from(Span::styled(
                format!("Could not read the bytes: {e}."),
                look.tone(Tone::Bad),
            ))),
            None if h.bytes.is_empty() => out.push(Line::from(Span::styled(
                "No bytes at this offset.",
                look.dim(),
            ))),
            None => out.extend(hex_lines(&h.bytes, h.base, f, look)),
        },
        _ => out.push(Line::from(Span::styled("Reading bytes...", look.dim()))),
    }
    out
}

/// The byte range a marker highlights in the hex view.
fn marker_span(m: &Marker) -> Option<(u64, u64)> {
    match m.removal {
        RemovalStrategy::RawBlank { .. } | RemovalStrategy::StructuralRemove => {
            Some((m.region.offset, m.region.end()))
        }
        RemovalStrategy::Truncate { from } => Some((from, u64::MAX)),
        RemovalStrategy::DeleteFile => None,
    }
}

/// The hex dump from `util::fmt::hex_dump`, restyled per byte: the marker
/// region filled in pink, the evidence bytes underlined, zeros faint.
pub fn hex_lines(bytes: &[u8], base: u64, f: &Finding, look: &Look) -> Vec<Line<'static>> {
    let dump = hex_dump(bytes, base);
    let marked = f.marker.as_ref().and_then(marker_span);
    let ev_start = f.evidence.offset;
    let ev_end = ev_start + (f.evidence.matched.len() as u64).max(1);
    let byte_style = |abs: u64, b: u8| -> Style {
        if marked.is_some_and(|(s, e)| abs >= s && abs < e) {
            look.hex_marker()
        } else if abs >= ev_start && abs < ev_end {
            look.hex_evidence()
        } else if b == 0 {
            look.faint()
        } else if (0x20..0x7f).contains(&b) {
            look.text()
        } else {
            look.dim()
        }
    };
    let mut out = Vec::new();
    for (rowi, text) in dump.lines().enumerate() {
        let row_base = base + rowi as u64 * 16;
        let chunk = bytes.get(rowi * 16..).unwrap_or(&[]);
        let chars: Vec<char> = text.chars().collect();
        let style_at = |col: usize| -> Style {
            if col < 8 {
                return look.faint();
            }
            // Columns as `hex_dump` lays them out: the offset and two spaces,
            // three columns per byte with an extra space after the eighth,
            // then a space and the ASCII column.
            for (i, &b) in chunk.iter().take(16).enumerate() {
                let hex_col = 10 + 3 * i + usize::from(i >= 8);
                if col == hex_col || col == hex_col + 1 || col == 60 + i {
                    return byte_style(row_base + i as u64, b);
                }
            }
            Style::new()
        };
        let mut spans: Vec<Span<'static>> = Vec::new();
        let mut cur = String::new();
        let mut cur_style = Style::new();
        for (col, ch) in chars.iter().enumerate() {
            let s = style_at(col);
            if s != cur_style && !cur.is_empty() {
                spans.push(Span::styled(std::mem::take(&mut cur), cur_style));
            }
            cur_style = s;
            cur.push(*ch);
        }
        if !cur.is_empty() {
            spans.push(Span::styled(cur, cur_style));
        }
        out.push(Line::from(spans));
    }
    out
}

fn verdict_spans(risk: &Risk, look: &Look) -> Vec<Span<'static>> {
    match risk {
        Risk::Safe => vec![
            Span::styled(" safe ", look.chip(Tone::Good)),
            Span::styled("  reversible: press u to undo", look.dim()),
        ],
        Risk::Warn(r) => vec![
            Span::styled(" warn ", look.chip(Tone::Warn)),
            Span::styled(format!("  {r}"), look.tone(Tone::Warn)),
        ],
        Risk::Refuse(r) => vec![
            Span::styled(" refuse ", look.chip(Tone::Bad)),
            Span::styled(format!("  {r}"), look.tone(Tone::Bad)),
        ],
    }
}

fn kind_name<T: Serialize>(k: &T) -> String {
    serde_json::to_value(k)
        .ok()
        .and_then(|v| v.as_str().map(|s| s.replace('_', " ")))
        .unwrap_or_default()
}

/// "junk: pdb path", "identity: really pe, named .jpg", and so on.
pub fn category_text(c: &Category) -> String {
    match c {
        Category::Identity {
            declared_ext,
            true_format,
            mismatch,
        } => match (declared_ext, mismatch) {
            (Some(ext), true) => format!("identity: really {true_format}, named .{ext}"),
            _ => format!("identity: {true_format}"),
        },
        Category::Brand(k) => format!("brand: {}", kind_name(k)),
        Category::Integrity(k) => format!("integrity: {}", kind_name(k)),
        Category::Tamper(k) => format!("tamper: {}", kind_name(k)),
        Category::Deception(k) => format!("deception: {}", kind_name(k)),
        Category::Bundleware => "bundleware".to_string(),
        Category::Junk(k) => format!("junk: {}", kind_name(k)),
    }
}

/// What a marker's removal does, in a few words.
pub fn marker_text(m: &Marker) -> String {
    let r = m.region;
    match m.removal {
        RemovalStrategy::RawBlank { fill } => format!(
            "blank {} at 0x{:x}..0x{:x} with 0x{fill:02x}",
            human_size(r.len),
            r.offset,
            r.end()
        ),
        RemovalStrategy::Truncate { from } => format!("cut the file at 0x{from:x}"),
        RemovalStrategy::StructuralRemove => format!(
            "rewrite the container without 0x{:x}..0x{:x}",
            r.offset,
            r.end()
        ),
        RemovalStrategy::DeleteFile => "delete the whole file".to_string(),
    }
}

// ---- buckets --------------------------------------------------------------

fn draw_buckets(buf: &mut Buffer, area: Rect, app: &mut App, look: &Look) {
    let title = format!("buckets by {}", app::bucket_by_name(app.bucket_by));
    let block = pane(&title, "b: regroup", true, look);
    let inner = block.inner(area);
    block.render(area, buf);
    if inner.height < 2 || inner.width < 20 {
        return;
    }
    let len = app.buckets().len();
    if len == 0 {
        put(
            buf,
            row(inner, 1),
            &Line::from(Span::styled("No findings to group yet.", look.dim())).centered(),
        );
        return;
    }
    let w = inner.width as usize;
    let nums = |a: &str, b: &str, c: &str| format!("{a:>6} {b:>9} {c:>6} ");
    let num_w = 6 + 1 + 9 + 1 + 6 + 1;
    let label_w = w.saturating_sub(1 + CHIP_W + 1 + num_w + 1);
    let head = Line::from(vec![
        Span::styled(
            format!(" {:<chip$} {:<label_w$} ", "worst", "bucket", chip = CHIP_W),
            look.label(),
        ),
        Span::styled(nums("found", "removable", "files"), look.label()),
    ]);
    put(buf, row(inner, 0), &head);

    let rows = (inner.height - 1) as usize;
    app.page = rows.max(1);
    app.bucket_offset = scroll_offset(app.bucket_cursor, app.bucket_offset, rows, len);
    for k in 0..rows {
        let pos = app.bucket_offset + k;
        let Some(b) = app.buckets().get(pos) else {
            break;
        };
        let rect = row(inner, 1 + k as u16);
        if pos == app.bucket_cursor {
            buf.set_style(rect, look.cursor_row(true));
        }
        let mut name = b.label.clone();
        if !b.key.eq_ignore_ascii_case(&b.label) {
            name = format!("{}  {}", b.label, b.key);
        }
        let label_len = b.label.chars().count().min(label_w);
        let shown = pad(&name, label_w);
        let (lab, key) = {
            let mut it = shown.chars();
            let lab: String = it.by_ref().take(label_len).collect();
            (lab, it.collect::<String>())
        };
        let line = Line::from(vec![
            Span::raw(" "),
            sev_chip(b.max_severity, look),
            Span::raw(" "),
            Span::styled(lab, look.strong()),
            Span::styled(key, look.dim()),
            Span::raw(" "),
            Span::styled(format!("{:>6} ", app::thousands(b.members)), look.text()),
            Span::styled(
                format!("{:>9} ", app::thousands(b.removable)),
                if b.removable > 0 {
                    look.pink()
                } else {
                    look.faint()
                },
            ),
            Span::styled(format!("{:>6} ", app::thousands(b.files)), look.text()),
        ]);
        put(buf, rect, &line);
    }
}

// ---- footer ---------------------------------------------------------------

fn draw_footer(buf: &mut Buffer, area: Rect, app: &App, look: &Look) {
    if matches!(app.overlay, Some(Overlay::Filter)) {
        draw_filter_bar(buf, area, app, look);
        return;
    }
    let ctx = app.context();
    let mut hints: Vec<Hint> = keymap::footer_hints(ctx).to_vec();
    if app.narrow && (ctx == "files" || ctx == "findings") {
        // One pane at a time: switching is the first thing to know.
        hints.retain(|h| h.key != "tab");
        let label = if ctx == "files" { "findings" } else { "files" };
        hints.insert(0, Hint { key: "tab", label });
    }

    let mut right: Vec<Span> = Vec::new();
    // Over a reopened picker the view's picks and filter are not in play.
    let picking = app.is_picking();
    let picked = app.picked();
    if picked > 0 && !picking {
        right.push(Span::styled(
            format!(" {} selected ", app::thousands(picked)),
            look.chip(Tone::Info),
        ));
        right.push(Span::raw(" "));
    }
    if let Some(f) = app.filter.describe().filter(|_| !picking) {
        right.push(Span::styled(
            format!(" filter: {} ", truncate(&f, 24)),
            look.chip(Tone::Good),
        ));
        right.push(Span::raw(" "));
    }
    let budget = (area.width as usize).saturating_sub(width_of(&right) + 1);

    // The way to the key reference (on the picker, the way out) always
    // stays; the rest fill what is left.
    let piece = |h: &Hint| {
        let mut p = hint_spans(h.key, h.label, h.key.len(), look);
        p.push(Span::raw("  "));
        p
    };
    let keep = if picking { "esc" } else { "?" };
    let help = hints
        .iter()
        .position(|h| h.key == keep)
        .map(|i| hints.remove(i));
    let reserve = help.as_ref().map(|h| width_of(&piece(h))).unwrap_or(0);
    let mut spans: Vec<Span> = vec![Span::raw(" ")];
    for hint in &hints {
        let p = piece(hint);
        if width_of(&spans) + width_of(&p) + reserve > budget {
            break;
        }
        spans.extend(p);
    }
    if let Some(h) = &help
        && width_of(&spans) + reserve <= budget
    {
        spans.extend(piece(h));
    }
    put(buf, area, &Line::from(spans));
    if !right.is_empty() {
        put(buf, area, &Line::from(right).right_aligned());
    }
}

fn draw_filter_bar(buf: &mut Buffer, area: Rect, app: &App, look: &Look) {
    let text = match &app.filter {
        app::Filter::Text(t) => t.clone(),
        _ => String::new(),
    };
    let right = vec![
        Span::styled(
            format!(
                "{} of {} files  ",
                app::thousands(app.visible().len()),
                app::thousands(app.reports().len())
            ),
            look.dim(),
        ),
        Span::styled(" enter ", look.key_chip()),
        Span::styled(" keep  ", look.dim()),
        Span::styled(" esc ", look.key_chip()),
        Span::styled(" clear ", look.dim()),
    ];
    let room = (area.width as usize).saturating_sub(width_of(&right) + 8);
    let line = Line::from(vec![
        Span::raw(" "),
        Span::styled(" / ", look.chip(Tone::Info)),
        Span::raw(" "),
        Span::styled(truncate_left(&text, room), look.strong()),
        Span::styled("_", look.bright()),
    ]);
    put(buf, area, &line);
    put(buf, area, &Line::from(right).right_aligned());
}

// ---- help -------------------------------------------------------------------

struct Group {
    title: &'static str,
    hints: &'static [Hint],
}

impl Group {
    fn height(&self) -> usize {
        1 + self.hints.len()
    }
    fn key_w(&self) -> usize {
        self.hints.iter().map(|h| h.key.len()).max().unwrap_or(1)
    }
    fn label_w(&self) -> usize {
        self.hints.iter().map(|h| h.label.len()).max().unwrap_or(1)
    }
}

/// Lay the help groups into `n` columns: the first `n` groups head the
/// columns, and each later group joins the shortest column.
fn help_columns(groups: &[Group], n: usize) -> Vec<Vec<usize>> {
    let n = n.clamp(1, groups.len().max(1));
    let mut cols: Vec<Vec<usize>> = (0..n).map(|i| vec![i]).collect();
    let height = |col: &Vec<usize>| -> usize {
        col.iter().map(|&g| groups[g].height()).sum::<usize>() + col.len().saturating_sub(1)
    };
    for g in n..groups.len() {
        let Some(best) = (0..n).min_by_key(|&c| (height(&cols[c]), c)) else {
            break;
        };
        cols[best].push(g);
    }
    cols.retain(|c| !c.is_empty() && c[0] < groups.len());
    cols
}

fn draw_help(buf: &mut Buffer, area: Rect, app: &mut App, look: &Look) {
    let groups: Vec<Group> = keymap::HELP_GROUPS
        .iter()
        .map(|(title, hints)| Group { title, hints })
        .collect();
    const GAP: usize = 3;
    const PAD: u16 = 2;

    let mut chosen = None;
    for n in [3usize, 2, 1] {
        let cols = help_columns(&groups, n);
        let widths: Vec<(usize, usize)> = cols
            .iter()
            .map(|c| {
                let kw = c.iter().map(|&g| groups[g].key_w()).max().unwrap_or(1);
                let lw = c.iter().map(|&g| groups[g].label_w()).max().unwrap_or(1);
                (kw, lw)
            })
            .collect();
        let total: usize = widths.iter().map(|(k, l)| k + 2 + 2 + l).sum::<usize>()
            + GAP * cols.len().saturating_sub(1);
        let outer = total + 2 * PAD as usize + 2;
        if outer <= area.width as usize || n == 1 {
            chosen = Some((cols, widths, outer));
            break;
        }
    }
    let Some((cols, widths, outer_w)) = chosen else {
        return;
    };
    let col_h = cols
        .iter()
        .map(|c| c.iter().map(|&g| groups[g].height()).sum::<usize>() + c.len() - 1)
        .max()
        .unwrap_or(0);
    let logo_h = 3usize;
    let content = logo_h + 1 + col_h + 1;
    let rect = centered(area, outer_w as u16, (content + 2) as u16);

    Clear.render(rect, buf);
    buf.set_style(rect, look.base());
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(look.border(true))
        .title_top(Line::from(vec![
            Span::raw(" "),
            Span::styled(" keys ", look.title(true)),
            Span::raw(" "),
        ]))
        .title_bottom(Line::from(Span::styled(" Press any key to close ", look.dim())).centered());
    let inner = block.inner(rect);
    block.render(rect, buf);
    let inner = if inner.width > 2 * PAD {
        Rect {
            x: inner.x + PAD,
            width: inner.width - 2 * PAD,
            ..inner
        }
    } else {
        inner
    };
    if inner.height == 0 {
        return;
    }

    // The wordmark and tagline, then two lines of reassurance.
    let tx = inner.x;
    if tx < inner.right() {
        let tw = inner.right() - tx;
        let spans = wordmark(app, look, tx, inner.y, tw);
        put(buf, Rect::new(tx, inner.y, tw, 1), &Line::from(spans));
        let lines = [
            "Edits keep the original in the trash. Press u to undo.",
            "Weak findings are never included in bulk scrubs.",
        ];
        for (i, l) in lines.iter().enumerate() {
            let y = inner.y + 1 + i as u16;
            if y < inner.bottom() {
                put(
                    buf,
                    Rect::new(tx, y, tw, 1),
                    &Line::from(Span::styled(*l, look.faint())),
                );
            }
        }
    }

    // The key groups, one column each.
    let top = inner.y + logo_h as u16 + 1;
    let mut x = inner.x;
    for (c, col) in cols.iter().enumerate() {
        let (kw, lw) = widths[c];
        let cw = kw + 2 + 2 + lw;
        let mut y = top;
        for (k, &g) in col.iter().enumerate() {
            if k > 0 {
                y += 1;
            }
            let group = &groups[g];
            if y >= inner.bottom() {
                break;
            }
            let rule = cw.saturating_sub(group.title.len() + 1);
            put(
                buf,
                Rect::new(x, y, cw as u16, 1),
                &Line::from(vec![
                    Span::styled(group.title, look.bright()),
                    Span::raw(" "),
                    Span::styled("─".repeat(rule), look.rule()),
                ]),
            );
            y += 1;
            for hint in group.hints {
                if y >= inner.bottom() {
                    break;
                }
                put(
                    buf,
                    Rect::new(x, y, cw as u16, 1),
                    &Line::from(hint_spans(hint.key, hint.label, kw, look)),
                );
                y += 1;
            }
        }
        x += (cw + GAP) as u16;
        if x >= inner.right() {
            break;
        }
    }
}

// ---- confirm ----------------------------------------------------------------

/// What one plan item will do, in a few words.
fn item_action(item: &app::PlanItem) -> String {
    if item.archive.is_some() {
        return "save a copy".to_string();
    }
    match item.marker.removal {
        RemovalStrategy::RawBlank { .. } if item.replacement.is_some() => format!(
            "rewrite {} at 0x{:x}",
            human_size(item.marker.region.len),
            item.marker.region.offset
        ),
        RemovalStrategy::RawBlank { .. } => {
            format!(
                "blank {} at 0x{:x}",
                human_size(item.marker.region.len),
                item.marker.region.offset
            )
        }
        RemovalStrategy::Truncate { from } => format!(
            "cut {} from 0x{from:x}",
            human_size(item.size.saturating_sub(from))
        ),
        RemovalStrategy::StructuralRemove => {
            format!("rewrite {}", app::container_slug(item.marker.container))
        }
        RemovalStrategy::DeleteFile => format!("delete, {}", human_size(item.size)),
    }
}

/// The lines a confirm modal lists for `plan`, plus the line index each item
/// starts at.
fn plan_lines(
    app: &App,
    plan: &Plan,
    width: usize,
    look: &Look,
) -> (Vec<Line<'static>>, Vec<usize>) {
    let mut lines = Vec::new();
    let mut starts = Vec::new();
    for item in &plan.items {
        starts.push(lines.len());
        let deep = plan.kind == app::PlanKind::DeepDeattribute;
        let (chip, reason, tone) = match &item.risk {
            // A deep edit is safe to write but may stop the copy loading.
            Risk::Safe if deep => (" deep    ", None, Tone::Warn),
            Risk::Safe => (" safe    ", None, Tone::Good),
            Risk::Warn(r) => (" warn    ", Some(r.clone()), Tone::Warn),
            Risk::Refuse(r) => (" refuse  ", Some(r.clone()), Tone::Bad),
        };
        let action = item_action(item);
        let label = if item.label == "delete file" {
            String::new()
        } else {
            item.label.clone()
        };
        let fixed = 1 + CHIP_W + 1 + 2 + label.len() + 2 + action.len();
        let path_w = width.saturating_sub(fixed).max(8);
        let mut spans = vec![
            Span::raw(" "),
            Span::styled(chip, look.chip(tone)),
            Span::raw(" "),
            Span::styled(
                truncate_left(&app.display_path(&item.path), path_w),
                look.strong(),
            ),
        ];
        if !label.is_empty() {
            spans.push(Span::raw("  "));
            spans.push(Span::styled(label, look.accent()));
        }
        spans.push(Span::raw("  "));
        spans.push(Span::styled(action, look.dim()));
        lines.push(Line::from(spans));
        if let Some(r) = reason {
            let skip = if matches!(item.risk, Risk::Refuse(_)) {
                ", skipped"
            } else {
                ""
            };
            lines.push(Line::from(vec![
                Span::raw(" ".repeat(CHIP_W + 2)),
                Span::styled(
                    truncate(&format!("{r}{skip}"), width.saturating_sub(CHIP_W + 2)),
                    look.tone(tone),
                ),
            ]));
        }
    }
    (lines, starts)
}

fn draw_confirm(buf: &mut Buffer, area: Rect, app: &App, look: &Look) {
    let Some(Overlay::Confirm(plan)) = &app.overlay else {
        return;
    };
    let w = area.width.saturating_sub(4).clamp(30, 88);
    let inner_w = w.saturating_sub(4) as usize;
    let (lines, starts) = plan_lines(app, plan, inner_w, look);

    let mut notes: Vec<Line> = Vec::new();
    // The deep warning goes first so a short terminal never drops it.
    if plan.kind == app::PlanKind::DeepDeattribute {
        notes.push(Line::from(Span::styled(
            "Deep edits can break loading or licensing. Check the copy before use.",
            look.tone(Tone::Warn),
        )));
    }
    for caveat in &plan.caveats {
        notes.push(Line::from(Span::styled(
            caveat.clone(),
            look.tone(Tone::Warn),
        )));
    }
    if let Some(first) = plan.replaces.first() {
        let name = first
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| app.display_path(first));
        let more = match plan.replaces.len() {
            1 => String::new(),
            n => format!(" +{} more", app::thousands(n - 1)),
        };
        notes.push(Line::from(Span::styled(
            format!("Replaces {name}{more}."),
            look.tone(Tone::Warn),
        )));
    }
    let refused = plan.items.len() - plan.runnable();
    if refused > 0 {
        notes.push(Line::from(Span::styled(
            format!(
                "{} {} would be refused and {} skipped.",
                app::thousands(refused),
                app::plural(refused, "item", "items"),
                app::plural(refused, "is", "are")
            ),
            look.tone(Tone::Bad),
        )));
    }
    if plan.weak_left_out > 0 {
        notes.push(Line::from(Span::styled(
            format!(
                "{} weak {} excluded. Scrub {} one at a time.",
                app::thousands(plan.weak_left_out),
                app::plural(plan.weak_left_out, "finding", "findings"),
                app::plural(plan.weak_left_out, "it", "them")
            ),
            look.dim(),
        )));
    }
    if !plan.private_skips.is_empty() {
        notes.push(Line::from(Span::styled(
            format!(
                "{} selected {} will be skipped. Esc keeps every file unchanged.",
                app::thousands(plan.private_skips.len()),
                app::plural(plan.private_skips.len(), "hit", "hits")
            ),
            look.tone(Tone::Warn),
        )));
    }
    if matches!(
        plan.kind,
        app::PlanKind::Deattribute | app::PlanKind::DeepDeattribute
    ) {
        notes.push(Line::from(Span::styled(
            "A copy is saved beside each original. The originals never change.",
            look.faint(),
        )));
        if plan.items.iter().any(|i| i.archive.is_some()) {
            notes.push(Line::from(Span::styled(
                "An archive is cleaned through the files inside it.",
                look.faint(),
            )));
        }
    } else {
        notes.push(Line::from(Span::styled(
            "The originals go to the trash first. Press u to undo the whole batch.",
            look.faint(),
        )));
    }

    let chrome = 2 + 1 + 1 + notes.len() + 1 + 1;
    let max_h = area.height.saturating_sub(1) as usize;
    let list_h = lines.len().min(max_h.saturating_sub(chrome)).max(1);
    let h = (list_h + chrome).min(area.height as usize) as u16;
    let rect = centered(area, w, h);

    Clear.render(rect, buf);
    buf.set_style(rect, look.base());
    let tone = match plan.kind {
        app::PlanKind::Scrub => Tone::Info,
        app::PlanKind::Deattribute => Tone::Info,
        app::PlanKind::DeepDeattribute | app::PlanKind::Delete => Tone::Warn,
    };
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(look.border(true))
        .title_top(Line::from(vec![
            Span::raw(" "),
            Span::styled(format!(" {} ", plan.title()), look.chip(tone)),
            Span::raw(" "),
        ]));
    let inner = block.inner(rect);
    block.render(rect, buf);
    let inner = Rect {
        x: inner.x + 1,
        width: inner.width.saturating_sub(2),
        ..inner
    };

    let first = plan.scroll.min(plan.items.len().saturating_sub(1));
    let mut start = starts.get(first).copied().unwrap_or(0);
    start = start.min(lines.len().saturating_sub(list_h));
    let mut y = inner.y + 1;
    for line in lines.iter().skip(start).take(list_h) {
        put(buf, Rect::new(inner.x, y, inner.width, 1), line);
        y += 1;
    }
    y += 1;
    for line in &notes {
        if y >= inner.bottom() {
            break;
        }
        put(buf, Rect::new(inner.x, y, inner.width, 1), line);
        y += 1;
    }
    if y < inner.bottom() {
        let mut spans = hint_spans("y", "confirm", 1, look);
        spans.push(Span::raw("   "));
        spans.extend(hint_spans("n", "cancel", 1, look));
        if lines.len() > list_h {
            spans.push(Span::raw("   "));
            spans.extend(hint_spans("up/down", "scroll", 7, look));
        }
        put(
            buf,
            Rect::new(inner.x, y, inner.width, 1),
            &Line::from(spans),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncation_keeps_ends_readable() {
        assert_eq!(truncate("abcdef", 10), "abcdef");
        assert_eq!(truncate("abcdefgh", 6), "abc...");
        assert_eq!(truncate_left("dir/sub/file.exe", 11), "...file.exe");
        assert_eq!(truncate_left("ab", 1), "b");
        assert_eq!(pad("ab", 4), "ab  ");
    }

    #[test]
    fn scroll_keeps_the_cursor_visible() {
        assert_eq!(scroll_offset(0, 0, 5, 3), 0);
        assert_eq!(scroll_offset(7, 0, 5, 20), 3);
        assert_eq!(scroll_offset(2, 3, 5, 20), 2);
        assert_eq!(scroll_offset(19, 30, 5, 20), 15);
        assert_eq!(scroll_offset(4, 0, 0, 20), 0);
    }

    #[test]
    fn help_columns_balance() {
        let groups: Vec<Group> = keymap::HELP_GROUPS
            .iter()
            .map(|(title, hints)| Group { title, hints })
            .collect();
        let three = help_columns(&groups, 3);
        assert_eq!(three.len(), 3);
        let mut all: Vec<usize> = three.iter().flatten().copied().collect();
        all.sort();
        assert_eq!(all, (0..groups.len()).collect::<Vec<_>>());
        assert_eq!(help_columns(&groups, 1).len(), 1);
    }

    #[test]
    fn category_and_marker_words() {
        use crate::model::{ContainerKind, JunkKind, Region};
        assert_eq!(
            category_text(&Category::Junk(JunkKind::PdbPath)),
            "junk: pdb path"
        );
        let id = Category::Identity {
            declared_ext: Some("jpg".into()),
            true_format: "pe".into(),
            mismatch: true,
        };
        assert_eq!(category_text(&id), "identity: really pe, named .jpg");
        let m = Marker::blank(Region::new(0x20, 16), ContainerKind::Raw);
        assert_eq!(marker_text(&m), "blank 16 B at 0x20..0x30 with 0x00");
    }
}
