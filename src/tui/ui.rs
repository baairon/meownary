//! Drawing. Everything the view shows is painted here from [`App`] state and a
//! [`Look`], straight into a ratatui [`Buffer`], so the live terminal and the
//! README previews (see `preview`) run exactly the same code.
//!
//! The renderer writes a few facts back into the app (pane height for paging,
//! scroll offsets, whether the layout is narrow, where the rainbow letters
//! landed); the state machine reads them on the next key.

#![cfg(feature = "tui")]

use ratatui::Frame;
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Clear, Widget};
use serde::Serialize;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::edit::{self, Risk};
use crate::model::{Category, Confidence, Finding, Marker, RemovalStrategy, Severity};
use crate::util::fmt::{hex_dump, human_size};

use super::app::{self, App, Overlay, Plan, Screen};
use super::keymap::{self, Hint};
use super::logo;
use super::theme::{Look, Tone};
use super::views;

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
        views::picker::draw_picker(buf, body, app, look);
        draw_footer(buf, footer, app, look);
        if matches!(app.overlay, Some(Overlay::Help)) {
            backdrop(buf, area, look);
            app.rainbow_cells.clear();
            draw_help(buf, area, app, look);
        }
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
        Screen::Main => views::files::draw_main(buf, body, app, look),
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
pub(crate) fn put(buf: &mut Buffer, rect: Rect, line: &Line) {
    if rect.width == 0 || rect.height == 0 {
        return;
    }
    line.render(Rect { height: 1, ..rect }, buf);
}

pub(crate) fn row(area: Rect, dy: u16) -> Rect {
    Rect::new(area.x, area.y + dy, area.width, 1)
}

pub(crate) fn width_of(spans: &[Span]) -> usize {
    spans.iter().map(|s| s.content.width()).sum()
}

/// The longest start of `s` that fits in `w` columns.
fn head_cols(s: &str, w: usize) -> String {
    let mut used = 0;
    let mut out = String::new();
    for c in s.chars() {
        let cw = c.width().unwrap_or(0);
        if used + cw > w {
            break;
        }
        used += cw;
        out.push(c);
    }
    out
}

/// The longest end of `s` that fits in `w` columns.
fn tail_cols(s: &str, w: usize) -> String {
    let mut used = 0;
    let mut out: Vec<char> = Vec::new();
    for c in s.chars().rev() {
        let cw = c.width().unwrap_or(0);
        if used + cw > w {
            break;
        }
        used += cw;
        out.push(c);
    }
    out.iter().rev().collect()
}

/// Cut `s` to `w` columns, ending in `...` when it was longer.
pub fn truncate(s: &str, w: usize) -> String {
    if s.width() <= w {
        return s.to_string();
    }
    if w <= 3 {
        return head_cols(s, w);
    }
    let mut out = head_cols(s, w - 3);
    out.push_str("...");
    out
}

/// Cut `s` to `w` columns from the left, keeping its end (the file name).
pub fn truncate_left(s: &str, w: usize) -> String {
    if s.width() <= w {
        return s.to_string();
    }
    if w <= 3 {
        return tail_cols(s, w);
    }
    let mut out = String::from("...");
    out.push_str(&tail_cols(s, w - 3));
    out
}

pub(crate) fn pad(s: &str, w: usize) -> String {
    let mut out = truncate(s, w);
    let n = out.width();
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
pub(crate) fn centered(area: Rect, w: u16, h: u16) -> Rect {
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
pub(crate) fn pane(title: &str, note: &str, focused: bool, look: &Look) -> Block<'static> {
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
pub(crate) fn backdrop(buf: &mut Buffer, area: Rect, look: &Look) {
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

pub(crate) fn severity_name(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Notice => "notice",
        Severity::Warn => "warn",
        Severity::Alert => "alert",
    }
}

pub(crate) fn confidence_name(c: Confidence) -> &'static str {
    match c {
        Confidence::Strong => "strong",
        Confidence::Moderate => "moderate",
        Confidence::Weak => "weak",
    }
}

/// Width of a severity chip.
pub(crate) const CHIP_W: usize = 9;

/// A severity chip, [`CHIP_W`] columns wide.
pub(crate) fn sev_chip(s: Severity, look: &Look) -> Span<'static> {
    Span::styled(format!(" {:<6}  ", severity_name(s)), look.severity_chip(s))
}

/// The key-chip and label pair used by the footer, the help and modals.
/// The chip is padded to `key_w`, so a stacked column of chips forms one even
/// block and the labels line up; callers that pass the key's own length get a
/// chip that hugs the key.
pub(crate) fn hint_spans(key: &str, label: &str, key_w: usize, look: &Look) -> Vec<Span<'static>> {
    vec![
        Span::styled(format!(" {key:<key_w$} "), look.key_chip()),
        Span::styled(format!(" {label}"), look.dim()),
    ]
}

/// "meownary": "meow" in the rainbow, "nary" in the pastel gradient. Records
/// the rainbow cells when the wordmark starts at `(x, y)` and fits `max_w`.
pub(crate) fn wordmark(
    app: &mut App,
    look: &Look,
    x: u16,
    y: u16,
    max_w: u16,
) -> Vec<Span<'static>> {
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

    // Row 1: scan progress or the summary. Row 2: what is running, the
    // latest message, or a gentle pointer at the keys.
    views::files::draw_scan_row(buf, row(line0, 1), app, look);
    views::status::draw_status_row(buf, row(line0, 2), app, look);
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
    if let Some(value) = views::files::saved_field(app, &r.path, width.saturating_sub(11), look) {
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

pub(crate) fn verdict_spans(risk: &Risk, look: &Look) -> Vec<Span<'static>> {
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
    let mut title = format!("buckets by {}", app::bucket_by_name(app.bucket_by));
    if !app.at_root() {
        title.push_str(&format!(" in {}", truncate_left(&app.cwd_name(), 24)));
    }
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
        let label_len = b.label.width().min(label_w);
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
    let mut hints: Vec<Hint> = if app.is_picking() {
        views::picker::picker_hints(app)
    } else {
        keymap::footer_hints(ctx).to_vec()
    };
    views::files::explorer_hints(app, ctx, &mut hints);
    views::status::busy_hints(app, ctx, &mut hints);
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
                app::thousands(if app.filter.is_active() {
                    app.rows().len()
                } else {
                    app.cwd_files()
                }),
                app::thousands(app.cwd_files())
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
    let ctx = if app.is_picking() { "picker" } else { "main" };
    let groups: Vec<Group> = keymap::help_groups(ctx)
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

/// How many lines an item takes in a confirm list: its own, plus a reason
/// line for a warn or a refuse.
fn item_height(item: &app::PlanItem) -> usize {
    if matches!(item.risk, Risk::Warn(_) | Risk::Refuse(_)) {
        2
    } else {
        1
    }
}

/// The line each of `plan`'s items starts at in a confirm list, and the
/// list's total length. Cheap, so a long plan can be measured every frame
/// while only the rows in view are formatted.
fn plan_starts(plan: &Plan) -> (Vec<usize>, usize) {
    let mut starts = Vec::with_capacity(plan.items.len());
    let mut at = 0;
    for item in &plan.items {
        starts.push(at);
        at += item_height(item);
    }
    (starts, at)
}

/// The lines one plan item shows.
fn item_lines(
    app: &App,
    plan: &Plan,
    item: &app::PlanItem,
    width: usize,
    look: &Look,
) -> Vec<Line<'static>> {
    let mut lines = Vec::with_capacity(2);
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
    lines
}

/// The `rows` lines of a confirm list from line `start` on, formatting only
/// the items in that window.
fn plan_lines(
    app: &App,
    plan: &Plan,
    starts: &[usize],
    (start, rows): (usize, usize),
    width: usize,
    look: &Look,
) -> Vec<Line<'static>> {
    let first = starts.partition_point(|&s| s <= start).saturating_sub(1);
    let mut lines = Vec::with_capacity(rows);
    for (k, item) in plan.items.iter().enumerate().skip(first) {
        for (j, line) in item_lines(app, plan, item, width, look)
            .into_iter()
            .enumerate()
        {
            if starts[k] + j < start {
                continue;
            }
            if lines.len() == rows {
                return lines;
            }
            lines.push(line);
        }
        if lines.len() == rows {
            break;
        }
    }
    lines
}

fn draw_confirm(buf: &mut Buffer, area: Rect, app: &App, look: &Look) {
    let Some(Overlay::Confirm(plan)) = &app.overlay else {
        return;
    };
    let w = area.width.saturating_sub(4).clamp(30, 88);
    let inner_w = w.saturating_sub(4) as usize;
    let (starts, total) = plan_starts(plan);

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
    let list_h = total.min(max_h.saturating_sub(chrome)).max(1);
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
    start = start.min(total.saturating_sub(list_h));
    let mut y = inner.y + 1;
    for line in plan_lines(app, plan, &starts, (start, list_h), inner_w, look) {
        put(buf, Rect::new(inner.x, y, inner.width, 1), &line);
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
        if total > list_h {
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
    fn wide_characters_take_two_columns() {
        // Each of these takes two columns, so four of them fill eight.
        let wide = "\u{6587}\u{4ef6}\u{540d}\u{5b57}";
        assert_eq!(wide.width(), 8);
        assert_eq!(truncate(wide, 8), wide);
        assert_eq!(truncate(wide, 7), "\u{6587}\u{4ef6}...");
        assert_eq!(truncate(wide, 7).width(), 7);
        assert_eq!(truncate_left(wide, 7).width(), 7);
        assert_eq!(pad(wide, 10).width(), 10);
        assert_eq!(
            pad("\u{6587}", 1),
            " ",
            "a wide letter never hangs over the edge"
        );
        assert_eq!(width_of(&[Span::raw(wide), Span::raw("ab")]), 10);
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
    fn a_confirm_formats_only_its_window() {
        use crate::model::{ContainerKind, Region};
        let item = |name: &str, risk: Risk| app::PlanItem {
            path: std::path::PathBuf::from("root").join(name),
            format: Some("pe".into()),
            size: 4096,
            label: "pe.pdb_path".into(),
            title: "PDB path".into(),
            marker: Marker::blank(Region::new(0x40, 8), ContainerKind::Raw),
            risk,
            expected_hash: None,
            replacement: None,
            credit: None,
            archive: None,
        };
        let plan = Plan {
            kind: app::PlanKind::Scrub,
            items: vec![
                item("a.exe", Risk::Safe),
                item("b.exe", Risk::Warn("cuts the signature".into())),
                item("c.exe", Risk::Safe),
                item("d.exe", Risk::Refuse("magic bytes".into())),
                item("e.exe", Risk::Safe),
            ],
            weak_left_out: 0,
            private_skips: Vec::new(),
            caveats: Vec::new(),
            replaces: Vec::new(),
            scroll: 0,
        };
        let (starts, total) = plan_starts(&plan);
        assert_eq!(starts, [0, 1, 3, 4, 6]);
        assert_eq!(total, 7);
        let app = App::new("root");
        let look = Look::vivid();
        let text = |l: &Line| {
            l.spans
                .iter()
                .map(|s| s.content.as_ref())
                .collect::<String>()
        };
        // From the middle of b.exe's two lines: its reason, then c and d.
        let lines = plan_lines(&app, &plan, &starts, (2, 3), 60, &look);
        assert_eq!(lines.len(), 3);
        assert!(
            text(&lines[0]).contains("cuts the signature"),
            "{}",
            text(&lines[0])
        );
        assert!(text(&lines[1]).contains("c.exe"));
        assert!(text(&lines[2]).contains("d.exe"));
        // Past the end it stops short instead of padding.
        let tail = plan_lines(&app, &plan, &starts, (5, 4), 60, &look);
        assert_eq!(tail.len(), 2);
        assert!(text(&tail[1]).contains("e.exe"));
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
