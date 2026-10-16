//! The main screen's two panes: the files list, which shows one folder at a
//! time (or a filter's matches under it), and the findings of the
//! highlighted file, with the peek under them, or a summary of the
//! highlighted folder. Header row 1, the scan's progress, is drawn here too.

#![cfg(feature = "tui")]

use std::path::{MAIN_SEPARATOR, Path};

use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use ratatui::widgets::Widget;

use crate::edit;
use crate::model::{Confidence, FileReport, Finding, Severity};

use crate::tui::app::{self, App, Pane};
use crate::tui::explorer::{FolderState, Row};
use crate::tui::keymap::Hint;
use crate::tui::theme::{Look, Tone};
use crate::tui::tree::{Agg, SEVERITIES, severity_slot};
use crate::tui::ui::{
    CHIP_W, category_text, confidence_name, hint_spans, marker_text, pane, put, row, scroll_offset,
    sev_chip, severity_name, truncate, truncate_left, verdict_spans, width_of,
};
use crate::tui::widgets::Gauge;

/// Cells of the small bar on a folder row the scan is in.
const MINI_GAUGE: usize = 8;
/// The files list drops that bar below this inner width.
const GAUGE_MIN_W: usize = 40;
/// The fewest columns a row's name keeps.
const MIN_NAME: usize = 6;

pub(crate) fn draw_main(buf: &mut Buffer, area: Rect, app: &mut App, look: &Look) {
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
    let filtered = app.filter.is_active();
    let shown = app.rows().len();
    let files = app.cwd_files();
    let note = if filtered {
        format!("{} of {}", app::thousands(shown), app::thousands(files))
    } else {
        app::thousands(files)
    };
    // The title is where the list is: the path from the root, cut from the
    // left so the folder itself stays readable.
    let title = if filtered {
        format!("matches in {}", app.cwd_name())
    } else {
        app.breadcrumb()
    };
    let room = (area.width as usize)
        .saturating_sub(note.width() + 12)
        .max(4);
    let block = pane(&truncate_left(&title, room), &note, focused, look);
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
        let msg = if let Some(why) = app.cwd_unreadable() {
            format!("Cannot open this folder: {}.", short_reason(why))
        } else if app.scanning {
            "Scanning...".to_string()
        } else if filtered {
            "No files match the filter.".to_string()
        } else if app.at_root() {
            "No files to scan.".to_string()
        } else {
            "This folder is empty.".to_string()
        };
        put(
            buf,
            row(inner, 1),
            &Line::from(Span::styled(msg, look.dim())).centered(),
        );
        return;
    }

    let window: Vec<Row> = app
        .rows()
        .iter()
        .skip(app.file_offset)
        .take(rows)
        .cloned()
        .collect();
    let fmt_w = window
        .iter()
        .filter(|r| !r.dir)
        .filter_map(|r| app.report(&r.path))
        .map(|r| r.format.as_deref().unwrap_or("?").len())
        .max()
        .unwrap_or(1)
        .min(8);
    let count_w = window
        .iter()
        .map(|r| count_cell(app, r, look).0.width())
        .max()
        .unwrap_or(1)
        .max(1);
    let w = inner.width as usize;
    for (k, r) in window.iter().enumerate() {
        let rect = row(inner, k as u16);
        if app.file_offset + k == app.file_cursor {
            buf.set_style(rect, look.cursor_row(focused));
        }
        if r.dir {
            let (line, bar) = folder_row(app, r, w, count_w, look);
            put(buf, rect, &line);
            if let Some((x, ratio)) = bar {
                let at = Rect::new(rect.x + x as u16, rect.y, MINI_GAUGE as u16, 1);
                Gauge::new(ratio)
                    .live(true)
                    .render(buf, at, look, app.anim_ms);
            }
        } else if let Some(report) = app.report(&r.path) {
            let line = file_row(app, report, &r.name, w, fmt_w, count_w, look);
            put(buf, rect, &line);
        } else {
            put(buf, rect, &listed_row(app, r, w, count_w, look));
        }
    }
}

/// The text after `cannot list directory:` or `cannot read:` in a scan
/// reason, which is what a row has room for.
fn short_reason(why: &str) -> &str {
    ["cannot list directory: ", "cannot read: "]
        .iter()
        .find_map(|p| why.strip_prefix(p))
        .unwrap_or(why)
}

/// The word a partial file shows when there is room: why it was only
/// partly read.
fn partial_word(reason: Option<&str>) -> &'static str {
    match reason {
        Some(r) if r.starts_with("cloud-only") => "cloud only",
        Some(r) if r.contains("permission denied") => "no access",
        _ => "~",
    }
}

/// "1,030 files", with a `+` while the count may still grow.
fn files_text(n: usize, exact: bool) -> String {
    format!(
        "{}{} {}",
        app::thousands(n),
        if exact { "" } else { "+" },
        app::plural(n, "file", "files")
    )
}

/// The findings count at the right of a row, and its style.
fn count_cell(app: &App, r: &Row, look: &Look) -> (String, Style) {
    if r.dir {
        if app.folder_state(r) != FolderState::Done {
            return (String::new(), look.text());
        }
        let agg = folder_agg(app, &r.path);
        return match agg.worst() {
            Some(worst) => (
                app::thousands(agg.findings),
                look.severity(worst).add_modifier(Modifier::BOLD),
            ),
            None => ("-".to_string(), look.faint()),
        };
    }
    match app.report(&r.path) {
        Some(report) if report.findings.is_empty() => ("-".to_string(), look.faint()),
        Some(report) => (
            report.findings.len().to_string(),
            look.severity(report.max_severity().unwrap_or(Severity::Info))
                .add_modifier(Modifier::BOLD),
        ),
        None => (String::new(), look.text()),
    }
}

fn folder_agg(app: &App, path: &Path) -> Agg {
    app.tree()
        .find(path)
        .map(|i| app.tree().node(i).agg)
        .unwrap_or_default()
}

fn severity_dot(worst: Option<Severity>, look: &Look) -> Span<'static> {
    match worst {
        Some(s) => Span::styled("●", look.severity(s).add_modifier(Modifier::BOLD)),
        None => Span::styled("·", look.faint()),
    }
}

/// One row laid out: the mark and dot, the name, then a middle part (with
/// room for a small bar in front of it) and the count, right-aligned to
/// the same columns as the files' format and count. Returns the line and,
/// when the bar kept its room, the column it starts at.
#[allow(clippy::too_many_arguments)]
fn compose(
    lead: [Span<'static>; 2],
    name: &str,
    name_style: Style,
    (mid, mid_style): (String, Style),
    bar_w: usize,
    (count, count_style): (String, Style),
    w: usize,
    count_w: usize,
) -> (Line<'static>, Option<usize>) {
    let tail = 2 + count_w + 1;
    let max_mid = w.saturating_sub(3 + 1 + tail + MIN_NAME);
    let gap = usize::from(bar_w > 0 && !mid.is_empty());
    let (bar_w, gap) = if bar_w + gap + 4 > max_mid {
        (0, 0)
    } else {
        (bar_w, gap)
    };
    let mid = truncate(&mid, max_mid.saturating_sub(bar_w + gap));
    let mid_w = bar_w + gap + mid.width();
    let name = truncate_left(name, w.saturating_sub(3 + 1 + mid_w + tail));
    let pad = w.saturating_sub(3 + name.width() + mid_w + tail);
    let [mark, dot] = lead;
    let bar_x = 3 + name.width() + pad;
    let line = Line::from(vec![
        mark,
        dot,
        Span::raw(" "),
        Span::styled(name, name_style),
        Span::raw(" ".repeat(pad + bar_w + gap)),
        Span::styled(mid, mid_style),
        Span::raw("  "),
        Span::styled(format!("{count:>count_w$}"), count_style),
    ]);
    (line, (bar_w > 0).then_some(bar_x))
}

/// A folder row: its name with a trailing separator, and what the scan
/// has made of it so far.
fn folder_row(
    app: &App,
    r: &Row,
    w: usize,
    count_w: usize,
    look: &Look,
) -> (Line<'static>, Option<(usize, f64)>) {
    let agg = folder_agg(app, &r.path);
    let mark = if app.is_dir_picked(&r.path) {
        Span::styled("+", look.pink())
    } else {
        Span::raw(" ")
    };
    let dot = severity_dot(agg.worst(), look);
    let name = format!("{}{MAIN_SEPARATOR}", r.name);
    let quiet = if agg.findings > 0 {
        look.text()
    } else {
        look.dim()
    };
    let mut ratio = None;
    let (name_style, mid, mid_style) = match app.folder_state(r) {
        FolderState::Pending { expected, exact } => (
            look.dim(),
            expected
                .map(|n| files_text(n as usize, exact))
                .unwrap_or_default(),
            look.faint(),
        ),
        FolderState::Scanning {
            scanned,
            expected,
            exact,
        } => {
            let of = expected.unwrap_or(0).max(scanned);
            if w >= GAUGE_MIN_W {
                ratio = Some(if of == 0 {
                    0.0
                } else {
                    scanned as f64 / of as f64
                });
            }
            let text = format!(
                "{}/{}{}",
                app::thousands(scanned as usize),
                app::thousands(of as usize),
                if exact { "" } else { "+" }
            );
            (look.text(), text, look.accent())
        }
        FolderState::Done => (quiet, files_text(agg.files, true), look.dim()),
        FolderState::Empty => (look.dim(), "empty".to_string(), look.faint()),
        FolderState::Unreadable(why) => (
            look.dim(),
            format!("cannot open: {}", short_reason(&why)),
            look.tone(Tone::Warn),
        ),
        FolderState::NotScanned => (look.dim(), "not scanned".to_string(), look.faint()),
    };
    let bar_w = if ratio.is_some() { MINI_GAUGE } else { 0 };
    let (line, x) = compose(
        [mark, dot],
        &name,
        name_style,
        (mid, mid_style),
        bar_w,
        count_cell(app, r, look),
        w,
        count_w,
    );
    (line, x.zip(ratio))
}

/// A file the folder's listing holds that the scan has not delivered: dim
/// until the scan is past it, then marked as never scanned.
fn listed_row(app: &App, r: &Row, w: usize, count_w: usize, look: &Look) -> Line<'static> {
    let mid = if app.is_final(&r.path) {
        "not scanned"
    } else {
        ""
    };
    compose(
        [Span::raw(" "), Span::styled("·", look.faint())],
        &r.name,
        look.dim(),
        (mid.to_string(), look.faint()),
        0,
        (String::new(), look.text()),
        w,
        count_w,
    )
    .0
}

fn file_row(
    app: &App,
    r: &FileReport,
    name: &str,
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
    let dot = severity_dot(r.max_severity(), look);
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
        if name_w >= full.width() + 1 + 6 {
            Span::styled(full, style)
        } else {
            Span::styled(" ✓ ", style)
        }
    });
    let chip_w = chip
        .as_ref()
        .filter(|c| name_w >= c.content.width() + 3)
        .map(|c| c.content.width() + 1)
        .unwrap_or(0);
    let text_w = name_w - chip_w;
    let mut name = truncate_left(name, text_w);
    // A partial file says why when there is room, else shows a `~`.
    if r.partial {
        let word = partial_word(app.tree().reason(&r.path));
        if name.width() + 1 + word.width() <= text_w {
            name.push(' ');
            name.push_str(word);
        } else if name.width() + 2 <= text_w {
            name.push_str(" ~");
        }
    }
    let name_len = name.width();
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
pub(crate) fn saved_field(
    app: &App,
    path: &Path,
    width: usize,
    look: &Look,
) -> Option<Vec<Span<'static>>> {
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
    if let Some(r) = app.current_row().cloned() {
        if r.dir {
            draw_folder_summary(buf, area, app, look, focused, &r);
            return;
        }
        if app.report(&r.path).is_none() {
            let block = pane("findings", "", focused, look);
            let inner = block.inner(area);
            block.render(area, buf);
            let msg = if app.is_final(&r.path) {
                "The scan left this file out."
            } else {
                "The scan has not reached this file yet."
            };
            put(
                buf,
                row(inner, 1),
                &Line::from(Span::styled(msg, look.dim())).centered(),
            );
            return;
        }
    }
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
            let chip_w = v.first().map(|c| c.content.width()).unwrap_or(0);
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
    if s.width() <= w {
        return (s.to_string(), String::new());
    }
    // The first w columns plus one more character, so a space right after
    // them still counts as a place to break.
    let mut used = 0;
    let head: String = s
        .chars()
        .take_while(|c| {
            used += c.width().unwrap_or(0);
            used <= w + 1
        })
        .collect();
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

/// Header row 1: while the scan runs, how far it has got, a bar, and the
/// folder it is in; a summary after. The bar is exact once the walk's
/// total is in, follows the walk's count (with a `+`) before that, and
/// before anything is counted shimmers across its whole width.
pub(crate) fn draw_scan_row(buf: &mut Buffer, area: Rect, app: &App, look: &Look) {
    let scan = app.scan_line();
    if !app.scanning {
        put(buf, area, &Line::from(Span::styled(scan, look.text())));
        return;
    }
    put(
        buf,
        area,
        &Line::from(Span::styled(scan.clone(), look.accent())),
    );
    let used = scan.width() + 2;
    let room = (area.width as usize).saturating_sub(used);
    let bar_w = room.min(24);
    if bar_w < 8 {
        return;
    }
    let gauge = match app.scan_progress() {
        Some((done, of, _)) if of > 0 => Gauge::new(done as f64 / of as f64),
        _ => Gauge::new(0.0).inflight(0.0, 1.0),
    };
    let x = area.x + used as u16;
    gauge.live(true).render(
        buf,
        Rect::new(x, area.y, bar_w as u16, 1),
        look,
        app.anim_ms,
    );
    let rest = room.saturating_sub(bar_w + 2);
    if let Some(folder) = app.scanning_folder()
        && rest >= 6
    {
        let at = Rect::new(x + bar_w as u16 + 2, area.y, rest as u16, 1);
        put(
            buf,
            at,
            &Line::from(Span::styled(truncate_left(&folder, rest), look.dim())),
        );
    }
}

/// Footer hints the files list adds for where it is: in a subfolder, the
/// way back up.
pub(crate) fn explorer_hints(app: &App, ctx: &str, hints: &mut Vec<Hint>) {
    if ctx != "files" || app.at_root() {
        return;
    }
    let at = hints
        .iter()
        .position(|h| h.key == "enter")
        .map_or(0, |i| i + 1);
    hints.insert(
        at,
        Hint {
            key: "left",
            label: "up",
        },
    );
}

/// The findings pane over a folder row: how far the scan has got in it,
/// what it holds by severity, its most common signatures, and what the
/// keys will do with it.
fn draw_folder_summary(
    buf: &mut Buffer,
    area: Rect,
    app: &mut App,
    look: &Look,
    focused: bool,
    r: &Row,
) {
    let note = truncate_left(
        &app.display_path(&r.path),
        (area.width as usize).saturating_sub(16),
    );
    let block = pane("folder", &note, focused, look);
    let inner = block.inner(area);
    block.render(area, buf);
    if inner.height == 0 || inner.width < 12 {
        return;
    }
    let w = inner.width as usize;
    let agg = folder_agg(app, &r.path);
    let state = app.folder_state(r);
    let mut lines: Vec<Line<'static>> = vec![Line::from(Span::styled(
        truncate(&format!(" {}{MAIN_SEPARATOR}", r.name), w),
        look.strong(),
    ))];
    // The bar, when there is one, goes on the line after the name.
    let mut bar: Option<(usize, f64)> = None;
    let text = |s: String, style: Style| Line::from(Span::styled(truncate(&s, w), style));
    match &state {
        FolderState::Scanning {
            scanned,
            expected,
            exact,
        } => {
            let of = expected.unwrap_or(0).max(*scanned);
            let bar_w = w.saturating_sub(24).min(20);
            let label = format!(
                "{} of {}{} files",
                app::thousands(*scanned as usize),
                app::thousands(of as usize),
                if *exact { "" } else { "+" }
            );
            if bar_w >= 6 {
                bar = Some((
                    bar_w,
                    if of == 0 {
                        0.0
                    } else {
                        *scanned as f64 / of as f64
                    },
                ));
                lines.push(Line::from(vec![
                    Span::raw(" ".repeat(bar_w + 2)),
                    Span::styled(label, look.accent()),
                ]));
            } else {
                lines.push(text(format!(" {label}"), look.accent()));
            }
        }
        FolderState::Pending { expected, exact } => {
            let mut s = " Waiting for the scan".to_string();
            if let Some(n) = expected {
                s.push_str(&format!(" ({} so far)", files_text(*n as usize, *exact)));
            }
            s.push('.');
            lines.push(text(s, look.dim()));
        }
        FolderState::Done => lines.push(text(
            format!(
                " {}, {} with findings",
                files_text(agg.files, true),
                app::thousands(agg.flagged)
            ),
            look.text(),
        )),
        FolderState::Empty => lines.push(text(" No files in this folder.".into(), look.dim())),
        FolderState::Unreadable(why) => lines.push(text(
            format!(" Cannot open this folder: {}.", short_reason(why)),
            look.tone(Tone::Warn),
        )),
        FolderState::NotScanned => {
            let why = match r.listed {
                Some(l) if l.link => " A link to another folder. Scans never follow links.",
                Some(l) if l.excluded => " meownary keeps its trash here, so scans leave it out.",
                _ => " The scan did not reach this folder.",
            };
            lines.push(text(why.into(), look.dim()));
        }
    }
    if agg.files > 0 {
        lines.push(Line::from(""));
        let mut spans = vec![Span::raw(" ")];
        for s in SEVERITIES.iter().rev() {
            let n = agg.severity[severity_slot(*s)];
            if n > 0 {
                spans.push(Span::styled(severity_name(*s), look.severity(*s)));
                spans.push(Span::styled(
                    format!(" {}   ", app::thousands(n)),
                    look.text(),
                ));
            }
        }
        if spans.len() == 1 {
            spans.push(Span::styled("No findings.", look.good()));
        }
        lines.push(Line::from(spans));
        lines.push(text(
            format!(
                " {} removable, {} partly read",
                app::thousands(agg.removable),
                app::thousands(agg.partial)
            ),
            look.dim(),
        ));
        let top = app.folder_signatures(&r.path);
        if !top.is_empty() {
            lines.push(Line::from(""));
            lines.push(text(" most common".into(), look.label()));
            let num_w = top
                .iter()
                .map(|(_, n)| app::thousands(*n).len())
                .max()
                .unwrap_or(1);
            let sig_w = w.saturating_sub(num_w + 5);
            for (sig, n) in &top {
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("   {:<sig_w$}", truncate(sig, sig_w)),
                        look.accent(),
                    ),
                    Span::styled(format!(" {:>num_w$}", app::thousands(*n)), look.text()),
                ]));
            }
        }
    }
    lines.push(Line::from(""));
    for (key, label) in [
        ("enter", "open it"),
        ("space", "select it"),
        ("d", "scrub its removable markers"),
        ("a", "deattribute every file in it"),
    ] {
        let mut spans = vec![Span::raw(" ")];
        spans.extend(hint_spans(key, label, 5, look));
        lines.push(Line::from(spans));
    }
    for (k, line) in lines.iter().take(inner.height as usize).enumerate() {
        put(buf, row(inner, k as u16), line);
    }
    if let Some((bar_w, ratio)) = bar
        && inner.height > 1
    {
        let at = Rect::new(inner.x + 1, inner.y + 1, bar_w as u16, 1);
        Gauge::new(ratio)
            .live(true)
            .render(buf, at, look, app.anim_ms);
    }
}
