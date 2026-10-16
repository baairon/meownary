//! Header row 2: the latest message, or a gentle pointer at the keys, and the
//! footer hints for work that is running.
//!
//! While work runs off the input thread the row becomes the activity row:
//! what is running and how far it is, the thin bar (filled by weight, with
//! the item in flight lit), the file it is on, how long it has taken, and
//! the way to stop it. When the row is short of room the pieces leave in a
//! fixed order: the stop hint, the elapsed time, the file name, the counts,
//! and last the bar. The verb always stays.

#![cfg(feature = "tui")]

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use unicode_width::UnicodeWidthStr;

use crate::tui::app::{self, App, Busy};
use crate::tui::keymap::{Hint, hint_names};
use crate::tui::progress::Activity;
use crate::tui::theme::{Look, Tone};
use crate::tui::ui::{put, truncate_left, width_of};
use crate::tui::widgets::Gauge;

/// The bar's width bounds, in columns.
const BAR_MIN: usize = 6;
const BAR_MAX: usize = 24;
/// The fewest columns worth giving a file name.
const NAME_MIN: usize = 8;
/// Elapsed time shows from this many milliseconds on.
const ELAPSED_FROM_MS: u64 = 2000;

/// Header row 2.
pub(crate) fn draw_status_row(buf: &mut Buffer, area: Rect, app: &App, look: &Look) {
    if let Some(work) = app.busy {
        draw_activity(buf, area, app, work, look);
        return;
    }
    let line = match &app.status {
        Some(s) => Line::from(Span::styled(s.text.clone(), look.tone(s.tone))),
        None => Line::from(vec![
            Span::styled(
                if app.has_subfolders() {
                    "Enter opens a folder. Press "
                } else {
                    "Press "
                },
                look.faint(),
            ),
            Span::styled("?", look.accent()),
            Span::styled(" for keys, ", look.faint()),
            Span::styled("q", look.accent()),
            Span::styled(" to quit.", look.faint()),
        ]),
    };
    put(buf, area, &line);
}

/// The verb the activity row leads with.
fn verb(work: Busy) -> &'static str {
    match work {
        Busy::Planning => "Planning",
        Busy::Writing => "Writing copies",
        Busy::Scrubbing => "Scrubbing",
        Busy::Deleting => "Deleting",
        Busy::Undoing => "Undoing",
    }
}

/// "3 of 7", with the unit the work counts in.
fn counts(work: Busy, a: &Activity) -> Option<String> {
    if a.total == 0 {
        return None;
    }
    let unit = if a.rescanning {
        " files"
    } else {
        match work {
            Busy::Planning | Busy::Deleting => " files",
            Busy::Scrubbing => " markers",
            Busy::Writing | Busy::Undoing => "",
        }
    };
    Some(format!(
        "{} of {}{unit}",
        app::thousands(a.ordinal()),
        app::thousands(a.total)
    ))
}

/// How long the work has run, in plain words.
pub(crate) fn elapsed_text(ms: u64) -> String {
    let s = ms / 1000;
    match s {
        0..60 => format!("{s} s"),
        60..3600 => format!("{} min {} s", s / 60, s % 60),
        _ => format!("{} h {} min", s / 3600, s % 3600 / 60),
    }
}

/// The pieces of one activity row, before they are fitted.
struct Pieces {
    head: String,
    head_tone: Tone,
    counts: Option<String>,
    bar: Option<Gauge>,
    name: Option<String>,
    elapsed: Option<String>,
    /// Shown at the right: a key and its label, or a note.
    hint: Option<Vec<Span<'static>>>,
}

fn draw_activity(buf: &mut Buffer, area: Rect, app: &App, work: Busy, look: &Look) {
    let a = app.activity.as_ref();
    let rescanning = a.is_some_and(|a| a.rescanning);
    let name = a
        .and_then(|a| a.current.as_ref())
        .map(|(p, _)| app.display_path(p));
    let ms = app.anim_ms.saturating_sub(app.busy_since);
    let elapsed = (ms >= ELAPSED_FROM_MS).then(|| elapsed_text(ms));
    let key_hint = |key: &str, label: &str| {
        vec![
            Span::styled(key.to_string(), look.accent()),
            Span::styled(format!(" {label}"), look.faint()),
        ]
    };

    if app.should_quit && !rescanning {
        // The view is ending and waits for this work to finish its file.
        let text = match &name {
            Some(n) => format!("Finishing {n}..."),
            None => "Finishing...".to_string(),
        };
        let w = area.width as usize;
        let line = Line::from(Span::styled(truncate_left(&text, w), look.tone(Tone::Warn)));
        put(buf, area, &line);
        return;
    }
    let pieces = if app.stopping && !rescanning {
        let quitting = if app.quit_after {
            ", then quitting"
        } else {
            ""
        };
        Pieces {
            head: if name.is_some() {
                "Stopping after".to_string()
            } else {
                format!("Stopping{quitting}")
            },
            head_tone: Tone::Warn,
            counts: None,
            bar: None,
            name: name.map(|n| format!("{n}{quitting}")),
            elapsed,
            hint: app.quit_after.then(|| key_hint("q", "quit now")),
        }
    } else {
        let bar = match a {
            Some(a) if a.total > 0 => {
                let g = Gauge::new(a.ratio()).live(true);
                Some(match a.inflight() {
                    Some((from, to)) => g.inflight(from, to),
                    None => g,
                })
            }
            // Nothing counted yet: the whole track shimmers while it runs.
            _ => Some(Gauge::new(0.0).inflight(0.0, 1.0).live(true)),
        };
        let hint = if let Some(note) = app.busy_note {
            Some(vec![Span::styled(note, look.tone(Tone::Warn))])
        } else if app.quit_after {
            Some(key_hint("q", "quit now"))
        } else if app.can_stop() && app.context() == "files" {
            Some(key_hint("esc", "stop"))
        } else {
            None
        };
        Pieces {
            head: if rescanning {
                "Rescanning".to_string()
            } else {
                verb(work).to_string()
            },
            head_tone: Tone::Info,
            counts: a.and_then(|a| counts(work, a)),
            bar,
            name,
            elapsed,
            hint,
        }
    };
    draw_pieces(buf, area, app, pieces, look);
}

/// Fit `p` into `area`, dropping pieces in the row's order, and draw it.
fn draw_pieces(buf: &mut Buffer, area: Rect, app: &App, p: Pieces, look: &Look) {
    let w = area.width as usize;
    let head_w = p.head.width();
    let counts_w = p.counts.as_ref().map_or(0, |c| 1 + c.width());
    let bar_w = (w / 5).clamp(BAR_MIN, BAR_MAX);
    let name_full = p.name.as_ref().map_or(0, |n| 1 + n.width());
    let name_min = p.name.as_ref().map_or(0, |n| 1 + n.width().min(NAME_MIN));
    let elapsed_w = p.elapsed.as_ref().map_or(0, |e| 3 + e.width());
    // Two columns of air before the hint, one after it.
    let hint_w = p.hint.as_ref().map_or(0, |h| 3 + width_of(h));

    let (mut hint, mut elapsed, mut name, mut count, mut bar) = (
        p.hint.is_some(),
        p.elapsed.is_some(),
        p.name.is_some(),
        p.counts.is_some(),
        p.bar.is_some(),
    );
    let need = |hint: bool, elapsed: bool, name_w: usize, count: bool, bar: bool| {
        head_w
            + if count { counts_w } else { 0 }
            + if bar { 1 + bar_w } else { 0 }
            + name_w
            + if elapsed { elapsed_w } else { 0 }
            + if hint { hint_w } else { 0 }
    };
    // The hint shows only when everything else fits whole.
    if need(hint, elapsed, name_full, count, bar) > w {
        hint = false;
    }
    if need(hint, elapsed, name_min, count, bar) > w {
        elapsed = false;
    }
    if need(hint, elapsed, name_min, count, bar) > w {
        name = false;
    }
    let name_at = |name: bool| if name { name_min } else { 0 };
    if need(hint, elapsed, name_at(name), count, bar) > w {
        count = false;
    }
    if need(hint, elapsed, name_at(name), count, bar) > w {
        bar = false;
    }

    let style = look.tone(p.head_tone);
    let mut left = vec![Span::styled(p.head.clone(), style)];
    if count && let Some(c) = &p.counts {
        left.push(Span::styled(format!(" {c}"), style));
    }
    let left_w = width_of(&left);
    put(buf, area, &Line::from(left));
    if left_w >= w {
        return;
    }
    let mut x = area.x + left_w as u16;
    if bar && let Some(g) = p.bar {
        g.render(
            buf,
            Rect::new(x + 1, area.y, bar_w as u16, 1),
            look,
            app.anim_ms,
        );
        x += 1 + bar_w as u16;
    }
    let used = need(hint, elapsed, 0, count, bar);
    let mut tail = Vec::new();
    if name && let Some(n) = &p.name {
        let room = w.saturating_sub(used + 1).min(n.width());
        tail.push(Span::raw(" "));
        tail.push(Span::styled(truncate_left(n, room), look.text()));
    }
    if elapsed && let Some(e) = &p.elapsed {
        tail.push(Span::styled(format!(" · {e}"), look.dim()));
    }
    if x < area.right() {
        put(
            buf,
            Rect::new(x, area.y, area.right() - x, 1),
            &Line::from(tail),
        );
    }
    if hint && let Some(mut h) = p.hint {
        h.push(Span::raw(" "));
        put(buf, area, &Line::from(h).right_aligned());
    }
}

/// Footer hints for work that is running: the keys the busy gate holds
/// leave the footer, and the files list offers the way to stop it.
pub(crate) fn busy_hints(app: &App, ctx: &str, hints: &mut Vec<Hint>) {
    if app.busy.is_none() || app.is_picking() {
        return;
    }
    hints.retain(|h| {
        !hint_names(h.key)
            .iter()
            .all(|n| matches!(*n, "d" | "a" | "A" | "D" | "x" | "e" | "u" | "o" | "y"))
    });
    if ctx == "files" && app.can_stop() {
        hints.insert(
            0,
            Hint {
                key: "esc",
                label: "stop",
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use ratatui::style::Color;

    use crate::model::FileReport;
    use crate::tui::ui::draw_into;

    fn busy_app(work: Busy) -> App {
        let root = PathBuf::from("downloads");
        let mut app = App::new(&root);
        app.push_reports(vec![FileReport::new(root.join("game-patch.zip"), 9)]);
        app.scan_done();
        app.begin_busy(work);
        app.busy_since = 1_000;
        app.anim_ms = 15_000;
        app
    }

    fn running(app: &mut App, done: usize, total: usize, name: &str) {
        let mut a = Activity::default();
        a.begin(total, total as u64 * 10);
        for i in 0..done {
            a.item(&app.root.join(format!("f{i}")), 10);
        }
        a.end();
        a.item(&app.root.join(name), 10);
        app.activity = Some(a);
    }

    /// Draw `app` at `w` by `h` and return header row 2 and the buffer.
    fn row2(app: &mut App, look: &Look, w: u16, h: u16) -> (String, Buffer) {
        let area = Rect::new(0, 0, w, h);
        let mut buf = Buffer::empty(area);
        draw_into(&mut buf, area, app, look);
        let text = (0..w).map(|x| buf[(x, 2)].symbol().to_string()).collect();
        (text, buf)
    }

    const SIZES: [(u16, u16); 5] = [(100, 30), (80, 24), (60, 24), (40, 12), (24, 8)];

    #[test]
    fn the_activity_row_reads_right_for_each_kind() {
        let look = Look::vivid();
        let cases = [
            (Busy::Planning, "Planning 3 of 7 files"),
            (Busy::Writing, "Writing copies 3 of 7"),
            (Busy::Scrubbing, "Scrubbing 3 of 7 markers"),
            (Busy::Deleting, "Deleting 3 of 7 files"),
        ];
        for (work, head) in cases {
            let mut app = busy_app(work);
            running(&mut app, 2, 7, "game-patch.zip");
            let (wide, _) = row2(&mut app, &look, 100, 30);
            for needle in [head, "━", "─", "game-patch.zip", "· 14 s", "esc stop"] {
                assert!(wide.contains(needle), "{work:?}: {needle}\n{wide}");
            }
            for (w, h) in SIZES {
                let (text, _) = row2(&mut app, &look, w, h);
                assert!(text.contains(verb(work)), "{work:?} {w}x{h}\n{text}");
            }
            let (narrow, _) = row2(&mut app, &look, 40, 12);
            assert!(!narrow.contains("esc stop"), "{narrow}");
        }
        // An undo has no counts until it rescans, and cannot stop.
        let mut app = busy_app(Busy::Undoing);
        let (text, _) = row2(&mut app, &look, 80, 24);
        assert!(text.contains("Undoing") && text.contains("14 s"), "{text}");
        assert!(!text.contains("esc"), "{text}");
        app.on_action(crate::tui::keymap::Key::Esc);
        let (text, _) = row2(&mut app, &look, 100, 30);
        assert!(text.contains(app::MSG_UNDO_RUNS), "{text}");
        // The rescan after an edit counts files.
        let mut app = busy_app(Busy::Scrubbing);
        let mut a = Activity::default();
        a.rescan(12);
        a.item(&app.root.join("game-patch.zip"), 1);
        app.activity = Some(a);
        let (text, _) = row2(&mut app, &look, 80, 24);
        assert!(text.contains("Rescanning 1 of 12 files"), "{text}");
    }

    #[test]
    fn the_row_degrades_in_order() {
        let look = Look::vivid();
        let mut app = busy_app(Busy::Writing);
        running(&mut app, 2, 7, "game-patch.zip");
        let (w80, _) = row2(&mut app, &look, 80, 24);
        assert!(w80.contains("esc stop") && w80.contains("14 s"), "{w80}");
        let (w40, _) = row2(&mut app, &look, 40, 12);
        assert!(!w40.contains("14 s"), "{w40}");
        assert!(w40.contains("Writing copies 3 of 7"), "{w40}");
        let (w24, _) = row2(&mut app, &look, 24, 8);
        assert!(w24.contains("Writing copies"), "{w24}");
        assert!(!w24.contains("zip"), "{w24}");
    }

    #[test]
    fn stopping_and_finishing_name_the_file() {
        let look = Look::vivid();
        let mut app = busy_app(Busy::Writing);
        running(&mut app, 2, 7, "game-patch.zip");
        app.anim_ms = 22_000;
        app.on_action(crate::tui::keymap::Key::Esc);
        assert!(app.stopping);
        for (w, h) in SIZES {
            let (text, _) = row2(&mut app, &look, w, h);
            assert!(text.contains("Stopping"), "{w}x{h}\n{text}");
            assert!(!text.contains('━'), "no bar while stopping\n{text}");
        }
        let (text, _) = row2(&mut app, &look, 80, 24);
        assert!(
            text.contains("Stopping after game-patch.zip · 21 s"),
            "{text}"
        );
        app.on_action(crate::tui::keymap::Key::Quit);
        let (text, _) = row2(&mut app, &look, 100, 30);
        assert!(
            text.contains(", then quitting") && text.contains("q quit now"),
            "{text}"
        );
        app.should_quit = true;
        let (text, _) = row2(&mut app, &look, 80, 24);
        assert!(text.contains("Finishing game-patch.zip..."), "{text}");
    }

    #[test]
    fn no_color_draws_a_plain_row() {
        let mono = Look::from_flags(true, false);
        let mut app = busy_app(Busy::Writing);
        running(&mut app, 2, 7, "game-patch.zip");
        let (text, buf) = row2(&mut app, &mono, 80, 24);
        assert!(text.contains('━'), "{text}");
        for x in 0..80 {
            let c = &buf[(x, 2)];
            assert!(!matches!(c.fg, Color::Rgb(..)) && !matches!(c.bg, Color::Rgb(..)));
        }
    }

    #[test]
    fn elapsed_reads_in_plain_words() {
        assert_eq!(elapsed_text(2_500), "2 s");
        assert_eq!(elapsed_text(65_000), "1 min 5 s");
        assert_eq!(elapsed_text(3_725_000), "1 h 2 min");
    }

    #[test]
    fn busy_hints_offer_stop_and_hide_held_keys() {
        let app = busy_app(Busy::Writing);
        let mut hints = crate::tui::keymap::footer_hints("files").to_vec();
        busy_hints(&app, "files", &mut hints);
        assert_eq!((hints[0].key, hints[0].label), ("esc", "stop"));
        for held in ["d", "a", "D", "o"] {
            assert!(!hints.iter().any(|h| h.key == held), "{held}");
        }
        let mut idle = App::new("root");
        idle.scan_done();
        let mut hints = crate::tui::keymap::footer_hints("files").to_vec();
        busy_hints(&idle, "files", &mut hints);
        assert_eq!(hints.len(), crate::tui::keymap::footer_hints("files").len());
    }
}
