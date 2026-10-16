//! The thin progress bar: ratatui's [`LineGauge`], `━` filled over a `─`
//! track, spanning exactly the area it is given. Filled cells carry the
//! wordmark's rainbow, flowing left to right while work runs, and the track
//! cells under the item being worked on shimmer in the same rainbow, a sheen
//! running rightward that peaks at the wordmark's own colors; held still,
//! they lean faintly toward it. The bar keeps moving under
//! `MEOWNARY_NO_ANIM`, since its motion is the sign that work is running; it
//! turns plain under `NO_COLOR` (with the in-flight span dashed so it still
//! shows), and is never bold.
//!
//! `LineGauge` panics on a ratio outside 0..=1 and draws a percentage label
//! unless given one, and its bar starts a column after the label even when
//! the label is empty. [`Gauge`] clamps the ratio, passes an empty label, and
//! draws off to the side one column wider so the gap never reaches the view.

#![cfg(feature = "tui")]

use std::ops::Range;

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Modifier;
use ratatui::text::Line;
use ratatui::widgets::{LineGauge, Widget};

use crate::tui::theme::Look;

/// A filled cell.
pub const FILLED: &str = "━";
/// An empty track cell.
pub const TRACK: &str = "─";
/// A track cell under the item being worked on, under `NO_COLOR`.
pub const INFLIGHT: &str = "╌";

/// A one-row progress bar, drawn with [`Gauge::render`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Gauge {
    /// How much is done, in 0..=1.
    ratio: f64,
    /// The span of the item being worked on, as ordered ratios in 0..=1.
    inflight: Option<(f64, f64)>,
    /// Work is running: the colors drift and the in-flight span shimmers.
    live: bool,
}

impl Gauge {
    /// A bar `ratio` full. NaN and infinities count as empty, and anything
    /// else is clamped to 0..=1.
    pub fn new(ratio: f64) -> Self {
        Self {
            ratio: clamp_ratio(ratio),
            inflight: None,
            live: false,
        }
    }

    /// Mark the span of the item being worked on, from `from` to `to` of the
    /// whole bar, clamped like the ratio and taken in either order. Track
    /// cells inside it are drawn faintly in the fill's colors.
    pub fn inflight(mut self, from: f64, to: f64) -> Self {
        let (a, b) = (clamp_ratio(from), clamp_ratio(to));
        self.inflight = Some((a.min(b), a.max(b)));
        self
    }

    /// Whether work is running: while it is (and the view animates), the
    /// colors drift and the in-flight span shimmers.
    pub fn live(mut self, live: bool) -> Self {
        self.live = live;
        self
    }

    /// Draw the bar along the first row of `area`, every column of it a bar
    /// cell, at `anim_ms` on the view's animation clock. Only the symbol,
    /// the foreground and the modifiers change, so the background already
    /// painted there stays. A zero-size area draws nothing.
    pub fn render(&self, buf: &mut Buffer, area: Rect, look: &Look, anim_ms: u64) {
        if area.is_empty() {
            return;
        }
        let w = area.width.min(u16::MAX - 1);
        // One column wider for the gap after the empty label. The scratch bar
        // decides which cells fill; each cell then takes its style from the
        // look.
        let mut scratch = Buffer::empty(Rect::new(0, 0, w + 1, 1));
        LineGauge::default()
            .ratio(self.ratio)
            .label(Line::default())
            .filled_symbol(FILLED)
            .unfilled_symbol(TRACK)
            .render(scratch.area, &mut scratch);
        let span = self.inflight_cells(w);
        for i in 0..w {
            let Some(x) = area.x.checked_add(i) else {
                break;
            };
            let Some(cell) = buf.cell_mut((x, area.y)) else {
                continue;
            };
            let k = usize::from(i);
            let (symbol, style) = if scratch[(i + 1, 0)].symbol() == FILLED {
                (FILLED, look.gauge_fill(k, anim_ms, self.live))
            } else if span.contains(&i) {
                let symbol = if look.mono { INFLIGHT } else { TRACK };
                (symbol, look.gauge_inflight(k, anim_ms, self.live))
            } else {
                (TRACK, look.rule())
            };
            cell.set_symbol(symbol).set_style(style);
            cell.modifier.remove(Modifier::BOLD);
        }
    }

    /// The cells of a `w`-wide bar the in-flight span covers: from the cell
    /// its start falls in through the cell its end falls in, so even a
    /// sliver of the bar shows. Filled cells inside it stay filled.
    fn inflight_cells(&self, w: u16) -> Range<u16> {
        match self.inflight {
            Some((from, to)) if to > from => {
                let end = (f64::from(w) * to).ceil() as u16;
                filled_cells(w, from)..end.min(w)
            }
            _ => 0..0,
        }
    }
}

/// How many of `bar_w` cells a bar `ratio` full fills: the floor formula
/// `LineGauge` itself uses, with `ratio` clamped like [`Gauge::new`].
pub fn filled_cells(bar_w: u16, ratio: f64) -> u16 {
    (f64::from(bar_w) * clamp_ratio(ratio)).floor() as u16
}

/// NaN and infinities become 0; anything else is clamped to 0..=1.
fn clamp_ratio(ratio: f64) -> f64 {
    if ratio.is_finite() {
        ratio.clamp(0.0, 1.0)
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::style::Color;

    /// `g` drawn into a fresh one-row buffer `w` wide, at `t_ms`.
    fn draw(g: Gauge, w: u16, look: &Look, t_ms: u64) -> Buffer {
        let area = Rect::new(0, 0, w, 1);
        let mut buf = Buffer::empty(area);
        g.render(&mut buf, area, look, t_ms);
        buf
    }

    fn symbols(buf: &Buffer) -> String {
        buf.content().iter().map(|c| c.symbol()).collect()
    }

    #[test]
    fn ratios_are_clamped_and_nan_is_empty() {
        let cases = [
            (0.25, 0.25),
            (-0.5, 0.0),
            (1.5, 1.0),
            (f64::NAN, 0.0),
            (f64::INFINITY, 0.0),
            (f64::NEG_INFINITY, 0.0),
        ];
        for (given, want) in cases {
            assert_eq!(Gauge::new(given).ratio, want, "{given}");
        }
        let g = Gauge::new(0.5).inflight(0.9, f64::NAN);
        assert_eq!(g.inflight, Some((0.0, 0.9)), "clamped and ordered");
        let g = Gauge::new(0.5).inflight(2.0, 0.6);
        assert_eq!(g.inflight, Some((0.6, 1.0)));
        // None of them reaches LineGauge's panic.
        for r in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0, 2.0] {
            let g = Gauge::new(r).inflight(r, -r).live(true);
            draw(g, 8, &Look::vivid(), 5);
        }
    }

    #[test]
    fn the_bar_fills_the_area_with_no_label_or_gap() {
        let look = Look::vivid();
        assert_eq!(symbols(&draw(Gauge::new(0.0), 6, &look, 0)), "──────");
        assert_eq!(symbols(&draw(Gauge::new(0.5), 6, &look, 0)), "━━━───");
        assert_eq!(symbols(&draw(Gauge::new(1.0), 6, &look, 0)), "━━━━━━");
        // Inside a bigger buffer the first column of the area is already
        // bar, and only the first row of a taller area is drawn.
        let mut buf = Buffer::empty(Rect::new(0, 0, 12, 3));
        Gauge::new(0.5).render(&mut buf, Rect::new(3, 1, 6, 2), &look, 0);
        let row = |y: u16| -> String { (0..12).map(|x| buf[(x, y)].symbol()).collect() };
        assert_eq!(row(0), " ".repeat(12));
        assert_eq!(row(1), "   ━━━───   ");
        assert_eq!(row(2), " ".repeat(12));
        assert!(!symbols(&buf).contains('%'));
    }

    #[test]
    fn filled_cells_matches_what_is_drawn() {
        let ratios = [0.0, 0.01, 0.1, 0.3, 1.0 / 3.0, 0.5, 0.7, 0.99, 0.999, 1.0];
        for w in 0..=41 {
            for r in ratios {
                let buf = draw(Gauge::new(r), w, &Look::vivid(), 0);
                let drawn = symbols(&buf).matches(FILLED).count();
                assert_eq!(drawn, usize::from(filled_cells(w, r)), "{w} cells at {r}");
            }
        }
        assert_eq!(filled_cells(10, f64::NAN), 0);
        assert_eq!(filled_cells(10, 7.0), 10);
        assert_eq!(filled_cells(10, -7.0), 0);
    }

    #[test]
    fn filled_cells_carry_distinct_pastels() {
        let buf = draw(Gauge::new(1.0), 20, &Look::vivid(), 0);
        let mut seen = Vec::new();
        for cell in buf.content() {
            assert!(matches!(cell.fg, Color::Rgb(..)), "{:?}", cell.fg);
            assert!(!seen.contains(&cell.fg), "{:?} repeats", cell.fg);
            seen.push(cell.fg);
        }
    }

    #[test]
    fn no_color_draws_a_plain_bar() {
        let mono = Look::from_flags(true, false);
        let g = Gauge::new(0.25).inflight(0.25, 0.5).live(true);
        let buf = draw(g, 20, &mono, 1234);
        for cell in buf.content() {
            let rgb = |c: Color| matches!(c, Color::Rgb(..));
            assert!(!rgb(cell.fg) && !rgb(cell.bg), "{cell:?}");
        }
        assert_eq!(symbols(&buf), "━━━━━╌╌╌╌╌──────────");
    }

    #[test]
    fn a_running_bar_moves_even_without_animation() {
        let still = Look::from_flags(false, true);
        let g = Gauge::new(0.5).inflight(0.5, 0.75).live(true);
        assert_ne!(draw(g, 20, &still, 0), draw(g, 20, &still, 900));
        // A bar with no work running holds still even when the view animates.
        let idle = Gauge::new(0.5).inflight(0.5, 0.75);
        let look = Look::vivid();
        assert_eq!(draw(idle, 20, &look, 0), draw(idle, 20, &look, 4321));
    }

    #[test]
    fn live_bars_drift_and_shimmer() {
        let look = Look::vivid();
        let g = Gauge::new(0.5).inflight(0.5, 0.75).live(true);
        let (a, b) = (draw(g, 20, &look, 0), draw(g, 20, &look, 800));
        for x in 0..15 {
            assert_ne!(a[(x, 0)].fg, b[(x, 0)].fg, "filled and in-flight cell {x}");
        }
        for x in 15..20 {
            assert_eq!(a[(x, 0)], b[(x, 0)], "plain track cell {x}");
        }
    }

    #[test]
    fn inflight_cells_stand_out_from_the_track() {
        let look = Look::vivid();
        let track = look.rule().fg;
        let buf = draw(Gauge::new(0.25).inflight(0.25, 0.5), 20, &look, 0);
        for x in 0..20 {
            let cell = &buf[(x, 0)];
            if x < 5 {
                assert_eq!(cell.symbol(), FILLED, "cell {x}");
            } else if x < 10 {
                assert_eq!(cell.symbol(), TRACK, "cell {x}");
                assert_ne!(Some(cell.fg), track, "cell {x}");
            } else {
                assert_eq!(cell.symbol(), TRACK, "cell {x}");
                assert_eq!(Some(cell.fg), track, "cell {x}");
            }
        }
        let lit = |b: &Buffer| {
            let track_cell = |c: &&ratatui::buffer::Cell| c.symbol() == TRACK;
            let iter = b.content().iter().filter(track_cell);
            iter.filter(|c| Some(c.fg) != track).count()
        };
        // A sliver still shows as one cell, and an empty span as none.
        assert_eq!(
            lit(&draw(Gauge::new(0.5).inflight(0.5, 0.51), 20, &look, 0)),
            1
        );
        assert_eq!(
            lit(&draw(Gauge::new(0.5).inflight(0.5, 0.5), 20, &look, 0)),
            0
        );
        // A span reaching back over the fill leaves the filled cells filled.
        let over = draw(Gauge::new(0.5).inflight(0.0, 0.75), 20, &look, 0);
        assert_eq!(symbols(&over).matches(FILLED).count(), 10);
        assert_eq!(lit(&over), 5);
        // Under NO_COLOR the span is dashed instead.
        let mono = Look::from_flags(true, false);
        let dashed = draw(Gauge::new(0.25).inflight(0.25, 0.5), 20, &mono, 0);
        assert_eq!(symbols(&dashed), "━━━━━╌╌╌╌╌──────────");
    }

    #[test]
    fn the_bar_is_never_bold_and_keeps_the_background() {
        let looks = [
            Look::vivid(),
            Look::from_flags(false, true),
            Look::from_flags(true, false),
        ];
        for look in looks {
            let area = Rect::new(0, 0, 16, 1);
            let mut buf = Buffer::empty(area);
            buf.set_style(area, look.base().add_modifier(Modifier::BOLD));
            let g = Gauge::new(0.5).inflight(0.5, 0.75).live(true);
            g.render(&mut buf, area, &look, 99);
            let bg = look.base().bg.unwrap_or(Color::Reset);
            for cell in buf.content() {
                assert!(!cell.modifier.contains(Modifier::BOLD), "{cell:?}");
                assert_eq!(cell.bg, bg, "{cell:?}");
            }
        }
    }

    #[test]
    fn tiny_and_empty_areas_are_safe() {
        let look = Look::vivid();
        for w in 0..=3 {
            for h in 0..=2 {
                for r in [0.0, 0.5, 1.0, f64::NAN] {
                    let mut buf = Buffer::empty(Rect::new(0, 0, 4, 3));
                    let blank = buf.clone();
                    let g = Gauge::new(r).inflight(0.0, 1.0).live(true);
                    g.render(&mut buf, Rect::new(0, 0, w, h), &look, 7);
                    let changed = buf
                        .content()
                        .iter()
                        .zip(blank.content())
                        .filter(|(a, b)| a != b)
                        .count();
                    let want = if h == 0 { 0 } else { usize::from(w) };
                    assert_eq!(changed, want, "{w}x{h} at {r}");
                }
            }
        }
        // An area hanging off the buffer draws only the part inside it.
        let mut buf = Buffer::empty(Rect::new(0, 0, 4, 1));
        Gauge::new(1.0).render(&mut buf, Rect::new(2, 0, 10, 1), &look, 0);
        assert_eq!(symbols(&buf), "  ━━");
        Gauge::new(1.0).render(&mut buf, Rect::new(0, 5, 10, 1), &look, 0);
        assert_eq!(symbols(&buf), "  ━━");
    }
}
