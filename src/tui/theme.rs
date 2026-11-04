//! The deep-violet palette, shared across every view, plus the rainbow math
//! behind the animated wordmark and the progress bars.
//!
//! Colors live in a [`Palette`] so the whole view can drop to the terminal's
//! default colors when `NO_COLOR` is set; [`Look`] bundles the palette with
//! the animation switch and turns it into ready-made styles, so render code
//! never picks raw colors. The plain constants below are the identity colors
//! the palette is built from.

#![cfg(feature = "tui")]

use ratatui::style::{Color, Modifier, Style};

use crate::model::{Confidence, Severity};

/// The view's own background, painted under everything: a deep violet,
/// warmer than blue-black and well short of plum.
pub const BG: Color = Color::Rgb(0x12, 0x0a, 0x1a);
/// Primary text.
pub const TEXT: Color = Color::Rgb(0xed, 0xe7, 0xfb);
/// Secondary text: readable, clearly below the primary text.
pub const DIM: Color = Color::Rgb(0xab, 0x9f, 0xcf);
/// Faint text: tips, zero bytes, weak findings.
pub const RULE: Color = Color::Rgb(0x7d, 0x71, 0x9c);
/// Unfocused borders, rules and the empty track of a progress bar.
pub const BORDER: Color = Color::Rgb(0x41, 0x30, 0x5c);
/// Vivid violet for whatever has focus: the active pane's border and title.
pub const FOCUS: Color = Color::Rgb(0xb4, 0x8c, 0xff);
/// The violet accent: signature ids, keys, folder names.
pub const ACCENT: Color = Color::Rgb(0x9d, 0x7b, 0xff);
/// Lavender highlight: group titles, the notice severity.
pub const BRIGHT: Color = Color::Rgb(0xd8, 0xbf, 0xff);
/// Rose pink, the second accent: selection marks, removable tags, the hex
/// marker.
pub const PINK: Color = Color::Rgb(0xf7, 0x9a, 0xd3);
/// The cursor row in a focused pane.
pub const TINT: Color = Color::Rgb(0x2e, 0x1d, 0x48);
/// The cursor row in an unfocused pane.
pub const TINT_DIM: Color = Color::Rgb(0x1f, 0x14, 0x31);
pub const GOOD: Color = Color::Rgb(0x6e, 0xe7, 0xa8);
pub const WARN: Color = Color::Rgb(0xf7, 0xc3, 0x5f);
pub const BAD: Color = Color::Rgb(0xff, 0x5c, 0x7c);
/// Calm blue for informational facts.
pub const INFO: Color = Color::Rgb(0x7f, 0xb8, 0xff);
/// Soft chip backgrounds: a filled chip that stays quiet.
pub const CHIP_INFO_BG: Color = Color::Rgb(0x17, 0x25, 0x40);
pub const CHIP_NOTICE_BG: Color = Color::Rgb(0x2f, 0x21, 0x54);
pub const CHIP_GOOD_BG: Color = Color::Rgb(0x16, 0x31, 0x25);
pub const CHIP_WARN_BG: Color = Color::Rgb(0x3a, 0x2d, 0x14);

/// Interpolate between two RGB colors (t in 0..=1). Non-RGB inputs return `a`.
pub fn lerp(a: Color, b: Color, t: f32) -> Color {
    if let (Color::Rgb(ar, ag, ab), Color::Rgb(br, bg, bb)) = (a, b) {
        let t = t.clamp(0.0, 1.0);
        let m = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t).round() as u8;
        Color::Rgb(m(ar, br), m(ag, bg), m(ab, bb))
    } else {
        a
    }
}

// ---- the wordmark and the bars ---------------------------------------------

/// Two-stop gradient for the wordmark.
pub const ACCENT_RAMP: [Color; 2] = [ACCENT, BRIGHT];

/// One full trip around the color wheel for the wordmark, in milliseconds.
pub const RAINBOW_CYCLE_MS: u64 = 3500;
/// Hue distance between neighbouring rainbow letters, in degrees.
pub const RAINBOW_STEP_DEG: f32 = 40.0;
/// Saturation and value of the rainbow letters.
pub const RAINBOW_SAT: f32 = 0.75;
pub const RAINBOW_VAL: f32 = 1.0;

/// The hue (degrees, 0..360) of rainbow letter `i` at time `t_ms`. The base
/// hue advances one full turn every [`RAINBOW_CYCLE_MS`], and each letter
/// trails its left neighbour by [`RAINBOW_STEP_DEG`], so the colors flow
/// left to right.
pub fn rainbow_hue(i: usize, t_ms: u64) -> f32 {
    let base = (t_ms % RAINBOW_CYCLE_MS) as f32 * 360.0 / RAINBOW_CYCLE_MS as f32;
    (base - i as f32 * RAINBOW_STEP_DEG).rem_euclid(360.0)
}

/// HSV (hue in degrees, saturation and value in 0..=1) to 8-bit RGB.
pub fn hsv_to_rgb(h: f32, s: f32, v: f32) -> (u8, u8, u8) {
    let h = h.rem_euclid(360.0);
    let s = s.clamp(0.0, 1.0);
    let v = v.clamp(0.0, 1.0);
    let c = v * s;
    let hp = h / 60.0;
    let x = c * (1.0 - (hp % 2.0 - 1.0).abs());
    let (r, g, b) = match hp as u32 {
        0 => (c, x, 0.0),
        1 => (x, c, 0.0),
        2 => (0.0, c, x),
        3 => (0.0, x, c),
        4 => (x, 0.0, c),
        _ => (c, 0.0, x),
    };
    let m = v - c;
    let to8 = |f: f32| ((f + m) * 255.0).round().clamp(0.0, 255.0) as u8;
    (to8(r), to8(g), to8(b))
}

/// The color of rainbow letter `i` at time `t_ms`.
pub fn rainbow_color(i: usize, t_ms: u64) -> Color {
    let (r, g, b) = hsv_to_rgb(rainbow_hue(i, t_ms), RAINBOW_SAT, RAINBOW_VAL);
    Color::Rgb(r, g, b)
}

/// Saturation and value of the progress bar's rainbow: the wordmark's own.
pub const GAUGE_SAT: f32 = RAINBOW_SAT;
pub const GAUGE_VAL: f32 = RAINBOW_VAL;
/// Hue distance between neighbouring cells of a progress bar, in degrees:
/// a 24-cell bar holds one whole rainbow.
pub const GAUGE_STEP_DEG: f32 = 15.0;
/// One full turn of the progress bar's flow while work runs, in
/// milliseconds: the wordmark's cycle, so the two move together.
pub const GAUGE_CYCLE_MS: u64 = RAINBOW_CYCLE_MS;
/// How far an in-flight cell leans from the track toward its pastel when
/// the bar holds still.
pub const GAUGE_INFLIGHT_MIX: f32 = 0.35;
/// The range in-flight cells shimmer through while work runs: at the crest
/// a cell wears the wordmark's own color.
pub const GAUGE_SHIMMER: (f32, f32) = (0.55, 1.0);
/// One full shimmer of an in-flight cell, in milliseconds.
pub const GAUGE_SHIMMER_MS: u64 = 1600;
/// How many cells apart the shimmer's crests run.
pub const GAUGE_SHIMMER_CELLS: usize = 8;

/// The hue (degrees, 0..360) of progress bar cell `i` at time `t_ms`. Each
/// cell trails its left neighbour by [`GAUGE_STEP_DEG`], and the whole ramp
/// turns once every [`GAUGE_CYCLE_MS`], so the colors flow left to right
/// with the progress, the way the wordmark's do.
pub fn gauge_hue(i: usize, t_ms: u64) -> f32 {
    let base = (t_ms % GAUGE_CYCLE_MS) as f32 * 360.0 / GAUGE_CYCLE_MS as f32;
    (base - i as f32 * GAUGE_STEP_DEG).rem_euclid(360.0)
}

/// The pastel of progress bar cell `i` at time `t_ms`.
pub fn gauge_color(i: usize, t_ms: u64) -> Color {
    let (r, g, b) = hsv_to_rgb(gauge_hue(i, t_ms), GAUGE_SAT, GAUGE_VAL);
    Color::Rgb(r, g, b)
}

/// How far in-flight cell `i` leans toward its color at `t_ms`: a swell from
/// the low end of [`GAUGE_SHIMMER`] to the high end and back once every
/// [`GAUGE_SHIMMER_MS`], each cell a step behind its left neighbour, so a
/// sheen runs rightward through the wordmark's rainbow.
pub fn gauge_shimmer(i: usize, t_ms: u64) -> f32 {
    let phase = (t_ms % GAUGE_SHIMMER_MS) as f32 / GAUGE_SHIMMER_MS as f32
        - (i % GAUGE_SHIMMER_CELLS) as f32 / GAUGE_SHIMMER_CELLS as f32;
    let swell = 0.5 - 0.5 * (phase * std::f32::consts::TAU).cos();
    let (lo, hi) = GAUGE_SHIMMER;
    lo + (hi - lo) * swell
}

/// Every color the view uses. [`Palette::mono`] maps all of them to the
/// terminal default, for `NO_COLOR`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Palette {
    pub bg: Color,
    pub text: Color,
    pub dim: Color,
    pub faint: Color,
    pub accent: Color,
    pub bright: Color,
    pub pink: Color,
    pub focus: Color,
    pub tint: Color,
    pub tint_dim: Color,
    pub border: Color,
    pub good: Color,
    pub warn: Color,
    pub bad: Color,
    pub info: Color,
    pub chip_info: Color,
    pub chip_notice: Color,
    pub chip_good: Color,
    pub chip_warn: Color,
}

impl Palette {
    /// The deep-violet identity with vivid accents.
    pub const fn vivid() -> Self {
        Self {
            bg: BG,
            text: TEXT,
            dim: DIM,
            faint: RULE,
            accent: ACCENT,
            bright: BRIGHT,
            pink: PINK,
            focus: FOCUS,
            tint: TINT,
            tint_dim: TINT_DIM,
            border: BORDER,
            good: GOOD,
            warn: WARN,
            bad: BAD,
            info: INFO,
            chip_info: CHIP_INFO_BG,
            chip_notice: CHIP_NOTICE_BG,
            chip_good: CHIP_GOOD_BG,
            chip_warn: CHIP_WARN_BG,
        }
    }

    /// Terminal defaults everywhere.
    pub const fn mono() -> Self {
        let r = Color::Reset;
        Self {
            bg: r,
            text: r,
            dim: r,
            faint: r,
            accent: r,
            bright: r,
            pink: r,
            focus: r,
            tint: r,
            tint_dim: r,
            border: r,
            good: r,
            warn: r,
            bad: r,
            info: r,
            chip_info: r,
            chip_notice: r,
            chip_good: r,
            chip_warn: r,
        }
    }
}

/// The tone of a status message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Info,
    Good,
    Warn,
    Bad,
}

/// Palette plus switches, turned into styles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Look {
    pub p: Palette,
    /// `NO_COLOR`: no colors at all, hierarchy from modifiers alone.
    pub mono: bool,
    /// Whether the wordmark and the progress bars animate (otherwise they
    /// hold their first frame).
    pub animate: bool,
}

impl Look {
    /// The full-color, animated look.
    pub const fn vivid() -> Self {
        Self {
            p: Palette::vivid(),
            mono: false,
            animate: true,
        }
    }

    /// Read `NO_COLOR` and `MEOWNARY_NO_ANIM` (each counts when set and not
    /// empty).
    pub fn from_env() -> Self {
        let set = |k: &str| std::env::var_os(k).is_some_and(|v| !v.is_empty());
        Self::from_flags(set("NO_COLOR"), set("MEOWNARY_NO_ANIM"))
    }

    /// The look for the given switches.
    pub const fn from_flags(no_color: bool, no_anim: bool) -> Self {
        if no_color {
            Self {
                p: Palette::mono(),
                mono: true,
                animate: false,
            }
        } else {
            Self {
                p: Palette::vivid(),
                mono: false,
                animate: !no_anim,
            }
        }
    }

    fn fg(&self, c: Color) -> Style {
        if self.mono {
            Style::new()
        } else {
            Style::new().fg(c)
        }
    }

    /// The painted background of the whole view.
    pub fn base(&self) -> Style {
        if self.mono {
            Style::new()
        } else {
            Style::new().bg(self.p.bg).fg(self.p.text)
        }
    }

    pub fn text(&self) -> Style {
        self.fg(self.p.text)
    }

    pub fn strong(&self) -> Style {
        self.fg(self.p.text).add_modifier(Modifier::BOLD)
    }

    pub fn dim(&self) -> Style {
        if self.mono {
            Style::new().add_modifier(Modifier::DIM)
        } else {
            self.fg(self.p.dim)
        }
    }

    pub fn faint(&self) -> Style {
        if self.mono {
            Style::new().add_modifier(Modifier::DIM)
        } else {
            self.fg(self.p.faint)
        }
    }

    pub fn accent(&self) -> Style {
        self.fg(self.p.accent)
    }

    pub fn bright(&self) -> Style {
        self.fg(self.p.bright).add_modifier(Modifier::BOLD)
    }

    pub fn pink(&self) -> Style {
        self.fg(self.p.pink).add_modifier(Modifier::BOLD)
    }

    pub fn good(&self) -> Style {
        self.fg(self.p.good)
    }

    pub fn tone(&self, t: Tone) -> Style {
        match t {
            Tone::Info => self.fg(self.p.bright),
            Tone::Good => self.fg(self.p.good).add_modifier(Modifier::BOLD),
            Tone::Warn => self.fg(self.p.warn).add_modifier(Modifier::BOLD),
            Tone::Bad => self.fg(self.p.bad).add_modifier(Modifier::BOLD),
        }
    }

    /// The mark a status line leads with when its outcome matters: a check
    /// for a good one, a cross for a failure. Plain messages and warnings
    /// carry only their color.
    pub fn tone_glyph(&self, t: Tone) -> &'static str {
        match t {
            Tone::Info | Tone::Warn => "",
            Tone::Good => "✓ ",
            Tone::Bad => "✗ ",
        }
    }

    /// Pane border: pops in the vivid focus violet when focused.
    pub fn border(&self, focused: bool) -> Style {
        match (self.mono, focused) {
            (true, true) => Style::new().add_modifier(Modifier::BOLD),
            (true, false) => Style::new().add_modifier(Modifier::DIM),
            (false, true) => Style::new().fg(self.p.focus).add_modifier(Modifier::BOLD),
            (false, false) => Style::new().fg(self.p.border),
        }
    }

    /// Pane title: bold in the focus violet when focused, dim otherwise.
    pub fn title(&self, focused: bool) -> Style {
        match (self.mono, focused) {
            (true, true) => Style::new().add_modifier(Modifier::BOLD),
            (true, false) => Style::new().add_modifier(Modifier::DIM),
            (false, true) => Style::new().fg(self.p.focus).add_modifier(Modifier::BOLD),
            (false, false) => Style::new().fg(self.p.dim),
        }
    }

    /// The cursor row: a soft tint, stronger in the focused pane.
    pub fn cursor_row(&self, focused: bool) -> Style {
        match (self.mono, focused) {
            (true, true) => Style::new().add_modifier(Modifier::REVERSED),
            (true, false) => Style::new().add_modifier(Modifier::UNDERLINED),
            (false, true) => Style::new().bg(self.p.tint),
            (false, false) => Style::new().bg(self.p.tint_dim),
        }
    }

    /// The thin bar at the left edge of the cursor row.
    pub fn cursor_mark(&self, focused: bool) -> Style {
        match (self.mono, focused) {
            (true, _) => Style::new().add_modifier(Modifier::BOLD),
            (false, true) => Style::new().fg(self.p.focus).add_modifier(Modifier::BOLD),
            (false, false) => Style::new().fg(self.p.border),
        }
    }

    pub fn severity(&self, s: Severity) -> Style {
        self.fg(self.sev_color(s))
    }

    fn sev_color(&self, s: Severity) -> Color {
        match s {
            Severity::Info => self.p.info,
            Severity::Notice => self.p.bright,
            Severity::Warn => self.p.warn,
            Severity::Alert => self.p.bad,
        }
    }

    /// A filled severity chip: soft for info/notice, solid for warn/alert.
    pub fn severity_chip(&self, s: Severity) -> Style {
        if self.mono {
            return match s {
                Severity::Info | Severity::Notice => Style::new(),
                Severity::Warn | Severity::Alert => {
                    Style::new().add_modifier(Modifier::REVERSED | Modifier::BOLD)
                }
            };
        }
        match s {
            Severity::Info => Style::new().fg(self.p.info).bg(self.p.chip_info),
            Severity::Notice => Style::new().fg(self.p.bright).bg(self.p.chip_notice),
            Severity::Warn => Style::new()
                .fg(self.p.bg)
                .bg(self.p.warn)
                .add_modifier(Modifier::BOLD),
            Severity::Alert => Style::new()
                .fg(self.p.bg)
                .bg(self.p.bad)
                .add_modifier(Modifier::BOLD),
        }
    }

    pub fn confidence(&self, c: Confidence) -> Style {
        let base = match c {
            Confidence::Strong => self.fg(self.p.good),
            Confidence::Moderate => self.fg(self.p.warn),
            Confidence::Weak => self.faint(),
        };
        base.add_modifier(Modifier::BOLD)
    }

    /// A key name in the footer, the help or a modal: bright and bold, with
    /// no fill, so a row of them reads as words rather than buttons.
    pub fn key(&self) -> Style {
        if self.mono {
            Style::new().add_modifier(Modifier::BOLD)
        } else {
            Style::new().fg(self.p.bright).add_modifier(Modifier::BOLD)
        }
    }

    /// A key that moves or shows rather than acts: bold but quiet, so the
    /// action keys beside it read first.
    pub fn key_dim(&self) -> Style {
        if self.mono {
            Style::new().add_modifier(Modifier::BOLD | Modifier::DIM)
        } else {
            Style::new().fg(self.p.dim).add_modifier(Modifier::BOLD)
        }
    }

    /// A solid chip carrying a verdict or a count.
    pub fn chip(&self, t: Tone) -> Style {
        if self.mono {
            return Style::new().add_modifier(Modifier::REVERSED);
        }
        let bg = match t {
            Tone::Info => self.p.bright,
            Tone::Good => self.p.good,
            Tone::Warn => self.p.warn,
            Tone::Bad => self.p.bad,
        };
        Style::new()
            .fg(self.p.bg)
            .bg(bg)
            .add_modifier(Modifier::BOLD)
    }

    /// A soft chip: the tone's color on a dark wash of it, for marks that
    /// should be seen without shouting (saved files, notice counts).
    pub fn soft_chip(&self, t: Tone) -> Style {
        if self.mono {
            return Style::new().add_modifier(Modifier::BOLD | Modifier::UNDERLINED);
        }
        let (fg, bg) = match t {
            Tone::Info => (self.p.info, self.p.chip_info),
            Tone::Good => (self.p.good, self.p.chip_good),
            Tone::Warn => (self.p.warn, self.p.chip_warn),
            Tone::Bad => (self.p.bright, self.p.chip_notice),
        };
        Style::new().fg(fg).bg(bg).add_modifier(Modifier::BOLD)
    }

    /// Labels in front of detail fields and section titles in the help.
    pub fn label(&self) -> Style {
        self.dim()
    }

    /// Thin rules and separators.
    pub fn rule(&self) -> Style {
        if self.mono {
            Style::new().add_modifier(Modifier::DIM)
        } else {
            Style::new().fg(self.p.border)
        }
    }

    /// Fade a color toward the background, for the backdrop behind a modal.
    pub fn fade(&self, c: Color) -> Color {
        match c {
            Color::Rgb(..) => lerp(c, self.p.bg, 0.6),
            _ => self.p.faint,
        }
    }

    /// The marker region inside the hex dump.
    pub fn hex_marker(&self) -> Style {
        if self.mono {
            Style::new().add_modifier(Modifier::REVERSED)
        } else {
            Style::new()
                .fg(self.p.bg)
                .bg(self.p.pink)
                .add_modifier(Modifier::BOLD)
        }
    }

    /// Evidence bytes inside the hex dump (outside the marker region).
    pub fn hex_evidence(&self) -> Style {
        self.fg(self.p.bright)
            .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
    }

    /// The color of wordmark letter `i` of "meow" at `t_ms`.
    pub fn rainbow(&self, i: usize, t_ms: u64) -> Style {
        if self.mono {
            return Style::new().add_modifier(Modifier::BOLD);
        }
        let t = if self.animate { t_ms } else { 0 };
        Style::new()
            .fg(rainbow_color(i, t))
            .add_modifier(Modifier::BOLD)
    }

    /// The pastel gradient for the rest of the wordmark, letter `i` of `n`.
    pub fn gradient(&self, i: usize, n: usize) -> Style {
        if self.mono {
            return Style::new().add_modifier(Modifier::BOLD);
        }
        let t = if n <= 1 {
            0.0
        } else {
            i as f32 / (n - 1) as f32
        };
        Style::new()
            .fg(lerp(ACCENT_RAMP[0], ACCENT_RAMP[1], t))
            .add_modifier(Modifier::BOLD)
    }

    /// The clock a progress bar runs on: the frame time while `live` work
    /// runs, otherwise held at the start. A bar moves while work runs even
    /// under `MEOWNARY_NO_ANIM`: its motion is how the view says it is
    /// working.
    fn gauge_clock(&self, t_ms: u64, live: bool) -> u64 {
        if live { t_ms } else { 0 }
    }

    /// Filled cell `i` of a progress bar: the wordmark's rainbow, flowing
    /// while `live` work runs. Plain under `NO_COLOR`, and never bold.
    pub fn gauge_fill(&self, i: usize, t_ms: u64, live: bool) -> Style {
        if self.mono {
            return Style::new();
        }
        Style::new().fg(gauge_color(i, self.gauge_clock(t_ms, live)))
    }

    /// Track cell `i` of a progress bar inside the span of the item being
    /// worked on: the track color leaning toward that cell's color, a fixed
    /// step when idle, and while `live` work runs a sheen through the
    /// wordmark's rainbow that peaks at the wordmark's own colors. Under
    /// `NO_COLOR` it is the plain track, and the bar marks the span with a
    /// dashed symbol instead.
    pub fn gauge_inflight(&self, i: usize, t_ms: u64, live: bool) -> Style {
        if self.mono {
            return self.rule();
        }
        let t = self.gauge_clock(t_ms, live);
        let mix = if live {
            gauge_shimmer(i, t)
        } else {
            GAUGE_INFLIGHT_MIX
        };
        Style::new().fg(lerp(self.p.border, gauge_color(i, t), mix))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lerp_runs_between_its_ends() {
        let a = Color::Rgb(0, 0, 0);
        let b = Color::Rgb(200, 100, 50);
        assert_eq!(lerp(a, b, 0.0), a);
        assert_eq!(lerp(a, b, 1.0), b);
        assert_eq!(lerp(a, b, 0.5), Color::Rgb(100, 50, 25));
        assert_eq!(lerp(a, b, 7.0), b, "clamped");
        assert_eq!(lerp(Color::Reset, b, 0.5), Color::Reset);
    }

    #[test]
    fn hsv_primaries() {
        assert_eq!(hsv_to_rgb(0.0, 1.0, 1.0), (255, 0, 0));
        assert_eq!(hsv_to_rgb(120.0, 1.0, 1.0), (0, 255, 0));
        assert_eq!(hsv_to_rgb(240.0, 1.0, 1.0), (0, 0, 255));
        assert_eq!(hsv_to_rgb(360.0, 1.0, 1.0), (255, 0, 0));
        assert_eq!(hsv_to_rgb(60.0, 0.75, 1.0), (255, 255, 64));
        assert_eq!(hsv_to_rgb(200.0, 0.0, 1.0), (255, 255, 255));
    }

    #[test]
    fn rainbow_offsets_and_cycle() {
        assert_eq!(rainbow_hue(0, 0), 0.0);
        assert_eq!(rainbow_hue(1, 0), 320.0);
        assert_eq!(rainbow_hue(3, 0), 240.0);
        // A quarter cycle later every letter has moved 90 degrees.
        let q = RAINBOW_CYCLE_MS / 4;
        assert!((rainbow_hue(0, q) - 90.0).abs() < 1e-3);
        assert!((rainbow_hue(2, q) - 10.0).abs() < 1e-3);
        // A full cycle comes back to the start.
        assert_eq!(rainbow_hue(2, RAINBOW_CYCLE_MS), rainbow_hue(2, 0));
        for i in 0..8 {
            for t in [0, 17, 999, 3599, 123_456] {
                let h = rainbow_hue(i, t);
                assert!((0.0..360.0).contains(&h), "{h}");
            }
        }
    }

    #[test]
    fn rainbow_is_vivid_and_static_without_animation() {
        match rainbow_color(0, 0) {
            Color::Rgb(r, g, b) => assert_eq!((r, g, b), (255, 64, 64)),
            other => panic!("{other:?}"),
        }
        let still = Look::from_flags(false, true);
        assert_eq!(still.rainbow(1, 0), still.rainbow(1, 1800));
        let live = Look::vivid();
        assert_ne!(live.rainbow(1, 0), live.rainbow(1, 1800));
        assert_eq!(live.gradient(0, 4).fg, Some(ACCENT));
        assert_eq!(live.gradient(3, 4).fg, Some(BRIGHT));
    }

    #[test]
    fn gauge_ramp_steps_drifts_and_shimmers() {
        assert_eq!(gauge_hue(0, 0), 0.0);
        assert_eq!(gauge_hue(3, 0), 315.0);
        assert_eq!(gauge_hue(24, 0), 0.0, "24 cells make a full turn");
        // A quarter cycle later every cell has moved 90 degrees.
        let q = GAUGE_CYCLE_MS / 4;
        assert!((gauge_hue(0, q) - 90.0).abs() < 1e-2);
        assert!((gauge_hue(3, q) - 45.0).abs() < 1e-2);
        // The bar wears the wordmark's colors and keeps its time.
        assert_eq!(GAUGE_CYCLE_MS, RAINBOW_CYCLE_MS);
        assert_eq!(gauge_color(0, 0), rainbow_color(0, 0));
        // The colors flow rightward: a hue reaches the next cell later.
        let step_ms = (GAUGE_STEP_DEG / 360.0 * GAUGE_CYCLE_MS as f32) as u64;
        assert!((gauge_hue(4, step_ms) - gauge_hue(3, 0)).abs() < 0.5);
        assert_eq!(gauge_hue(5, GAUGE_CYCLE_MS), gauge_hue(5, 0));
        // The shimmer swells from the low end to the wordmark's own color and
        // back, and its crest reaches the next cell later: a sheen running
        // rightward.
        let (lo, hi) = GAUGE_SHIMMER;
        assert_eq!(hi, 1.0);
        assert!((gauge_shimmer(0, 0) - lo).abs() < 1e-6);
        assert!((gauge_shimmer(0, GAUGE_SHIMMER_MS / 2) - hi).abs() < 1e-6);
        assert_eq!(gauge_shimmer(0, GAUGE_SHIMMER_MS), gauge_shimmer(0, 0));
        let cell_ms = GAUGE_SHIMMER_MS / GAUGE_SHIMMER_CELLS as u64;
        assert!((gauge_shimmer(1, GAUGE_SHIMMER_MS / 2 + cell_ms) - hi).abs() < 1e-6);
        assert_eq!(
            gauge_shimmer(GAUGE_SHIMMER_CELLS, 300),
            gauge_shimmer(0, 300)
        );
        for i in [0, 1, 7, 8, 23] {
            for t in [1, 399, 800, 1201, 1599, 123_457] {
                let s = gauge_shimmer(i, t);
                assert!((lo..=hi).contains(&s), "{s}");
            }
        }
        // At the crest an in-flight cell wears exactly the filled color.
        let look = Look::vivid();
        let crest = GAUGE_SHIMMER_MS / 2;
        assert_eq!(
            look.gauge_inflight(0, crest, true).fg,
            look.gauge_fill(0, crest, true).fg
        );
    }

    #[test]
    fn gauge_styles_follow_the_switches() {
        let live = Look::vivid();
        assert_ne!(live.gauge_fill(2, 0, true), live.gauge_fill(2, 2000, true));
        assert_eq!(
            live.gauge_fill(2, 0, false),
            live.gauge_fill(2, 2000, false),
            "an idle bar holds still"
        );
        // MEOWNARY_NO_ANIM stills the wordmark, never a bar with work running.
        let still = Look::from_flags(false, true);
        assert_ne!(
            still.gauge_fill(2, 0, true),
            still.gauge_fill(2, 2000, true)
        );
        assert_ne!(
            still.gauge_inflight(2, 0, true),
            still.gauge_inflight(2, 400, true)
        );
        let mono = Look::from_flags(true, false);
        assert_eq!(mono.gauge_fill(2, 2000, true).fg, None);
        assert_eq!(mono.gauge_inflight(2, 2000, true), mono.rule());
        for look in [live, still, mono] {
            for s in [
                look.gauge_fill(1, 50, true),
                look.gauge_inflight(1, 50, true),
            ] {
                assert!(!s.add_modifier.contains(Modifier::BOLD), "{s:?}");
            }
        }
    }

    #[test]
    fn keys_and_titles_carry_no_fill() {
        let look = Look::vivid();
        assert_eq!(look.key().bg, None);
        assert_eq!(look.title(true).bg, None);
        assert!(look.title(true).add_modifier.contains(Modifier::BOLD));
        assert_eq!(look.title(false).fg, Some(DIM));
        assert_eq!(look.soft_chip(Tone::Good).bg, Some(CHIP_GOOD_BG));
    }

    #[test]
    fn no_color_means_terminal_defaults() {
        let mono = Look::from_flags(true, false);
        assert!(mono.mono && !mono.animate);
        assert_eq!(mono.p, Palette::mono());
        assert_eq!(mono.text().fg, None);
        assert_eq!(mono.severity_chip(Severity::Alert).bg, None);
        assert_eq!(mono.soft_chip(Tone::Info).bg, None);
        assert_eq!(mono.base().bg, None);
    }
}
