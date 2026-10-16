//! SVG rendering of a drawn frame, for the README previews. The grid sits
//! inside a rounded frame with even padding, and each kind of cell becomes
//! the SVG element that draws it best, so the image looks the same whatever
//! monospace font the viewer falls back to:
//!
//! - runs of background become small rounded rects, and a cursor row that
//!   spans a pane wall to wall becomes one soft pill over all its rows;
//! - box-drawing cells become strokes on the cell grid, traced into one path
//!   per line with true quarter arcs for the rounded corners, so borders are
//!   seamless;
//! - a run of `━` in several colors (a progress bar's fill) becomes one
//!   round-capped stroke with a gradient through its cell colors, over the
//!   thinner track the `─` cells beside it trace;
//! - severity dots become circles;
//! - everything else stays text, one `<text>` per run of equal style held to
//!   the cell grid with `textLength`. The rainbow wordmark letters carry SMIL
//!   `<animate>` children so they cycle even inside an `<img>` tag, and the
//!   still frame reads complete without them.

#![cfg(feature = "tui")]

use std::fmt::Write as _;

use ratatui::buffer::{Buffer, Cell};
use ratatui::style::{Color, Modifier};

use super::theme;

/// Cell width in tenths of a pixel (9.6 px). With [`LINE_H`] this is the
/// nominal cell, which sets the image size; the grid itself is drawn a
/// little smaller, inside the frame's padding.
pub const CELL_W_TENTHS: u32 = 96;
/// Line height in pixels, at the nominal cell size.
pub const LINE_H: u32 = 20;
/// Font size in pixels at the nominal cell size; it shrinks with the cell.
pub const FONT_SIZE: u32 = 16;
/// The font stack every text run uses.
pub const FONT_STACK: &str = "Cascadia Mono, Consolas, Menlo, monospace";
/// How many rainbow samples each animated letter carries (first equals last).
pub const ANIM_STEPS: usize = 24;

/// Space between the frame's edge and the grid, in pixels.
const PAD: f64 = 15.0;
/// Corner radius of the frame.
const FRAME_R: f64 = 12.0;
/// Corner radius of a background chip or pill.
const CHIP_R: f64 = 3.0;
/// How far a chip or pill stays clear of its row's top and bottom, so
/// stacked ones read apart.
const CHIP_INSET: f64 = 1.0;
/// Stroke width of a light line: `─`, `│` and the corners.
const LIGHT_W: f64 = 1.2;
/// Stroke width of a heavy line: `━`, a progress bar's fill.
const HEAVY_W: f64 = 3.0;
/// How strongly dim ink shows over its background: the opacity of dim
/// text, and the mix of a dim line or dot.
const DIM_ALPHA: f64 = 0.6;

/// An 8-bit RGB color.
type Rgb = (u8, u8, u8);

/// Escape text for XML content and attribute values.
pub fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

/// `tenths` of a pixel as a short decimal ("28.8", "960").
fn px(tenths: u32) -> String {
    if tenths.is_multiple_of(10) {
        (tenths / 10).to_string()
    } else {
        format!("{}.{}", tenths / 10, tenths % 10)
    }
}

/// `v` rounded to `places` decimals, without trailing zeros ("9.3", "960").
fn dec(v: f64, places: usize) -> String {
    let s = format!("{v:.places$}");
    let s = if s.contains('.') {
        s.trim_end_matches('0').trim_end_matches('.')
    } else {
        &s
    };
    if s == "-0" {
        "0".to_string()
    } else {
        s.to_string()
    }
}

/// A length in pixels, to the hundredth.
fn num(v: f64) -> String {
    dec(v, 2)
}

fn hex(c: Rgb) -> String {
    format!("#{:02x}{:02x}{:02x}", c.0, c.1, c.2)
}

fn rgb_of(c: Color, fallback: Color) -> Rgb {
    match c {
        Color::Rgb(r, g, b) => (r, g, b),
        Color::Reset => rgb_of(fallback, Color::Rgb(0xff, 0xff, 0xff)),
        Color::Black => (0x16, 0x13, 0x1d),
        Color::Red => (0xff, 0x6b, 0x8b),
        Color::Green => (0x7e, 0xe0, 0xa1),
        Color::Yellow => (0xf6, 0xc5, 0x60),
        Color::Blue => (0x8f, 0xbc, 0xff),
        Color::Magenta => (0xd8, 0xb4, 0xfe),
        Color::Cyan => (0x7f, 0xdb, 0xe6),
        Color::Gray => (0x9a, 0x91, 0xb0),
        Color::DarkGray => (0x6b, 0x65, 0x77),
        _ => rgb_of(fallback, Color::Rgb(0xff, 0xff, 0xff)),
    }
}

/// A cell's drawn colors, with REVERSED applied.
fn cell_colors(cell: &Cell) -> (Rgb, Rgb) {
    let fg = rgb_of(cell.fg, theme::TEXT);
    let bg = rgb_of(cell.bg, theme::BG);
    if cell.modifier.contains(Modifier::REVERSED) {
        (bg, fg)
    } else {
        (fg, bg)
    }
}

/// `fg` showing at `alpha` over `bg`, as one opaque color, so lines that
/// meet never darken where they overlap.
fn mix(fg: Rgb, bg: Rgb, alpha: f64) -> Rgb {
    let m = |f: u8, b: u8| (f64::from(b) + (f64::from(f) - f64::from(b)) * alpha).round() as u8;
    (m(fg.0, bg.0), m(fg.1, bg.1), m(fg.2, bg.2))
}

/// The color a cell's line or dot is drawn in: its foreground, faded toward
/// its background when dim.
fn ink(cell: &Cell) -> Rgb {
    let (fg, bg) = cell_colors(cell);
    if cell.modifier.contains(Modifier::DIM) {
        mix(fg, bg, DIM_ALPHA)
    } else {
        fg
    }
}

/// The text attributes that split runs.
#[derive(Clone, PartialEq, Eq)]
struct RunStyle {
    fill: Rgb,
    bold: bool,
    dim: bool,
    underline: bool,
    italic: bool,
}

fn run_style(cell: &Cell) -> RunStyle {
    let m = cell.modifier;
    RunStyle {
        fill: cell_colors(cell).0,
        bold: m.contains(Modifier::BOLD),
        dim: m.contains(Modifier::DIM),
        underline: m.contains(Modifier::UNDERLINED),
        italic: m.contains(Modifier::ITALIC),
    }
}

fn style_attrs(s: &RunStyle) -> String {
    let mut a = format!(" fill=\"{}\"", hex(s.fill));
    if s.bold {
        a.push_str(" font-weight=\"bold\"");
    }
    if s.dim {
        let _ = write!(a, " fill-opacity=\"{}\"", dec(DIM_ALPHA, 2));
    }
    if s.underline {
        a.push_str(" text-decoration=\"underline\"");
    }
    if s.italic {
        a.push_str(" font-style=\"italic\"");
    }
    a
}

/// The SMIL `values` list for rainbow letter `i`: [`ANIM_STEPS`] samples of
/// [`theme::rainbow_color`] evenly spaced across one cycle, endpoints
/// included, so the first and last are equal and the loop is seamless.
pub fn rainbow_values(i: usize) -> Vec<String> {
    let cycle = theme::RAINBOW_CYCLE_MS;
    (0..ANIM_STEPS)
        .map(|k| {
            let t = cycle * k as u64 / (ANIM_STEPS as u64 - 1);
            hex(rgb_of(theme::rainbow_color(i, t), theme::TEXT))
        })
        .collect()
}

/// The SMIL `values` list for progress bar cell `i`: [`ANIM_STEPS`] samples
/// of [`theme::gauge_color`] across one cycle, endpoints included, so the
/// loop is seamless. The bar keeps the wordmark's cycle, so one duration
/// serves both.
pub fn gauge_values(i: usize) -> Vec<String> {
    let cycle = theme::GAUGE_CYCLE_MS;
    (0..ANIM_STEPS)
        .map(|k| {
            let t = cycle * k as u64 / (ANIM_STEPS as u64 - 1);
            hex(rgb_of(theme::gauge_color(i, t), theme::TEXT))
        })
        .collect()
}

fn anim_dur() -> String {
    let ms = theme::RAINBOW_CYCLE_MS;
    if ms.is_multiple_of(1000) {
        format!("{}s", ms / 1000)
    } else {
        format!("{}.{}s", ms / 1000, (ms % 1000) / 100)
    }
}

/// Where the grid sits inside the frame: the top-left corner of cell (0, 0)
/// and the size of one cell, in pixels.
#[derive(Debug, Clone, Copy)]
struct Grid {
    x0: f64,
    y0: f64,
    cw: f64,
    lh: f64,
}

impl Grid {
    /// The grid for `w` by `h` cells inside a frame `fw` by `fh` pixels,
    /// padded evenly on every side. A tiny frame gets less padding, so the
    /// grid never collapses.
    fn new(w: u32, h: u32, fw: f64, fh: f64) -> Self {
        let pad = PAD.min(fw / 16.0).min(fh / 10.0);
        let size = |total: f64, n: u32| {
            if n == 0 {
                0.0
            } else {
                (total - 2.0 * pad) / f64::from(n)
            }
        };
        Self {
            x0: pad,
            y0: pad,
            cw: size(fw, w),
            lh: size(fh, h),
        }
    }

    fn left(&self, col: u32) -> f64 {
        self.x0 + f64::from(col) * self.cw
    }

    fn top(&self, row: u32) -> f64 {
        self.y0 + f64::from(row) * self.lh
    }

    fn mid_x(&self, col: u32) -> f64 {
        self.left(col) + self.cw / 2.0
    }

    fn mid_y(&self, row: u32) -> f64 {
        self.top(row) + self.lh / 2.0
    }

    /// The font size, scaled with the cell width, so a font whose advance
    /// fills the nominal cell still fills this one.
    fn font_size(&self) -> f64 {
        f64::from(FONT_SIZE) * self.cw * 10.0 / f64::from(CELL_W_TENTHS)
    }

    /// The text baseline of `row`, as far below the row's middle as the
    /// nominal cell puts it (15 px down a 20 px line at 16 px).
    fn baseline(&self, row: u32) -> f64 {
        self.mid_y(row) + self.font_size() * 0.3125
    }

    /// The radius of a rounded corner: about half a cell, and inside the
    /// cell even once its lines snap to the pixel grid.
    fn corner_r(&self) -> f64 {
        (self.cw / 2.0 - 0.5).min(self.lh / 2.0 - 0.5).max(0.0)
    }
}

/// `v` moved to a pixel's center, so a line one or three pixels wide covers
/// whole pixels.
fn snap(v: f64) -> f64 {
    v.floor() + 0.5
}

// ---- box drawing --------------------------------------------------------

/// The arms of a box-drawing cell: the directions its lines reach from its
/// center to its edges, as bits.
const UP: u8 = 1;
const RIGHT: u8 = 2;
const DOWN: u8 = 4;
const LEFT: u8 = 8;
const ACROSS: u8 = LEFT | RIGHT;
const DIRS: [u8; 4] = [UP, RIGHT, DOWN, LEFT];

fn opposite(dir: u8) -> u8 {
    match dir {
        UP => DOWN,
        DOWN => UP,
        LEFT => RIGHT,
        _ => LEFT,
    }
}

/// One step toward `dir` on screen, where y grows downward.
fn unit(dir: u8) -> (f64, f64) {
    match dir {
        UP => (0.0, -1.0),
        DOWN => (0.0, 1.0),
        LEFT => (-1.0, 0.0),
        _ => (1.0, 0.0),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Weight {
    Light,
    Heavy,
    Dashed,
}

/// A box-drawing cell: its arms, their weight, whether its corner is
/// rounded, and its ink.
#[derive(Debug, Clone, Copy)]
struct Art {
    arms: u8,
    weight: Weight,
    round: bool,
    ink: Rgb,
}

/// The arms, weight and corner of the box-drawing symbols drawn as strokes;
/// every other symbol stays text.
fn line_art(symbol: &str) -> Option<(u8, Weight, bool)> {
    use Weight::{Dashed, Heavy, Light};
    Some(match symbol {
        "─" => (ACROSS, Light, false),
        "━" => (ACROSS, Heavy, false),
        "╌" => (ACROSS, Dashed, false),
        "│" => (UP | DOWN, Light, false),
        "┃" => (UP | DOWN, Heavy, false),
        "╎" => (UP | DOWN, Dashed, false),
        "╭" => (DOWN | RIGHT, Light, true),
        "╮" => (DOWN | LEFT, Light, true),
        "╰" => (UP | RIGHT, Light, true),
        "╯" => (UP | LEFT, Light, true),
        "┌" => (DOWN | RIGHT, Light, false),
        "┐" => (DOWN | LEFT, Light, false),
        "└" => (UP | RIGHT, Light, false),
        "┘" => (UP | LEFT, Light, false),
        "├" => (UP | DOWN | RIGHT, Light, false),
        "┤" => (UP | DOWN | LEFT, Light, false),
        "┬" => (ACROSS | DOWN, Light, false),
        "┴" => (ACROSS | UP, Light, false),
        "┼" => (ACROSS | UP | DOWN, Light, false),
        "┏" => (DOWN | RIGHT, Heavy, false),
        "┓" => (DOWN | LEFT, Heavy, false),
        "┗" => (UP | RIGHT, Heavy, false),
        "┛" => (UP | LEFT, Heavy, false),
        _ => return None,
    })
}

/// The arm a line coming in through `dir` leaves by: the other arm of a
/// line or a corner, straight across a tee or a cross, and none at a stub
/// (the odd arm of a tee), where the line ends at the center.
fn partner(arms: u8, dir: u8) -> Option<u8> {
    match arms.count_ones() {
        2 => Some(arms & !dir),
        3 | 4 => Some(opposite(dir)).filter(|o| arms & o != 0),
        _ => None,
    }
}

/// One step of a path.
#[derive(Debug, Clone, Copy)]
enum Seg {
    Move(f64, f64),
    Line(f64, f64),
    Arc {
        r: f64,
        clockwise: bool,
        x: f64,
        y: f64,
    },
    Close,
}

impl Seg {
    fn end(&self) -> Option<(f64, f64)> {
        match *self {
            Seg::Move(x, y) | Seg::Line(x, y) | Seg::Arc { x, y, .. } => Some((x, y)),
            Seg::Close => None,
        }
    }
}

/// A path being traced. A straight segment that carries on along the same
/// axis extends the one before, so a border's edge is a single segment.
#[derive(Debug, Default)]
struct Pen {
    segs: Vec<Seg>,
    /// Where the last segment starts, and where the pen is.
    from: (f64, f64),
    at: (f64, f64),
}

impl Pen {
    fn move_to(&mut self, x: f64, y: f64) {
        self.segs.push(Seg::Move(x, y));
        self.from = (x, y);
        self.at = (x, y);
    }

    fn line_to(&mut self, x: f64, y: f64) {
        let ((fx, fy), (ax, ay)) = (self.from, self.at);
        if (x, y) == (ax, ay) {
            return;
        }
        if let Some(Seg::Line(..)) = self.segs.last() {
            let along_x = fy == ay && ay == y && (ax - fx).signum() == (x - ax).signum();
            let along_y = fx == ax && ax == x && (ay - fy).signum() == (y - ay).signum();
            if along_x || along_y {
                self.segs.pop();
                self.segs.push(Seg::Line(x, y));
                self.at = (x, y);
                return;
            }
        }
        self.segs.push(Seg::Line(x, y));
        self.from = self.at;
        self.at = (x, y);
    }

    fn arc_to(&mut self, r: f64, clockwise: bool, x: f64, y: f64) {
        self.segs.push(Seg::Arc { r, clockwise, x, y });
        self.from = self.at;
        self.at = (x, y);
    }

    fn close(&mut self) {
        self.segs.push(Seg::Close);
    }

    /// Pull a free start or end in along its segment by `by` (at most half
    /// the segment), so a round cap stops right where the line ends.
    fn trim(&mut self, start: bool, end: bool, by: f64) {
        let n = self.segs.len();
        if n < 2 {
            return;
        }
        let pull = |from: (f64, f64), toward: (f64, f64)| {
            let (dx, dy) = (toward.0 - from.0, toward.1 - from.1);
            let len = dx.hypot(dy);
            if len > 0.0 {
                let t = by.min(len / 2.0) / len;
                (from.0 + dx * t, from.1 + dy * t)
            } else {
                from
            }
        };
        let head = match self.segs[..] {
            [Seg::Move(x0, y0), Seg::Line(x1, y1), ..] if start => Some(pull((x0, y0), (x1, y1))),
            _ => None,
        };
        let tail = match (self.segs[n - 1], self.segs[n - 2].end()) {
            (Seg::Line(x, y), Some(prev)) if end => Some(pull((x, y), prev)),
            _ => None,
        };
        if let Some((x, y)) = head {
            self.segs[0] = Seg::Move(x, y);
        }
        if let Some((x, y)) = tail {
            self.segs[n - 1] = Seg::Line(x, y);
        }
    }

    /// The path data, with `H` and `V` for the straight runs.
    fn data(&self) -> String {
        let mut d = String::new();
        let mut at = (0.0, 0.0);
        for seg in &self.segs {
            if !d.is_empty() {
                d.push(' ');
            }
            match *seg {
                Seg::Move(x, y) => {
                    let _ = write!(d, "M{} {}", num(x), num(y));
                }
                Seg::Line(x, y) if y == at.1 => {
                    let _ = write!(d, "H{}", num(x));
                }
                Seg::Line(x, y) if x == at.0 => {
                    let _ = write!(d, "V{}", num(y));
                }
                Seg::Line(x, y) => {
                    let _ = write!(d, "L{} {}", num(x), num(y));
                }
                Seg::Arc { r, clockwise, x, y } => {
                    let r = num(r);
                    let sweep = u8::from(clockwise);
                    let _ = write!(d, "A{r} {r} 0 0 {sweep} {} {}", num(x), num(y));
                }
                Seg::Close => d.push('Z'),
            }
            at = seg.end().unwrap_or(at);
        }
        d
    }
}

/// Carry the pen through a cell's center `c` from arm `from` to arm `to`:
/// straight on, around a sharp corner, or along a quarter arc of radius `r`.
fn turn(pen: &mut Pen, c: (f64, f64), from: u8, to: u8, round: bool, r: f64) {
    if to == opposite(from) {
        return;
    }
    if !round || r <= 0.0 {
        pen.line_to(c.0, c.1);
        return;
    }
    let (fx, fy) = unit(from);
    let (tx, ty) = unit(to);
    pen.line_to(c.0 + fx * r, c.1 + fy * r);
    // Heading in along -from and out along `to`: a positive cross product is
    // a clockwise turn on screen.
    let clockwise = fy * tx - fx * ty > 0.0;
    pen.arc_to(r, clockwise, c.0 + tx * r, c.1 + ty * r);
}

/// One traced line: its path data, weight and direction, and the ink of
/// each cell it passes through, by the x of the cell's center.
#[derive(Debug)]
struct Stroke {
    d: String,
    weight: Weight,
    across: bool,
    inks: Vec<(f64, Rgb)>,
}

/// Where a trace begins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Start {
    /// At a cell's center, going out through a stub.
    Center,
    /// At a cell's edge, coming in through an arm that joins nothing there.
    Edge,
    /// At a cell's edge, on a closed loop.
    Loop,
}

/// The box-drawing cells of a frame, to be traced into strokes.
struct Lines {
    w: u32,
    h: u32,
    grid: Grid,
    art: Vec<Option<Art>>,
}

impl Lines {
    fn index(&self, x: u32, y: u32) -> usize {
        (y * self.w + x) as usize
    }

    fn at(&self, x: u32, y: u32) -> Option<Art> {
        if x < self.w && y < self.h {
            self.art[self.index(x, y)]
        } else {
            None
        }
    }

    /// The neighbor that arm `dir` of (x, y) joins: one reaching back with
    /// the same weight and ink. Straight horizontal cells join whatever
    /// their inks, so a bar in many colors traces as one line.
    fn link(&self, x: u32, y: u32, dir: u8) -> Option<(u32, u32)> {
        let a = self.at(x, y)?;
        let (nx, ny) = match dir {
            UP => (x, y.checked_sub(1)?),
            DOWN => (x, y + 1),
            LEFT => (x.checked_sub(1)?, y),
            _ => (x + 1, y),
        };
        let b = self.at(nx, ny)?;
        let joins = a.arms & dir != 0
            && b.arms & opposite(dir) != 0
            && a.weight == b.weight
            && (a.ink == b.ink || (a.arms == ACROSS && b.arms == ACROSS));
        joins.then_some((nx, ny))
    }

    /// A cell's center, snapped so its lines are crisp.
    fn center(&self, x: u32, y: u32) -> (f64, f64) {
        (snap(self.grid.mid_x(x)), snap(self.grid.mid_y(y)))
    }

    /// Where arm `dir` of (x, y) meets the cell's edge.
    fn edge(&self, x: u32, y: u32, dir: u8) -> (f64, f64) {
        let (cx, cy) = self.center(x, y);
        match dir {
            UP => (cx, self.grid.top(y)),
            DOWN => (cx, self.grid.top(y + 1)),
            LEFT => (self.grid.left(x), cy),
            _ => (self.grid.left(x + 1), cy),
        }
    }

    /// Every line: the open ones first, from their free ends, then the
    /// closed loops. Light and dashed lines come before heavy ones, so a
    /// bar's fill lies over its track.
    fn trace(&self) -> Vec<Stroke> {
        let mut seen = vec![0u8; self.art.len()];
        let mut out = Vec::new();
        for loops in [false, true] {
            for y in 0..self.h {
                for x in 0..self.w {
                    let Some(a) = self.at(x, y) else { continue };
                    for dir in DIRS {
                        if a.arms & dir == 0 || seen[self.index(x, y)] & dir != 0 {
                            continue;
                        }
                        let start = if partner(a.arms, dir).is_none() {
                            Start::Center
                        } else if self.link(x, y, dir).is_none() {
                            Start::Edge
                        } else if loops {
                            Start::Loop
                        } else {
                            continue;
                        };
                        out.push(self.walk(x, y, dir, start, &mut seen));
                    }
                }
            }
        }
        out.sort_by_key(|s| s.weight == Weight::Heavy);
        out
    }

    /// Trace the line through arm `dir` of (x, y), marking every arm it
    /// covers in `seen`.
    fn walk(&self, x: u32, y: u32, dir: u8, start: Start, seen: &mut [u8]) -> Stroke {
        let first = self.art[self.index(x, y)].unwrap_or(Art {
            arms: dir,
            weight: Weight::Light,
            round: false,
            ink: (0, 0, 0),
        });
        let r = self.grid.corner_r();
        let mut pen = Pen::default();
        let mut inks = Vec::new();
        let (mut cell, mut arm) = ((x, y), dir);
        let mut entering = start != Start::Center;
        if entering {
            let (ex, ey) = self.edge(x, y, dir);
            pen.move_to(ex, ey);
        } else {
            let (cx, cy) = self.center(x, y);
            pen.move_to(cx, cy);
            inks.push((self.grid.mid_x(x), first.ink));
        }
        let (mut closed, mut free_end) = (false, false);
        while let Some(a) = self.at(cell.0, cell.1) {
            let i = self.index(cell.0, cell.1);
            seen[i] |= arm;
            if entering {
                inks.push((self.grid.mid_x(cell.0), a.ink));
                let c = self.center(cell.0, cell.1);
                let Some(out) = partner(a.arms, arm) else {
                    pen.line_to(c.0, c.1);
                    break;
                };
                seen[i] |= out;
                turn(&mut pen, c, arm, out, a.round, r);
                arm = out;
                entering = false;
            } else {
                let (ex, ey) = self.edge(cell.0, cell.1, arm);
                pen.line_to(ex, ey);
                let Some(next) = self.link(cell.0, cell.1, arm) else {
                    free_end = true;
                    break;
                };
                let back = opposite(arm);
                if seen[self.index(next.0, next.1)] & back != 0 {
                    closed = true;
                    break;
                }
                (cell, arm, entering) = (next, back, true);
            }
        }
        if closed {
            pen.close();
        }
        if first.weight == Weight::Heavy {
            pen.trim(start == Start::Edge, free_end, HEAVY_W / 2.0);
        }
        Stroke {
            d: pen.data(),
            weight: first.weight,
            across: first.arms & ACROSS != 0,
            inks,
        }
    }
}

/// Write `stroke` as a `<path>`. A line in one ink is painted with it; one
/// in several (a progress bar) gets a gradient with a stop at each cell's
/// center, written into `defs`.
fn write_stroke(out: &mut String, defs: &mut String, stroke: &Stroke, grid: &Grid, ids: &mut u32) {
    let Some(&(_, first)) = stroke.inks.first() else {
        return;
    };
    let mut paint = hex(first);
    if stroke.inks.iter().any(|&(_, c)| c != first) {
        let mut stops = stroke.inks.clone();
        stops.sort_by(|a, b| a.0.total_cmp(&b.0));
        stops.dedup_by(|a, b| a.0 == b.0);
        let (x1, x2) = (stops[0].0, stops[stops.len() - 1].0);
        if x2 > x1 {
            let id = format!("bar{ids}");
            *ids += 1;
            let _ = writeln!(
                defs,
                "<linearGradient id=\"{id}\" gradientUnits=\"userSpaceOnUse\" x1=\"{}\" y1=\"0\" \
                 x2=\"{}\" y2=\"0\">",
                num(x1),
                num(x2)
            );
            // A progress bar in the wordmark's rainbow flows the way the
            // wordmark does: each stop cycles through its cell's colors.
            let flows = stroke.weight == Weight::Heavy
                && stops
                    .iter()
                    .enumerate()
                    .all(|(j, &(_, c))| c == rgb_of(theme::gauge_color(j, 0), theme::TEXT));
            let dur = anim_dur();
            for (j, (x, c)) in stops.iter().enumerate() {
                let offset = dec((x - x1) / (x2 - x1), 4);
                if flows {
                    let _ = writeln!(
                        defs,
                        "<stop offset=\"{offset}\" stop-color=\"{}\"><animate \
                         attributeName=\"stop-color\" dur=\"{dur}\" repeatCount=\"indefinite\" \
                         values=\"{}\"/></stop>",
                        hex(*c),
                        gauge_values(j).join(";")
                    );
                } else {
                    let _ = writeln!(
                        defs,
                        "<stop offset=\"{offset}\" stop-color=\"{}\"/>",
                        hex(*c)
                    );
                }
            }
            defs.push_str("</linearGradient>\n");
            paint = format!("url(#{id})");
        }
    }
    let width = match stroke.weight {
        Weight::Heavy => HEAVY_W,
        Weight::Light | Weight::Dashed => LIGHT_W,
    };
    let mut attrs = format!(" stroke=\"{paint}\" stroke-width=\"{}\"", num(width));
    match stroke.weight {
        Weight::Heavy => attrs.push_str(" stroke-linecap=\"round\" stroke-linejoin=\"round\""),
        // Two dashes a cell, each centered in its half, like `╌`.
        Weight::Dashed => {
            let dash = if stroke.across { grid.cw } else { grid.lh } / 4.0;
            let _ = write!(
                attrs,
                " stroke-dasharray=\"{d} {d}\" stroke-dashoffset=\"{}\"",
                num(dash * 1.5),
                d = num(dash)
            );
        }
        Weight::Light => {}
    }
    let _ = writeln!(out, "<path d=\"{}\"{attrs}/>", stroke.d);
}

// ---- backgrounds --------------------------------------------------------

/// A background shape: columns `x0..x1` of rows `y0..=y1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Fill {
    x0: u32,
    x1: u32,
    y0: u32,
    y1: u32,
    color: Rgb,
}

/// The background shapes of a `w` by `h` frame whose cell backgrounds are
/// `bg` over the view's own `base`. Each row's stretch of other background
/// lies under one shape in its most common color, and the runs in other
/// colors sit on top as chips. A stretch from one pane wall to the other (a
/// cursor row, where `wall` tells a vertical line) joins the same stretch in
/// the next row, so a two-line cursor is one pill. Returns the shapes
/// underneath, then the chips.
fn fills(
    w: u32,
    h: u32,
    bg: impl Fn(u32, u32) -> Rgb,
    base: Rgb,
    wall: impl Fn(u32, u32) -> bool,
) -> (Vec<Fill>, Vec<Fill>) {
    let (mut under, mut chips) = (Vec::new(), Vec::new());
    let mut open: Vec<Fill> = Vec::new();
    for y in 0..h {
        let mut still = Vec::new();
        let mut x = 0;
        while x < w {
            if bg(x, y) == base {
                x += 1;
                continue;
            }
            let start = x;
            let mut runs = Vec::new();
            while x < w && bg(x, y) != base {
                let (from, color) = (x, bg(x, y));
                while x < w && bg(x, y) == color {
                    x += 1;
                }
                runs.push((from, x, color));
            }
            // The most common color, the first of equals.
            let cells =
                |c: Rgb| -> u32 { runs.iter().filter(|r| r.2 == c).map(|r| r.1 - r.0).sum() };
            let mut color = runs[0].2;
            for &(_, _, c) in &runs {
                if cells(c) > cells(color) {
                    color = c;
                }
            }
            let fill = Fill {
                x0: start,
                x1: x,
                y0: y,
                y1: y,
                color,
            };
            let wide = (start == 0 || wall(start - 1, y)) && (x == w || wall(x, y));
            let above = open
                .iter()
                .position(|f| (f.x0, f.x1, f.color) == (start, x, color));
            match above {
                Some(k) if wide => {
                    let mut pill = open.swap_remove(k);
                    pill.y1 = y;
                    still.push(pill);
                }
                _ if wide => still.push(fill),
                _ => under.push(fill),
            }
            chips.extend(
                runs.iter()
                    .filter(|r| r.2 != color)
                    .map(|&(x0, x1, c)| Fill {
                        x0,
                        x1,
                        y0: y,
                        y1: y,
                        color: c,
                    }),
            );
        }
        under.append(&mut open);
        open = still;
    }
    under.append(&mut open);
    (under, chips)
}

/// Write `f` as a small rounded rect, kept clear of its rows' edges.
fn write_fill(out: &mut String, f: &Fill, grid: &Grid) {
    let (x0, x1) = (grid.left(f.x0).round(), grid.left(f.x1).round());
    let y0 = grid.top(f.y0).round() + CHIP_INSET;
    let y1 = grid.top(f.y1 + 1).round() - CHIP_INSET;
    let _ = writeln!(
        out,
        "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" rx=\"{}\" fill=\"{}\"/>",
        num(x0),
        num(y0),
        num(x1 - x0),
        num((y1 - y0).max(0.0)),
        num(CHIP_R),
        hex(f.color)
    );
}

/// A severity dot, drawn as a circle.
fn is_dot(cell: &Cell) -> bool {
    cell.symbol() == "●"
}

/// Convert a rendered buffer to a standalone SVG. `rainbow` lists the cells
/// (column, row, letter index) that animate through the rainbow.
pub fn buffer_to_svg(buf: &Buffer, rainbow: &[(u16, u16, usize)], title: &str) -> String {
    let area = buf.area;
    let (w, h) = (u32::from(area.width), u32::from(area.height));
    let (width, height) = (px(w * CELL_W_TENTHS), (h * LINE_H).to_string());
    let (fw, fh) = (f64::from(w * CELL_W_TENTHS) / 10.0, f64::from(h * LINE_H));
    let grid = Grid::new(w, h, fw, fh);
    let base_bg = rgb_of(theme::BG, theme::BG);

    let cell = |x: u32, y: u32| buf.cell((area.x + x as u16, area.y + y as u16));
    let is_rainbow = |x: u32, y: u32| -> Option<usize> {
        rainbow
            .iter()
            .find(|(cx, cy, _)| {
                u32::from(*cx) == area.x as u32 + x && u32::from(*cy) == area.y as u32 + y
            })
            .map(|(_, _, i)| *i)
    };
    let mut art = Vec::with_capacity((w * h) as usize);
    for y in 0..h {
        for x in 0..w {
            art.push(cell(x, y).and_then(|c| {
                let (arms, weight, round) = line_art(c.symbol())?;
                Some(Art {
                    arms,
                    weight,
                    round,
                    ink: ink(c),
                })
            }));
        }
    }
    let lines = Lines { w, h, grid, art };
    let mut defs = String::new();
    let mut body = String::new();

    // Backgrounds: the shapes underneath, then the chips on top.
    let bg = |x: u32, y: u32| cell(x, y).map_or(base_bg, |c| cell_colors(c).1);
    let wall = |x: u32, y: u32| lines.at(x, y).is_some_and(|a| a.arms & (UP | DOWN) != 0);
    let (under, chips) = fills(w, h, bg, base_bg, wall);
    body.push_str("<g>\n");
    for f in under.iter().chain(&chips) {
        write_fill(&mut body, f, &grid);
    }
    body.push_str("</g>\n");

    // Lines, then dots.
    body.push_str("<g fill=\"none\">\n");
    let mut ids = 0;
    for stroke in lines.trace() {
        write_stroke(&mut body, &mut defs, &stroke, &grid, &mut ids);
    }
    body.push_str("</g>\n<g>\n");
    for y in 0..h {
        for x in 0..w {
            if let Some(c) = cell(x, y).filter(|c| is_dot(c)) {
                let _ = writeln!(
                    body,
                    "<circle cx=\"{}\" cy=\"{}\" r=\"{}\" fill=\"{}\"/>",
                    num(grid.mid_x(x)),
                    num(grid.mid_y(y)),
                    num(grid.cw / 3.0),
                    hex(ink(c))
                );
            }
        }
    }
    body.push_str("</g>\n");

    // Text: one <text> per same-style run, placed at its first cell and held
    // to the grid with textLength, so any monospace fallback lines up. Cells
    // drawn as shapes end a run. The rainbow letters are single-cell runs
    // whose <tspan> carries the animation.
    let dur = anim_dur();
    let shape = |c: &Cell| line_art(c.symbol()).is_some() || is_dot(c);
    for y in 0..h {
        let baseline = num(grid.baseline(y));
        let mut x = 0;
        while x < w {
            let Some(c) = cell(x, y) else { break };
            if shape(c) {
                x += 1;
                continue;
            }
            if let Some(i) = is_rainbow(x, y) {
                let style = run_style(c);
                let values = rainbow_values(i).join(";");
                let _ = writeln!(
                    body,
                    "<text x=\"{}\" y=\"{baseline}\"><tspan{}>{}<animate attributeName=\"fill\" \
                     dur=\"{dur}\" repeatCount=\"indefinite\" values=\"{values}\"/></tspan></text>",
                    num(grid.left(x)),
                    style_attrs(&style),
                    xml_escape(c.symbol())
                );
                x += 1;
                continue;
            }
            let style = run_style(c);
            let start = x;
            let mut text = String::new();
            while x < w {
                let Some(c) = cell(x, y) else { break };
                if shape(c) || is_rainbow(x, y).is_some() || run_style(c) != style {
                    break;
                }
                text.push_str(c.symbol());
                x += 1;
            }
            // Trailing blanks carry nothing visible; leading ones shift the x.
            let shown = text.trim_end();
            let lead = shown.chars().take_while(|c| *c == ' ').count() as u32;
            let shown = shown.trim_start();
            if shown.is_empty() {
                continue;
            }
            let n = shown.chars().count() as u32;
            let length = if n > 1 {
                format!(
                    " textLength=\"{}\" lengthAdjust=\"spacing\"",
                    num(f64::from(n) * grid.cw)
                )
            } else {
                String::new()
            };
            let _ = writeln!(
                body,
                "<text x=\"{}\" y=\"{baseline}\"{length}{}>{}</text>",
                num(grid.left(start + lead)),
                style_attrs(&style),
                xml_escape(shown)
            );
        }
    }

    // The frame: the view's background clipped to a rounded rect, with a
    // hairline around it on whole pixels.
    let mut out = String::new();
    let _ = writeln!(
        out,
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{width}\" height=\"{height}\" \
         viewBox=\"0 0 {width} {height}\" font-family=\"{}\" font-size=\"{}\" \
         xml:space=\"preserve\">",
        xml_escape(FONT_STACK),
        num(grid.font_size())
    );
    let _ = writeln!(out, "<title>{}</title>", xml_escape(title));
    let _ = writeln!(
        out,
        "<defs>\n<clipPath id=\"frame\"><rect width=\"{width}\" height=\"{height}\" \
         rx=\"{}\"/></clipPath>\n{defs}</defs>",
        num(FRAME_R)
    );
    let _ = writeln!(
        out,
        "<g clip-path=\"url(#frame)\">\n<rect width=\"{width}\" height=\"{height}\" \
         fill=\"{}\"/>\n{body}</g>",
        hex(base_bg)
    );
    let _ = writeln!(
        out,
        "<rect x=\"0.5\" y=\"0.5\" width=\"{}\" height=\"{}\" rx=\"{}\" fill=\"none\" \
         stroke=\"{}\"/>",
        num((fw - 1.0).max(0.0)),
        num((fh - 1.0).max(0.0)),
        num(FRAME_R - 0.5),
        hex(rgb_of(theme::BORDER, theme::BORDER))
    );
    out.push_str("</svg>\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rainbow_samples_come_from_the_hue_function() {
        let v = rainbow_values(2);
        assert_eq!(v[0], hex(rgb_of(theme::rainbow_color(2, 0), theme::TEXT)));
        assert_eq!(anim_dur(), "3.5s");
        assert_eq!(px(96), "9.6");
        assert_eq!(px(9600), "960");
        assert_eq!(xml_escape("a&<b>\"'"), "a&amp;&lt;b&gt;&quot;&apos;");
        assert_eq!(num(9.3), "9.3");
        assert_eq!(num(945.0000000001), "945");
        assert_eq!(num(-0.001), "0");
    }

    use crate::tui::theme::Look;
    use crate::tui::widgets::gauge::Gauge;
    use ratatui::layout::Rect;
    use ratatui::style::Style;
    use ratatui::widgets::{Block, BorderType, Widget};

    const LINE_SYMBOLS: [char; 13] = [
        '─', '━', '│', '╭', '╮', '╰', '╯', '╌', '┌', '┐', '├', '┼', '┴',
    ];

    fn frame() -> Buffer {
        Buffer::empty(Rect::new(0, 0, 100, 30))
    }

    fn svg_of(buf: &Buffer) -> String {
        buffer_to_svg(buf, &[], "test")
    }

    /// The `d` of every path.
    fn paths(svg: &str) -> Vec<&str> {
        svg.split("<path d=\"")
            .skip(1)
            .map(|r| r.split('"').next().unwrap_or(""))
            .collect()
    }

    fn assert_well_formed(svg: &str) {
        assert!(svg.starts_with("<svg"), "{svg}");
        assert!(svg.trim_end().ends_with("</svg>"));
        assert!(svg.match_indices('&').all(|(i, _)| {
            ["&amp;", "&lt;", "&gt;", "&quot;", "&apos;"]
                .iter()
                .any(|e| svg[i..].starts_with(e))
        }));
        for c in LINE_SYMBOLS {
            assert!(!svg.contains(c), "{c} left in the text");
        }
    }

    #[test]
    fn the_frame_is_rounded_padded_and_keeps_the_size() {
        let mut buf = frame();
        buf.set_string(0, 0, "Tom & Jerry <3", Style::new());
        buf.set_style(Rect::new(0, 29, 100, 1), Style::new().bg(theme::TINT));
        let svg = buffer_to_svg(&buf, &[], "a & b");
        assert_well_formed(&svg);
        assert!(svg.contains("width=\"960\" height=\"600\" viewBox=\"0 0 960 600\""));
        assert!(
            svg.contains("<clipPath id=\"frame\"><rect width=\"960\" height=\"600\" rx=\"12\"/>")
        );
        assert!(svg.contains("clip-path=\"url(#frame)\""));
        assert!(svg.contains("<rect x=\"0.5\" y=\"0.5\" width=\"959\" height=\"599\" rx=\"11.5\""));
        assert!(svg.contains("<title>a &amp; b</title>"));
        assert!(svg.contains("Tom &amp; Jerry &lt;3"));
        // Even padding: the last row spans 15 px in from left and right and
        // ends (with its 1 px inset) 15 px above the bottom.
        assert!(svg.contains("<rect x=\"15\" y=\"567\" width=\"930\" height=\"17\" rx=\"3\""));
    }

    #[test]
    fn borders_trace_into_seamless_paths_with_arcs() {
        let mut buf = frame();
        Block::bordered()
            .border_type(BorderType::Rounded)
            .render(Rect::new(0, 0, 12, 5), &mut buf);
        let svg = svg_of(&buf);
        assert_well_formed(&svg);
        let ds = paths(&svg);
        assert_eq!(ds.len(), 1, "{ds:?}");
        assert_eq!(ds[0].matches('A').count(), 4, "four quarter arcs");
        assert!(ds[0].ends_with('Z'), "a closed loop");

        // A title breaks the top edge; the corners stay arcs in one path.
        let mut buf = frame();
        Block::bordered()
            .border_type(BorderType::Rounded)
            .title(" files ")
            .render(Rect::new(0, 0, 20, 6), &mut buf);
        let ds = paths(&svg_of(&buf))
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>();
        assert_eq!(ds.len(), 1, "{ds:?}");
        assert_eq!(ds[0].matches('A').count(), 4);
        assert!(!ds[0].ends_with('Z'));
    }

    #[test]
    fn tees_and_sharp_corners_join() {
        let mut buf = frame();
        for (y, row) in ["┌──┬──┐", "│  │  │", "├──┼──┤", "│  │  │", "└──┴──┘"]
            .iter()
            .enumerate()
        {
            buf.set_string(0, y as u16, row, Style::new());
        }
        let svg = svg_of(&buf);
        assert_well_formed(&svg);
        let ds = paths(&svg);
        assert_eq!(ds.len(), 3, "{ds:?}");
        assert!(ds.iter().all(|d| !d.contains('A')));
        assert_eq!(ds.iter().filter(|d| d.ends_with('Z')).count(), 1);
    }

    #[test]
    fn a_bar_in_many_colors_is_one_gradient_stroke_over_its_track() {
        let mut buf = frame();
        Gauge::new(0.5).render(&mut buf, Rect::new(10, 3, 20, 1), &Look::vivid(), 0);
        let svg = svg_of(&buf);
        assert_well_formed(&svg);
        assert_eq!(svg.matches("<linearGradient").count(), 1);
        assert_eq!(
            svg.matches("<stop ").count(),
            10,
            "one stop per filled cell"
        );
        assert!(svg.contains(
            "<path d=\"M109.5 81.5 H199.5\" stroke=\"url(#bar0)\" stroke-width=\"3\" \
             stroke-linecap=\"round\""
        ));
        let track = hex(rgb_of(theme::BORDER, theme::BORDER));
        assert!(svg.contains(&format!(
            "<path d=\"M201 81.5 H294\" stroke=\"{track}\" stroke-width=\"1.2\"/>"
        )));
        // The fill lies over the track.
        assert!(svg.find("url(#bar0)\" stroke-width") > svg.find("H294"));
        // Every stop flows through its cell's rainbow on the wordmark's clock.
        assert_eq!(svg.matches("attributeName=\"stop-color\"").count(), 10);
        for j in 0..10 {
            assert!(svg.contains(&gauge_values(j).join(";")), "stop {j}");
        }
        assert_eq!(gauge_values(3).first(), gauge_values(3).last());
    }

    #[test]
    fn a_bar_in_other_colors_holds_still() {
        // A multi-color heavy run that is not the gauge's rainbow keeps a
        // static gradient.
        let mut buf = frame();
        buf.set_string(10, 3, "━━━", Style::new().fg(theme::ACCENT));
        buf.set_string(13, 3, "━━━", Style::new().fg(theme::PINK));
        let svg = svg_of(&buf);
        assert!(svg.contains("<linearGradient"));
        assert!(!svg.contains("stop-color\" dur"));
    }

    #[test]
    fn a_bar_in_one_color_is_a_plain_stroke() {
        let mut buf = frame();
        buf.set_string(10, 3, "━━━━━━", Style::new().fg(theme::ACCENT));
        let svg = svg_of(&buf);
        assert!(!svg.contains("linearGradient"));
        assert!(svg.contains(&format!(
            "stroke=\"{}\" stroke-width=\"3\" stroke-linecap=\"round\"",
            hex(rgb_of(theme::ACCENT, theme::ACCENT))
        )));
    }

    #[test]
    fn backgrounds_are_rounded_and_cursor_rows_are_pills() {
        let mut buf = frame();
        buf.set_string(40, 0, " enter ", Style::new().bg(theme::ACCENT));
        buf.set_string(40, 1, " space ", Style::new().bg(theme::ACCENT));
        Block::bordered()
            .border_type(BorderType::Rounded)
            .render(Rect::new(0, 2, 30, 6), &mut buf);
        buf.set_style(Rect::new(1, 3, 28, 2), Style::new().bg(theme::TINT));
        buf.set_string(3, 3, " warn ", Style::new().bg(theme::WARN));
        let svg = svg_of(&buf);
        assert_well_formed(&svg);
        let accent = hex(rgb_of(theme::ACCENT, theme::ACCENT));
        assert_eq!(
            svg.matches(&format!("rx=\"3\" fill=\"{accent}\"")).count(),
            2,
            "stacked chips stay apart"
        );
        let tint = hex(rgb_of(theme::TINT, theme::TINT));
        assert!(
            svg.contains(&format!(
                "<rect x=\"24\" y=\"73\" width=\"261\" height=\"36\" rx=\"3\" fill=\"{tint}\"/>"
            )),
            "{svg}"
        );
        let warn = hex(rgb_of(theme::WARN, theme::WARN));
        let (pill, chip) = (svg.find(&tint), svg.find(&format!("fill=\"{warn}\"")));
        assert!(chip > pill, "the chip lies over the pill");
    }

    #[test]
    fn dots_become_circles() {
        let mut buf = frame();
        buf.set_string(4, 6, "● report.pdf", Style::new().fg(theme::WARN));
        let svg = svg_of(&buf);
        assert!(!svg.contains('●'));
        assert!(
            svg.contains("<circle cx=\"56.85\" cy=\"138.5\" r=\"3.1\" fill=\"#f6c560\"/>"),
            "{svg}"
        );
        assert!(svg.contains(">report.pdf</text>"));
    }

    #[test]
    fn rainbow_cells_animate() {
        let mut buf = frame();
        buf.set_string(1, 0, "meownary", Style::new());
        let rainbow: Vec<_> = (0..4).map(|i| (1 + i as u16, 0, i)).collect();
        let svg = buffer_to_svg(&buf, &rainbow, "t");
        assert_eq!(svg.matches("<animate").count(), 4);
        for i in 0..4 {
            assert!(svg.contains(&rainbow_values(i).join(";")));
        }
        assert!(svg.contains("dur=\"3.5s\" repeatCount=\"indefinite\""));
        assert!(svg.contains(">nary</text>"));
    }

    #[test]
    fn no_color_buffers_still_render() {
        let mono = Look::from_flags(true, false);
        let mut buf = frame();
        Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(mono.border(false))
            .title(" files ")
            .render(Rect::new(0, 0, 40, 10), &mut buf);
        buf.set_style(Rect::new(1, 3, 38, 1), mono.cursor_row(true));
        Gauge::new(0.25)
            .inflight(0.25, 0.5)
            .render(&mut buf, Rect::new(2, 5, 20, 1), &mono, 0);
        assert!(
            !buf.content()
                .iter()
                .any(|c| matches!(c.fg, Color::Rgb(..)) || matches!(c.bg, Color::Rgb(..)))
        );
        let svg = svg_of(&buf);
        assert_well_formed(&svg);
        assert!(svg.contains("stroke-dasharray"), "the in-flight span");
        assert!(!svg.contains("linearGradient"));
        let text = hex(rgb_of(theme::TEXT, theme::TEXT));
        assert!(
            svg.contains(&format!("rx=\"3\" fill=\"{text}\"")),
            "reversed cursor row"
        );
        let _ = svg_of(&Buffer::empty(Rect::new(0, 0, 1, 1)));
        let _ = svg_of(&Buffer::empty(Rect::new(0, 0, 0, 0)));
    }
}
