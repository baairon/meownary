//! README previews. A demo [`App`] built from synthetic reports is drawn by
//! the real renderer (`ui::draw`) into ratatui's `TestBackend`, and the buffer
//! is converted to a standalone SVG. The four "meow" wordmark cells carry SMIL
//! `<animate>` children sampled from the same rainbow function the terminal
//! uses, so the wordmark cycles even when GitHub shows the file through an
//! `<img>` tag (which runs SMIL but not scripts).
//!
//! Regenerate them with `cargo test --lib -- --ignored write_preview_svg`,
//! which writes `assets/preview.svg`, `assets/keys.svg` and
//! `assets/picker.svg` (100x30), the images the README embeds.

#![cfg(feature = "tui")]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::buffer::{Buffer, Cell};
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier};

use crate::model::{
    BrandKind, Category, Confidence, ContainerKind, Evidence, FileReport, Finding, JunkKind,
    Marker, Region, RemovalStrategy, Severity, SignatureStatus, TamperKind,
};

use super::app::{App, Pane};
use super::keymap::Key;
use super::picker::{Picker, Suggestion};
use super::theme::{self, Look};
use super::ui;

/// Cell width in tenths of a pixel (9.6 px).
pub const CELL_W_TENTHS: u32 = 96;
/// Line height in pixels.
pub const LINE_H: u32 = 20;
/// Font size in pixels.
pub const FONT_SIZE: u32 = 16;
/// The font stack every text run uses.
pub const FONT_STACK: &str = "Cascadia Mono, Consolas, Menlo, monospace";
/// How many rainbow samples each animated letter carries (first equals last).
pub const ANIM_STEPS: usize = 24;

/// The interactive view as an animated SVG, `width` by `height` cells.
pub fn render_preview_svg(width: u16, height: u16) -> String {
    let mut app = demo_app();
    render_svg(&mut app, width, height, "meownary interactive view")
}

/// The same view with the `?` key reference open.
pub fn render_help_svg(width: u16, height: u16) -> String {
    let mut app = demo_app();
    app.on_action(Key::Help);
    render_svg(&mut app, width, height, "meownary keys")
}

/// The picker a bare `meownary` opens on, showing its places.
pub fn render_picker_svg(width: u16, height: u16) -> String {
    let mut app = demo_picker();
    render_svg(&mut app, width, height, "meownary picker")
}

/// The picker over invented places. Recent picks are left out: the picker
/// only lists ones that exist, and a preview must not depend on the disk.
pub fn demo_picker() -> App {
    let place = |label: &str, path: &str| Suggestion {
        label: label.to_string(),
        path: PathBuf::from(path),
    };
    App::picking(Picker::with_suggestions(
        vec![
            place("Downloads", r"C:\Users\you\Downloads"),
            place("Desktop", r"C:\Users\you\Desktop"),
            place("Documents", r"C:\Users\you\Documents"),
            place("Pictures", r"C:\Users\you\Pictures"),
            place("Current folder", r"C:\Users\you\projects\site"),
            place("Drive C:", r"C:\"),
            place("Home", r"C:\Users\you"),
        ],
        Vec::new(),
    ))
}

/// A scan of an invented downloads folder: an installer with a PDB path and
/// an overlay, a photo with EXIF, a PDF with producer and author, a zip with
/// a comment, an executable posing as a photo, and some clean files. The
/// installer is highlighted, its findings pane focused, one finding picked.
pub fn demo_app() -> App {
    let root = PathBuf::from("downloads");
    let mut app = App::new(&root);
    app.total = Some(16);
    app.push_reports(demo_reports(&root));
    app.scan_done();
    if let Some(pos) = app
        .visible()
        .iter()
        .position(|&i| app.reports()[i].path.ends_with("setup-tool-2.4.1.exe"))
    {
        app.file_cursor = pos;
    }
    app.on_action(Key::Tab);
    app.on_action(Key::Down);
    app.on_action(Key::Space);
    app.on_action(Key::Up);
    debug_assert_eq!(app.pane, Pane::Findings);
    app
}

fn finding(
    category: Category,
    confidence: Confidence,
    severity: Severity,
    sig: &str,
    title: &str,
    evidence: Evidence,
    marker: Option<Marker>,
) -> Finding {
    Finding {
        category,
        confidence,
        severity,
        signature_id: sig.to_string(),
        title: title.to_string(),
        evidence,
        marker,
    }
}

fn text_blank(offset: u64, len: u64, container: ContainerKind) -> Marker {
    Marker {
        region: Region::new(offset, len),
        removal: RemovalStrategy::RawBlank { fill: 0x20 },
        container,
        reversible: true,
    }
}

fn structural(offset: u64, len: u64, container: ContainerKind) -> Marker {
    Marker {
        region: Region::new(offset, len),
        removal: RemovalStrategy::StructuralRemove,
        container,
        reversible: true,
    }
}

fn report(
    root: &Path,
    name: &str,
    format: Option<&str>,
    size: u64,
    findings: Vec<Finding>,
) -> FileReport {
    let mut r = FileReport::new(root.join(name), size);
    r.format = format.map(str::to_string);
    r.findings = findings;
    r
}

fn demo_reports(root: &Path) -> Vec<FileReport> {
    use Confidence::{Moderate, Strong};
    use Severity::{Alert, Info, Notice, Warn};
    vec![
        report(
            root,
            "setup-tool-2.4.1.exe",
            Some("pe"),
            2_412_544,
            vec![
                finding(
                    Category::Brand(BrandKind::Installer),
                    Moderate,
                    Info,
                    "catalog.installer.nsis",
                    "NSIS installer stub (Nullsoft 3.09)",
                    Evidence::at(0x3e20).with_note("Nullsoft Install System v3.09"),
                    None,
                ),
                finding(
                    Category::Brand(BrandKind::Toolchain),
                    Strong,
                    Info,
                    "pe.rich_header",
                    "Linked with MSVC 19.38 (Rich header)",
                    Evidence::at(0x80),
                    None,
                ),
                finding(
                    Category::Junk(JunkKind::PdbPath),
                    Strong,
                    Notice,
                    "pe.pdb_path",
                    "PDB path left in the debug directory",
                    Evidence::at(0x2f40).with_note(r"C:\build\agent\setup\Release\setup.pdb"),
                    Some(Marker::blank(
                        Region::new(0x2f40, 38),
                        ContainerKind::Generic,
                    )),
                ),
                finding(
                    Category::Tamper(TamperKind::AppendedData),
                    Moderate,
                    Warn,
                    "pe.overlay",
                    "1.8 MB appended after the image",
                    Evidence::at(0x9_c400),
                    Some(Marker::truncate_at(0x9_c400, ContainerKind::PeOverlay)),
                ),
                finding(
                    Category::Integrity(SignatureStatus::NoEmbedded),
                    Strong,
                    Notice,
                    "pe.authenticode",
                    "No embedded Authenticode signature",
                    Evidence::at(0x168),
                    None,
                ),
            ],
        ),
        report(
            root,
            "beach-day.jpg",
            Some("jpeg"),
            3_145_728,
            vec![
                finding(
                    Category::Junk(JunkKind::Exif),
                    Strong,
                    Notice,
                    "jpeg.exif",
                    "EXIF block with camera model and GPS position",
                    Evidence::at(0x18),
                    Some(Marker::blank(
                        Region::new(0x18, 0x2a40),
                        ContainerKind::JpegApp1,
                    )),
                ),
                finding(
                    Category::Junk(JunkKind::Xmp),
                    Moderate,
                    Notice,
                    "jpeg.xmp",
                    "XMP packet from a photo editor",
                    Evidence::at(0x2a5c),
                    Some(Marker::blank(
                        Region::new(0x2a5c, 0xc80),
                        ContainerKind::JpegApp1,
                    )),
                ),
            ],
        ),
        report(
            root,
            "lease-draft.pdf",
            Some("pdf"),
            184_320,
            vec![
                finding(
                    Category::Brand(BrandKind::DocProducer),
                    Strong,
                    Info,
                    "pdf.producer",
                    "Producer: LibreOffice 7.6",
                    Evidence::at(0x2_c8a0),
                    Some(text_blank(0x2_c8a0, 26, ContainerKind::PdfObject)),
                ),
                finding(
                    Category::Junk(JunkKind::DocInfo),
                    Strong,
                    Notice,
                    "pdf.info",
                    "Author field names a person",
                    Evidence::at(0x2_c8c4),
                    Some(text_blank(0x2_c8c4, 12, ContainerKind::PdfObject)),
                ),
            ],
        ),
        report(
            root,
            "sources.zip",
            Some("zip"),
            52_480,
            vec![finding(
                Category::Junk(JunkKind::ArchiveComment),
                Strong,
                Notice,
                "zip.comment",
                "Archive comment (64 bytes)",
                Evidence::at(52_416),
                Some(structural(52_416, 64, ContainerKind::ZipComment)),
            )],
        ),
        report(
            root,
            "photo.jpg",
            Some("pe"),
            98_304,
            vec![
                finding(
                    Category::Identity {
                        declared_ext: Some("jpg".to_string()),
                        true_format: "pe".to_string(),
                        mismatch: true,
                    },
                    Strong,
                    Alert,
                    "identity.ext_mismatch",
                    "Executable wearing a .jpg extension",
                    Evidence::at(0).with_bytes(b"MZ".to_vec()),
                    None,
                ),
                finding(
                    Category::Integrity(SignatureStatus::NoEmbedded),
                    Strong,
                    Notice,
                    "pe.authenticode",
                    "No embedded Authenticode signature",
                    Evidence::at(0x158),
                    None,
                ),
            ],
        ),
        report(root, "icon.png", Some("png"), 4_096, vec![]),
        report(
            root,
            "voice-memo.mp3",
            Some("mp3"),
            1_048_576,
            vec![finding(
                Category::Junk(JunkKind::Id3),
                Strong,
                Notice,
                "mp3.id3v2",
                "ID3v2 tag with encoder and comment",
                Evidence::at(0),
                Some(structural(0, 1024, ContainerKind::Id3v2)),
            )],
        ),
        report(root, "install.sh", Some("script"), 2_210, vec![]),
        report(
            root,
            "invoice-0425.pdf",
            Some("pdf"),
            96_512,
            vec![finding(
                Category::Brand(BrandKind::DocProducer),
                Strong,
                Info,
                "pdf.producer",
                "Producer: Ghostscript 10.02",
                Evidence::at(0x1_7a10),
                Some(text_blank(0x1_7a10, 27, ContainerKind::PdfObject)),
            )],
        ),
        report(
            root,
            "portrait.png",
            Some("png"),
            612_004,
            vec![finding(
                Category::Junk(JunkKind::TextChunk),
                Strong,
                Notice,
                "png.text",
                "tEXt chunk naming the editing software",
                Evidence::at(0x21),
                Some(structural(0x21, 41, ContainerKind::PngChunk)),
            )],
        ),
        report(
            root,
            "game-patch.zip",
            Some("zip"),
            8_388_608,
            vec![finding(
                Category::Junk(JunkKind::ArchiveComment),
                Strong,
                Notice,
                "zip.comment",
                "Archive comment (120 bytes)",
                Evidence::at(8_388_466),
                Some(structural(8_388_466, 120, ContainerKind::ZipComment)),
            )],
        ),
        report(
            root,
            "clip-0193.mp4",
            Some("mp4"),
            24_117_248,
            vec![finding(
                Category::Brand(BrandKind::MediaEncoder),
                Strong,
                Info,
                "mp4.encoder",
                "Encoded with Lavf 60.16",
                Evidence::at(0x1_6f0c),
                Some(text_blank(0x1_6f0c, 13, ContainerKind::IsoBox)),
            )],
        ),
        report(
            root,
            "report-final.docx",
            Some("ooxml"),
            41_230,
            vec![finding(
                Category::Junk(JunkKind::DocInfo),
                Strong,
                Notice,
                "ooxml.docinfo",
                "Document properties name an author",
                Evidence::at(0x9_2c0),
                None,
            )],
        ),
        report(root, "fonts.7z", Some("7z"), 3_407_872, vec![]),
        report(root, "wallpaper.webp", Some("webp"), 288_340, vec![]),
        report(root, "notes.txt", None, 1_204, vec![]),
    ]
}

/// Draw `app` once at `width` by `height` and convert the buffer.
fn render_svg(app: &mut App, width: u16, height: u16, title: &str) -> String {
    let look = Look::vivid();
    app.anim_ms = 0;
    let buf = match Terminal::new(TestBackend::new(width, height)) {
        Ok(mut terminal) => match terminal.draw(|f| ui::draw(f, app, &look)) {
            Ok(frame) => frame.buffer.clone(),
            Err(e) => match e {},
        },
        Err(e) => match e {},
    };
    buffer_to_svg(&buf, &app.rainbow_cells, title)
}

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

fn col_x(col: u32) -> String {
    px(col * CELL_W_TENTHS)
}

fn hex(c: (u8, u8, u8)) -> String {
    format!("#{:02x}{:02x}{:02x}", c.0, c.1, c.2)
}

fn rgb_of(c: Color, fallback: Color) -> (u8, u8, u8) {
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
fn cell_colors(cell: &Cell) -> ((u8, u8, u8), (u8, u8, u8)) {
    let fg = rgb_of(cell.fg, theme::TEXT);
    let bg = rgb_of(cell.bg, theme::BG);
    if cell.modifier.contains(Modifier::REVERSED) {
        (bg, fg)
    } else {
        (fg, bg)
    }
}

/// The text attributes that split runs.
#[derive(Clone, PartialEq, Eq)]
struct RunStyle {
    fill: (u8, u8, u8),
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
        a.push_str(" fill-opacity=\"0.6\"");
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

fn anim_dur() -> String {
    let ms = theme::RAINBOW_CYCLE_MS;
    if ms.is_multiple_of(1000) {
        format!("{}s", ms / 1000)
    } else {
        format!("{}.{}s", ms / 1000, (ms % 1000) / 100)
    }
}

/// Convert a rendered buffer to a standalone SVG. `rainbow` lists the cells
/// (column, row, letter index) that animate through the rainbow.
pub fn buffer_to_svg(buf: &Buffer, rainbow: &[(u16, u16, usize)], title: &str) -> String {
    let area: Rect = buf.area;
    let (w, h) = (u32::from(area.width), u32::from(area.height));
    let width = col_x(w);
    let height = (h * LINE_H).to_string();
    let base_bg = rgb_of(theme::BG, theme::BG);
    let mut out = String::new();
    let _ = writeln!(
        out,
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{width}\" height=\"{height}\" \
         viewBox=\"0 0 {width} {height}\" font-family=\"{}\" font-size=\"{FONT_SIZE}\" \
         xml:space=\"preserve\">",
        xml_escape(FONT_STACK)
    );
    let _ = writeln!(out, "<title>{}</title>", xml_escape(title));
    let _ = writeln!(
        out,
        "<rect width=\"{width}\" height=\"{height}\" fill=\"{}\"/>",
        hex(base_bg)
    );

    let cell = |x: u32, y: u32| buf.cell((area.x + x as u16, area.y + y as u16));
    let is_rainbow = |x: u32, y: u32| -> Option<usize> {
        rainbow
            .iter()
            .find(|(cx, cy, _)| {
                u32::from(*cx) == area.x as u32 + x && u32::from(*cy) == area.y as u32 + y
            })
            .map(|(_, _, i)| *i)
    };

    // Backgrounds: one rect per run of equal, non-default background.
    let _ = writeln!(out, "<g>");
    for y in 0..h {
        let mut x = 0;
        while x < w {
            let Some(c) = cell(x, y) else { break };
            let bg = cell_colors(c).1;
            let start = x;
            x += 1;
            while x < w && cell(x, y).map(|c| cell_colors(c).1) == Some(bg) {
                x += 1;
            }
            if bg != base_bg {
                let _ = writeln!(
                    out,
                    "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{LINE_H}\" fill=\"{}\"/>",
                    col_x(start),
                    y * LINE_H,
                    px((x - start) * CELL_W_TENTHS),
                    hex(bg)
                );
            }
        }
    }
    let _ = writeln!(out, "</g>");

    // Text: one <text> per same-style run, placed at its first cell and held
    // to the grid with textLength, so any monospace fallback lines up. The
    // rainbow letters are single-cell runs whose <tspan> carries the animation.
    let dur = anim_dur();
    for y in 0..h {
        let baseline = y * LINE_H + 15;
        let mut x = 0;
        while x < w {
            let Some(c) = cell(x, y) else { break };
            if let Some(i) = is_rainbow(x, y) {
                let style = run_style(c);
                let values = rainbow_values(i).join(";");
                let _ = writeln!(
                    out,
                    "<text x=\"{}\" y=\"{baseline}\"><tspan{}>{}<animate attributeName=\"fill\" \
                     dur=\"{dur}\" repeatCount=\"indefinite\" values=\"{values}\"/></tspan></text>",
                    col_x(x),
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
                if is_rainbow(x, y).is_some() || run_style(c) != style {
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
                    px(n * CELL_W_TENTHS)
                )
            } else {
                String::new()
            };
            let _ = writeln!(
                out,
                "<text x=\"{}\" y=\"{baseline}\"{length}{}>{}</text>",
                col_x(start + lead),
                style_attrs(&style),
                xml_escape(shown)
            );
        }
    }
    out.push_str("</svg>\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::keymap::HELP_GROUPS;

    /// Every `&` must start an entity.
    fn only_entities(svg: &str) -> bool {
        svg.match_indices('&').all(|(i, _)| {
            let rest = &svg[i..];
            ["&amp;", "&lt;", "&gt;", "&quot;", "&apos;"]
                .iter()
                .any(|e| rest.starts_with(e))
        })
    }

    fn values_of(svg: &str) -> Vec<Vec<String>> {
        svg.split("values=\"")
            .skip(1)
            .map(|rest| {
                rest.split('"')
                    .next()
                    .unwrap_or("")
                    .split(';')
                    .map(str::to_string)
                    .collect()
            })
            .collect()
    }

    #[test]
    fn preview_and_help_svgs_are_well_formed() {
        let preview = render_preview_svg(100, 30);
        let help = render_help_svg(100, 30);
        for svg in [&preview, &help] {
            assert!(svg.starts_with("<svg"), "{}", &svg[..40]);
            assert!(svg.contains("width=\"960\" height=\"600\" viewBox=\"0 0 960 600\""));
            assert!(svg.trim_end().ends_with("</svg>"));
            assert!(only_entities(svg), "raw ampersand");
            assert!(svg.contains(FONT_STACK));
        }
        assert!(preview.contains("<title>meownary interactive view</title>"));
        for svg in [&preview, &help] {
            assert!(!svg.contains("o.o"), "no cat face anywhere");
        }
        assert!(help.contains("<title>meownary keys</title>"));

        assert_eq!(preview.matches("<animate").count(), 4);
        let vals = values_of(&preview);
        assert_eq!(vals.len(), 4);
        for (i, v) in vals.iter().enumerate() {
            assert_eq!(v.len(), ANIM_STEPS);
            assert_eq!(v.first(), v.last(), "seamless loop");
            assert_eq!(v, &rainbow_values(i), "letter {i} carries its own offset");
        }
        assert_ne!(
            vals[0][0], vals[1][0],
            "the wave travels across the letters"
        );
        assert!(preview.contains("dur=\"3.5s\" repeatCount=\"indefinite\""));

        for (title, hints) in HELP_GROUPS {
            assert!(help.contains(title), "group {title}");
            for hint in *hints {
                assert!(help.contains(hint.label), "label {}", hint.label);
            }
        }
        assert_eq!(
            help.matches("<animate").count(),
            4,
            "the overlay's wordmark"
        );
    }

    #[test]
    fn preview_shows_the_demo_scan() {
        let svg = render_preview_svg(100, 30);
        for needle in [
            "setup-tool-2.4.1.exe",
            "pe.pdb_path",
            "pe.overlay",
            "photo.jpg",
            "Scanned 16 files",
            "1 selected",
        ] {
            assert!(svg.contains(needle), "{needle}");
        }
    }

    #[test]
    fn picker_svg_is_well_formed() {
        let svg = render_picker_svg(100, 30);
        assert!(svg.starts_with("<svg"), "{}", &svg[..40]);
        assert!(svg.contains("width=\"960\" height=\"600\" viewBox=\"0 0 960 600\""));
        assert!(svg.trim_end().ends_with("</svg>"));
        assert!(only_entities(&svg), "raw ampersand");
        assert!(svg.contains("<title>meownary picker</title>"));
        assert_eq!(svg.matches("<animate").count(), 4, "the wordmark");
        for needle in [
            "path",
            "places",
            "Downloads",
            r"C:\Users\you\Documents",
            "Current folder",
            PICKER_LINE,
        ] {
            assert!(svg.contains(needle), "{needle}");
        }
    }

    const PICKER_LINE: &str =
        "Pick a file or folder to scan. Nothing is changed until you confirm an action.";

    #[test]
    fn the_picker_draws_calmly_at_every_size() {
        let look = Look::vivid();
        for (w, h) in [(100, 30), (80, 24)] {
            let mut app = demo_picker();
            let (text, _) = screen(&mut app, &look, w, h);
            for needle in [
                "meownary",
                " path ",
                "places",
                "place   Downloads",
                r"C:\Users\you\Desktop",
                "up/dn",
                "enter",
                "esc",
            ] {
                assert!(text.contains(needle), "{w}x{h}: {needle}\n{text}");
            }
            assert!(
                text.contains(PICKER_LINE)
                    || (text.contains("Pick a file or folder to scan.")
                        && text.contains("Nothing is changed until you confirm an action.")),
                "{w}x{h} tagline\n{text}"
            );
            assert!(!text.contains("files  "), "no scan view behind\n{text}");
        }
        // The tagline splits where it no longer fits on one line.
        let (narrow, _) = screen(&mut demo_picker(), &look, 60, 24);
        assert!(
            narrow.contains("Pick a file or folder to scan."),
            "{narrow}"
        );
        assert!(narrow.contains("Downloads"), "{narrow}");
        // Short and tiny terminals keep the path box, and never panic.
        let (short, _) = screen(&mut demo_picker(), &look, 80, 10);
        assert!(short.contains(" path "), "{short}");
        for (w, h) in [(24, 8), (30, 9), (40, 12), (10, 4), (200, 60), (1, 1)] {
            let _ = screen(&mut demo_picker(), &look, w, h);
        }
        // NO_COLOR draws the picker in terminal defaults.
        let mono = Look::from_flags(true, false);
        let mut app = demo_picker();
        let (_, buf) = screen(&mut app, &mono, 80, 24);
        assert!(
            !buf.content()
                .iter()
                .any(|c| matches!(c.fg, Color::Rgb(..)) || matches!(c.bg, Color::Rgb(..)))
        );
    }

    #[test]
    fn rainbow_samples_come_from_the_hue_function() {
        let v = rainbow_values(2);
        assert_eq!(v[0], hex(rgb_of(theme::rainbow_color(2, 0), theme::TEXT)));
        assert_eq!(anim_dur(), "3.5s");
        assert_eq!(px(96), "9.6");
        assert_eq!(px(9600), "960");
        assert_eq!(xml_escape("a&<b>\"'"), "a&amp;&lt;b&gt;&quot;&apos;");
    }

    fn screen(app: &mut App, look: &Look, w: u16, h: u16) -> (String, Buffer) {
        let mut t = match Terminal::new(TestBackend::new(w, h)) {
            Ok(t) => t,
            Err(e) => match e {},
        };
        let buf = match t.draw(|f| ui::draw(f, app, look)) {
            Ok(f) => f.buffer.clone(),
            Err(e) => match e {},
        };
        let mut text = String::new();
        for y in 0..h {
            for x in 0..w {
                text.push_str(buf.cell((x, y)).map(|c| c.symbol()).unwrap_or(" "));
            }
            text.push('\n');
        }
        (text, buf)
    }

    #[test]
    fn every_screen_renders_at_common_sizes() {
        let look = Look::vivid();
        for (w, h) in [(100, 30), (80, 24)] {
            let mut app = demo_app();
            let (main, _) = screen(&mut app, &look, w, h);
            for needle in ["files", "findings", "meownary", "pe.pdb_path", "?  keys"] {
                assert!(main.contains(needle), "{w}x{h} main: {needle}\n{main}");
            }
            assert!(!app.narrow);

            app.on_action(Key::Help);
            let (help, _) = screen(&mut app, &look, w, h);
            for (title, hints) in HELP_GROUPS {
                assert!(help.contains(title), "{w}x{h} help: {title}\n{help}");
                for hint in *hints {
                    assert!(
                        help.contains(hint.label),
                        "{w}x{h} help: {}\n{help}",
                        hint.label
                    );
                }
            }
            app.on_action(Key::Esc);

            app.on_action(Key::Scrub);
            let (confirm, _) = screen(&mut app, &look, w, h);
            assert!(confirm.contains("Scrub 1 marker?"), "{confirm}");
            assert!(confirm.contains("confirm"));
            app.on_action(Key::No);

            app.on_action(Key::Down);
            app.on_action(Key::Enter);
            let (detail, _) = screen(&mut app, &look, w, h);
            for needle in ["verdict", "pe.pdb_path", "Reading bytes...", "safe"] {
                assert!(
                    detail.contains(needle),
                    "{w}x{h} detail: {needle}\n{detail}"
                );
            }
            app.on_action(Key::Esc);

            app.on_action(Key::Buckets);
            let (buckets, _) = screen(&mut app, &look, w, h);
            assert!(buckets.contains("buckets by category"), "{buckets}");
            assert!(buckets.contains("Junk / metadata"));
            app.on_action(Key::Esc);

            app.on_action(Key::Filter);
            let (filter, _) = screen(&mut app, &look, w, h);
            assert!(filter.contains("16 of 16 files"), "{filter}");
        }

        // Narrow: one pane, and tab is the first hint.
        let mut app = demo_app();
        let (narrow, _) = screen(&mut app, &look, 50, 20);
        assert!(app.narrow);
        assert!(
            narrow.contains("findings") && !narrow.contains("╭  files"),
            "{narrow}"
        );
        assert!(narrow.contains(" tab  files"), "{narrow}");

        // Tiny and empty never panic.
        let _ = screen(&mut demo_app(), &look, 10, 4);
        let mut empty = App::new("nowhere");
        let (scanning, _) = screen(&mut empty, &look, 80, 24);
        assert!(scanning.contains("Scanning 0 files..."), "{scanning}");
        empty.scan_done();
        let (none, _) = screen(&mut empty, &look, 80, 24);
        assert!(none.contains("No files to scan."), "{none}");
    }

    #[test]
    fn saved_files_carry_a_chip_and_keep_columns_aligned() {
        use crate::tui::app::SavedKind;
        let look = Look::vivid();
        let mut app = demo_app();
        let root = PathBuf::from("downloads");
        let pdf = root.join("lease-draft.pdf");
        let exe = root.join("setup-tool-2.4.1.exe");
        app.mark_saved(&pdf, SavedKind::Scrubbed, pdf.clone(), 2);
        app.mark_saved(
            &exe,
            SavedKind::Deattributed,
            root.join("setup-tool-2.4.1.deattributed.exe"),
            1,
        );
        let (text, _) = screen(&mut app, &look, 100, 30);
        let row_of = |needle: &str| {
            text.lines()
                .find(|l| l.starts_with('│') && l.contains(needle))
                .unwrap_or_else(|| panic!("{needle}\n{text}"))
                .to_string()
        };
        let pdf_row = row_of("lease-draft.pdf");
        let exe_row = row_of("2.4.1.exe");
        assert!(pdf_row.contains("lease-draft.pdf  scrubbed "), "{pdf_row}");
        assert!(exe_row.contains(" deattributed "), "{exe_row}");
        // The format column sits where it does on an unmarked row.
        let col = |row: &str, word: &str| row.find(word).map(|i| row[..i].chars().count());
        let plain = row_of("invoice-0425.pdf");
        assert_eq!(col(&pdf_row, " pdf "), col(&plain, " pdf "), "\n{text}");
        // The peek and the detail view name the output.
        assert!(text.contains("saved    deattributed  "), "{text}");
        app.on_action(Key::Enter);
        let (detail, _) = screen(&mut app, &look, 100, 30);
        assert!(
            detail.contains("setup-tool-2.4.1.deattributed.exe"),
            "{detail}"
        );
        app.on_action(Key::Esc);

        // Narrow still shows a mark and never panics.
        app.on_action(Key::Left);
        let (narrow, _) = screen(&mut app, &look, 34, 20);
        assert!(
            narrow.contains('✓') || narrow.contains("scrubbed"),
            "{narrow}"
        );
        let _ = screen(&mut app, &look, 24, 8);
    }

    #[test]
    fn no_color_draws_in_terminal_defaults() {
        let look = Look::from_flags(true, false);
        let mut app = demo_app();
        app.anim_ms = 1234;
        let (_, buf) = screen(&mut app, &look, 80, 24);
        let colored = buf
            .content()
            .iter()
            .any(|c| matches!(c.fg, Color::Rgb(..)) || matches!(c.bg, Color::Rgb(..)));
        assert!(
            !colored,
            "NO_COLOR leaves every cell in the terminal's colors"
        );
        assert!(app.rainbow_cells.is_empty(), "nothing to animate");
    }

    #[test]
    #[ignore = "writes the README previews into assets/"]
    fn write_preview_svg() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets");
        std::fs::create_dir_all(&dir).unwrap();
        let preview = dir.join("preview.svg");
        let help = dir.join("keys.svg");
        let picker = dir.join("picker.svg");
        std::fs::write(&preview, render_preview_svg(100, 30)).unwrap();
        std::fs::write(&help, render_help_svg(100, 30)).unwrap();
        std::fs::write(&picker, render_picker_svg(100, 30)).unwrap();
        println!(
            "wrote {}, {} and {}",
            preview.display(),
            help.display(),
            picker.display()
        );
    }
}
