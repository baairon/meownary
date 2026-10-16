//! README previews. A demo [`App`] built from synthetic reports is drawn by
//! the real renderer (`ui::draw`) into ratatui's `TestBackend`, and `svg`
//! converts the buffer to a standalone SVG. The four "meow" wordmark cells
//! carry SMIL `<animate>` children sampled from the same rainbow function the
//! terminal uses, so the wordmark cycles even when GitHub shows the file
//! through an `<img>` tag (which runs SMIL but not scripts).
//!
//! Regenerate them with `cargo test --lib -- --ignored write_preview_svg`,
//! which writes `assets/preview.svg`, `assets/keys.svg` and
//! `assets/picker.svg` (100x30), the images the README embeds.

#![cfg(feature = "tui")]

use std::path::{Path, PathBuf};

use ratatui::Terminal;
use ratatui::backend::TestBackend;

use crate::model::{
    BrandKind, Category, Confidence, ContainerKind, Evidence, FileReport, Finding, JunkKind,
    Marker, Region, RemovalStrategy, Severity, SignatureStatus, TamperKind,
};

use super::app::{App, Pane};
use super::keymap::Key;
use super::picker::{Picker, Suggestion};
use super::svg;
use super::theme::Look;
use super::ui;

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
    svg::buffer_to_svg(&buf, &app.rainbow_cells, title)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::keymap::HELP_GROUPS;
    use crate::tui::svg::{ANIM_STEPS, FONT_STACK, rainbow_values};
    use ratatui::buffer::Buffer;
    use ratatui::style::Color;

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
