//! Text hygiene (`text`): the invisible characters, exotic spaces and
//! bidirectional controls that hide in plain-text files, and the AI-provenance
//! comments of Markdown and HTML. The rules come from the upstream cleaner
//! credited in [`super::provenance`].
//!
//! The probe runs on files the identity probe left unlabeled (or labeled as
//! scripts) whose extension names a text format, that look like text (no NUL
//! in the first 8 KiB and few control bytes), and that fit one read (16 MiB).
//! Agent configuration is never read: anything under a `.claude`, `.ethagent`
//! or `.git` directory, and files named `CLAUDE.md`, `CLAUDE.local.md`,
//! `AGENTS.md` or `SKILL.md`, because upstream drops any comment that names
//! an AI tool and these files carry such notes on purpose.
//!
//! Findings, one per kind per file (comments one each):
//!
//! * `text.invisible`: zero-width, tag, variation-selector and other
//!   invisible characters. Removed.
//! * `text.spaces`: exotic spaces. Replaced with U+0020.
//! * `text.bidi`: overrides and unpaired embeddings. Removed.
//! * `text.ai_comment`: a Markdown or HTML comment naming an AI tool.
//!
//! Removal is a structural rewrite of the text ([`structural_remove`]). A
//! character finding's region is the first character of its kind; the
//! rewrite changes every character of that kind in the file, and nothing
//! before the region moves, so edits applied from the highest offset down
//! stay valid.

use std::path::Path;

use crate::model::{
    Category, Confidence, ContainerKind, Evidence, Finding, JunkKind, Marker, Region,
    RemovalStrategy, Severity,
};
use crate::parsers::image::shared::{NOTE_CHARS, TITLE_CHARS, clip, excerpt, fetch, finding};
use crate::parsers::provenance::markup::{self, Flavor};
use crate::parsers::provenance::unicode::{self, Class};
use crate::scan::reader::MAX_READ;
use crate::scan::{Probe, ProbeCtx};

/// Extensions of the plain-text formats the cleaner reads.
const TEXT_EXTS: &[&str] = &[
    "txt",
    "text",
    "css",
    "js",
    "jsx",
    "mjs",
    "cjs",
    "ts",
    "tsx",
    "gd",
    "gdshader",
    "py",
    "rs",
    "go",
    "json",
    "yaml",
    "yml",
    "toml",
    "csv",
    "c",
    "h",
    "cpp",
    "cc",
    "hpp",
    "cs",
    "java",
    "kt",
    "kts",
    "swift",
    "scala",
    "dart",
    "rb",
    "php",
    "lua",
    "pl",
    "r",
    "sh",
    "bash",
    "zsh",
    "ps1",
    "sql",
    "vue",
    "svelte",
    "astro",
    "rst",
    "adoc",
    "asciidoc",
    "org",
    "po",
    "pot",
    "strings",
    "arb",
    "resx",
    "properties",
    "ini",
    "cfg",
    "conf",
    "tsv",
    "xml",
    "tex",
    "ltx",
    "md",
    "markdown",
    "mdx",
    "html",
    "htm",
];
const MARKDOWN_EXTS: &[&str] = &["md", "markdown", "mdx"];
const HTML_EXTS: &[&str] = &["html", "htm"];

/// Directory names whose contents are agent configuration.
const PROTECTED_DIRS: &[&str] = &[".claude", ".ethagent", ".git"];
/// File names that are agent configuration wherever they sit.
const PROTECTED_FILES: &[&str] = &["claude.md", "claude.local.md", "agents.md", "skill.md"];

/// How many leading bytes the binary sniff reads.
const SNIFF: usize = 8192;

struct TextProbe;

impl Probe for TextProbe {
    fn id(&self) -> &'static str {
        "text"
    }

    fn run(&self, ctx: &ProbeCtx, out: &mut Vec<Finding>) {
        if !matches!(ctx.format, None | Some("script")) {
            return;
        }
        let path = ctx.view.path();
        let Some(ext) = extension(path) else {
            return;
        };
        if !TEXT_EXTS.contains(&ext.as_str()) || is_protected(path) {
            return;
        }
        let size = ctx.view.size();
        if size == 0 || size > MAX_READ as u64 {
            return;
        }
        let Some(bytes) = usize::try_from(size)
            .ok()
            .and_then(|len| fetch(ctx.view, 0, len))
        else {
            return;
        };
        if looks_binary(&bytes) {
            return;
        }
        let flavor = if MARKDOWN_EXTS.contains(&ext.as_str()) {
            Some(Flavor::Markdown)
        } else if HTML_EXTS.contains(&ext.as_str()) {
            Some(Flavor::Html)
        } else {
            None
        };
        scan(&bytes, flavor, out);
    }
}

/// Probes contributed by this module.
pub fn probes() -> Vec<Box<dyn Probe>> {
    vec![Box::new(TextProbe)]
}

fn extension(path: &Path) -> Option<String> {
    path.extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
}

/// Whether `path` is agent configuration the cleaner must not read.
fn is_protected(path: &Path) -> bool {
    let real = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let name_hit = real
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| PROTECTED_FILES.contains(&n.to_ascii_lowercase().as_str()));
    let mut parts: Vec<String> = real
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_ascii_lowercase())
        .collect();
    parts.pop();
    name_hit || parts.iter().any(|p| PROTECTED_DIRS.contains(&p.as_str()))
}

/// The upstream sniff: a NUL in the first 8 KiB, or more than 5% control
/// bytes (other than tab, newline, vertical tab, form feed, return and escape).
fn looks_binary(bytes: &[u8]) -> bool {
    let head = &bytes[..bytes.len().min(SNIFF)];
    if head.contains(&0) {
        return true;
    }
    let controls = head
        .iter()
        .filter(|&&b| b < 0x20 && !matches!(b, 0x09..=0x0D | 0x1B))
        .count();
    controls * 20 > head.len()
}

fn scan(bytes: &[u8], flavor: Option<Flavor>, out: &mut Vec<Finding>) {
    if let Some(flavor) = flavor {
        for range in markup::provenance_comments(bytes, flavor) {
            let block = &bytes[range.clone()];
            let shown = String::from_utf8_lossy(block);
            out.push(finding(
                "text.ai_comment",
                Category::Junk(JunkKind::Provenance),
                Confidence::Strong,
                Severity::Notice,
                format!("AI provenance comment \"{}\"", clip(&shown, TITLE_CHARS)),
                Evidence::at(range.start as u64)
                    .with_bytes(excerpt(block))
                    .with_note(format!(
                        "a comment that names an AI tool: \"{}\"",
                        clip(&shown, NOTE_CHARS)
                    )),
                Some(marker(range.start, range.len())),
            ));
        }
    }
    let hits = unicode::hits(bytes);
    for (class, id, noun, severity, confidence) in [
        (
            Class::Invisible,
            "text.invisible",
            "invisible character",
            Severity::Notice,
            Confidence::Strong,
        ),
        (
            Class::Space,
            "text.spaces",
            "exotic space",
            Severity::Info,
            Confidence::Moderate,
        ),
        (
            Class::Bidi,
            "text.bidi",
            "bidirectional control",
            Severity::Notice,
            Confidence::Strong,
        ),
    ] {
        let mine: Vec<&unicode::Hit> = hits.iter().filter(|h| h.class == class).collect();
        let Some(first) = mine.first() else {
            continue;
        };
        let plural = if mine.len() == 1 { "" } else { "s" };
        let mut kinds: Vec<(String, usize)> = Vec::new();
        for h in &mine {
            let label = unicode::describe(h.ch);
            match kinds.iter_mut().find(|(l, _)| *l == label) {
                Some((_, n)) => *n += 1,
                None => kinds.push((label, 1)),
            }
        }
        kinds.sort_by_key(|k| std::cmp::Reverse(k.1));
        let listed: Vec<String> = kinds
            .iter()
            .take(4)
            .map(|(l, n)| format!("{l} x{n}"))
            .collect();
        let mut note = listed.join(", ");
        if kinds.len() > 4 {
            note.push_str(&format!(", and {} more kinds", kinds.len() - 4));
        }
        note.push_str(if class == Class::Space {
            "; scrubbing replaces each with U+0020"
        } else {
            "; scrubbing removes each"
        });
        out.push(finding(
            id,
            Category::Junk(JunkKind::HiddenText),
            confidence,
            severity,
            format!("{} {noun}{plural} in text", mine.len()),
            Evidence::at(first.start as u64)
                .with_bytes(excerpt(&bytes[first.start..first.start + first.len]))
                .with_note(note),
            Some(marker(first.start, first.len)),
        ));
    }
}

fn marker(offset: usize, len: usize) -> Marker {
    Marker {
        region: Region::new(offset as u64, len as u64),
        removal: RemovalStrategy::StructuralRemove,
        container: ContainerKind::Raw,
        reversible: true,
    }
}

/// Structural removal for a text finding ([`ContainerKind::Raw`] with a
/// structural rewrite).
///
/// * A region that holds a provenance comment (it starts with `<!--` and is
///   exactly one of the file's provenance comments, found as Markdown or as
///   HTML) drops that comment.
/// * A region that holds one character the pass changes rewrites every
///   character of that character's kind: invisible characters are removed,
///   exotic spaces become U+0020, bidirectional controls are removed.
///
/// Anything else, and a rewrite that changes nothing, returns `None`.
pub fn structural_remove(data: &[u8], region: Region) -> Option<Vec<u8>> {
    let start = usize::try_from(region.offset).ok()?;
    let len = usize::try_from(region.len).ok()?;
    let end = start.checked_add(len)?;
    if len == 0 || end > data.len() {
        return None;
    }
    if data[start..end].starts_with(b"<!--") {
        for flavor in [Flavor::Markdown, Flavor::Html] {
            if markup::provenance_comments(data, flavor)
                .iter()
                .any(|r| r.start == start && r.end == end)
            {
                let mut out = Vec::with_capacity(data.len() - len);
                out.extend_from_slice(&data[..start]);
                out.extend_from_slice(&data[end..]);
                return Some(out);
            }
        }
        return None;
    }
    let hit = unicode::hits(data)
        .into_iter()
        .find(|h| h.start == start && h.len == len)?;
    unicode::clean(data, hit.class)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::image::shared::testkit::garbage;
    use crate::scan::MemView;

    fn scan_named(name: &str, data: &[u8]) -> Vec<Finding> {
        let view = MemView::new(name, data.to_vec());
        let ctx = ProbeCtx::new(&view, None);
        let mut out = Vec::new();
        TextProbe.run(&ctx, &mut out);
        out
    }

    /// Apply every removable finding the way the headless run orders them:
    /// length-changing edits from the highest offset down.
    fn scrub(name: &str, data: &[u8]) -> Vec<u8> {
        let mut cur = data.to_vec();
        let mut fs = scan_named(name, &cur);
        fs.sort_by_key(|f| std::cmp::Reverse(f.marker.as_ref().map_or(0, |m| m.region.offset)));
        for f in &fs {
            let m = f.marker.as_ref().unwrap();
            cur = structural_remove(&cur, m.region).expect("remover accepted the region");
        }
        cur
    }

    const DIRTY: &str = "Title\u{200B}\nsome\u{00A0}words \u{202E}here\u{E0041}\n";

    #[test]
    fn invisible_spaces_and_bidi_are_three_findings() {
        let data = DIRTY.as_bytes();
        let fs = scan_named("notes.txt", data);
        let ids: Vec<&str> = fs.iter().map(|f| f.signature_id.as_str()).collect();
        assert_eq!(ids, ["text.invisible", "text.spaces", "text.bidi"]);
        let inv = &fs[0];
        assert_eq!(inv.title, "2 invisible characters in text");
        assert_eq!(inv.category, Category::Junk(JunkKind::HiddenText));
        assert_eq!(inv.evidence.offset, 5);
        let note = inv.evidence.note.as_deref().unwrap();
        assert!(note.contains("U+200B zero width space x1"), "{note}");
        assert!(note.contains("U+E0041 tag character x1"), "{note}");
        assert_eq!(fs[1].title, "1 exotic space in text");
        assert_eq!(fs[2].title, "1 bidirectional control in text");
        for f in &fs {
            let m = f.marker.as_ref().unwrap();
            assert_eq!(m.removal, RemovalStrategy::StructuralRemove);
            assert_eq!(m.container, ContainerKind::Raw);
            assert_eq!(m.region.offset, f.evidence.offset);
        }
    }

    #[test]
    fn scrubbing_leaves_clean_text_and_a_quiet_rescan() {
        let out = scrub("notes.txt", DIRTY.as_bytes());
        assert_eq!(out, b"Title\nsome words here\n");
        assert!(scan_named("notes.txt", &out).is_empty());
        // Each finding alone cleans only its own kind.
        let fs = scan_named("notes.txt", DIRTY.as_bytes());
        let one = structural_remove(DIRTY.as_bytes(), fs[1].marker.as_ref().unwrap().region);
        let one = String::from_utf8(one.unwrap()).unwrap();
        assert!(one.contains("some words") && one.contains('\u{200B}'));
        let again = scan_named("notes.txt", one.as_bytes());
        assert_eq!(again.len(), 2);
    }

    #[test]
    fn edits_from_the_top_down_keep_every_region_valid() {
        let data = DIRTY.as_bytes();
        let fs = scan_named("a.json", data);
        for skip in 0..fs.len() {
            let mut cur = data.to_vec();
            let mut order: Vec<&Finding> = fs.iter().collect();
            order.rotate_left(skip);
            order.sort_by_key(|f| std::cmp::Reverse(f.marker.as_ref().unwrap().region.offset));
            for f in order {
                cur = structural_remove(&cur, f.marker.as_ref().unwrap().region).unwrap();
            }
            assert_eq!(cur, b"Title\nsome words here\n");
        }
    }

    #[test]
    fn ai_comments_in_markdown_and_html() {
        let md =
            "# Notes\n<!-- drafted by Claude -->\ntext\n```\n<!-- Claude -->\n```\n<!-- hugo -->\n";
        let fs = scan_named("README.md", md.as_bytes());
        assert_eq!(fs.len(), 1);
        let f = &fs[0];
        assert_eq!(f.signature_id, "text.ai_comment");
        assert_eq!(f.category, Category::Junk(JunkKind::Provenance));
        assert_eq!(
            f.title,
            "AI provenance comment \"<!-- drafted by Claude -->\""
        );
        let out = scrub("README.md", md.as_bytes());
        assert_eq!(
            String::from_utf8(out.clone()).unwrap(),
            "# Notes\n\ntext\n```\n<!-- Claude -->\n```\n<!-- hugo -->\n"
        );
        assert!(scan_named("README.md", &out).is_empty());

        let html = "<p>x</p><!-- ChatGPT --><!-- c2pa --><p>y</p>";
        let fs = scan_named("page.html", html.as_bytes());
        assert_eq!(fs.len(), 2);
        let out = scrub("page.html", html.as_bytes());
        assert_eq!(out, b"<p>x</p><p>y</p>");
        assert!(scan_named("page.htm", &out).is_empty());
        // Plain text files do not get the comment rule.
        assert!(scan_named("page.txt", html.as_bytes()).is_empty());
    }

    #[test]
    fn comments_and_characters_together() {
        let md = "a\u{200B}b <!-- by Claude --> c\u{00A0}d\n";
        let out = scrub("x.md", md.as_bytes());
        assert_eq!(out, b"ab  c d\n");
        assert!(scan_named("x.md", &out).is_empty());
        // A hidden character inside the comment: the comment edit is stale
        // once the character edit has run, and a rescan offers it again.
        let tricky = "<!-- Cl\u{200B}aude Claude -->\n";
        let fs = scan_named("t.md", tricky.as_bytes());
        assert_eq!(fs.len(), 2);
    }

    #[test]
    fn protected_paths_and_other_gates() {
        let data = DIRTY.as_bytes();
        for name in [
            "proj/.claude/notes.md",
            "a/.git/hooks.txt",
            ".ethagent/x.txt",
            "repo/CLAUDE.md",
            "repo/claude.local.md",
            "repo/Agents.md",
            "skills/SKILL.md",
        ] {
            assert!(scan_named(name, data).is_empty(), "{name}");
        }
        assert!(!scan_named("proj/claude.md.txt", data).is_empty());
        assert!(!scan_named("proj/notes.TXT", data).is_empty());
        assert!(scan_named("proj/notes.bin", data).is_empty());
        assert!(scan_named("proj/Makefile", data).is_empty());
        // Labeled formats belong to their own parsers.
        let view = MemView::new("x.txt", data.to_vec());
        let ctx = ProbeCtx::new(&view, Some("png"));
        let mut out = Vec::new();
        TextProbe.run(&ctx, &mut out);
        assert!(out.is_empty());
        let ctx = ProbeCtx::new(&view, Some("script"));
        TextProbe.run(&ctx, &mut out);
        assert!(!out.is_empty());
    }

    #[test]
    fn binary_and_invalid_files() {
        let mut nul = DIRTY.as_bytes().to_vec();
        nul.push(0);
        assert!(scan_named("a.txt", &nul).is_empty());
        let mut ctrl = vec![1u8; 400];
        ctrl.extend_from_slice(DIRTY.as_bytes());
        assert!(scan_named("a.txt", &ctrl).is_empty());
        assert!(scan_named("a.txt", b"").is_empty());
        for seed in 0..16 {
            let _ = scan_named("g.txt", &garbage(seed, 3000));
        }
        // Invalid UTF-8 stays byte for byte.
        let mut mixed = b"caf\xE9 ".to_vec();
        mixed.extend_from_slice("x\u{200B}y".as_bytes());
        let out = scrub("l1.txt", &mixed);
        assert_eq!(out, b"caf\xE9 xy");
    }

    #[test]
    fn remover_validates_the_region() {
        let data = DIRTY.as_bytes();
        assert!(structural_remove(data, Region::new(0, 1)).is_none());
        assert!(structural_remove(data, Region::new(5, 1)).is_none());
        assert!(structural_remove(data, Region::new(5, 3)).is_some());
        assert!(structural_remove(data, Region::new(5, 0)).is_none());
        assert!(structural_remove(data, Region::new(900, 3)).is_none());
        assert!(structural_remove(data, Region::new(u64::MAX, 3)).is_none());
        let md = b"<!-- Claude --> and <!-- hugo -->";
        assert!(structural_remove(md, Region::new(0, 15)).is_some());
        assert!(structural_remove(md, Region::new(20, 13)).is_none());
        assert!(structural_remove(md, Region::new(0, 14)).is_none());
    }

    #[test]
    fn large_inputs_are_skipped() {
        let big = vec![b'a'; MAX_READ + 1];
        assert!(scan_named("big.txt", &big).is_empty());
    }
}
