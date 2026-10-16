//! Probes for naming tricks. These read only the file name: a double
//! extension such as `invoice.pdf.exe`, a bidirectional override character
//! that reverses how the name displays, padding that pushes the real
//! extension out of view, and an archive password written into the name.
//!
//! None of these findings carry a marker. A rename is not a byte edit, so the
//! note tells the user they can rename the file instead.

use crate::model::{Category, Confidence, DeceptionKind, Evidence, Finding, Severity};
use crate::scan::{Probe, ProbeCtx};

/// Probes contributed by this module.
pub fn probes() -> Vec<Box<dyn Probe>> {
    vec![Box::new(NameProbe)]
}

struct NameProbe;

impl Probe for NameProbe {
    fn id(&self) -> &'static str {
        "deception"
    }

    fn formats(&self) -> &'static [&'static str] {
        &[]
    }

    fn run(&self, ctx: &ProbeCtx, out: &mut Vec<Finding>) {
        let Some(name) = ctx.view.path().file_name() else {
            return;
        };
        let name = name.to_string_lossy();
        check_name(&name, ctx.format, out);
    }
}

const RENAME: &str = "no bytes are changed; renaming the file clears this";

/// Run every name rule over `name`, appending findings.
fn check_name(name: &str, format: Option<&str>, out: &mut Vec<Finding>) {
    if let Some(f) = double_ext(name) {
        out.push(f);
    }
    if let Some(f) = bidi_override(name) {
        out.push(f);
    }
    if let Some(f) = hidden_ext(name) {
        out.push(f);
    }
    if let Some(f) = pw_in_name(name, format) {
        out.push(f);
    }
}

fn finding(
    kind: DeceptionKind,
    confidence: Confidence,
    severity: Severity,
    id: &str,
    title: String,
    matched: &str,
    note: String,
) -> Finding {
    let mut bytes = matched.as_bytes().to_vec();
    bytes.truncate(64);
    Finding {
        category: Category::Deception(kind),
        confidence,
        severity,
        signature_id: id.to_string(),
        title,
        evidence: Evidence::at(0).with_bytes(bytes).with_note(note),
        marker: None,
    }
}

/// Extensions that run when opened.
fn is_exec_ext(ext: &str) -> bool {
    matches!(
        ext,
        "exe"
            | "scr"
            | "com"
            | "pif"
            | "bat"
            | "cmd"
            | "js"
            | "vbs"
            | "ps1"
            | "hta"
            | "lnk"
            | "msi"
            | "jar"
            | "apk"
    )
}

/// Document, image and media extensions a lure would borrow.
fn is_bait_ext(ext: &str) -> bool {
    matches!(
        ext,
        "pdf"
            | "doc"
            | "docx"
            | "xls"
            | "xlsx"
            | "ppt"
            | "pptx"
            | "rtf"
            | "txt"
            | "odt"
            | "ods"
            | "odp"
            | "csv"
            | "jpg"
            | "jpeg"
            | "png"
            | "gif"
            | "bmp"
            | "webp"
            | "tif"
            | "tiff"
            | "heic"
            | "svg"
            | "mp3"
            | "mp4"
            | "wav"
            | "avi"
            | "mkv"
            | "mov"
            | "wmv"
            | "flac"
            | "ogg"
            | "m4a"
            | "webm"
    )
}

/// Characters that render as nothing or as blank space.
fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00A0}'
            | '\u{115F}'
            | '\u{1160}'
            | '\u{180E}'
            | '\u{2000}'..='\u{200F}'
            | '\u{2028}'..='\u{202F}'
            | '\u{205F}'..='\u{2064}'
            | '\u{3000}'
            | '\u{3164}'
            | '\u{FEFF}'
            | '\u{FFA0}'
    ) || (c.is_whitespace() && c != ' ')
}

/// Bidirectional embedding, override and isolate controls.
fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

fn trim_padding(s: &str) -> &str {
    s.trim_matches(|c: char| c == ' ' || is_invisible(c))
}

/// `invoice.pdf.exe`: an executable extension behind a document, image or
/// media one. Windows hides known extensions by default, so the file shows
/// as `invoice.pdf`.
fn double_ext(name: &str) -> Option<Finding> {
    let (rest, last) = name.rsplit_once('.')?;
    let (stem, prev) = rest.rsplit_once('.')?;
    let last = trim_padding(last).to_ascii_lowercase();
    let prev_clean = trim_padding(prev).to_ascii_lowercase();
    if trim_padding(stem).is_empty() || !is_exec_ext(&last) || !is_bait_ext(&prev_clean) {
        return None;
    }
    let shown = format!("{}.{prev_clean}", trim_padding(stem));
    Some(finding(
        DeceptionKind::DoubleExt,
        Confidence::Strong,
        Severity::Alert,
        "deception.double_ext",
        format!("double extension .{prev_clean}.{last}"),
        &format!("{prev}.{last}"),
        format!(
            "the real extension is .{last}, hidden behind .{prev_clean}; with known extensions \
             hidden this displays as \"{shown}\"; {RENAME}"
        ),
    ))
}

/// A bidirectional control character (U+202A to U+202E, U+2066 to U+2069) in
/// the name, which reorders how the following characters display.
fn bidi_override(name: &str) -> Option<Finding> {
    let (pos, c) = name
        .chars()
        .enumerate()
        .find(|&(_, c)| is_bidi_control(c))?;
    let escaped: String = name
        .chars()
        .map(|ch| {
            if is_bidi_control(ch) {
                format!("<U+{:04X}>", ch as u32)
            } else {
                ch.to_string()
            }
        })
        .collect();
    Some(finding(
        DeceptionKind::Rtlo,
        Confidence::Strong,
        Severity::Alert,
        "deception.rtlo",
        format!("bidirectional control U+{:04X} in the file name", c as u32),
        c.encode_utf8(&mut [0u8; 4]),
        format!(
            "character {} reorders the displayed name; the stored name is \"{escaped}\"; {RENAME}",
            pos + 1
        ),
    ))
}

/// Five or more spaces, or any invisible character, right before the final
/// extension, so a narrow view cuts the real extension off.
fn hidden_ext(name: &str) -> Option<Finding> {
    let (stem, ext) = name.rsplit_once('.')?;
    if ext.is_empty() {
        return None;
    }
    let run: Vec<char> = stem
        .chars()
        .rev()
        .take_while(|&c| c == ' ' || is_invisible(c))
        .collect();
    if run.len() == stem.chars().count() {
        // Nothing but padding before the dot: a dotfile, not a disguise.
        return None;
    }
    let spaces = run.iter().filter(|&&c| c == ' ').count();
    let invisible = run.iter().filter(|&&c| is_invisible(c)).count();
    if spaces < 5 && invisible == 0 {
        return None;
    }
    let what = match (spaces, invisible) {
        (s, 0) => format!("{s} spaces"),
        (0, i) => format!("{i} invisible character(s)"),
        (s, i) => format!("{s} spaces and {i} invisible character(s)"),
    };
    let padding: String = run.iter().rev().collect();
    Some(finding(
        DeceptionKind::HiddenExt,
        Confidence::Strong,
        Severity::Warn,
        "deception.hidden_ext",
        format!("extension .{ext} pushed out of view by padding"),
        &format!("{padding}.{ext}"),
        format!("{what} sit right before .{ext}, so a narrow view hides the real type; {RENAME}"),
    ))
}

const ARCHIVES: &[&str] = &[
    "zip", "jar", "apk", "rar", "7z", "gzip", "xz", "zstd", "bzip2", "tar",
];

/// Words that follow "password" in names without being a password.
const NOT_A_VALUE: &[&str] = &[
    "protected",
    "protection",
    "required",
    "reset",
    "list",
    "lists",
    "manager",
    "recovery",
    "cracker",
    "file",
    "files",
    "inside",
];

/// An archive whose name carries `pass`, `pw`, `pwd` or `password` followed by
/// an optional separator and a value, such as `tools_pw-infected.zip`.
fn pw_in_name(name: &str, format: Option<&str>) -> Option<Finding> {
    if !format.is_some_and(|f| ARCHIVES.contains(&f)) {
        return None;
    }
    let stem = name.rsplit_once('.').map_or(name, |(s, _)| s);
    let lower: Vec<char> = stem.chars().map(|c| c.to_ascii_lowercase()).collect();
    let mut i = 0;
    while i < lower.len() {
        let boundary = i == 0 || !lower[i - 1].is_alphanumeric();
        if boundary && let Some((start, end)) = pw_value_at(&lower, i) {
            let original: String = stem.chars().skip(i).take(end - i).collect();
            let value: String = stem.chars().skip(start).take(end - start).collect();
            return Some(finding(
                DeceptionKind::PwInFilename,
                Confidence::Moderate,
                Severity::Notice,
                "deception.pw_in_name",
                "archive password written into the file name".to_string(),
                &original,
                format!(
                    "\"{original}\" looks like a password (\"{value}\"); encrypted archives \
                     passed around this way often hide content from scanners; {RENAME}"
                ),
            ));
        }
        i += 1;
    }
    None
}

/// At `i`, match a keyword then an optional separator and a value. Returns
/// the value's start and end char indices.
fn pw_value_at(s: &[char], i: usize) -> Option<(usize, usize)> {
    const KEYWORDS: [&str; 4] = ["password", "pass", "pwd", "pw"];
    let kw = KEYWORDS.iter().find(|k| {
        k.chars()
            .enumerate()
            .all(|(j, kc)| s.get(i + j) == Some(&kc))
    })?;
    let mut j = i + kw.len();
    let is_sep = |c: char| matches!(c, '=' | ':' | '_' | '-' | ' ' | '~');
    let sep_start = j;
    while s.get(j).is_some_and(|&c| is_sep(c)) {
        j += 1;
    }
    let had_sep = j > sep_start;
    // "password is x" / "pw is x"
    if had_sep && s.get(j) == Some(&'i') && s.get(j + 1) == Some(&'s') {
        let after = j + 2;
        if s.get(after).is_some_and(|&c| is_sep(c)) {
            j = after;
            while s.get(j).is_some_and(|&c| is_sep(c)) {
                j += 1;
            }
        }
    }
    let start = j;
    if !had_sep && !s.get(start).is_some_and(|c| c.is_ascii_digit()) {
        // Letters glued to the keyword form a word ("passport", "pwned").
        return None;
    }
    let mut end = start;
    while s
        .get(end)
        .is_some_and(|&c| !is_sep(c) && !matches!(c, '.' | ')' | ']' | '}' | '(' | '[' | '{'))
    {
        end += 1;
    }
    if end - start < 2 {
        return None;
    }
    let value: String = s[start..end].iter().collect();
    if NOT_A_VALUE.contains(&value.as_str()) {
        return None;
    }
    Some((start, end))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::MemView;

    fn run(name: &str, format: Option<&str>) -> Vec<Finding> {
        let view = MemView::new(name, b"payload".to_vec());
        let ctx = ProbeCtx::new(&view, format);
        let mut out = Vec::new();
        NameProbe.run(&ctx, &mut out);
        out
    }

    fn ids(name: &str, format: Option<&str>) -> Vec<String> {
        run(name, format)
            .into_iter()
            .map(|f| f.signature_id)
            .collect()
    }

    #[test]
    fn double_extension() {
        let f = run("invoice.pdf.exe", Some("pe"));
        assert_eq!(f.len(), 1);
        let f = &f[0];
        assert_eq!(f.signature_id, "deception.double_ext");
        assert_eq!(f.category, Category::Deception(DeceptionKind::DoubleExt));
        assert_eq!(f.confidence, Confidence::Strong);
        assert_eq!(f.severity, Severity::Alert);
        assert!(f.marker.is_none());
        assert!(f.evidence.note.as_deref().unwrap().contains("renaming"));
        assert_eq!(f.evidence.matched, b"pdf.exe");
        for name in [
            "Photo.JPG.scr",
            "song.mp3.js",
            "scan.docx.lnk",
            "clip.mp4.bat",
            "a.b.png.hta",
        ] {
            assert_eq!(ids(name, None), ["deception.double_ext"], "{name}");
        }
        for name in [
            "archive.tar.gz",
            "setup.x86.exe",
            "report.pdf",
            "lib.so.1",
            ".pdf.exe",
            "data.zip.exe",
            "invoice.exe.pdf",
            "plain",
        ] {
            assert!(ids(name, None).is_empty(), "{name}");
        }
    }

    #[test]
    fn bidi_controls() {
        let f = run("photo\u{202E}gpj.exe", Some("pe"));
        assert_eq!(f.len(), 1);
        let f = &f[0];
        assert_eq!(f.signature_id, "deception.rtlo");
        assert_eq!(f.category, Category::Deception(DeceptionKind::Rtlo));
        assert_eq!(f.severity, Severity::Alert);
        assert_eq!(f.confidence, Confidence::Strong);
        assert_eq!(f.evidence.matched, "\u{202E}".as_bytes());
        assert!(f.evidence.note.as_deref().unwrap().contains("<U+202E>"));
        for c in [
            '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{2066}', '\u{2069}',
        ] {
            let name = format!("a{c}b.txt");
            assert_eq!(ids(&name, None), ["deception.rtlo"], "{c:?}");
        }
        assert!(ids("a\u{2029}b\u{2070}.txt", None).is_empty());
    }

    #[test]
    fn hidden_extension() {
        let f = run("invoice      .exe", Some("pe"));
        assert_eq!(f.len(), 1);
        let f = &f[0];
        assert_eq!(f.signature_id, "deception.hidden_ext");
        assert_eq!(f.category, Category::Deception(DeceptionKind::HiddenExt));
        assert_eq!(f.severity, Severity::Warn);
        assert_eq!(f.confidence, Confidence::Strong);
        assert_eq!(f.evidence.matched, b"      .exe");
        for name in [
            "a\u{00A0}.exe",
            "a\u{2007}\u{2007}.exe",
            "a\u{200B}.exe",
            "a\u{3164}.exe",
            "a  \u{00A0}  .exe",
        ] {
            assert_eq!(ids(name, None), ["deception.hidden_ext"], "{name:?}");
        }
        for name in ["a    .exe", "my file.txt", "     .bashrc", "trailing.", "x"] {
            assert!(ids(name, None).is_empty(), "{name:?}");
        }
    }

    #[test]
    fn padded_double_extension_fires_both() {
        let got = ids("invoice.pdf                    .exe", Some("pe"));
        assert_eq!(got, ["deception.double_ext", "deception.hidden_ext"]);
    }

    #[test]
    fn password_in_archive_name() {
        let f = run("tools_pw-infected.zip", Some("zip"));
        assert_eq!(f.len(), 1);
        let f = &f[0];
        assert_eq!(f.signature_id, "deception.pw_in_name");
        assert_eq!(f.category, Category::Deception(DeceptionKind::PwInFilename));
        assert_eq!(f.confidence, Confidence::Moderate);
        assert_eq!(f.severity, Severity::Notice);
        assert_eq!(f.evidence.matched, b"pw-infected");
        for (name, fmt) in [
            ("game [pass=abc123].rar", "rar"),
            ("Password is hunter2.7z", "7z"),
            ("files PWD_x9y8.zip", "zip"),
            ("dump pass123.tar", "tar"),
            ("PASSWORD：nope pw: 2024.zip", "zip"),
            ("sample (password infected).zip", "zip"),
        ] {
            assert_eq!(ids(name, Some(fmt)), ["deception.pw_in_name"], "{name}");
        }
        for (name, fmt) in [
            ("passport_scans.zip", Some("zip")),
            ("pwned_tools.zip", Some("zip")),
            ("password-protected.zip", Some("zip")),
            ("password manager.7z", Some("7z")),
            ("bypass=foo.zip", Some("zip")),
            ("pw-infected.pdf", Some("pdf")),
            ("pw-infected.zip", None),
            ("pass.zip", Some("zip")),
            ("pw_1.zip", Some("zip")),
        ] {
            assert!(ids(name, fmt).is_empty(), "{name}");
        }
    }

    #[test]
    fn ordinary_and_odd_names_are_quiet() {
        for name in [
            "",
            ".",
            "..",
            "report.pdf",
            "setup.exe",
            "photo.jpg",
            "naïve résumé.docx",
            "日本語.txt",
            "a.b.c.d.e",
            "....exe",
        ] {
            assert!(ids(name, Some("zip")).is_empty(), "{name:?}");
        }
    }
}
