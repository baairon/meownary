//! Identify what a file really is from its leading bytes (plus a few
//! positioned reads), independent of its name, and flag when the content
//! contradicts the extension. This runs before every other probe; its format
//! label is what the format-specific parsers gate on.
//!
//! Detection order: the tar magic at offset 257 is checked first, then every
//! magic of four or more bytes, then the short two- and three-byte magics
//! (`MZ`, gzip, `BZh`, JPEG, `BM`, the MP3 frame sync, `#!`). Short magics are
//! only accepted with a plausibility check on the bytes that follow.
//!
//! `MZ` files: a `PE\0\0` signature at `e_lfanew` confirms `pe`. A bare `MZ`
//! (a DOS, NE or LE executable with no PE header) keeps the `pe` label only
//! when its DOS header fields are plausible, and any extension mismatch it
//! causes is reported with Moderate confidence. Text that merely starts with
//! the letters "MZ" gets no label.

use crate::model::{Category, Confidence, DeceptionKind, Evidence, Finding, Severity};
use crate::scan::FileView;
use crate::util::bytes::{slice, u8_at, u16_le, u32_be, u32_le};

use super::media::ebml;

/// Identify `view`. Returns the true-format label (if any matched) and any
/// findings worth surfacing (extension and content mismatches). A file whose
/// content matches its extension produces no finding here; its format still
/// rides along in the report so the UI can label it.
pub fn identify(view: &dyn FileView) -> (Option<&'static str>, Vec<Finding>) {
    let detected = detect(view);
    let mut findings = Vec::new();

    if let (Some(det), Some(ext)) = (detected, extension(view))
        && let Some(info) = ext_info(&ext)
    {
        let harmless = info
            .expected
            .is_some_and(|expected| harmless_swap(&ext, expected, det.label));
        let actual = class_of(det.label);
        if harmless {
            // A known-benign pairing, such as a .zip that is really a jar.
        } else if info.class != actual {
            findings.push(mismatch_finding(&ext, det, info, view));
        } else if let Some(expected) = info.expected
            && expected != det.label
        {
            findings.push(soft_mismatch_finding(&ext, det, expected, view));
        }
    }

    (detected.map(|d| d.label), findings)
}

/// Lowercased final extension of the file, if any.
fn extension(view: &dyn FileView) -> Option<String> {
    view.path()
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
}

/// The magic that matched: the label, where the magic sits, how long it is,
/// and whether it is long or structurally confirmed (Strong) or a short
/// two- or three-byte magic (Moderate).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Detected {
    label: &'static str,
    off: usize,
    len: usize,
    strong: bool,
}

impl Detected {
    fn strong(label: &'static str, off: usize, len: usize) -> Self {
        Self {
            label,
            off,
            len,
            strong: true,
        }
    }

    fn short(label: &'static str, len: usize) -> Self {
        Self {
            label,
            off: 0,
            len,
            strong: false,
        }
    }

    fn confidence(&self) -> Confidence {
        if self.strong {
            Confidence::Strong
        } else {
            Confidence::Moderate
        }
    }

    fn evidence(&self, view: &dyn FileView, note: String) -> Evidence {
        let bytes = slice(view.header(), self.off, self.len.min(16)).unwrap_or_default();
        Evidence::at(self.off as u64)
            .with_bytes(bytes.to_vec())
            .with_note(note)
    }
}

fn mismatch_finding(ext: &str, det: Detected, info: ExtInfo, view: &dyn FileView) -> Finding {
    let actual_class = class_of(det.label);
    // An executable wearing a document, media, image or plain-file extension
    // is the classic lure; call that Alert. Any other class swap is a Notice.
    let severity = if actual_class == Class::Executable
        && matches!(
            info.class,
            Class::Document | Class::Media | Class::Image | Class::Other
        ) {
        Severity::Alert
    } else {
        Severity::Notice
    };
    let implied = match info.expected {
        Some(fmt) => fmt.to_string(),
        None => format!("a {} file", info.class.name()),
    };
    let note = format!(
        "extension implies {implied}, content is {} ({}); a rename to .{} would match",
        det.label,
        actual_class.name(),
        det.label
    );
    Finding {
        category: Category::Identity {
            declared_ext: Some(ext.to_string()),
            true_format: det.label.to_string(),
            mismatch: true,
        },
        confidence: det.confidence(),
        severity,
        signature_id: "identity.ext_mismatch".to_string(),
        title: format!(".{ext} but the bytes are {}", det.label),
        evidence: det.evidence(view, note),
        marker: None,
    }
}

fn soft_mismatch_finding(
    ext: &str,
    det: Detected,
    expected: &'static str,
    view: &dyn FileView,
) -> Finding {
    let note = format!(
        "extension implies {expected}, content is {} (both {}); the file may still open, but its name is wrong",
        det.label,
        class_of(det.label).name()
    );
    Finding {
        category: Category::Deception(DeceptionKind::ExtMismatch),
        confidence: Confidence::Moderate,
        severity: Severity::Notice,
        signature_id: "identity.ext_soft_mismatch".to_string(),
        title: format!(".{ext} holds {} content", det.label),
        evidence: det.evidence(view, note),
        marker: None,
    }
}

/// Pairings that are normal in practice and never worth a finding, even when
/// the classes differ (a .zip holding an Office document, a .doc holding an
/// installer database: both still open as what the extension says).
fn harmless_swap(ext: &str, expected: &str, actual: &str) -> bool {
    match (expected, actual) {
        ("zip", "jar" | "apk" | "ooxml") => ext == "zip",
        ("cfb", "msi") => matches!(ext, "doc" | "xls" | "ppt"),
        ("matroska", "webm") | ("webm", "matroska") => true,
        _ => false,
    }
}

/// Coarse classes used only to decide whether an extension swap is notable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Executable,
    Archive,
    Media,
    Image,
    Document,
    Other,
}

impl Class {
    fn name(self) -> &'static str {
        match self {
            Class::Executable => "executable",
            Class::Archive => "archive",
            Class::Media => "media",
            Class::Image => "image",
            Class::Document => "document",
            Class::Other => "plain",
        }
    }
}

fn class_of(fmt: &str) -> Class {
    match fmt {
        "pe" | "elf" | "macho" | "wasm" | "script" | "lnk" | "class" | "msi" => Class::Executable,
        "zip" | "jar" | "apk" | "rar" | "7z" | "gzip" | "xz" | "zstd" | "bzip2" | "tar" => {
            Class::Archive
        }
        "mp4" | "matroska" | "webm" | "ogg" | "flac" | "mp3" | "wav" | "avi" => Class::Media,
        "png" | "jpeg" | "gif" | "bmp" | "webp" => Class::Image,
        "pdf" | "cfb" | "ooxml" => Class::Document,
        _ => Class::Other,
    }
}

/// What an extension promises: the exact format, when one is unambiguous, and
/// the class either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExtInfo {
    expected: Option<&'static str>,
    class: Class,
}

fn ext_info(ext: &str) -> Option<ExtInfo> {
    if let Some(fmt) = ext_format(ext) {
        return Some(ExtInfo {
            expected: Some(fmt),
            class: class_of(fmt),
        });
    }
    let class = match ext {
        // Scripts run by an interpreter; no magic to expect.
        "js" | "vbs" | "ps1" | "bat" | "cmd" | "hta" => Class::Executable,
        "txt" | "md" | "csv" | "json" | "xml" | "html" | "htm" | "svg" => Class::Other,
        "ico" => Class::Image,
        "iso" => Class::Archive,
        _ => return None,
    };
    Some(ExtInfo {
        expected: None,
        class,
    })
}

/// The format an extension is supposed to carry. Only extensions with an
/// unambiguous expected format are listed.
fn ext_format(ext: &str) -> Option<&'static str> {
    Some(match ext {
        "exe" | "dll" | "sys" | "scr" | "ocx" | "cpl" | "com" | "pif" => "pe",
        "elf" | "so" | "o" => "elf",
        "dylib" => "macho",
        "wasm" => "wasm",
        "lnk" => "lnk",
        "class" => "class",
        "msi" => "msi",
        "zip" => "zip",
        "jar" => "jar",
        "apk" => "apk",
        "rar" => "rar",
        "7z" => "7z",
        "gz" | "tgz" => "gzip",
        "xz" => "xz",
        "zst" => "zstd",
        "bz2" => "bzip2",
        "tar" => "tar",
        "mp4" | "m4v" | "m4a" | "mov" | "heic" | "heif" | "avif" => "mp4",
        "mkv" | "mka" => "matroska",
        "webm" => "webm",
        "ogg" | "oga" | "opus" => "ogg",
        "flac" => "flac",
        "mp3" => "mp3",
        "wav" => "wav",
        "avi" => "avi",
        "png" => "png",
        "jpg" | "jpeg" => "jpeg",
        "gif" => "gif",
        "bmp" => "bmp",
        "webp" => "webp",
        "pdf" => "pdf",
        "doc" | "xls" | "ppt" => "cfb",
        "docx" | "xlsx" | "pptx" => "ooxml",
        _ => return None,
    })
}

fn starts(h: &[u8], sig: &[u8]) -> bool {
    h.starts_with(sig)
}

fn at(h: &[u8], off: usize, sig: &[u8]) -> bool {
    slice(h, off, sig.len()) == Some(sig)
}

/// The magic-byte matcher. Order matters where signatures overlap.
fn detect(view: &dyn FileView) -> Option<Detected> {
    let h = view.header();
    if h.is_empty() {
        return None;
    }
    // A tar header's first 100 bytes are a file name that can begin with any
    // short magic, so the 5-byte `ustar` at 257 wins over them.
    if at(h, 257, b"ustar") {
        return Some(Detected::strong("tar", 257, 5));
    }
    if let Some(d) = detect_long(h, view) {
        return Some(d);
    }
    detect_short(h, view)
}

/// Magics of four bytes or more, or structurally confirmed ones.
fn detect_long(h: &[u8], view: &dyn FileView) -> Option<Detected> {
    let s = Detected::strong;
    if starts(h, b"\x7fELF") {
        return Some(s("elf", 0, 4));
    }
    if starts(h, b"\0asm") {
        return Some(s("wasm", 0, 4));
    }
    match slice(h, 0, 4)? {
        // Mach-O thin, both endiannesses and 32/64-bit.
        [0xfe, 0xed, 0xfa, 0xce]
        | [0xfe, 0xed, 0xfa, 0xcf]
        | [0xce, 0xfa, 0xed, 0xfe]
        | [0xcf, 0xfa, 0xed, 0xfe] => return Some(s("macho", 0, 4)),
        // 0xCAFEBABE is a Mach-O fat header and a Java class file; the u32 at
        // offset 4 disambiguates: a small arch count means fat, a class file
        // carries minor/major version (major >= 45) there.
        [0xca, 0xfe, 0xba, 0xbe] => match u32_be(h, 4) {
            Some(1..=39) => return Some(s("macho", 0, 8)),
            Some(n) if n >= 45 => return Some(s("class", 0, 8)),
            _ => {}
        },
        // 0xCAFEBABF is the 64-bit fat header.
        [0xca, 0xfe, 0xba, 0xbf] => {
            if let Some(1..=39) = u32_be(h, 4) {
                return Some(s("macho", 0, 8));
            }
        }
        _ => {}
    }
    if starts(h, b"PK\x03\x04") || starts(h, b"PK\x05\x06") || starts(h, b"PK\x07\x08") {
        return Some(s(zip_flavor(h), 0, 4));
    }
    if starts(h, b"Rar!\x1a\x07") {
        return Some(s("rar", 0, 6));
    }
    if starts(h, b"7z\xbc\xaf\x27\x1c") {
        return Some(s("7z", 0, 6));
    }
    if starts(h, &[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
        return Some(s("xz", 0, 6));
    }
    if starts(h, &[0x28, 0xb5, 0x2f, 0xfd]) {
        return Some(s("zstd", 0, 4));
    }
    if starts(h, b"%PDF-") {
        return Some(s("pdf", 0, 5));
    }
    if starts(h, &[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]) {
        let label = if cfb_is_msi(h, view) { "msi" } else { "cfb" };
        return Some(s(label, 0, 8));
    }
    if starts(h, &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]) {
        return Some(s("png", 0, 8));
    }
    if starts(h, b"GIF87a") || starts(h, b"GIF89a") {
        return Some(s("gif", 0, 6));
    }
    // RIFF containers: WEBP / WAV / AVI share the leading "RIFF".
    if starts(h, b"RIFF")
        && let Some(form) = slice(h, 8, 4)
    {
        let label = match form {
            b"WEBP" => "webp",
            b"WAVE" => "wav",
            b"AVI " => "avi",
            _ => "riff",
        };
        return Some(s(label, 0, 12));
    }
    if at(h, 4, b"ftyp") {
        return Some(s("mp4", 4, 4));
    }
    if starts(h, &[0x1a, 0x45, 0xdf, 0xa3]) {
        let label = match ebml::doc_type(h) {
            Some(b"webm") => "webm",
            _ => "matroska",
        };
        return Some(s(label, 0, 4));
    }
    if starts(h, b"OggS") {
        return Some(s("ogg", 0, 4));
    }
    if starts(h, b"fLaC") {
        return Some(s("flac", 0, 4));
    }
    if starts(h, &[0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00]) {
        return Some(s("lnk", 0, 8));
    }
    if id3_header_ok(h) {
        return Some(s("mp3", 0, 10));
    }
    None
}

/// Two- and three-byte magics, each with a plausibility check.
fn detect_short(h: &[u8], view: &dyn FileView) -> Option<Detected> {
    if starts(h, b"MZ") {
        match mz_kind(h, view) {
            MzKind::Pe => return Some(Detected::strong("pe", 0, 2)),
            MzKind::BareDos => return Some(Detected::short("pe", 2)),
            MzKind::NotMz => {}
        }
    }
    if starts(h, &[0x1f, 0x8b, 0x08]) {
        return Some(Detected::short("gzip", 3));
    }
    if starts(h, b"BZh") && matches!(u8_at(h, 3), Some(b'1'..=b'9')) {
        return Some(Detected::short("bzip2", 3));
    }
    if starts(h, &[0xff, 0xd8, 0xff]) {
        // The fourth byte is the first segment marker; a real one is structure.
        return Some(match u8_at(h, 3) {
            Some(0xc0..=0xfe) => Detected::strong("jpeg", 0, 4),
            _ => Detected::short("jpeg", 3),
        });
    }
    if starts(h, b"BM") && bmp_header_ok(h) {
        return Some(Detected::short("bmp", 2));
    }
    if mp3_frame_ok(h) {
        return Some(Detected::short("mp3", 2));
    }
    if starts(h, b"#!") {
        return Some(Detected::short("script", 2));
    }
    None
}

enum MzKind {
    /// `PE\0\0` sits at `e_lfanew`.
    Pe,
    /// A plausible DOS header with no PE signature (DOS, NE, LE executables).
    BareDos,
    /// Not an executable at all, just bytes that start with "MZ".
    NotMz,
}

fn mz_kind(h: &[u8], view: &dyn FileView) -> MzKind {
    if let Some(lfanew) = u32_le(h, 0x3c) {
        let lfanew = lfanew as usize;
        let sig = match slice(h, lfanew, 4) {
            Some(s) => Some(s.to_vec()),
            None if lfanew >= h.len() => view.read_at(lfanew as u64, 4).ok(),
            None => None,
        };
        if lfanew >= 4 && sig.as_deref() == Some(b"PE\0\0") {
            return MzKind::Pe;
        }
    }
    // DOS header sanity: bytes in the last page < 512, at least one page, and
    // a header of at least two paragraphs. Printable text never passes the
    // first rule because both of its bytes are 0x20 or higher.
    let plausible = matches!(u16_le(h, 2), Some(0..=511))
        && matches!(u16_le(h, 4), Some(1..=0x1000))
        && matches!(u16_le(h, 8), Some(2..=0x400));
    if plausible {
        MzKind::BareDos
    } else {
        MzKind::NotMz
    }
}

/// Root directory entry CLSID of a Windows Installer database,
/// {000C1084-0000-0000-C000-000000000046}, in its on-disk byte order.
const MSI_CLSID: [u8; 16] = [
    0x84, 0x10, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

/// Whether a compound file's root directory entry carries the MSI CLSID. The
/// sector size comes from the header and the directory is read with one
/// positioned read.
fn cfb_is_msi(h: &[u8], view: &dyn FileView) -> bool {
    let Some(shift) = u16_le(h, 0x1e) else {
        return false;
    };
    if !(7..=16).contains(&shift) {
        return false;
    }
    let Some(first_dir) = u32_le(h, 0x30) else {
        return false;
    };
    if first_dir >= 0xFFFF_FFFA {
        return false;
    }
    let Some(off) = (u64::from(first_dir) + 1).checked_shl(u32::from(shift)) else {
        return false;
    };
    let Ok(entry) = view.read_at(off, 128) else {
        return false;
    };
    u8_at(&entry, 0x42) == Some(5) && slice(&entry, 0x50, 16) == Some(&MSI_CLSID[..])
}

/// Classify a zip by the names in the first local headers that fit in the
/// header window: `apk`, `jar`, `ooxml`, or plain `zip`.
fn zip_flavor(h: &[u8]) -> &'static str {
    let names = local_names(h);
    if names
        .iter()
        .any(|n| *n == b"AndroidManifest.xml" || *n == b"classes.dex")
    {
        return "apk";
    }
    if let Some(first) = names.first()
        && (*first == b"META-INF/" || *first == b"META-INF/MANIFEST.MF")
    {
        return "jar";
    }
    let ooxml = names.iter().take(8).any(|n| {
        *n == b"[Content_Types].xml" || n.starts_with(b"_rels/") || n.starts_with(b"docProps/")
    });
    if ooxml { "ooxml" } else { "zip" }
}

/// File names of up to 64 consecutive local file headers from the start of
/// the header window. Stops at the first header whose data length is unknown.
fn local_names(h: &[u8]) -> Vec<&[u8]> {
    let mut names = Vec::new();
    let mut off = if starts(h, b"PK\x07\x08") { 4 } else { 0 };
    for _ in 0..64 {
        if slice(h, off, 4) != Some(b"PK\x03\x04") {
            break;
        }
        let (Some(flags), Some(csize), Some(nlen), Some(xlen)) = (
            u16_le(h, off + 6),
            u32_le(h, off + 18),
            u16_le(h, off + 26),
            u16_le(h, off + 28),
        ) else {
            break;
        };
        let Some(name) = slice(h, off + 30, usize::from(nlen)) else {
            break;
        };
        names.push(name);
        let descriptor = flags & 0x08 != 0;
        if (descriptor && csize == 0) || csize == u32::MAX {
            break;
        }
        let next = off
            .checked_add(30 + usize::from(nlen) + usize::from(xlen))
            .and_then(|o| o.checked_add(csize as usize));
        let Some(next) = next else {
            break;
        };
        off = next;
        if descriptor {
            let skip = if slice(h, off, 4) == Some(b"PK\x07\x08") {
                16
            } else {
                12
            };
            off = off.saturating_add(skip);
        }
    }
    names
}

/// A valid ID3v2 tag header: version 2 to 4, and four syncsafe size bytes.
fn id3_header_ok(h: &[u8]) -> bool {
    let Some(hdr) = slice(h, 0, 10) else {
        return false;
    };
    hdr.starts_with(b"ID3")
        && (2..=4).contains(&hdr[3])
        && hdr[4] != 0xff
        && hdr[6..10].iter().all(|&b| b < 0x80)
}

/// A plausible MPEG audio frame header at offset 0: sync, a defined version
/// and layer, and a usable bitrate and sample rate.
fn mp3_frame_ok(h: &[u8]) -> bool {
    let Some(f) = slice(h, 0, 3) else {
        return false;
    };
    f[0] == 0xff
        && f[1] & 0xe0 == 0xe0
        && (f[1] >> 3) & 0x03 != 0x01
        && (f[1] >> 1) & 0x03 != 0x00
        && f[2] >> 4 != 0x0f
        && (f[2] >> 2) & 0x03 != 0x03
}

/// A `BM` file header followed by a known DIB header size.
fn bmp_header_ok(h: &[u8]) -> bool {
    matches!(u32_le(h, 14), Some(12 | 16 | 40 | 52 | 56 | 64 | 108 | 124))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::MemView;

    fn id(name: &str, bytes: &[u8]) -> (Option<&'static str>, Vec<Finding>) {
        identify(&MemView::new(name, bytes.to_vec()))
    }

    fn label(bytes: &[u8]) -> Option<&'static str> {
        id("noext", bytes).0
    }

    pub(super) fn pe() -> Vec<u8> {
        let mut b = vec![0u8; 0x80];
        b[0..2].copy_from_slice(b"MZ");
        b[2..4].copy_from_slice(&0x90u16.to_le_bytes());
        b[4..6].copy_from_slice(&3u16.to_le_bytes());
        b[8..10].copy_from_slice(&4u16.to_le_bytes());
        b[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        b[0x40..0x44].copy_from_slice(b"PE\0\0");
        b
    }

    fn bare_mz() -> Vec<u8> {
        let mut b = pe();
        b[0x40..0x44].copy_from_slice(b"NE\0\0");
        b
    }

    fn zip_entry(name: &str, data: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(b"PK\x03\x04");
        b.extend_from_slice(&20u16.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes()); // flags
        b.extend_from_slice(&0u16.to_le_bytes()); // stored
        b.extend_from_slice(&[0; 8]); // time, date, crc
        b.extend_from_slice(&(data.len() as u32).to_le_bytes());
        b.extend_from_slice(&(data.len() as u32).to_le_bytes());
        b.extend_from_slice(&(name.len() as u16).to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(name.as_bytes());
        b.extend_from_slice(data);
        b
    }

    fn zip_of(names: &[&str]) -> Vec<u8> {
        names.iter().flat_map(|n| zip_entry(n, b"data")).collect()
    }

    fn cfb(clsid: [u8; 16]) -> Vec<u8> {
        let mut b = vec![0u8; 512 * 3];
        b[0..8].copy_from_slice(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
        b[0x1a..0x1c].copy_from_slice(&3u16.to_le_bytes());
        b[0x1c..0x1e].copy_from_slice(&0xfffeu16.to_le_bytes());
        b[0x1e..0x20].copy_from_slice(&9u16.to_le_bytes());
        b[0x30..0x34].copy_from_slice(&1u32.to_le_bytes());
        let dir = 1024;
        for (i, c) in "Root Entry".encode_utf16().enumerate() {
            b[dir + i * 2..dir + i * 2 + 2].copy_from_slice(&c.to_le_bytes());
        }
        b[dir + 0x40] = 22;
        b[dir + 0x42] = 5;
        b[dir + 0x50..dir + 0x60].copy_from_slice(&clsid);
        b
    }

    fn ebml(doc: &[u8]) -> Vec<u8> {
        let mut kids = vec![0x42, 0x86, 0x81, 0x01, 0x42, 0x82, 0x80 | doc.len() as u8];
        kids.extend_from_slice(doc);
        let mut b = vec![0x1a, 0x45, 0xdf, 0xa3, 0x80 | kids.len() as u8];
        b.extend_from_slice(&kids);
        b.extend_from_slice(&[0x18, 0x53, 0x80, 0x67, 0x80]);
        b
    }

    fn tar_with_name(name: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; 1024];
        b[..name.len()].copy_from_slice(name);
        b[257..263].copy_from_slice(b"ustar\0");
        b
    }

    fn bmp() -> Vec<u8> {
        let mut b = vec![0u8; 64];
        b[0..2].copy_from_slice(b"BM");
        b[14..18].copy_from_slice(&40u32.to_le_bytes());
        b
    }

    fn riff(form: &[u8]) -> Vec<u8> {
        let mut b = b"RIFF\x04\0\0\0".to_vec();
        b.extend_from_slice(form);
        b
    }

    #[test]
    fn executables() {
        assert_eq!(label(&pe()), Some("pe"));
        assert_eq!(label(&bare_mz()), Some("pe"));
        assert_eq!(
            label(b"MZ is a text file that starts with two letters"),
            None
        );
        assert_eq!(label(b"\x7fELF\x02\x01\x01\0"), Some("elf"));
        assert_eq!(label(b"\x7fELG\x02\x01\x01\0"), None);
        assert_eq!(label(b"\0asm\x01\0\0\0"), Some("wasm"));
        assert_eq!(label(b"\0asn\x01\0\0\0"), None);
        assert_eq!(label(&[0xcf, 0xfa, 0xed, 0xfe, 7, 0, 0, 1]), Some("macho"));
        assert_eq!(label(&[0xfe, 0xed, 0xfa, 0xce, 0, 0, 0, 7]), Some("macho"));
        assert_eq!(label(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2]), Some("macho"));
        assert_eq!(label(&[0xca, 0xfe, 0xba, 0xbf, 0, 0, 0, 2]), Some("macho"));
        assert_eq!(
            label(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0x34]),
            Some("class")
        );
        assert_eq!(label(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 42]), None);
        assert_eq!(label(&[0xca, 0xfe, 0xba, 0xbe, 0, 0]), None);
        assert_eq!(label(&[0xca, 0xfe, 0xba, 0xbf, 0, 0, 0x01, 0]), None);
        let mut lnk = vec![0x4c, 0, 0, 0, 0x01, 0x14, 0x02, 0x00];
        lnk.extend_from_slice(&[0; 12]);
        assert_eq!(label(&lnk), Some("lnk"));
        lnk[4] = 0x02;
        assert_eq!(label(&lnk), None);
        assert_eq!(label(b"#!/bin/sh\necho hi\n"), Some("script"));
        assert_eq!(label(b"# not a shebang"), None);
    }

    #[test]
    fn pe_signature_beyond_header_window() {
        let mut b = pe();
        b.resize(70_000, 0);
        b[0x40..0x44].copy_from_slice(&[0; 4]);
        b[0x3c..0x40].copy_from_slice(&66_000u32.to_le_bytes());
        b[66_000..66_004].copy_from_slice(b"PE\0\0");
        let det = detect(&MemView::new("x", b)).unwrap();
        assert_eq!(det.label, "pe");
        assert!(det.strong);
    }

    #[test]
    fn bare_mz_is_moderate() {
        let det = detect(&MemView::new("x", bare_mz())).unwrap();
        assert_eq!(det.label, "pe");
        assert!(!det.strong);
    }

    #[test]
    fn zip_family() {
        assert_eq!(label(&zip_of(&["readme.txt"])), Some("zip"));
        assert_eq!(label(&zip_of(&["META-INF/", "a.class"])), Some("jar"));
        assert_eq!(label(&zip_of(&["META-INF/MANIFEST.MF"])), Some("jar"));
        assert_eq!(label(&zip_of(&["META-INF2/", "a.class"])), Some("zip"));
        assert_eq!(
            label(&zip_of(&["res/a.png", "AndroidManifest.xml"])),
            Some("apk")
        );
        assert_eq!(
            label(&zip_of(&["META-INF/MANIFEST.MF", "classes.dex"])),
            Some("apk")
        );
        assert_eq!(
            label(&zip_of(&["[Content_Types].xml", "word/document.xml"])),
            Some("ooxml")
        );
        assert_eq!(label(&zip_of(&["_rels/.rels"])), Some("ooxml"));
        assert_eq!(
            label(&zip_of(&["mimetype", "docProps/app.xml"])),
            Some("ooxml")
        );
        assert_eq!(label(&zip_of(&["Content_Types.xml"])), Some("zip"));
        assert_eq!(
            label(b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"),
            Some("zip")
        );
        assert_eq!(label(b"PK\x03"), None);
        // A header whose name runs past the buffer still labels as zip.
        let mut cut = zip_entry("AndroidManifest.xml", b"");
        cut.truncate(35);
        assert_eq!(label(&cut), Some("zip"));
    }

    #[test]
    fn archives() {
        assert_eq!(label(b"Rar!\x1a\x07\x01\0"), Some("rar"));
        assert_eq!(label(b"Rar!\x1a\x08\x01\0"), None);
        assert_eq!(label(b"7z\xbc\xaf\x27\x1c\0\x04"), Some("7z"));
        assert_eq!(label(b"7z\xbc\xaf\x27\x1d\0\x04"), None);
        assert_eq!(label(b"\x1f\x8b\x08\0\0\0\0\0"), Some("gzip"));
        assert_eq!(label(b"\x1f\x8b\x07\0\0\0\0\0"), None);
        assert_eq!(label(b"\xfd7zXZ\0\0\x04"), Some("xz"));
        assert_eq!(label(b"\xfd7zXY\0\0\x04"), None);
        assert_eq!(label(&[0x28, 0xb5, 0x2f, 0xfd, 0, 0]), Some("zstd"));
        assert_eq!(label(&[0x28, 0xb5, 0x2f, 0xfe, 0, 0]), None);
        assert_eq!(label(b"BZh91AY&SY"), Some("bzip2"));
        assert_eq!(label(b"BZh is not bzip2"), None);
        assert_eq!(label(&tar_with_name(b"notes.txt")), Some("tar"));
        let mut near = tar_with_name(b"notes.txt");
        near[257..263].copy_from_slice(b"\0ustar");
        assert_eq!(label(&near), None);
    }

    #[test]
    fn tar_wins_over_short_magics_in_its_name_field() {
        assert_eq!(label(&tar_with_name(b"MZ_tool.exe")), Some("tar"));
        assert_eq!(
            label(&tar_with_name(b"BM\0\0\0\0\0\0\0\0\0\0\0\0\x28\0\0\0")),
            Some("tar")
        );
        assert_eq!(label(&tar_with_name(b"#!run.sh")), Some("tar"));
    }

    #[test]
    fn documents() {
        assert_eq!(label(b"%PDF-1.7\n"), Some("pdf"));
        assert_eq!(label(b"%PDF1.7\n"), None);
        assert_eq!(label(&cfb([0; 16])), Some("cfb"));
        assert_eq!(label(&cfb(MSI_CLSID)), Some("msi"));
        let mut patch = MSI_CLSID;
        patch[0] = 0x86;
        assert_eq!(label(&cfb(patch)), Some("cfb"));
        // A directory sector pointing past EOF is plain cfb, no panic.
        let mut far = cfb(MSI_CLSID);
        far[0x30..0x34].copy_from_slice(&0x00ff_ffffu32.to_le_bytes());
        assert_eq!(label(&far), Some("cfb"));
        let mut bad_shift = cfb(MSI_CLSID);
        bad_shift[0x1e..0x20].copy_from_slice(&40u16.to_le_bytes());
        assert_eq!(label(&bad_shift), Some("cfb"));
        assert_eq!(label(&cfb(MSI_CLSID)[..8]), Some("cfb"));
    }

    #[test]
    fn images() {
        assert_eq!(label(b"\x89PNG\r\n\x1a\n\0\0"), Some("png"));
        assert_eq!(label(b"\x89PNG\r\n\x1a\x0b"), None);
        assert_eq!(label(&[0xff, 0xd8, 0xff, 0xe0, 0, 0x10]), Some("jpeg"));
        assert_eq!(label(&[0xff, 0xd8, 0xff]), Some("jpeg"));
        assert_eq!(label(&[0xff, 0xd8, 0xfe, 0xe0]), None);
        assert_eq!(label(b"GIF89a\x01\0"), Some("gif"));
        assert_eq!(label(b"GIF90a\x01\0"), None);
        assert_eq!(label(&bmp()), Some("bmp"));
        assert_eq!(label(b"BMW owners manual, chapter one"), None);
        assert_eq!(label(&riff(b"WEBP")), Some("webp"));
    }

    #[test]
    fn media() {
        assert_eq!(label(&riff(b"WAVE")), Some("wav"));
        assert_eq!(label(&riff(b"AVI ")), Some("avi"));
        assert_eq!(label(&riff(b"CDXA")), Some("riff"));
        assert_eq!(label(b"RIFF\x04\0\0\0WA"), None);
        assert_eq!(label(b"\0\0\0\x18ftypisom"), Some("mp4"));
        assert_eq!(label(b"\0\0\0\x18ftyq"), None);
        assert_eq!(label(&ebml(b"webm")), Some("webm"));
        assert_eq!(label(&ebml(b"matroska")), Some("matroska"));
        assert_eq!(label(&[0x1a, 0x45, 0xdf, 0xa3, 0x00]), Some("matroska"));
        assert_eq!(label(b"OggS\0\x02\0\0"), Some("ogg"));
        assert_eq!(label(b"Oggs\0\x02\0\0"), None);
        assert_eq!(label(b"fLaC\0\0\0\x22"), Some("flac"));
        assert_eq!(label(b"FLAC\0\0\0\x22"), None);
        assert_eq!(label(b"ID3\x04\0\0\0\0\0\x0a"), Some("mp3"));
        assert_eq!(label(b"ID3\x04\0\0\x80\0\0\x0a"), None);
        assert_eq!(label(b"ID3 tags are nice"), None);
        assert_eq!(label(&[0xff, 0xfb, 0x90, 0x64]), Some("mp3"));
        // AAC ADTS (layer bits 00) and reserved values are not MP3.
        assert_eq!(label(&[0xff, 0xf1, 0x50, 0x80]), None);
        assert_eq!(label(&[0xff, 0xfb, 0xf0, 0x64]), None);
        assert_eq!(label(&[0xff, 0xfb, 0x9c, 0x64]), None);
    }

    #[test]
    fn tiny_inputs_never_panic() {
        let seeds: [&[u8]; 12] = [
            b"",
            b"M",
            b"MZ",
            b"PK",
            b"\xca\xfe\xba\xbe",
            b"\xca\xfe\xba\xbf\0",
            b"ID3",
            b"\xff\xfb",
            b"\x1a\x45\xdf\xa3",
            b"RIFF",
            b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
            b"BM\0\0\0\0\0\0",
        ];
        for seed in seeds {
            for n in 0..=seed.len().min(8) {
                for name in ["a.jpg", "a.exe", "noext", "a.zip"] {
                    let _ = id(name, &seed[..n]);
                }
            }
        }
        for len in 0..=8 {
            for fill in [0u8, 0xff, b'M', b'P'] {
                let _ = id("x.pdf", &vec![fill; len]);
            }
        }
    }

    fn only(findings: &[Finding]) -> &Finding {
        assert_eq!(findings.len(), 1, "{findings:?}");
        &findings[0]
    }

    #[test]
    fn exe_wearing_image_mask_is_strong_alert() {
        let (fmt, f) = id("photo.jpg", &pe());
        assert_eq!(fmt, Some("pe"));
        let f = only(&f);
        assert_eq!(f.signature_id, "identity.ext_mismatch");
        assert_eq!(f.severity, Severity::Alert);
        assert_eq!(f.confidence, Confidence::Strong);
        assert_eq!(
            f.category,
            Category::Identity {
                declared_ext: Some("jpg".into()),
                true_format: "pe".into(),
                mismatch: true
            }
        );
        assert_eq!(f.evidence.offset, 0);
        assert_eq!(f.evidence.matched, b"MZ");
        assert!(f.marker.is_none());
    }

    #[test]
    fn mismatch_confidence_follows_magic_length() {
        let (_, f) = id("photo.jpg", &bare_mz());
        let f = only(&f);
        assert_eq!(f.severity, Severity::Alert);
        assert_eq!(f.confidence, Confidence::Moderate);

        let (_, f) = id("song.mp3", &bmp());
        let f = only(&f);
        assert_eq!(f.severity, Severity::Notice);
        assert_eq!(f.confidence, Confidence::Moderate);

        let (_, f) = id("notes.txt", &zip_of(&["a"]));
        let f = only(&f);
        assert_eq!(f.signature_id, "identity.ext_mismatch");
        assert_eq!(f.severity, Severity::Notice);
        assert_eq!(f.confidence, Confidence::Strong);

        let (_, f) = id("clip.mp4", &tar_with_name(b"a"));
        let f = only(&f);
        assert_eq!(f.evidence.offset, 257);
        assert_eq!(f.evidence.matched, b"ustar");
    }

    #[test]
    fn alert_only_for_executable_behind_non_executable_mask() {
        for (name, alert) in [
            ("a.pdf", true),
            ("a.mp3", true),
            ("a.png", true),
            ("a.txt", true),
            ("a.zip", false),
            ("a.tar", false),
        ] {
            let (_, f) = id(name, &pe());
            let f = only(&f);
            assert_eq!(f.severity == Severity::Alert, alert, "{name}");
        }
        // A document wearing an executable extension is only a notice.
        let (_, f) = id("setup.exe", b"%PDF-1.4\n");
        assert_eq!(only(&f).severity, Severity::Notice);
        // A .pdf holding an installer is an executable behind a document mask.
        let (_, f) = id("report.pdf", &cfb(MSI_CLSID));
        let f = only(&f);
        assert_eq!(f.severity, Severity::Alert);
        assert_eq!(f.signature_id, "identity.ext_mismatch");
        // Script-only extensions carry no magic but are executable class.
        let (_, f) = id("run.js", &pe());
        assert!(f.is_empty());
        let (_, f) = id("run.js", b"%PDF-1.4\n");
        assert_eq!(only(&f).severity, Severity::Notice);
    }

    #[test]
    fn matching_content_is_silent() {
        assert!(id("a.exe", &pe()).1.is_empty());
        assert!(id("a.scr", &pe()).1.is_empty());
        assert!(id("a.jar", &zip_of(&["META-INF/"])).1.is_empty());
        assert!(id("a.docx", &zip_of(&["[Content_Types].xml"])).1.is_empty());
        assert!(id("a.msi", &cfb(MSI_CLSID)).1.is_empty());
        assert!(id("a.webm", &ebml(b"webm")).1.is_empty());
        assert!(id("a.heic", b"\0\0\0\x18ftypheic").1.is_empty());
        assert!(id("a.m4a", b"\0\0\0\x18ftypM4A ").1.is_empty());
        assert!(id("a.unknownext", &pe()).1.is_empty());
        assert!(id("noext", &pe()).1.is_empty());
        assert!(id("a.txt", b"plain words").1.is_empty());
    }

    #[test]
    fn soft_mismatch_within_class() {
        let (_, f) = id("photo.png", &[0xff, 0xd8, 0xff, 0xe0, 0, 0x10]);
        let f = only(&f);
        assert_eq!(f.signature_id, "identity.ext_soft_mismatch");
        assert_eq!(f.category, Category::Deception(DeceptionKind::ExtMismatch));
        assert_eq!(f.confidence, Confidence::Moderate);
        assert_eq!(f.severity, Severity::Notice);

        let (_, f) = id("tool.exe", b"\x7fELF\x02\x01\x01\0");
        assert_eq!(only(&f).signature_id, "identity.ext_soft_mismatch");
        let (_, f) = id("app.apk", &zip_of(&["META-INF/"]));
        assert_eq!(only(&f).signature_id, "identity.ext_soft_mismatch");
        let (_, f) = id("setup.exe", &cfb(MSI_CLSID));
        assert_eq!(only(&f).signature_id, "identity.ext_soft_mismatch");
    }

    #[test]
    fn harmless_families_are_skipped() {
        assert!(id("a.zip", &zip_of(&["META-INF/"])).1.is_empty());
        assert!(id("a.zip", &zip_of(&["AndroidManifest.xml"])).1.is_empty());
        assert!(id("a.zip", &zip_of(&["[Content_Types].xml"])).1.is_empty());
        assert!(id("a.jpeg", &[0xff, 0xd8, 0xff, 0xe1]).1.is_empty());
        assert!(id("a.mov", b"\0\0\0\x14ftypqt  ").1.is_empty());
        assert!(id("a.mkv", &ebml(b"webm")).1.is_empty());
        assert!(id("a.webm", &ebml(b"matroska")).1.is_empty());
        assert!(id("a.xls", &cfb([0; 16])).1.is_empty());
        assert!(id("a.doc", &cfb(MSI_CLSID)).1.is_empty());
        assert!(id("a.ppt", &cfb(MSI_CLSID)).1.is_empty());
        // A jar named .zip is fine, but a zip named .jar is still a swap.
        assert!(!id("a.jar", &zip_of(&["readme"])).1.is_empty());
    }
}
