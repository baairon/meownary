//! Identify what a file really is from its leading (and a few trailing) bytes,
//! independent of its name, and flag when the content contradicts the
//! extension. This runs before every other probe; its format slug is what the
//! format-specific parsers gate on.

use crate::model::{Category, Confidence, Evidence, Finding, Severity};
use crate::scan::FileView;

/// Identify `view`. Returns the true-format slug (if any matched) and any
/// findings worth surfacing (currently: extension/content mismatches). A file
/// whose content matches its extension produces no finding here; its format
/// still rides along in the report so the UI can label it.
pub fn identify(view: &dyn FileView) -> (Option<&'static str>, Vec<Finding>) {
    let header = view.header();
    let format = detect(header, view);
    let mut findings = Vec::new();

    if let Some(fmt) = format {
        if let Some(ext) = extension(view) {
            if let Some(expected) = ext_format(&ext) {
                if class_of(expected) != class_of(fmt) {
                    findings.push(mismatch_finding(&ext, fmt, expected));
                }
            }
        }
    }

    (format, findings)
}

/// Lowercased final extension of the file, if any.
fn extension(view: &dyn FileView) -> Option<String> {
    view.path()
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
}

fn mismatch_finding(ext: &str, actual: &'static str, expected: &'static str) -> Finding {
    // An executable wearing a document/media/image extension is the classic
    // lure; call that Alert. Any other class swap is a Notice.
    let severity =
        if class_of(actual) == Class::Executable && class_of(expected) != Class::Executable {
            Severity::Alert
        } else {
            Severity::Notice
        };
    Finding {
        category: Category::Identity {
            declared_ext: Some(ext.to_string()),
            true_format: actual.to_string(),
            mismatch: true,
        },
        confidence: Confidence::Strong,
        severity,
        signature_id: "identity.ext_mismatch".to_string(),
        title: format!(".{ext} but the bytes are {actual}"),
        evidence: Evidence::at(0)
            .with_note(format!("extension implies {expected}, content is {actual}")),
        marker: None,
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

fn class_of(fmt: &str) -> Class {
    match fmt {
        "pe" | "elf" | "macho" | "wasm" | "script" | "lnk" | "class" => Class::Executable,
        "zip" | "rar" | "7z" | "gzip" | "xz" | "zstd" | "bzip2" | "tar" => Class::Archive,
        "mp4" | "matroska" | "ogg" | "flac" | "mp3" | "wav" | "avi" => Class::Media,
        "png" | "jpeg" | "gif" | "bmp" | "webp" => Class::Image,
        "pdf" | "cfb" => Class::Document,
        _ => Class::Other,
    }
}

/// The format an extension is supposed to carry (for mismatch detection). Only
/// extensions with an unambiguous expected format are listed.
fn ext_format(ext: &str) -> Option<&'static str> {
    Some(match ext {
        "exe" | "dll" | "sys" | "scr" | "ocx" | "cpl" => "pe",
        "elf" | "so" | "o" => "elf",
        "dylib" => "macho",
        "wasm" => "wasm",
        "lnk" => "lnk",
        "class" => "class",
        "zip" => "zip",
        "rar" => "rar",
        "7z" => "7z",
        "gz" | "tgz" => "gzip",
        "xz" => "xz",
        "zst" => "zstd",
        "bz2" => "bzip2",
        "tar" => "tar",
        "mp4" | "m4v" | "mov" => "mp4",
        "mkv" | "webm" => "matroska",
        "ogg" | "oga" => "ogg",
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
        "doc" | "xls" | "ppt" | "msi" => "cfb",
        _ => return None,
    })
}

fn starts(h: &[u8], sig: &[u8]) -> bool {
    h.len() >= sig.len() && &h[..sig.len()] == sig
}

fn at(h: &[u8], off: usize, sig: &[u8]) -> bool {
    h.len() >= off + sig.len() && &h[off..off + sig.len()] == sig
}

/// The magic-byte matcher. Order matters where signatures overlap.
fn detect(h: &[u8], view: &dyn FileView) -> Option<&'static str> {
    if h.len() < 4 {
        return None;
    }
    // Executables
    if starts(h, b"MZ") {
        return Some("pe");
    }
    if starts(h, &[0x7f, b'E', b'L', b'F']) {
        return Some("elf");
    }
    if starts(h, b"\0asm") {
        return Some("wasm");
    }
    match h[..4] {
        // Mach-O thin, both endiannesses and 32/64-bit.
        [0xfe, 0xed, 0xfa, 0xce]
        | [0xfe, 0xed, 0xfa, 0xcf]
        | [0xce, 0xfa, 0xed, 0xfe]
        | [0xcf, 0xfa, 0xed, 0xfe] => return Some("macho"),
        // 0xCAFEBABE is a Mach-O fat header *and* a Java class file; the u32 at
        // offset 4 (big-endian) disambiguates: a small arch count means fat.
        [0xca, 0xfe, 0xba, 0xbe] => {
            let n = u32::from_be_bytes([h[4], h[5], h[6], h[7]]);
            return Some(if n < 40 { "macho" } else { "class" });
        }
        _ => {}
    }
    // Archives / compression
    if starts(h, b"PK\x03\x04") || starts(h, b"PK\x05\x06") || starts(h, b"PK\x07\x08") {
        return Some("zip");
    }
    if starts(h, b"Rar!\x1a\x07") {
        return Some("rar");
    }
    if starts(h, b"7z\xbc\xaf\x27\x1c") {
        return Some("7z");
    }
    if starts(h, &[0x1f, 0x8b]) {
        return Some("gzip");
    }
    if starts(h, &[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
        return Some("xz");
    }
    if starts(h, &[0x28, 0xb5, 0x2f, 0xfd]) {
        return Some("zstd");
    }
    if starts(h, b"BZh") {
        return Some("bzip2");
    }
    if at(h, 257, b"ustar") {
        return Some("tar");
    }
    // Documents
    if starts(h, b"%PDF-") {
        return Some("pdf");
    }
    if starts(h, &[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]) {
        return Some("cfb");
    }
    // Images
    if starts(h, &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]) {
        return Some("png");
    }
    if starts(h, &[0xff, 0xd8, 0xff]) {
        return Some("jpeg");
    }
    if starts(h, b"GIF87a") || starts(h, b"GIF89a") {
        return Some("gif");
    }
    if starts(h, b"BM") && view.size() >= 2 {
        return Some("bmp");
    }
    // RIFF containers: WEBP / WAV / AVI share the leading "RIFF".
    if starts(h, b"RIFF") && h.len() >= 12 {
        return Some(match &h[8..12] {
            b"WEBP" => "webp",
            b"WAVE" => "wav",
            b"AVI " => "avi",
            _ => "riff",
        });
    }
    // Media
    if at(h, 4, b"ftyp") {
        return Some("mp4");
    }
    if starts(h, &[0x1a, 0x45, 0xdf, 0xa3]) {
        return Some("matroska");
    }
    if starts(h, b"OggS") {
        return Some("ogg");
    }
    if starts(h, b"fLaC") {
        return Some("flac");
    }
    if starts(h, b"ID3") || (h[0] == 0xff && (h[1] & 0xe0) == 0xe0) {
        return Some("mp3");
    }
    // Windows shortcut
    if starts(h, &[0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00]) {
        return Some("lnk");
    }
    // Scripts
    if starts(h, b"#!") {
        return Some("script");
    }
    None
}
