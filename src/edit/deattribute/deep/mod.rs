//! The opt-in deep pass. It sweeps the strings of whatever regions a format
//! says hold plain data (never code, and never tables the loader resolves by
//! content) for credits, licensing and vendor marks, and adds same-length
//! rewrites of build fields for PE images. Every edit keeps the file's length
//! and layout, so the copy still parses and disassembles even when it no
//! longer loads.
//!
//! The sweep is a pure function of the file's bytes and format: it never looks
//! at the file's name or path, iterates only ordered collections, and plans
//! nothing on its own output, so a file on disk, the same file inside an
//! archive, and a rerun over the copy all agree.

use std::collections::{BTreeMap, BTreeSet};

use crate::model::{ContainerKind, FileReport, Marker, Region, RemovalStrategy};
use crate::parsers::{elf, macho};
use crate::scan::FileView;

use super::{Caveat, Kind};

mod pe;

pub(super) use pe::{checksum_target, signed as pe_signed};

/// Longest string the sweep considers, in characters.
const MAX_STRING: usize = 4096;
/// Largest region read in one piece.
const WINDOW: u64 = 8 * 1024 * 1024;
/// Most bytes one file's sweep reads in total.
const MAX_TOTAL: u64 = 256 * 1024 * 1024;
/// Largest plain-text file the text sweep reads.
const MAX_TEXT: u64 = 16 * 1024 * 1024;
/// Window for the entropy guard of the fallback sweep.
const ENTROPY_WINDOW: usize = 4096;
/// Bits per byte above which a window is treated as compressed or encrypted.
const ENTROPY_LIMIT: f64 = 6.0;

/// What the deep pass adds to a file's plan.
#[derive(Debug, Default)]
pub(super) struct Deep {
    /// Raw blanks, merged with the basic plan's markers.
    pub blanks: Vec<(Kind, Marker)>,
    /// Same-length field rewrites at `(offset, new bytes)`.
    pub rewrites: Vec<(Kind, u64, Vec<u8>)>,
    pub caveats: Vec<Caveat>,
}

/// Plan the deep pass for one file.
pub(super) fn sweep(report: &FileReport, view: &dyn FileView) -> Deep {
    match report.format.as_deref() {
        Some("pe") => pe::sweep(view),
        Some("elf") => binary(view, &elf::data_regions(view), &Protected::default()),
        Some("macho") => {
            let found = macho::deep_regions(view);
            let mut deep = binary(view, &found.regions, &Protected::default());
            if found.signed {
                deep.caveats.push(Caveat::SignatureInvalidated);
            }
            deep
        }
        None | Some("script") if looks_text(view) => text(view),
        None => fallback(view),
        _ => Deep::default(),
    }
}

// ---------------------------------------------------------------------------
// Strings

/// One NUL-bounded string found in a region.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Hit {
    pub off: u64,
    /// Length in bytes.
    pub len: usize,
    pub text: String,
}

/// Byte ranges a sweep must never touch, as sorted `(start, end)` pairs.
#[derive(Debug, Default)]
pub(super) struct Protected(Vec<(u64, u64)>);

impl Protected {
    pub fn add(&mut self, start: u64, len: u64) {
        if len > 0 {
            self.0.push((start, start.saturating_add(len)));
        }
    }

    fn overlaps(&self, start: u64, end: u64) -> bool {
        self.0.iter().any(|&(a, b)| start < b && end > a)
    }
}

/// Printable ASCII, or a byte of a multi-byte UTF-8 sequence.
fn textual(b: u8) -> bool {
    (0x20..=0x7e).contains(&b) || b >= 0x80
}

/// Collect the NUL-bounded strings of `bytes`, which sit at file offset
/// `base`. A string must start at `bytes[0]` when `bounded_start`, or right
/// after a NUL, and must end at a NUL: a run inside larger text is not a
/// string the program reads on its own, so it is left alone. ASCII and UTF-8
/// runs must decode as UTF-8; UTF-16LE runs are ASCII-range characters.
fn strings(bytes: &[u8], base: u64, bounded_start: bool, out: &mut Vec<Hit>) {
    let starts_ok = |i: usize, width: usize| {
        if i == 0 {
            bounded_start
        } else {
            i >= width && bytes[i - width..i].iter().all(|&b| b == 0)
        }
    };
    let mut i = 0;
    while i < bytes.len() {
        if !textual(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && textual(bytes[i]) {
            i += 1;
        }
        let len = i - start;
        if (4..=MAX_STRING).contains(&len)
            && bytes.get(i) == Some(&0)
            && starts_ok(start, 1)
            && let Ok(text) = std::str::from_utf8(&bytes[start..i])
        {
            out.push(Hit {
                off: base + start as u64,
                len,
                text: text.to_string(),
            });
        }
    }
    for parity in 0..2 {
        let mut i = parity;
        while i + 1 < bytes.len() {
            if bytes[i + 1] != 0 || !(0x20..=0x7e).contains(&bytes[i]) {
                i += 2;
                continue;
            }
            let start = i;
            while i + 1 < bytes.len() && bytes[i + 1] == 0 && (0x20..=0x7e).contains(&bytes[i]) {
                i += 2;
            }
            let chars = (i - start) / 2;
            if (4..=MAX_STRING).contains(&chars)
                && bytes.get(i..i + 2) == Some(&[0, 0][..])
                && starts_ok(start, 2)
            {
                out.push(Hit {
                    off: base + start as u64,
                    len: i - start,
                    text: bytes[start..i]
                        .iter()
                        .step_by(2)
                        .map(|&b| char::from(b))
                        .collect(),
                });
            }
        }
    }
}

/// Read `len` bytes at `off`, looping over short reads. `None` on an error or
/// when the file ends first.
pub(super) fn read_full(view: &dyn FileView, off: u64, len: usize) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        let part = view.read_at(off + out.len() as u64, len - out.len()).ok()?;
        if part.is_empty() {
            return None;
        }
        out.extend_from_slice(&part);
    }
    Some(out)
}

/// Every string in each region, read in overlapping windows so a string that
/// straddles a window edge is still seen whole. Regions past `MAX_TOTAL` are
/// not read. Sorted and deduplicated.
fn region_strings(view: &dyn FileView, regions: &[(u64, u64)]) -> Vec<Hit> {
    let overlap = (MAX_STRING as u64 + 1) * 2;
    let mut budget = MAX_TOTAL;
    let mut hits = Vec::new();
    for &(off, len) in regions {
        let Some(end) = off.checked_add(len).filter(|&e| e <= view.size()) else {
            continue;
        };
        if len > budget {
            break;
        }
        budget -= len;
        let mut pos = off;
        while pos < end {
            let stop = pos.saturating_add(WINDOW).min(end);
            let lead = if pos == off { 0 } else { 2 };
            let from = pos - lead;
            let to = stop.saturating_add(overlap).min(end);
            let Some(bytes) = read_full(view, from, (to - from) as usize) else {
                break;
            };
            let mut found = Vec::new();
            strings(&bytes, from, pos == off, &mut found);
            hits.extend(found.into_iter().filter(|h| h.off >= pos && h.off < stop));
            pos = stop;
        }
    }
    hits.sort();
    hits.dedup();
    hits
}

// ---------------------------------------------------------------------------
// Matching

/// Credits that name who patched or cracked the file.
const PATCH_CREDITS: &[&str] = &[
    "patched by",
    "cracked by",
    "k'ed by",
    "keygen by",
    "modified by",
    "unlocked by",
    "repacked by",
    "released by",
];

/// Vendor marks of licensing libraries, which name the protection outright.
const LICENSING_VENDORS: &[&str] = &["limelm", "wyday.com", "floatinglicenses", "turboactivate"];

/// Licensing words that count only beside another attribution signal.
const LICENSING_WORDS: &[&str] = &[
    "license",
    "licence",
    "licensing",
    "activation",
    "deactivation",
    "trial",
    "serial number",
    "isgenuine",
];

/// Paths that name the machine or the person who built the file.
const BUILD_PATHS: &[&str] = &[
    "c:\\users\\",
    "/home/",
    "/users/",
    "visual studio\\projects\\",
];

/// Platform and toolchain vendors, never treated as a file's own vendor root:
/// their names appear in runtime strings and manifests the program needs.
const ROOT_STOPLIST: &[&str] = &[
    "microsoft",
    "windows",
    "apple",
    "google",
    "intel",
    "nvidia",
    "mozilla",
    "oracle",
    "the qt company",
    "free software foundation",
    "module",
    "plugin",
    "library",
    "runtime",
    "system",
    "common",
    "default",
    "version",
    "corporation",
    "company",
    "rights",
    "reserved",
    "copyright",
];

/// Uppercase words too common to count as a product mark.
const ACRONYM_STOPLIST: &[&str] = &[
    "COPYRIGHT",
    "GROUP",
    "ERROR",
    "DWORD",
    "QWORD",
    "GUID",
    "NULL",
    "TRUE",
    "FALSE",
    "THIS",
    "FILE",
    "PATH",
    "HTTP",
    "HTTPS",
    "TEXT",
    "TYPE",
    "BYTE",
    "DATA",
    "INFO",
    "UTF8",
    "ASCII",
    "UNICODE",
    "WARNING",
    "DEBUG",
    "RELEASE",
];

/// `needle` (lowercase) occurs in `lower` with no letter or digit on either
/// side, so `dispatched by` does not match `patched by`.
fn has_word(lower: &str, needle: &str) -> bool {
    find_word(lower, needle).is_some()
}

/// Where `needle` first occurs in `lower` as a whole word.
fn find_word(lower: &str, needle: &str) -> Option<usize> {
    let b = lower.as_bytes();
    lower.match_indices(needle).map(|(at, _)| at).find(|&at| {
        let before = at.checked_sub(1).map(|i| b[i]);
        let after = b.get(at + needle.len()).copied();
        !before.is_some_and(|c| c.is_ascii_alphanumeric())
            && !after.is_some_and(|c| c.is_ascii_alphanumeric())
    })
}

fn is_copyright(lower: &str) -> bool {
    has_word(lower, "copyright") || lower.contains("(c) ") || lower.contains('\u{a9}')
}

fn is_patch_credit(lower: &str) -> bool {
    PATCH_CREDITS.iter().any(|n| has_word(lower, n))
}

fn names_build_path(lower: &str) -> bool {
    BUILD_PATHS.iter().any(|n| lower.contains(n)) || lower.ends_with(".pdb")
}

/// The vendor named after a copyright mark: `Copyright (c) 2001-2026 Vendor
/// Name, Inc.` gives `vendor`.
fn copyright_vendor(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let at = lower
        .find("copyright")
        .map(|i| i + "copyright".len())
        .or_else(|| lower.find("(c)").map(|i| i + 3))
        .or_else(|| lower.find('\u{a9}').map(|i| i + '\u{a9}'.len_utf8()))?;
    let rest = text.get(at..)?.trim_start_matches(|c: char| {
        c.is_ascii_digit() || matches!(c, '-' | ' ' | ',' | '(' | ')' | 'c' | 'C' | '\u{a9}')
    });
    let head = rest
        .split([',', ' '])
        .next()?
        .trim_end_matches(['.', ';'])
        .to_ascii_lowercase();
    (head.len() >= 5 && !ROOT_STOPLIST.contains(&head.as_str())).then_some(head)
}

/// Vendor and product roots corroborated across the file: the module stem
/// the caller passes (a PE export name), copyright owners, and uppercase
/// product marks repeated at least three times with class or UI context.
pub(super) fn roots(hits: &[Hit], module: Option<&str>) -> BTreeSet<String> {
    let mut roots = BTreeSet::new();
    if let Some(stem) = module {
        let lower = stem.to_ascii_lowercase();
        if lower.len() >= 5 && !ROOT_STOPLIST.contains(&lower.as_str()) {
            roots.insert(lower);
        }
    }
    let mut acronyms: BTreeMap<String, (usize, bool)> = BTreeMap::new();
    for hit in hits {
        if let Some(vendor) = copyright_vendor(&hit.text) {
            roots.insert(vendor);
        }
        let contextual = hit.text.starts_with(".?AV")
            || hit.text.starts_with(".?AU")
            || hit.text.contains(" GUI")
            || hit.text.contains(" Render");
        let text = hit
            .text
            .strip_prefix(".?AV")
            .or_else(|| hit.text.strip_prefix(".?AU"))
            .unwrap_or(&hit.text);
        let b = text.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if !b[i].is_ascii_uppercase() {
                i += 1;
                continue;
            }
            let start = i;
            while i < b.len() && b[i].is_ascii_uppercase() {
                i += 1;
            }
            // In `VFXQObject` the last capital starts the next word.
            let end = if b.get(i).is_some_and(u8::is_ascii_lowercase) {
                i - 1
            } else {
                i
            };
            if !(4..=10).contains(&(end - start)) {
                continue;
            }
            let word = &text[start..end];
            if ACRONYM_STOPLIST.contains(&word) {
                continue;
            }
            let entry = acronyms.entry(word.to_ascii_lowercase()).or_default();
            entry.0 += 1;
            entry.1 |= contextual;
        }
    }
    roots.extend(
        acronyms
            .into_iter()
            .filter(|(_, (count, contextual))| *count >= 3 && *contextual)
            .map(|(word, _)| word),
    );
    roots
}

/// What a string is, when the deep pass blanks it.
fn classify(text: &str, roots: &BTreeSet<String>) -> Option<Kind> {
    let lower = text.to_ascii_lowercase();
    if is_patch_credit(&lower) {
        return Some(Kind::Patch);
    }
    let rooted = roots.iter().any(|r| lower.contains(r.as_str()));
    let attributed = rooted
        || is_copyright(&lower)
        || names_build_path(&lower)
        || LICENSING_VENDORS.iter().any(|n| lower.contains(n));
    if attributed {
        return Some(Kind::Brand);
    }
    let licensing = LICENSING_WORDS.iter().any(|n| has_word(&lower, n));
    let linked = lower.contains("http://") || lower.contains("https://");
    (licensing && linked).then_some(Kind::Brand)
}

/// Raw-blank markers for every classified hit outside `protected`. RTTI type
/// names are never blanked: exception matching across modules compares them.
fn blank_hits(
    hits: &[Hit],
    roots: &BTreeSet<String>,
    protected: &Protected,
    fill: u8,
) -> Vec<(Kind, Marker)> {
    hits.iter()
        .filter(|h| !h.text.starts_with(".?AV") && !h.text.starts_with(".?AU"))
        .filter(|h| !protected.overlaps(h.off, h.off + h.len as u64))
        .filter_map(|h| {
            let kind = classify(&h.text, roots)?;
            Some((kind, fill_marker(h.off, h.len as u64, fill)))
        })
        .collect()
}

pub(super) fn fill_marker(off: u64, len: u64, fill: u8) -> Marker {
    Marker {
        removal: RemovalStrategy::RawBlank { fill },
        ..Marker::blank(Region::new(off, len), ContainerKind::Raw)
    }
}

// ---------------------------------------------------------------------------
// Sweeps

/// A native image: NUL-filled blanks of the classified strings in its data
/// regions.
fn binary(view: &dyn FileView, regions: &[(u64, u64)], protected: &Protected) -> Deep {
    let hits = region_strings(view, regions);
    let roots = roots(&hits, None);
    Deep {
        blanks: blank_hits(&hits, &roots, protected, 0),
        ..Deep::default()
    }
}

/// Whether the file reads as UTF-8 text: under the size cap, no NUL in its
/// first 8 KiB, valid UTF-8 there apart from a sequence cut at the window end.
fn looks_text(view: &dyn FileView) -> bool {
    let size = view.size();
    if size == 0 || size > MAX_TEXT {
        return false;
    }
    let head = view.header();
    let sniff = &head[..head.len().min(8192)];
    if sniff.contains(&0) {
        return false;
    }
    match std::str::from_utf8(sniff) {
        Ok(_) => true,
        Err(e) => e.error_len().is_none() && sniff.len() == 8192,
    }
}

/// A plain-text file: the span from each credit, copyright mark or build path
/// to the end of its line or quoted value is filled with spaces, so newlines,
/// quotes and the bytes around them stay where they are and JSON, XML and
/// source keep parsing. Vendor roots are not swept here: in source text a
/// vendor name is often an identifier the code depends on.
fn text(view: &dyn FileView) -> Deep {
    if crate::parsers::text::is_protected(view.path()) {
        return Deep::default();
    }
    let Some(bytes) = read_full(view, 0, view.size() as usize) else {
        return Deep::default();
    };
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return Deep::default();
    };
    let mut blanks = Vec::new();
    // Split at quotes, tags and line ends: each piece is one value, comment
    // or line, and a blank never crosses into the next.
    let mut piece_start = 0usize;
    let cuts = text
        .char_indices()
        .filter(|(_, c)| matches!(c, '"' | '\'' | '<' | '>' | '`' | '\r' | '\n'))
        .chain(std::iter::once((text.len(), '\n')));
    for (at, c) in cuts {
        let piece = &text[piece_start..at];
        let base = piece_start;
        piece_start = at + c.len_utf8();
        let lower = piece.to_ascii_lowercase();
        let kind = if is_patch_credit(&lower) {
            Kind::Patch
        } else if is_copyright(&lower) || names_build_path(&lower) {
            Kind::Brand
        } else {
            continue;
        };
        let starts = PATCH_CREDITS
            .iter()
            .chain(["copyright"].iter())
            .filter_map(|n| find_word(&lower, n))
            .chain(["(c) ", "\u{a9}"].iter().filter_map(|n| lower.find(n)))
            .chain(BUILD_PATHS.iter().filter_map(|n| lower.find(n)))
            .min();
        let Some(start) = starts else {
            continue;
        };
        let value = piece[start..].trim_end();
        if value.len() >= 4 {
            blanks.push((
                kind,
                fill_marker((base + start) as u64, value.len() as u64, b' '),
            ));
        }
    }
    Deep {
        blanks,
        ..Deep::default()
    }
}

/// Shannon entropy of `bytes` in bits per byte.
fn entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let n = bytes.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// A file no parser describes: only patch credits, copyright marks and build
/// paths in NUL-bounded strings, and only where the bytes around the string
/// are not compressed or encrypted.
fn fallback(view: &dyn FileView) -> Deep {
    let size = view.size();
    let hits = region_strings(view, &[(0, size.min(MAX_TOTAL))]);
    let mut blanks = Vec::new();
    for hit in hits {
        let lower = hit.text.to_ascii_lowercase();
        let kind = if is_patch_credit(&lower) {
            Kind::Patch
        } else if is_copyright(&lower) || names_build_path(&lower) {
            Kind::Brand
        } else {
            continue;
        };
        let half = (ENTROPY_WINDOW / 2) as u64;
        let from = hit.off.saturating_sub(half);
        let len = (hit.off + hit.len as u64 + half).min(size) - from;
        let Some(around) = read_full(view, from, len as usize) else {
            continue;
        };
        if entropy(&around) < ENTROPY_LIMIT {
            blanks.push((kind, fill_marker(hit.off, hit.len as u64, 0)));
        }
    }
    Deep {
        blanks,
        ..Deep::default()
    }
}

#[cfg(test)]
mod tests;
