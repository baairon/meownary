//! The PE part of the deep pass. Structured parsers mine identities and keep
//! fixed-size resource fields valid. A second pass replaces those identities
//! wherever their readable bytes occur in raw sections, including code and
//! exports. Parsed import names and thunk tables remain byte-exact.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use aho_corasick::AhoCorasickBuilder;

use crate::model::{ContainerKind, Marker, Region};
use crate::parsers::pe::image::{
    DIR_CLR, DIR_DEBUG, DIR_EXPORT, DIR_RESOURCE, DIR_SECURITY, PeImage,
};
use crate::parsers::pe::version;
use crate::scan::FileView;
use crate::util::hash::hash_hex;

use super::super::{Caveat, Kind, Reason, Target};
use super::dotnet;
use super::pipl::Pipl;
use super::{
    Deep, Encoding, Evidence, Hit, Protected, Rewrite, Source, candidate, fill_marker, read_full,
    redact_hits, region_strings, registry_candidates, roots, single_byte, strings,
};

const DIR_IMPORT: usize = 1;
const DIR_EXCEPTION: usize = 3;
const DIR_BASERELOC: usize = 5;
const DIR_TLS: usize = 9;
const DIR_LOAD_CONFIG: usize = 10;
const DIR_BOUND_IMPORT: usize = 11;
const DIR_IAT: usize = 12;
const DIR_DELAY_IMPORT: usize = 13;

const RT_VERSION: u32 = 16;
const RT_MANIFEST: u32 = 24;
const RT_STRING: u32 = 6;
const RT_DIALOG: u32 = 5;
const RT_MESSAGETABLE: u32 = 11;
const RT_PIPL: u32 = u32::MAX;

const IMAGE_SCN_CNT_CODE: u32 = 0x20;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x40;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

const DEBUG_CODEVIEW: u32 = 2;
const DEBUG_MISC: u32 = 4;
const DEBUG_VC_FEATURE: u32 = 12;
const DEBUG_POGO: u32 = 13;
const DEBUG_REPRO: u32 = 16;
const DEBUG_EMBEDDED_PDB: u32 = 17;

/// Cap on import descriptors, thunks, export names and resource entries.
const MAX_ENTRIES: usize = 65_536;
/// Longest import, export or module name read.
const MAX_NAME: usize = 512;
/// Largest debug record body rewritten.
const MAX_DEBUG_BODY: usize = 64 * 1024;
const MAX_RESOURCE_STRING: usize = 256 * 1024;
const MAX_CERT_BODY: usize = 4 * 1024 * 1024;

/// These are library identifiers, not host APIs. Deep mode can sacrifice licensing.
const LICENSE_TERMS: &[&str] = &[
    "limelm",
    "wyday",
    "floatinglicenses",
    "turboactivate",
    "turbofloat",
];

fn identity_terms(roots: &BTreeSet<String>) -> BTreeSet<String> {
    let mut terms: BTreeSet<String> = roots.iter().filter(|s| s.len() >= 4).cloned().collect();
    terms.extend(LICENSE_TERMS.iter().map(|s| (*s).to_string()));
    // Some vendors punctuate the same mark in display copy and class names.
    for root in roots {
        if let Some(tail) = root.strip_prefix("re")
            && tail.len() >= 5
        {
            terms.insert(format!("re:{tail}"));
        }
    }
    terms
}

/// Learn third-party attribution from repeated diagnostic labels and related
/// licensing symbols. A single generic "Debug" string is not evidence of a
/// library name; two distinct labels or identifiers are required.
fn library_terms(hits: &[Hit]) -> BTreeSet<String> {
    let mut labels: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut symbols: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for hit in hits {
        for line in hit.text.split(['\r', '\n']) {
            let words: Vec<&str> = line.split_whitespace().collect();
            if words.len() >= 2 {
                let name = words[0].trim_matches(|c: char| !c.is_ascii_alphanumeric());
                let marker = words[1].to_ascii_lowercase();
                if name.len() >= 5
                    && name.bytes().all(|b| b.is_ascii_alphanumeric())
                    && matches!(marker.as_str(), "debug" | "license" | "licensing")
                {
                    labels
                        .entry(name.to_ascii_lowercase())
                        .or_default()
                        .insert(words[1..].join(" ").to_ascii_lowercase());
                }
            }
        }
        for token in hit
            .text
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        {
            let Some((tag, rest)) = token.split_once('_') else {
                continue;
            };
            if tag.len() >= 4
                && tag.len() <= 8
                && tag.bytes().all(|b| b.is_ascii_alphabetic())
                && rest.len() >= 3
                && rest.bytes().any(|b| b.is_ascii_alphabetic())
            {
                symbols
                    .entry(tag.to_ascii_lowercase())
                    .or_default()
                    .insert(token.to_ascii_lowercase());
            }
        }
    }
    let mut terms: BTreeSet<String> = labels
        .into_iter()
        .filter(|(_, contexts)| contexts.len() >= 2)
        .map(|(name, _)| name)
        .collect();
    for (_, family) in symbols {
        if family.len() >= 2
            && family.iter().any(|s| {
                ["lic", "client", "server", "debug", "report"]
                    .iter()
                    .any(|word| s.contains(word))
            })
        {
            terms.extend(family);
        }
    }
    terms
}

/// Expand a corroborated vendor's mixed-case initials only in identifiers that
/// carry those initials as a prefix. Short initials alone are too ambiguous to
/// search through executable bytes.
fn vendor_alias_terms(
    hits: &[Hit],
    roots: &BTreeSet<String>,
    module: Option<&str>,
    evidence: &Evidence,
) -> BTreeSet<String> {
    let mut explicit = BTreeSet::new();
    if let Some(root) = module.and_then(candidate) {
        explicit.insert(root);
    }
    for (value, source) in evidence {
        if *source == Source::Company
            && let Some(root) = candidate(value)
        {
            explicit.insert(root);
        }
    }
    for hit in hits {
        explicit.extend(registry_candidates(&hit.text));
        if let Some(vendor) = super::copyright_vendor(&hit.text) {
            explicit.insert(vendor);
        }
    }
    explicit.retain(|root| roots.contains(root));

    let mut aliases = BTreeSet::new();
    for root in explicit {
        for hit in hits {
            let lower = hit.text.to_ascii_lowercase();
            for (at, _) in lower.match_indices(&root) {
                let Some(surface) = hit.text.get(at..at + root.len()) else {
                    continue;
                };
                let bytes = surface.as_bytes();
                if !bytes.first().is_some_and(u8::is_ascii_uppercase) {
                    continue;
                }
                let second = (1..bytes.len()).find(|&i| {
                    bytes[i].is_ascii_uppercase()
                        && (bytes[i - 1].is_ascii_lowercase()
                            || (i >= 2
                                && bytes[i - 1].is_ascii_uppercase()
                                && bytes.get(i + 1).is_some_and(u8::is_ascii_lowercase)))
                });
                if let Some(i) = second {
                    aliases.insert(format!(
                        "{}{}",
                        (bytes[0] as char).to_ascii_lowercase(),
                        (bytes[i] as char).to_ascii_lowercase()
                    ));
                }
            }
        }
    }

    let mut terms = BTreeSet::new();
    for alias in aliases {
        let mut tags: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut tokens = Vec::new();
        for hit in hits {
            let text = hit
                .text
                .strip_prefix(".?AV")
                .or_else(|| hit.text.strip_prefix(".?AU"))
                .unwrap_or(&hit.text);
            for token in text.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
                let raw = token.as_bytes();
                if raw.len() < 4
                    || !raw[..2].eq_ignore_ascii_case(alias.as_bytes())
                    || !raw[..2].iter().all(u8::is_ascii_uppercase)
                {
                    tokens.push(token.to_string());
                    continue;
                }
                terms.insert(token.to_ascii_lowercase());
                tokens.push(token.to_string());
                if raw[2].is_ascii_uppercase() && raw.get(3) == Some(&b'_') {
                    tags.entry(token[..3].to_ascii_lowercase())
                        .or_default()
                        .insert(token.to_string());
                }
            }
            let namespace = format!("@{alias}@@");
            if hit.text.to_ascii_lowercase().contains(&namespace) {
                terms.insert(namespace);
            }
        }
        for (tag, found) in tags {
            if found.len() >= 2 {
                terms.extend(
                    tokens
                        .iter()
                        .filter(|token| {
                            token.to_ascii_lowercase().starts_with(&tag) && token.len() >= 4
                        })
                        .map(|token| token.to_ascii_lowercase()),
                );
            }
        }
    }
    terms
}

fn matcher(terms: &BTreeSet<String>) -> Option<(aho_corasick::AhoCorasick, Vec<bool>)> {
    let mut patterns = Vec::new();
    let mut wide = Vec::new();
    for term in terms {
        if !term.is_ascii() || term.len() < 4 {
            continue;
        }
        patterns.push(term.as_bytes().to_vec());
        wide.push(false);
        patterns.push(term.bytes().flat_map(|b| [b, 0]).collect());
        wide.push(true);
    }
    AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .build(patterns)
        .ok()
        .map(|ac| (ac, wide))
}

/// Search every raw section and the overlay past the loaded image, including
/// executable sections. A hit is a fixed-width textual byte sequence, so the PE
/// directory layout remains readable even if the plug-in's runtime behavior
/// does not.
fn identity_bytes(
    view: &dyn FileView,
    img: &PeImage,
    terms: &BTreeSet<String>,
    protected: &Protected,
    detached: Option<(u64, u64)>,
    edit: bool,
) -> (Vec<Rewrite>, Option<&'static str>, bool) {
    let Some((ac, wide)) = matcher(terms) else {
        return (Vec::new(), None, false);
    };
    let mut spans: Vec<(u64, u64, &'static str)> = img
        .sections
        .iter()
        .map(|section| {
            let category =
                if section.characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE) != 0 {
                    "PE code"
                } else if section.name.starts_with(b".rsrc") {
                    "PE resource"
                } else {
                    "PE data"
                };
            (
                u64::from(section.raw_ptr),
                u64::from(section.raw_size),
                category,
            )
        })
        .collect();
    spans.extend(overlay_spans(view.size(), img.image_end(), detached));
    let mut edits = BTreeMap::new();
    let mut budget = super::MAX_TOTAL;
    for (start, size, category) in spans {
        if size == 0 {
            continue;
        }
        if size > budget {
            return (Vec::new(), None, true);
        }
        budget -= size;
        let Some(bytes) = read_full(view, start, size as usize) else {
            return (Vec::new(), None, true);
        };
        for hit in ac.find_overlapping_iter(&bytes) {
            let start = start + hit.start() as u64;
            let end = start + hit.len() as u64;
            if protected.overlaps(start, end) {
                continue;
            }
            if !edit {
                return (Vec::new(), Some(category), false);
            }
            let base = start;
            let is_wide = wide[hit.pattern().as_usize()];
            for index in 0..hit.len() {
                if !is_wide || index % 2 == 0 {
                    edits.insert(base + index as u64, b' ');
                }
            }
        }
    }
    let mut rewrites: Vec<Rewrite> = Vec::new();
    for (off, byte) in edits {
        if let Some((_, start, bytes)) = rewrites.last_mut()
            && *start + bytes.len() as u64 == off
        {
            bytes.push(byte);
        } else {
            rewrites.push((Kind::Brand, off, vec![byte]));
        }
    }
    (rewrites, None, false)
}

/// The file past the loaded image, less a detached certificate that the sweep
/// clears. Each span is `(start, len, category)`.
fn overlay_spans(
    size: u64,
    image_end: u64,
    detached: Option<(u64, u64)>,
) -> Vec<(u64, u64, &'static str)> {
    if image_end >= size {
        return Vec::new();
    }
    match detached.filter(|&(off, _)| off >= image_end && off < size) {
        Some((off, len)) => {
            let end = off.saturating_add(len).min(size);
            vec![
                (image_end, off - image_end, "PE overlay"),
                (end, size - end, "PE overlay"),
            ]
        }
        None => vec![(image_end, size - image_end, "PE overlay")],
    }
}

pub(super) fn residual_category(
    view: &dyn FileView,
    terms: &BTreeSet<String>,
) -> Option<&'static str> {
    let img = PeImage::parse(view)?;
    let (ac, _) = matcher(terms)?;
    let size = usize::try_from(view.size()).ok()?;
    let Some(bytes) = read_full(view, 0, size) else {
        return Some("PE scan budget");
    };
    let hit = ac.find(&bytes)?;
    let at = hit.start() as u64;
    Some(
        match img.sections.iter().find(|section| {
            at >= u64::from(section.raw_ptr)
                && at < u64::from(section.raw_ptr) + u64::from(section.raw_size)
        }) {
            Some(section)
                if section.characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE) != 0 =>
            {
                "PE code"
            }
            Some(section) if section.name.starts_with(b".rsrc") => "PE resource",
            Some(_) => "PE data",
            None if at < u64::from(img.size_of_headers) => "PE header",
            None => "PE overlay",
        },
    )
}

/// Compare the loader's import records and every name reached from them. A PE
/// can still parse after a DLL name is damaged, so format detection alone is
/// insufficient verification for a deep copy.
pub(super) fn imports_unchanged(original: &dyn FileView, output: &dyn FileView) -> bool {
    fn ranges(view: &dyn FileView) -> Option<Protected> {
        let img = PeImage::parse(view)?;
        let mut walk = Walk {
            view,
            img: &img,
            protected: Protected::default(),
            import_protected: Protected::default(),
            rewrites: Vec::new(),
            caveats: Vec::new(),
            resource_hits: Vec::new(),
            structured_hits: Vec::new(),
            pipls: Vec::new(),
            evidence: Vec::new(),
            skipped: Vec::new(),
        };
        for dir in [DIR_IMPORT, DIR_IAT, DIR_DELAY_IMPORT, DIR_BOUND_IMPORT] {
            if let Some(d) = img.dir(dir)
                && let Some(off) = img.rva_to_off(d.rva)
            {
                walk.import_protected.add(off, u64::from(d.size));
            }
        }
        walk.imports();
        walk.delay_imports();
        Some(walk.import_protected)
    }
    let (Some(before), Some(after)) = (ranges(original), ranges(output)) else {
        return PeImage::parse(original).is_none() && PeImage::parse(output).is_none();
    };
    if before.0 != after.0 {
        return false;
    }
    before.0.into_iter().all(|(start, end)| {
        let Ok(len) = usize::try_from(end - start) else {
            return false;
        };
        match (read_full(original, start, len), read_full(output, start, len)) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        }
    })
}

fn merge_rewrites(rewrites: Vec<Rewrite>) -> Vec<Rewrite> {
    let mut bytes = BTreeMap::new();
    for (_, off, value) in rewrites {
        for (i, b) in value.into_iter().enumerate() {
            bytes.insert(off + i as u64, b);
        }
    }
    let mut merged: Vec<Rewrite> = Vec::new();
    for (off, byte) in bytes {
        if let Some((_, start, value)) = merged.last_mut()
            && *start + value.len() as u64 == off
        {
            value.push(byte);
        } else {
            merged.push((Kind::Brand, off, vec![byte]));
        }
    }
    merged
}

fn aggressive_roots(
    hits: &[Hit],
    evidence: &Evidence,
    mut roots: BTreeSet<String>,
) -> BTreeSet<String> {
    for (value, source) in evidence {
        if *source == Source::Product
            && value.bytes().all(|b| b.is_ascii_alphanumeric())
            && let Some(root) = candidate(value)
        {
            roots.insert(root);
        }
    }
    for hit in hits {
        roots.extend(registry_candidates(&hit.text));
        let lower = hit.text.to_ascii_lowercase();
        if lower.contains("program files") {
            for folder in hit.text.split('\\') {
                let name = folder.trim().to_ascii_lowercase();
                let stem = name.strip_suffix("effects").unwrap_or(&name);
                if stem.len() >= 5
                    && name != "program files"
                    && name != "program files (x86)"
                    && let Some(root) = candidate(stem)
                {
                    roots.insert(root);
                }
            }
        }
    }
    let mut class_names = BTreeSet::new();
    for hit in hits {
        let Some(class) = hit
            .text
            .strip_prefix(".?AV")
            .or_else(|| hit.text.strip_prefix(".?AU"))
        else {
            continue;
        };
        let bytes = class.as_bytes();
        if bytes.len() < 8
            || !bytes[..3].iter().all(u8::is_ascii_uppercase)
            || !bytes[3].is_ascii_lowercase()
        {
            continue;
        }
        let tail = &class[2..];
        let end = tail[1..]
            .find(|c: char| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '@')
            .map_or(tail.len(), |n| n + 1);
        if end >= 5 && tail.as_bytes().get(end).is_some_and(u8::is_ascii_digit) {
            class_names.insert(tail[..end].to_ascii_lowercase());
        }
    }
    for name in class_names {
        if hits
            .iter()
            .any(|h| {
                !h.text.starts_with(".?A")
                    && h.text.to_ascii_lowercase().starts_with(&name)
                    && [" gui", " plugin", " effect"]
                        .iter()
                        .any(|hint| h.text.to_ascii_lowercase().contains(hint))
            })
        {
            roots.insert(name);
        }
    }
    roots
}

/// The neutral stem a deep copy's export module name is rewritten to.
pub(super) const NEUTRAL_MODULE: &[u8] = b"module";

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

/// RT_STRING has sixteen length-prefixed UTF-16 values and no terminators.
fn string_table(view: &dyn FileView, off: u64, size: usize) -> Vec<Hit> {
    if size > MAX_RESOURCE_STRING {
        return Vec::new();
    }
    let Some(bytes) = read_full(view, off, size) else {
        return Vec::new();
    };
    let mut hits = Vec::new();
    let mut at = 0usize;
    for _ in 0..16 {
        let Some(units) = u16_at(&bytes, at).map(usize::from) else {
            break;
        };
        at += 2;
        let Some(end) = at.checked_add(units * 2).filter(|&n| n <= bytes.len()) else {
            break;
        };
        if (4..=super::MAX_STRING).contains(&units) {
            let raw: Vec<u16> = bytes[at..end]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect();
            if let Ok(text) = String::from_utf16(&raw) {
                hits.push(Hit {
                    off: off + at as u64,
                    len: end - at,
                    text,
                    encoding: Encoding::Utf16,
                });
            }
        }
        at = end;
    }
    hits
}

fn utf16_field(
    raw: &[u8],
    at: &mut usize,
    base: u64,
    hits: &mut Vec<Hit>,
    emit: bool,
) -> Option<()> {
    let first = u16_at(raw, *at)?;
    if first == 0 {
        *at += 2;
        return Some(());
    }
    if first == 0xffff {
        *at += 4;
        return (*at <= raw.len()).then_some(());
    }
    let start = *at;
    let mut units = Vec::new();
    loop {
        let unit = u16_at(raw, *at)?;
        *at += 2;
        if unit == 0 {
            break;
        }
        units.push(unit);
        if units.len() > super::MAX_STRING {
            return None;
        }
    }
    if emit
        && units.len() >= 4
        && let Ok(text) = String::from_utf16(&units)
    {
        hits.push(Hit {
            off: base + start as u64,
            len: units.len() * 2,
            text,
            encoding: Encoding::Utf16,
        });
    }
    Some(())
}

/// Dialog headers and controls carry counted UTF-16 fields without NULs before them.
fn dialog_table(view: &dyn FileView, off: u64, size: usize) -> Vec<Hit> {
    if size > 1024 * 1024 {
        return Vec::new();
    }
    let Some(raw) = read_full(view, off, size) else {
        return Vec::new();
    };
    let extended = u16_at(&raw, 2) == Some(0xffff);
    let (style, count, mut at) = if extended {
        let (Some(style), Some(count)) = (u32_at(&raw, 12), u16_at(&raw, 16)) else {
            return Vec::new();
        };
        (style, count as usize, 26usize)
    } else {
        let (Some(style), Some(count)) = (u32_at(&raw, 0), u16_at(&raw, 8)) else {
            return Vec::new();
        };
        (style, count as usize, 18usize)
    };
    if count > 4096 {
        return Vec::new();
    }
    let mut hits = Vec::new();
    for i in 0..3 {
        if utf16_field(&raw, &mut at, off, &mut hits, i == 2).is_none() {
            return Vec::new();
        }
    }
    if style & 0x40 != 0 {
        at += if extended { 6 } else { 2 };
        if utf16_field(&raw, &mut at, off, &mut hits, false).is_none() {
            return Vec::new();
        }
    }
    for _ in 0..count {
        at = (at + 3) & !3;
        at += if extended { 24 } else { 18 };
        if at > raw.len() {
            return Vec::new();
        }
        for i in 0..2 {
            if utf16_field(&raw, &mut at, off, &mut hits, i == 1).is_none() {
                return Vec::new();
            }
        }
        let Some(extra) = u16_at(&raw, at) else {
            return Vec::new();
        };
        at += 2 + extra as usize;
        if at > raw.len() {
            return Vec::new();
        }
    }
    hits
}

/// Message table entries contain ANSI or UTF-16 text after a four-byte header.
fn message_table(view: &dyn FileView, off: u64, size: usize) -> Vec<Hit> {
    if size > 1024 * 1024 {
        return Vec::new();
    }
    let Some(raw) = read_full(view, off, size) else {
        return Vec::new();
    };
    let Some(blocks) = u32_at(&raw, 0).map(|n| n as usize).filter(|&n| n <= 4096) else {
        return Vec::new();
    };
    if 4 + blocks * 12 > raw.len() {
        return Vec::new();
    }
    let mut hits = Vec::new();
    for block in 0..blocks {
        let at = 4 + block * 12;
        let (Some(low), Some(high), Some(mut pos)) = (
            u32_at(&raw, at),
            u32_at(&raw, at + 4),
            u32_at(&raw, at + 8).map(|n| n as usize),
        ) else {
            return Vec::new();
        };
        if high < low || high - low > 65_536 {
            return Vec::new();
        }
        for _ in low..=high {
            let (Some(len), Some(flags)) = (u16_at(&raw, pos), u16_at(&raw, pos + 2)) else {
                return Vec::new();
            };
            let len = len as usize;
            if len < 4 || pos + len > raw.len() {
                return Vec::new();
            }
            let body = &raw[pos + 4..pos + len];
            if flags & 1 != 0 {
                let units = body
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|p| u16::from_le_bytes(*p))
                    .take_while(|&u| u != 0)
                    .collect::<Vec<_>>();
                if units.len() >= 4
                    && let Ok(text) = String::from_utf16(&units)
                {
                    hits.push(Hit {
                        off: off + pos as u64 + 4,
                        len: units.len() * 2,
                        text,
                        encoding: Encoding::Utf16,
                    });
                }
            } else {
                let end = body.iter().position(|&b| b == 0).unwrap_or(body.len());
                if end >= 4 {
                    hits.push(Hit {
                        off: off + pos as u64 + 4,
                        len: end,
                        text: single_byte(&body[..end]),
                        encoding: Encoding::SingleByte,
                    });
                }
            }
            pos += len;
        }
    }
    hits
}

/// Only assembly identities are used as evidence. The XML bytes stay intact.
fn manifest_names(view: &dyn FileView, off: u64, size: usize) -> Vec<String> {
    if size > MAX_RESOURCE_STRING {
        return Vec::new();
    }
    let Some(bytes) = read_full(view, off, size) else {
        return Vec::new();
    };
    let utf16 =
        bytes.starts_with(&[0xff, 0xfe]) || (bytes.len() >= 4 && bytes[1] == 0 && bytes[3] == 0);
    let text = if utf16 {
        let start = if bytes.starts_with(&[0xff, 0xfe]) {
            2
        } else {
            0
        };
        let units: Vec<u16> = bytes[start..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| u16::from_le_bytes([p[0], p[1]]))
            .collect();
        String::from_utf16(&units).ok()
    } else {
        std::str::from_utf8(&bytes).ok().map(str::to_string)
    };
    let Some(text) = text else { return Vec::new() };
    let lower = text.to_ascii_lowercase();
    let mut names = Vec::new();
    let mut from = 0;
    while let Some(rel) = lower[from..].find("<assemblyidentity") {
        let begin = from + rel;
        let Some(end) = lower[begin..].find('>').map(|n| begin + n) else {
            break;
        };
        let tag = &text[begin..end];
        let tag_lower = &lower[begin..end];
        let name_at = tag_lower
            .match_indices("name")
            .map(|(at, _)| at)
            .find(|&at| {
                at.checked_sub(1)
                    .and_then(|before| tag.as_bytes().get(before))
                    .is_some_and(u8::is_ascii_whitespace)
                    && tag
                        .as_bytes()
                        .get(at + 4)
                        .is_some_and(|b| b.is_ascii_whitespace() || *b == b'=')
            });
        if let Some(at) = name_at {
            let mut value = at + 4;
            while tag
                .as_bytes()
                .get(value)
                .is_some_and(u8::is_ascii_whitespace)
            {
                value += 1;
            }
            if tag.as_bytes().get(value) == Some(&b'=') {
                value += 1;
                while tag
                    .as_bytes()
                    .get(value)
                    .is_some_and(u8::is_ascii_whitespace)
                {
                    value += 1;
                }
                if let Some(&quote @ (b'"' | b'\'')) = tag.as_bytes().get(value) {
                    value += 1;
                    if let Some(close) = tag[value..].find(char::from(quote)) {
                        names.push(
                            tag[value..value + close]
                                .split('.')
                                .next()
                                .unwrap_or("")
                                .to_string(),
                        );
                    }
                }
            }
        }
        from = end + 1;
    }
    names
}

/// Read O and CN name attributes from bounded DER in PKCS#7. These are weak
/// evidence because a certificate table may also contain CA certificates.
fn certificate_names(table: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at + 8 <= table.len() {
        let Some(len) = u32_at(table, at).map(|n| n as usize) else {
            break;
        };
        if len < 8 || at + len > table.len() {
            break;
        }
        if u16_at(table, at + 6) == Some(2) {
            let der = &table[at + 8..at + len];
            for pos in 0..der.len().saturating_sub(6) {
                if der.get(pos..pos + 4) != Some(&[6, 3, 0x55, 4][..])
                    || !matches!(der.get(pos + 4), Some(3 | 10))
                {
                    continue;
                }
                let tag = der[pos + 5];
                if !matches!(tag, 0x0c | 0x13 | 0x16 | 0x1e) {
                    continue;
                }
                let len0 = der[pos + 6];
                let (body, size) = if len0 & 0x80 == 0 {
                    (pos + 7, len0 as usize)
                } else if len0 == 0x81 && pos + 7 < der.len() {
                    (pos + 8, der[pos + 7] as usize)
                } else if len0 == 0x82 && pos + 8 < der.len() {
                    (
                        pos + 9,
                        u16::from_be_bytes([der[pos + 7], der[pos + 8]]) as usize,
                    )
                } else {
                    continue;
                };
                if size == 0 || size > 512 {
                    continue;
                }
                let Some(value) = der.get(body..body + size) else {
                    continue;
                };
                let name = if tag == 0x1e {
                    let units: Vec<u16> = value
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|p| u16::from_be_bytes([p[0], p[1]]))
                        .collect();
                    String::from_utf16(&units).ok()
                } else {
                    std::str::from_utf8(value).ok().map(str::to_string)
                };
                if let Some(name) = name {
                    out.push(name);
                }
            }
        }
        at = (at + len + 7) & !7;
    }
    out
}

struct Walk<'a> {
    view: &'a dyn FileView,
    img: &'a PeImage,
    protected: Protected,
    import_protected: Protected,
    rewrites: Vec<Rewrite>,
    caveats: Vec<Caveat>,
    resource_hits: Vec<Hit>,
    structured_hits: Vec<Hit>,
    pipls: Vec<Pipl>,
    evidence: Evidence,
    skipped: Vec<Reason>,
}

impl Walk<'_> {
    fn safe_resource_leaf(&self, rva: u32, size: u32) -> Option<u64> {
        let section = self.img.sections.iter().find(|s| s.contains_rva(rva))?;
        let delta = rva.checked_sub(section.va)?;
        if section.characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE) != 0
            || section.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA == 0
            || delta.checked_add(size)? > section.raw_size
        {
            return None;
        }
        let off = u64::from(section.raw_ptr) + u64::from(delta);
        off.checked_add(u64::from(size))
            .filter(|&end| end <= self.view.size())
            .map(|_| off)
    }

    /// Protect a data directory's whole range.
    fn dir_range(&mut self, index: usize) {
        if let Some(d) = self.img.dir(index)
            && let Some(off) = self.img.rva_to_off(d.rva)
        {
            self.protected.add(off, u64::from(d.size));
        }
    }

    /// Locate the NUL-terminated name at `rva`, returning its offset and bytes.
    fn name_at(&mut self, rva: u32) -> Option<(u64, Vec<u8>)> {
        let off = self.img.rva_to_off(rva)?;
        let bytes = self.view.read_at(off, MAX_NAME).ok()?;
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        self.protected.add(off, end as u64 + 1);
        Some((off, bytes[..end].to_vec()))
    }

    fn import_name_at(&mut self, rva: u32) {
        if let Some((off, name)) = self.name_at(rva) {
            self.import_protected.add(off, name.len() as u64 + 1);
        }
    }

    /// Protect a thunk array at `rva` and every hint/name entry it points to.
    fn thunks(&mut self, rva: u32) {
        let Some(mut at) = self.img.rva_to_off(rva) else {
            return;
        };
        let width = if self.img.is64 { 8usize } else { 4 };
        for _ in 0..MAX_ENTRIES {
            let Some(raw) = read_full(self.view, at, width) else {
                return;
            };
            let value = if self.img.is64 {
                u64_at(&raw, 0)
            } else {
                u32_at(&raw, 0).map(u64::from)
            };
            let Some(value) = value.filter(|&v| v != 0) else {
                return;
            };
            self.protected.add(at, width as u64);
            self.import_protected.add(at, width as u64);
            let ordinal = value >> (width * 8 - 1) != 0;
            if !ordinal && let Ok(name_rva) = u32::try_from(value & 0x7fff_ffff) {
                // A hint/name entry: a two-byte hint, then the name.
                self.import_name_at(name_rva.wrapping_add(2));
                if let Some(off) = self.img.rva_to_off(name_rva) {
                    self.protected.add(off, 2);
                    self.import_protected.add(off, 2);
                }
            }
            at += width as u64;
        }
    }

    fn imports(&mut self) {
        let Some(d) = self.img.dir(DIR_IMPORT) else {
            return;
        };
        if let Some(off) = self.img.rva_to_off(d.rva) {
            self.import_protected.add(off, u64::from(d.size));
        }
        let Some(mut at) = self.img.rva_to_off(d.rva) else {
            return;
        };
        for _ in 0..MAX_ENTRIES {
            let Some(desc) = read_full(self.view, at, 20) else {
                return;
            };
            if desc.iter().all(|&b| b == 0) {
                return;
            }
            let (Some(lookup), Some(name), Some(iat)) =
                (u32_at(&desc, 0), u32_at(&desc, 12), u32_at(&desc, 16))
            else {
                return;
            };
            self.import_name_at(name);
            self.thunks(if lookup != 0 { lookup } else { iat });
            at += 20;
        }
    }

    fn delay_imports(&mut self) {
        let Some(d) = self.img.dir(DIR_DELAY_IMPORT) else {
            return;
        };
        if let Some(off) = self.img.rva_to_off(d.rva) {
            self.import_protected.add(off, u64::from(d.size));
        }
        let Some(mut at) = self.img.rva_to_off(d.rva) else {
            return;
        };
        for _ in 0..MAX_ENTRIES {
            let Some(desc) = read_full(self.view, at, 32) else {
                return;
            };
            if desc.iter().all(|&b| b == 0) {
                return;
            }
            let (Some(attrs), Some(name), Some(names)) =
                (u32_at(&desc, 0), u32_at(&desc, 4), u32_at(&desc, 16))
            else {
                return;
            };
            // Version 1 descriptors hold RVAs; the older form holds VAs.
            if attrs & 1 != 0 {
                self.import_name_at(name);
                self.thunks(names);
            }
            at += 32;
        }
    }

    /// Protect the export name arrays and names, returning the module name.
    fn exports(&mut self) -> Option<(u64, Vec<u8>)> {
        let d = self.img.dir(DIR_EXPORT)?;
        let at = self.img.rva_to_off(d.rva)?;
        let dir = read_full(self.view, at, 40)?;
        let name_rva = u32_at(&dir, 12)?;
        let functions = (u32_at(&dir, 20)? as usize).min(MAX_ENTRIES);
        let names = (u32_at(&dir, 24)? as usize).min(MAX_ENTRIES);
        let (Some(funcs_rva), Some(names_rva), Some(ords_rva)) =
            (u32_at(&dir, 28), u32_at(&dir, 32), u32_at(&dir, 36))
        else {
            return None;
        };
        if let Some(off) = self.img.rva_to_off(funcs_rva) {
            self.protected.add(off, functions as u64 * 4);
        }
        if let Some(off) = self.img.rva_to_off(ords_rva) {
            self.protected.add(off, names as u64 * 2);
        }
        if let Some(off) = self.img.rva_to_off(names_rva) {
            self.protected.add(off, names as u64 * 4);
            if let Some(table) = read_full(self.view, off, names * 4) {
                for i in 0..names {
                    if let Some(rva) = u32_at(&table, i * 4) {
                        self.name_at(rva);
                    }
                }
            }
        }
        if let Some(stamp) = at.checked_add(4) {
            self.zero(stamp, 4);
        }
        let module = self.name_at(name_rva)?;
        let rewritable = module.1.len() >= 4 && module.1.iter().all(|b| (0x20..=0x7e).contains(b));
        rewritable.then_some(module)
    }

    /// Queue a same-length zero rewrite when the field is not zero already.
    fn zero(&mut self, off: u64, len: usize) {
        if let Some(cur) = read_full(self.view, off, len)
            && cur.iter().any(|&b| b != 0)
        {
            self.rewrites.push((Kind::Brand, off, vec![0; len]));
        }
    }

    /// Walk the resource tree: protect every directory node, entry, name and
    /// data entry, plus version and manifest leaves whole; zero node stamps.
    fn resources(&mut self) {
        let Some(d) = self.img.dir(DIR_RESOURCE) else {
            return;
        };
        let Some(base) = self.img.rva_to_off(d.rva) else {
            return;
        };
        let mut seen = BTreeSet::new();
        let mut budget = 4096usize;
        self.node(base, 0, 0, None, &mut seen, &mut budget);
    }

    fn node(
        &mut self,
        base: u64,
        rel: u64,
        depth: usize,
        kind: Option<u32>,
        seen: &mut BTreeSet<u64>,
        budget: &mut usize,
    ) {
        if depth > 3 || *budget == 0 || !seen.insert(rel) {
            return;
        }
        *budget -= 1;
        let Some(at) = base.checked_add(rel) else {
            return;
        };
        let Some(head) = read_full(self.view, at, 16) else {
            return;
        };
        self.protected.add(at, 16);
        self.zero(at + 4, 4);
        let (Some(named), Some(ids)) = (u16_at(&head, 12), u16_at(&head, 14)) else {
            return;
        };
        let total = (usize::from(named) + usize::from(ids)).min(1024);
        let Some(table) = read_full(self.view, at + 16, total * 8) else {
            return;
        };
        self.protected.add(at + 16, total as u64 * 8);
        for i in 0..total {
            let (Some(name), Some(target)) = (u32_at(&table, i * 8), u32_at(&table, i * 8 + 4))
            else {
                continue;
            };
            let mut named_pipl = false;
            if name & 0x8000_0000 != 0 {
                let off = base + u64::from(name & 0x7fff_ffff);
                if let Some(len) = read_full(self.view, off, 2).and_then(|b| u16_at(&b, 0)) {
                    self.protected.add(off, 2 + u64::from(len) * 2);
                    if depth == 0
                        && len == 4
                        && let Some(raw) = read_full(self.view, off + 2, 8)
                    {
                        named_pipl = raw == b"P\0i\0P\0L\0" || raw == b"P\0I\0P\0L\0";
                    }
                }
            }
            let kind = if depth == 0 {
                if named_pipl {
                    Some(RT_PIPL)
                } else {
                    (name & 0x8000_0000 == 0).then_some(name)
                }
            } else {
                kind
            };
            let child = u64::from(target & 0x7fff_ffff);
            if target & 0x8000_0000 != 0 {
                self.node(base, child, depth + 1, kind, seen, budget);
                continue;
            }
            let Some(entry_off) = base.checked_add(child) else {
                continue;
            };
            self.protected.add(entry_off, 16);
            if let Some(entry) = read_full(self.view, entry_off, 16)
                && let (Some(rva), Some(size)) = (u32_at(&entry, 0), u32_at(&entry, 4))
                && let Some(off) = self.safe_resource_leaf(rva, size)
            {
                match kind {
                    Some(RT_VERSION) => self.protected.add(off, u64::from(size)),
                    Some(RT_MANIFEST) => {
                        self.protected.add(off, u64::from(size));
                        self.evidence.extend(
                            manifest_names(self.view, off, size as usize)
                                .into_iter()
                                .map(|name| (name, Source::Manifest)),
                        );
                    }
                    Some(RT_STRING) => {
                        self.protected.add(off, u64::from(size));
                        self.structured_hits
                            .extend(string_table(self.view, off, size as usize))
                    }
                    Some(RT_DIALOG) => {
                        self.protected.add(off, u64::from(size));
                        self.structured_hits
                            .extend(dialog_table(self.view, off, size as usize));
                    }
                    Some(RT_MESSAGETABLE) => {
                        self.protected.add(off, u64::from(size));
                        self.structured_hits
                            .extend(message_table(self.view, off, size as usize));
                    }
                    Some(RT_PIPL) => {
                        self.protected.add(off, u64::from(size));
                        match read_full(self.view, off, size as usize)
                            .and_then(|raw| Pipl::parse(&raw, off))
                        {
                            Some(pipl) => {
                                self.evidence.extend(pipl.evidence());
                                self.pipls.push(pipl);
                            }
                            None => self.skipped.push(Reason::MalformedMetadata),
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// Protect .NET metadata and return the strings of its user string heap,
    /// the one heap the runtime reads as text rather than resolving by name.
    fn dotnet(&mut self) -> Vec<Hit> {
        let Some(d) = self.img.dir(DIR_CLR) else {
            return Vec::new();
        };
        let Some(off) = self.img.rva_to_off(d.rva) else {
            return Vec::new();
        };
        let Some(h) = read_full(self.view, off, 72) else {
            return Vec::new();
        };
        let (Some(md_rva), Some(md_size), Some(flags)) =
            (u32_at(&h, 8), u32_at(&h, 12), u32_at(&h, 16))
        else {
            return Vec::new();
        };
        if flags & 0x8 != 0 {
            self.caveats.push(Caveat::SignatureInvalidated);
        }
        for (rva_at, size_at) in [(24, 28), (32, 36)] {
            if let (Some(rva), Some(size)) = (u32_at(&h, rva_at), u32_at(&h, size_at))
                && let Some(o) = self.img.rva_to_off(rva)
            {
                self.protected.add(o, u64::from(size));
            }
        }
        let Some(md) = self.img.rva_to_off(md_rva) else {
            return Vec::new();
        };
        self.protected.add(md, u64::from(md_size));
        let (rewrites, evidence, skipped) = dotnet::attributes(self.view, md, u64::from(md_size));
        self.rewrites.extend(rewrites);
        self.evidence.extend(evidence);
        self.skipped.extend(skipped);
        user_strings(self.view, md, u64::from(md_size)).unwrap_or_default()
    }

    fn debug(&mut self) {
        let Some(d) = self.img.dir(DIR_DEBUG) else {
            return;
        };
        let Some(dir) = self.img.rva_to_off(d.rva) else {
            return;
        };
        for i in 0..(u64::from(d.size) / 28).min(1024) {
            let at = dir + i * 28;
            let Some(entry) = read_full(self.view, at, 28) else {
                return;
            };
            self.zero(at + 4, 4);
            let (Some(kind), Some(size), Some(ptr)) =
                (u32_at(&entry, 12), u32_at(&entry, 16), u32_at(&entry, 24))
            else {
                continue;
            };
            let (ptr, size) = (u64::from(ptr), size as usize);
            if ptr == 0 || size == 0 || size > MAX_DEBUG_BODY {
                continue;
            }
            self.protected.add(ptr, size as u64);
            match kind {
                DEBUG_CODEVIEW => self.codeview(ptr, size),
                DEBUG_MISC => self.misc(ptr, size),
                DEBUG_EMBEDDED_PDB => self.embedded_pdb(at, ptr, size),
                DEBUG_VC_FEATURE | DEBUG_POGO | DEBUG_REPRO => self.zero(ptr, size),
                _ => {}
            }
        }
    }

    /// Zero a CodeView record's PDB path, and for RSDS its GUID (the age stays).
    fn codeview(&mut self, ptr: u64, size: usize) {
        let Some(data) = read_full(self.view, ptr, size) else {
            return;
        };
        let path_at = match data.get(..4) {
            Some(b"RSDS") => {
                self.zero(ptr + 4, 16);
                24
            }
            Some(b"NB10") => 16,
            _ => return,
        };
        if let Some(end) = data
            .get(path_at..)
            .and_then(|b| b.iter().position(|&x| x == 0))
            .filter(|&e| e > 0)
        {
            let path = String::from_utf8_lossy(&data[path_at..path_at + end]);
            let file = path.rsplit(['\\', '/']).next().unwrap_or("");
            if let Some(stem) = file.to_ascii_lowercase().strip_suffix(".pdb") {
                self.evidence.push((stem.to_string(), Source::Pdb));
            }
            self.zero(ptr + path_at as u64, end);
        }
    }

    fn misc(&mut self, ptr: u64, size: usize) {
        let Some(raw) = read_full(self.view, ptr, size) else {
            return;
        };
        if raw.len() < 12
            || u32_at(&raw, 0) != Some(1)
            || u32_at(&raw, 4).is_none_or(|n| n as usize > size || n < 12)
        {
            return;
        }
        let unicode = raw[8] != 0;
        let data = &raw[12..];
        let len = if unicode {
            data.as_chunks::<2>()
                .0
                .iter()
                .position(|p| *p == [0, 0])
                .map(|n| n * 2)
        } else {
            data.iter().position(|&b| b == 0)
        };
        let Some(len) = len.filter(|&n| n > 0) else {
            return;
        };
        let value = if unicode {
            String::from_utf16(
                &data[..len]
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|p| u16::from_le_bytes(*p))
                    .collect::<Vec<_>>(),
            )
            .ok()
        } else {
            Some(single_byte(&data[..len]))
        };
        if let Some(value) = value {
            let stem = value
                .rsplit(['\\', '/'])
                .next()
                .unwrap_or("")
                .split('.')
                .next()
                .unwrap_or("");
            self.evidence.push((stem.to_string(), Source::Pdb));
            self.zero(ptr + 12, len);
        }
    }

    fn embedded_pdb(&mut self, entry: u64, ptr: u64, size: usize) {
        let Some(raw) = read_full(self.view, ptr, size) else {
            return;
        };
        if raw.get(..4) != Some(b"MPDB") {
            return;
        }
        let Some(unpacked) = u32_at(&raw, 4)
            .map(|n| n as usize)
            .filter(|&n| n <= 64 * 1024 * 1024)
        else {
            self.skipped.push(Reason::DeepBudget);
            return;
        };
        let Ok(data) = miniz_oxide::inflate::decompress_to_vec_with_limit(&raw[8..], unpacked)
        else {
            self.skipped.push(Reason::MalformedMetadata);
            return;
        };
        if data.len() != unpacked {
            self.skipped.push(Reason::MalformedMetadata);
            return;
        }
        let mut hits = Vec::new();
        strings(&data, 0, true, &mut hits);
        for hit in hits {
            if hit.text.to_ascii_lowercase().contains(".pdb") {
                let stem = hit
                    .text
                    .rsplit(['\\', '/'])
                    .next()
                    .unwrap_or("")
                    .split('.')
                    .next()
                    .unwrap_or("");
                self.evidence.push((stem.to_string(), Source::Pdb));
            }
        }
        self.zero(ptr, size);
        self.zero(entry + 16, 12);
    }

    /// The certificate is outside the loaded image. Mine its names before
    /// clearing the detached payload and the directory slot.
    fn certificate(&mut self) -> Option<Marker> {
        let d = self.img.dir(DIR_SECURITY)?;
        let off = u64::from(d.rva);
        let len = d.size as usize;
        if !(8..=MAX_CERT_BODY).contains(&len)
            || off < self.img.image_end()
            || off
                .checked_add(len as u64)
                .is_none_or(|end| end > self.view.size())
        {
            self.skipped.push(Reason::Unsafe);
            return None;
        }
        let Some(table) = read_full(self.view, off, len) else {
            self.skipped.push(Reason::Io);
            return None;
        };
        if u32_at(&table, 0).is_none_or(|n| n < 8 || n as usize > len) {
            self.skipped.push(Reason::Unsafe);
            return None;
        }
        self.evidence.extend(
            certificate_names(&table)
                .into_iter()
                .map(|name| (name, Source::Certificate)),
        );
        Some(fill_marker(off, len as u64, 0))
    }

    /// Initialized data sections past the headers that hold no code.
    fn data_regions(&self) -> Vec<(u64, u64)> {
        let headers = u64::from(self.img.size_of_headers).max(self.img.table_end);
        let mut out: Vec<(u64, u64)> = self
            .img
            .sections
            .iter()
            .filter(|s| {
                s.characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE) == 0
                    && s.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA != 0
                    && s.raw_size != 0
                    && u64::from(s.raw_ptr) >= headers
                    && u64::from(s.raw_ptr) + u64::from(s.raw_size) <= self.view.size()
            })
            .map(|s| (u64::from(s.raw_ptr), u64::from(s.raw_size)))
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }
}

/// The strings of a .NET `#US` heap: length-prefixed UTF-16 with a trailing
/// flag byte, reported without the prefix and flag so a blank keeps both.
fn user_strings(view: &dyn FileView, md: u64, md_size: u64) -> Option<Vec<Hit>> {
    let root = read_full(view, md, 16)?;
    if root.get(..4)? != b"BSJB" {
        return None;
    }
    let ver_len = u64::from(u32_at(&root, 12)?);
    let streams_at = md.checked_add(16)?.checked_add(ver_len)?;
    let head = read_full(view, streams_at, 4)?;
    let count = usize::from(u16_at(&head, 2)?).min(16);
    let mut at = streams_at + 4;
    for _ in 0..count {
        let h = read_full(view, at, 8 + 32)?;
        let offset = u64::from(u32_at(&h, 0)?);
        let size = u64::from(u32_at(&h, 4)?);
        let name_end = h[8..].iter().position(|&b| b == 0)?;
        let name = &h[8..8 + name_end];
        at += 8 + (name_end as u64 + 4) / 4 * 4;
        if name != b"#US" {
            continue;
        }
        if offset.checked_add(size)? > md_size || size > 64 * 1024 * 1024 {
            return None;
        }
        let heap_off = md + offset;
        let heap = read_full(view, heap_off, size as usize)?;
        let mut hits = Vec::new();
        let mut pos = 1usize;
        while pos < heap.len() {
            let b0 = heap[pos];
            let (len, hdr) = if b0 & 0x80 == 0 {
                (usize::from(b0), 1)
            } else if b0 & 0xc0 == 0x80 {
                (
                    usize::from(b0 & 0x3f) << 8 | usize::from(*heap.get(pos + 1)?),
                    2,
                )
            } else {
                let b = heap.get(pos..pos + 4)?;
                (
                    usize::from(b[0] & 0x1f) << 24
                        | usize::from(b[1]) << 16
                        | usize::from(b[2]) << 8
                        | usize::from(b[3]),
                    4,
                )
            };
            let body = pos + hdr;
            let chars = len.saturating_sub(1);
            if len == 0 {
                pos = body;
                continue;
            }
            if body + len > heap.len() {
                break;
            }
            let bytes = &heap[body..body + chars];
            if chars >= 8
                && chars % 2 == 0
                && bytes
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .all(|p| p[1] == 0 && (0x20..=0x7e).contains(&p[0]))
            {
                hits.push(Hit {
                    off: heap_off + body as u64,
                    len: chars,
                    text: bytes.iter().step_by(2).map(|&b| char::from(b)).collect(),
                    encoding: Encoding::Utf16,
                });
            }
            pos = body + len;
        }
        return Some(hits);
    }
    None
}

pub(super) fn sweep(view: &dyn FileView) -> Deep {
    let Some(img) = PeImage::parse(view) else {
        return Deep::default();
    };
    let mut w = Walk {
        view,
        img: &img,
        protected: Protected::default(),
        import_protected: Protected::default(),
        rewrites: Vec::new(),
        caveats: Vec::new(),
        resource_hits: Vec::new(),
        structured_hits: Vec::new(),
        pipls: Vec::new(),
        evidence: Vec::new(),
        skipped: Vec::new(),
    };
    w.protected
        .add(0, u64::from(img.size_of_headers).max(img.table_end));
    for dir in [
        DIR_EXPORT,
        DIR_IMPORT,
        DIR_EXCEPTION,
        DIR_BASERELOC,
        DIR_DEBUG,
        DIR_TLS,
        DIR_LOAD_CONFIG,
        DIR_BOUND_IMPORT,
        DIR_IAT,
        DIR_DELAY_IMPORT,
        DIR_CLR,
    ] {
        w.dir_range(dir);
    }
    for dir in [DIR_IMPORT, DIR_IAT, DIR_DELAY_IMPORT, DIR_BOUND_IMPORT] {
        if let Some(d) = img.dir(dir)
            && let Some(off) = img.rva_to_off(d.rva)
        {
            w.import_protected.add(off, u64::from(d.size));
        }
    }
    w.imports();
    w.delay_imports();
    let module = w.exports();
    w.resources();
    let user = w.dotnet();
    w.debug();
    let certificate = w.certificate();
    if let Some(info) = version::find(&img, view) {
        for item in info.strings {
            let source = match item.key.as_str() {
                "CompanyName" => Some(Source::Company),
                "ProductName" | "InternalName" | "OriginalFilename" => Some(Source::Product),
                _ => None,
            };
            if let Some(source) = source {
                let value = if item.key == "OriginalFilename" {
                    item.value.split('.').next().unwrap_or("").to_string()
                } else {
                    item.value
                };
                w.evidence.push((value, source));
            }
        }
    }

    // COFF header TimeDateStamp.
    w.zero(img.e_lfanew + 8, 4);
    // A cleared security slot leaves the copy unsigned rather than carrying a
    // signature that no longer matches.
    if img.dir(DIR_SECURITY).is_some() {
        w.zero(img.dirs_off + DIR_SECURITY as u64 * 8, 8);
        w.caveats.push(Caveat::SignatureInvalidated);
    }

    let regions = w.data_regions();
    let mut hits = region_strings(view, &regions, &mut w.skipped);
    hits.extend(w.resource_hits.iter().cloned());
    hits.extend(w.structured_hits.iter().cloned());
    hits.sort();
    hits.dedup();
    let mut all_hits = hits.clone();
    all_hits.extend(user.iter().cloned());
    let stem = module.as_ref().and_then(|(_, name)| {
        let name = std::str::from_utf8(name).ok()?;
        name.split(['.', '_']).next()
    });
    let roots = aggressive_roots(&all_hits, &w.evidence, roots(&all_hits, stem, &w.evidence));
    let mut audit_terms = identity_terms(&roots);
    let code_regions: Vec<(u64, u64)> = img
        .sections
        .iter()
        .filter(|section| {
            section.characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE) != 0
        })
        .map(|section| (u64::from(section.raw_ptr), u64::from(section.raw_size)))
        .collect();
    let mut alias_hits = all_hits.clone();
    alias_hits.extend(region_strings(view, &code_regions, &mut w.skipped));
    audit_terms.extend(vendor_alias_terms(&alias_hits, &roots, stem, &w.evidence));
    audit_terms.extend(library_terms(&alias_hits));
    // Deep PE rewrites the readable identity bytes in these ranges below.
    let mut rewrites = redact_hits(&hits, &roots, &w.protected);
    rewrites.extend(redact_hits(
        &w.structured_hits,
        &roots,
        &Protected::default(),
    ));
    rewrites.extend(redact_hits(&user, &roots, &Protected::default()));
    let detached = certificate
        .as_ref()
        .map(|marker| (marker.region.offset, marker.region.len));
    let (identity_rewrites, _, budget_hit) = identity_bytes(
        view,
        &img,
        &audit_terms,
        &w.import_protected,
        detached,
        true,
    );
    if budget_hit {
        w.skipped.push(Reason::DeepBudget);
    }
    rewrites.extend(identity_rewrites);
    for pipl in &w.pipls {
        let (planned, skipped) = pipl.rewrites(&roots);
        rewrites.extend(planned);
        w.skipped.extend(
            skipped
                .into_iter()
                .filter(|reason| *reason != Reason::FunctionalName),
        );
    }
    let blanks = certificate
        .into_iter()
        .map(|marker| (Kind::Brand, marker))
        .collect();

    if let Some((off, old)) = module {
        let suffix = old
            .iter()
            .rposition(|&b| b == b'.')
            .map_or(&[][..], |i| &old[i..]);
        let room = old.len() - suffix.len();
        let mut name: Vec<u8> = NEUTRAL_MODULE.iter().copied().take(room).collect();
        name.resize(room, b'_');
        name.extend_from_slice(suffix);
        if name != old {
            w.rewrites.push((Kind::Brand, off, name));
        }
    }

    Deep {
        blanks,
        rewrites: merge_rewrites(rewrites.into_iter().chain(w.rewrites).collect()),
        caveats: w.caveats,
        skipped: w.skipped,
        audit_terms,
    }
}

/// Whether the PE carries an Authenticode signature.
pub(in super::super) fn signed(view: &dyn FileView) -> bool {
    PeImage::parse(view).is_some_and(|img| img.dir(DIR_SECURITY).is_some())
}

/// The checksum the PE will need once `targets` are applied, as one more
/// target, when the original carries a non-zero checksum that would change.
/// It is computed from the planned bytes, so the copy on disk and the same
/// file cleaned inside an archive get the same value.
pub(in super::super) fn checksum_target(view: &dyn FileView, targets: &[Target]) -> Option<Target> {
    if targets.is_empty() {
        return None;
    }
    let img = PeImage::parse(view)?;
    let field = img.checksum_off;
    if img.checksum == 0
        || targets
            .iter()
            .any(|t| t.marker.region.offset < field + 4 && t.marker.region.end() > field)
    {
        return None;
    }
    let size = view.size();
    let mut overlays: Vec<(u64, Vec<u8>)> = targets
        .iter()
        .map(|t| (t.marker.region.offset, t.new_bytes()))
        .collect();
    overlays.sort_by_key(|(off, _)| *off);
    const CHUNK: u64 = 1 << 20;
    let mut sum: u64 = 0;
    let mut pos = 0u64;
    // Overlays sorted by offset: each chunk skips the finished prefix and
    // stops at the first one past its end.
    let mut first = 0;
    while pos < size {
        let n = CHUNK.min(size - pos);
        let mut buf = read_full(view, pos, n as usize)?;
        let end = pos + n;
        while overlays
            .get(first)
            .is_some_and(|(off, bytes)| off + bytes.len() as u64 <= pos)
        {
            first += 1;
        }
        for (off, bytes) in overlays[first..].iter().take_while(|(off, _)| *off < end) {
            let o_end = off + bytes.len() as u64;
            if o_end <= pos || *off >= end {
                continue;
            }
            let from = (*off).max(pos);
            let to = o_end.min(end);
            buf[(from - pos) as usize..(to - pos) as usize]
                .copy_from_slice(&bytes[(from - off) as usize..(to - off) as usize]);
        }
        for f in field..field + 4 {
            if f >= pos && f < end {
                buf[(f - pos) as usize] = 0;
            }
        }
        for w in buf.chunks(2) {
            let word = match *w {
                [lo, hi] => u16::from_le_bytes([lo, hi]),
                [lo] => u16::from(lo),
                _ => 0,
            };
            sum += u64::from(word);
            sum = (sum & 0xffff) + (sum >> 16);
        }
        pos = end;
    }
    let folded = ((sum & 0xffff) + (sum >> 16)) & 0xffff;
    let value = (folded as u32).wrapping_add(size as u32);
    if value == img.checksum {
        return None;
    }
    let original = read_full(view, field, 4)?;
    Some(Target {
        kind: Kind::Brand,
        marker: Marker::blank(Region::new(field, 4), ContainerKind::Raw),
        expected_hash: hash_hex(&original),
        replacement: Some(value.to_le_bytes().to_vec()),
    })
}
