//! PDF: the document information dictionary (`/Info`), any `/Producer` and
//! `/Creator` strings, incremental updates (more than one `%%EOF`) and the
//! trailer's `/Encrypt` entry.
//!
//! A file of at most 4 MiB is searched whole; a larger one through its header
//! and tail windows, plus the Info object itself when a classic xref table
//! places it outside them. Xref streams and object streams are compressed, so
//! an Info dictionary stored inside one is not reached.

use crate::model::{
    BrandKind, Category, Confidence, ContainerKind, Evidence, Finding, JunkKind, Marker, Region,
    RemovalStrategy, Severity, SignatureStatus, TamperKind,
};
use crate::scan::FileView;
use crate::util::bytes::{find, rfind};

use crate::parsers::image::shared::{
    NOTE_CHARS, TITLE_CHARS, clip, excerpt, fetch, finding, latin1,
};

/// Files up to this size are searched whole.
const WHOLE_FILE: u64 = 4 * 1024 * 1024;
/// Bytes read at an object located through the xref table.
const OBJECT_READ: usize = 16 * 1024;
/// Most xref sections followed through `/Prev`.
const MAX_XREF: usize = 8;
/// Most subsections read in one xref section.
const MAX_SUBSECTIONS: usize = 256;
/// Most occurrences of one needle considered per buffer.
const MAX_HITS: usize = 64;
/// Longest string value accepted.
const MAX_STRING: usize = 32 * 1024;
/// Deepest nesting of dictionaries and arrays parsed.
const MAX_DEPTH: usize = 32;
/// Most entries in one dictionary or array.
const MAX_ENTRIES: usize = 512;
/// How far back from a key an enclosing `<<` is looked for.
const ENCLOSE_BACK: usize = 8 * 1024;
/// Most `<<` candidates tried when looking for an enclosing dictionary.
const ENCLOSE_TRIES: usize = 16;
/// Most bytes one top-level dictionary may span. Info, trailer and
/// encryption dictionaries are far smaller; the cap bounds the work a
/// hostile file can cause.
const MAX_DICT: usize = 32 * 1024;

/// Info keys reported: name, signature id, and the label used in titles.
const INFO_KEYS: &[(&[u8], &str, &str)] = &[
    (b"Producer", "pdf.producer", "producer"),
    (b"Creator", "pdf.creator", "creator"),
    (b"Author", "pdf.info", "author"),
    (b"Title", "pdf.info", "title"),
    (b"Subject", "pdf.info", "subject"),
    (b"Keywords", "pdf.info", "keywords"),
    (b"CreationDate", "pdf.info", "creation date"),
    (b"ModDate", "pdf.info", "modification date"),
];

/// A searched piece of the file.
struct Seg {
    off: u64,
    buf: Vec<u8>,
}

/// A parsed value. Offsets index the buffer it was parsed from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Val {
    /// A literal `( )` or hex `< >` string; `start..end` is the content
    /// between the delimiters.
    Str {
        start: usize,
        end: usize,
        hex: bool,
    },
    Ref(u32, u16),
    Int(i64),
    Name {
        start: usize,
        end: usize,
    },
    Dict {
        start: usize,
    },
    Other,
}

/// One dictionary entry: the key's `/` offset, the end of the key name, the
/// value, and one past the value.
#[derive(Debug, Clone, Copy)]
struct Entry {
    key_at: usize,
    key_end: usize,
    val: Val,
    val_end: usize,
}

impl Entry {
    fn key<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        buf.get(self.key_at + 1..self.key_end).unwrap_or_default()
    }
}

fn is_ws(b: u8) -> bool {
    matches!(b, 0 | 9 | 10 | 12 | 13 | 32)
}

fn is_regular(b: u8) -> bool {
    !is_ws(b)
        && !matches!(
            b,
            b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
        )
}

/// Skip whitespace and comments.
fn skip_ws(buf: &[u8], mut i: usize) -> usize {
    while let Some(&b) = buf.get(i) {
        if is_ws(b) {
            i += 1;
        } else if b == b'%' {
            while buf.get(i).is_some_and(|&c| c != b'\n' && c != b'\r') {
                i += 1;
            }
        } else {
            break;
        }
    }
    i
}

/// One past a run of regular characters starting at `i`.
fn token_end(buf: &[u8], mut i: usize) -> usize {
    while buf.get(i).is_some_and(|&b| is_regular(b)) {
        i += 1;
    }
    i
}

fn int(tok: &[u8]) -> Option<i64> {
    if tok.is_empty() || tok.len() > 18 {
        return None;
    }
    std::str::from_utf8(tok).ok()?.parse().ok()
}

/// The index of the `)` closing the literal string opened at `open`.
fn literal_end(buf: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut i = open;
    let limit = open.saturating_add(MAX_STRING).min(buf.len());
    while i < limit {
        match *buf.get(i)? {
            b'\\' => i += 1,
            b'(' => depth += 1,
            b')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// The index of the `>` closing the hex string opened at `open`.
fn hex_end(buf: &[u8], open: usize) -> Option<usize> {
    let limit = open.saturating_add(MAX_STRING).min(buf.len());
    for i in open + 1..limit {
        match *buf.get(i)? {
            b'>' => return Some(i),
            b if b.is_ascii_hexdigit() || is_ws(b) => {}
            _ => return None,
        }
    }
    None
}

/// Parse the value starting at `i`, returning it and the index one past it.
fn parse_value(buf: &[u8], i: usize, depth: usize) -> Option<(Val, usize)> {
    if depth > MAX_DEPTH {
        return None;
    }
    let b = *buf.get(i)?;
    match b {
        b'(' => {
            let e = literal_end(buf, i)?;
            Some((
                Val::Str {
                    start: i + 1,
                    end: e,
                    hex: false,
                },
                e + 1,
            ))
        }
        b'<' if buf.get(i + 1) == Some(&b'<') => {
            let (_, end) = parse_dict(buf, i, depth + 1)?;
            Some((Val::Dict { start: i }, end))
        }
        b'<' => {
            let e = hex_end(buf, i)?;
            Some((
                Val::Str {
                    start: i + 1,
                    end: e,
                    hex: true,
                },
                e + 1,
            ))
        }
        b'[' => {
            let mut j = i + 1;
            for _ in 0..MAX_ENTRIES {
                j = skip_ws(buf, j);
                if *buf.get(j)? == b']' {
                    return Some((Val::Other, j + 1));
                }
                j = parse_value(buf, j, depth + 1)?.1;
            }
            None
        }
        b'/' => {
            let e = token_end(buf, i + 1);
            Some((
                Val::Name {
                    start: i + 1,
                    end: e,
                },
                e,
            ))
        }
        _ if is_regular(b) => {
            let e = token_end(buf, i);
            let Some(n) = buf.get(i..e).and_then(int) else {
                return Some((Val::Other, e));
            };
            // An indirect reference: `N G R`.
            let j = skip_ws(buf, e);
            let je = token_end(buf, j);
            if let Some(g) = buf.get(j..je).and_then(int) {
                let k = skip_ws(buf, je);
                let ends = buf.get(k + 1).is_none_or(|&c| !is_regular(c));
                if buf.get(k) == Some(&b'R')
                    && ends
                    && let (Ok(n), Ok(g)) = (u32::try_from(n), u16::try_from(g))
                {
                    return Some((Val::Ref(n, g), k + 1));
                }
            }
            Some((Val::Int(n), e))
        }
        _ => None,
    }
}

/// Parse the dictionary whose `<<` is at `at`: its entries and the index one
/// past its `>>`.
fn parse_dict(buf: &[u8], at: usize, depth: usize) -> Option<(Vec<Entry>, usize)> {
    if depth > MAX_DEPTH || buf.get(at..at + 2)? != b"<<" {
        return None;
    }
    let mut entries = Vec::new();
    let mut i = at + 2;
    loop {
        i = skip_ws(buf, i);
        if buf.get(i..i + 2)? == b">>" {
            return Some((entries, i + 2));
        }
        if *buf.get(i)? != b'/' || entries.len() >= MAX_ENTRIES {
            return None;
        }
        let key_end = token_end(buf, i + 1);
        let (val, next) = parse_value(buf, skip_ws(buf, key_end), depth)?;
        entries.push(Entry {
            key_at: i,
            key_end,
            val,
            val_end: next,
        });
        i = next;
    }
}

/// `buf` cut to at most [`MAX_DICT`] bytes past `at`, so a top-level parse
/// starting there stays bounded. Offsets into the result equal offsets into
/// `buf`.
fn bounded(buf: &[u8], at: usize) -> &[u8] {
    &buf[..buf.len().min(at.saturating_add(MAX_DICT))]
}

/// Parse the top-level dictionary at `at`, within the [`MAX_DICT`] budget.
fn dict_at(buf: &[u8], at: usize) -> Option<(Vec<Entry>, usize)> {
    parse_dict(bounded(buf, at), at, 0)
}

/// Offsets of `needle` in `hay`, at most [`MAX_HITS`].
fn find_all(hay: &[u8], needle: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    let mut from = 0usize;
    while out.len() < MAX_HITS {
        let Some(p) = hay.get(from..).and_then(|h| find(h, needle)) else {
            break;
        };
        out.push(from + p);
        from += p + 1;
    }
    out
}

/// Offsets of `/Key` tokens (`key` includes the slash) not followed by more
/// name characters.
fn key_hits(buf: &[u8], key: &[u8]) -> Vec<usize> {
    find_all(buf, key)
        .into_iter()
        .filter(|&p| buf.get(p + key.len()).is_none_or(|&b| !is_regular(b)))
        .collect()
}

/// The dictionary that directly holds the key at `p`.
fn enclosing_dict(buf: &[u8], p: usize) -> Option<(usize, Vec<Entry>)> {
    let lo = p.saturating_sub(ENCLOSE_BACK);
    let mut hi = p;
    for _ in 0..ENCLOSE_TRIES {
        let c = lo + rfind(buf.get(lo..hi)?, b"<<")?;
        if let Some((entries, _)) = dict_at(buf, c)
            && entries.iter().any(|e| e.key_at == p)
        {
            return Some((c, entries));
        }
        hi = c + 1;
    }
    None
}

/// Where each definition of object `n g` opens its dictionary: (segment
/// index, offset of `<<`).
fn find_objects(segs: &[Seg], (n, g): (u32, u16)) -> Vec<(usize, usize)> {
    let pat = format!("{n} {g} obj");
    let mut out = Vec::new();
    for (si, s) in segs.iter().enumerate() {
        for p in find_all(&s.buf, pat.as_bytes()) {
            if p > 0 && s.buf.get(p - 1).is_some_and(u8::is_ascii_digit) {
                continue;
            }
            let after = p + pat.len();
            if s.buf.get(after).is_some_and(|&b| is_regular(b)) {
                continue;
            }
            let at = skip_ws(&s.buf, after);
            if s.buf.get(at..at + 2) == Some(b"<<") {
                out.push((si, at));
            }
        }
    }
    out
}

/// A trailer dictionary (classic `trailer` or an xref stream's dictionary).
struct Trailer {
    seg: usize,
    entries: Vec<Entry>,
}

impl Trailer {
    fn get(&self, segs: &[Seg], key: &[u8]) -> Option<Entry> {
        let buf = &segs.get(self.seg)?.buf;
        self.entries.iter().find(|e| e.key(buf) == key).copied()
    }
}

fn trailers(segs: &[Seg]) -> Vec<Trailer> {
    let mut out = Vec::new();
    for (si, s) in segs.iter().enumerate() {
        let buf = &s.buf;
        for p in find_all(buf, b"trailer") {
            let before = p == 0 || buf.get(p - 1).is_some_and(|&b| !is_regular(b));
            if !before || buf.get(p + 7).is_some_and(|&b| is_regular(b)) {
                continue;
            }
            if let Some((entries, _)) = dict_at(buf, skip_ws(buf, p + 7)) {
                out.push(Trailer { seg: si, entries });
            }
        }
        for p in key_hits(buf, b"/XRef") {
            // `/XRef` is the value of `/Type`; its dictionary encloses the
            // `/Type` key just before it.
            let lo = p.saturating_sub(64);
            let Some(t) = buf
                .get(lo..p)
                .and_then(|b| rfind(b, b"/Type"))
                .map(|t| lo + t)
            else {
                continue;
            };
            if skip_ws(buf, t + 5) != p {
                continue;
            }
            if let Some((_, entries)) = enclosing_dict(buf, t) {
                out.push(Trailer { seg: si, entries });
            }
        }
    }
    out
}

/// Resolve object `num` through the classic xref table(s) that `startxref`
/// points at, following `/Prev`. Returns the object's file offset.
fn xref_lookup(view: &dyn FileView, num: u32) -> Option<u64> {
    let tail = view.tail();
    let p = rfind(tail, b"startxref")?;
    let i = skip_ws(tail, p + 9);
    let mut off = u64::try_from(int(tail.get(i..token_end(tail, i))?)?).ok()?;
    for _ in 0..MAX_XREF {
        let head = fetch(view, off, 4)?;
        if head != b"xref" {
            return None;
        }
        let mut pos = off + 4;
        let mut trailer_at = None;
        for _ in 0..MAX_SUBSECTIONS {
            let chunk = view.read_at(pos, 64).ok()?;
            let j = skip_ws(&chunk, 0);
            if chunk.get(j..j + 7) == Some(b"trailer") {
                trailer_at = Some(pos + j as u64);
                break;
            }
            let je = token_end(&chunk, j);
            let start = u64::try_from(int(chunk.get(j..je)?)?).ok()?;
            let k = skip_ws(&chunk, je);
            let ke = token_end(&chunk, k);
            let count = u64::try_from(int(chunk.get(k..ke)?)?).ok()?;
            let entries = pos + skip_ws(&chunk, ke) as u64;
            if (start..start.saturating_add(count)).contains(&(num as u64)) {
                let at = entries.checked_add((num as u64 - start).checked_mul(20)?)?;
                let e = fetch(view, at, 18)?;
                let obj = u64::try_from(int(e.get(..10)?)?).ok()?;
                return (e.get(17) == Some(&b'n')).then_some(obj);
            }
            pos = entries.checked_add(count.checked_mul(20)?)?;
        }
        let t = trailer_at?;
        let chunk = view.read_at(t, 4096).ok()?;
        let (entries, _) = parse_dict(&chunk, skip_ws(&chunk, 7), 0)?;
        let prev = entries.iter().find(|e| e.key(&chunk) == b"Prev")?;
        let Val::Int(prev) = prev.val else {
            return None;
        };
        off = u64::try_from(prev).ok()?;
    }
    None
}

/// The raw bytes a string value stands for.
fn string_bytes(buf: &[u8], start: usize, end: usize, hex: bool) -> Option<Vec<u8>> {
    let raw = buf.get(start..end)?;
    if hex {
        let digits: Vec<u8> = raw
            .iter()
            .filter_map(|&b| (b as char).to_digit(16).map(|d| d as u8))
            .collect();
        return Some(
            digits
                .chunks(2)
                .map(|c| (c[0] << 4) | c.get(1).copied().unwrap_or(0))
                .collect(),
        );
    }
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0usize;
    while let Some(&b) = raw.get(i) {
        i += 1;
        if b != b'\\' {
            out.push(b);
            continue;
        }
        let Some(&e) = raw.get(i) else {
            break;
        };
        i += 1;
        match e {
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b't' => out.push(b'\t'),
            b'b' => out.push(8),
            b'f' => out.push(12),
            b'\r' => {
                if raw.get(i) == Some(&b'\n') {
                    i += 1;
                }
            }
            b'\n' => {}
            b'0'..=b'7' => {
                let mut v = (e - b'0') as u32;
                for _ in 0..2 {
                    match raw.get(i) {
                        Some(&d @ b'0'..=b'7') => {
                            v = v * 8 + (d - b'0') as u32;
                            i += 1;
                        }
                        _ => break,
                    }
                }
                out.push((v & 0xFF) as u8);
            }
            other => out.push(other),
        }
    }
    Some(out)
}

/// Text from string bytes: UTF-16BE or UTF-8 with a byte order mark, else
/// PDFDocEncoding (read as ISO-8859-1, which matches it for text).
fn decode_text(bytes: &[u8]) -> String {
    if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        let units: Vec<u16> = rest
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_be_bytes(*c))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        return String::from_utf8_lossy(rest).to_string();
    }
    latin1(bytes)
}

/// `D:YYYYMMDDHHmmSS` plus an offset, rendered readably; other text as is.
fn pretty_date(s: &str) -> String {
    let body = s.strip_prefix("D:").unwrap_or(s);
    let digits: String = body.chars().take_while(char::is_ascii_digit).collect();
    if digits.len() < 8 {
        return s.to_string();
    }
    let d = |a: usize, b: usize| digits.get(a..b).unwrap_or("00");
    let rest = body.get(digits.len()..).unwrap_or("");
    let mut out = format!("{}-{}-{}", d(0, 4), d(4, 6), d(6, 8));
    if digits.len() >= 14 {
        out.push_str(&format!(" {}:{}:{}", d(8, 10), d(10, 12), d(12, 14)));
    }
    if !rest.is_empty() {
        out.push(' ');
        out.push_str(rest);
    }
    out
}

/// A finding for `entry` in `seg` when its key is one we report and its value
/// is a non-blank string.
fn entry_finding(seg: &Seg, e: &Entry, encrypted: bool) -> Option<Finding> {
    let buf = &seg.buf;
    let key = e.key(buf);
    let &(_, sig, label) = INFO_KEYS.iter().find(|(k, _, _)| *k == key)?;
    let Val::Str { start, end, hex } = e.val else {
        return None;
    };
    let bytes = string_bytes(buf, start, end, hex)?;
    let text = decode_text(&bytes);
    if text
        .trim_matches(|c: char| c == '\0' || c.is_whitespace())
        .is_empty()
    {
        return None;
    }
    let shown = if label.ends_with("date") {
        pretty_date(text.trim())
    } else {
        text
    };
    let key_name = latin1(key);
    let abs_key = seg.off + e.key_at as u64;
    let matched = excerpt(buf.get(e.key_at..e.val_end)?);
    let (category, severity) = match sig {
        "pdf.info" => (Category::Junk(JunkKind::DocInfo), Severity::Notice),
        _ => (Category::Brand(BrandKind::DocProducer), Severity::Info),
    };
    let (title, note, marker) = if encrypted {
        (
            format!("PDF {label} (encrypted value)"),
            format!(
                "/{key_name} holds an encrypted string; it is not blanked because the \
                 document's strings are encrypted"
            ),
            None,
        )
    } else {
        let mut note = format!("/{key_name} = \"{}\"", clip(&shown, NOTE_CHARS));
        if hex {
            note.push_str(" (hex string)");
        }
        let fill = if hex { b'0' } else { b' ' };
        (
            format!("PDF {label} \"{}\"", clip(&shown, TITLE_CHARS)),
            note,
            Some(Marker {
                region: Region::new(seg.off + start as u64, (end - start) as u64),
                removal: RemovalStrategy::RawBlank { fill },
                container: ContainerKind::PdfObject,
                reversible: true,
            }),
        )
    };
    Some(finding(
        sig,
        category,
        Confidence::Moderate,
        severity,
        title,
        Evidence::at(abs_key).with_bytes(matched).with_note(note),
        marker,
    ))
}

pub(super) fn run(view: &dyn FileView, out: &mut Vec<Finding>) {
    let size = view.size();
    let mut segs = if size <= WHOLE_FILE {
        let Ok(len) = usize::try_from(size) else {
            return;
        };
        let Some(buf) = fetch(view, 0, len) else {
            return;
        };
        vec![Seg { off: 0, buf }]
    } else {
        vec![
            Seg {
                off: 0,
                buf: view.header().to_vec(),
            },
            Seg {
                off: view.tail_start(),
                buf: view.tail().to_vec(),
            },
        ]
    };
    let windows = segs.len();
    let Some(first) = segs.first() else {
        return;
    };
    let lead = &first.buf[..first.buf.len().min(1024)];
    if find(lead, b"%PDF-").is_none() {
        return;
    }
    let linearized = find(lead, b"/Linearized").is_some();

    let trailers = trailers(&segs);
    let encrypt = trailers
        .iter()
        .find_map(|t| t.get(&segs, b"Encrypt").map(|e| (t.seg, e)));
    let mut refs: Vec<(u32, u16)> = Vec::new();
    for t in &trailers {
        if let Some(Entry {
            val: Val::Ref(n, g),
            ..
        }) = t.get(&segs, b"Info")
            && !refs.contains(&(n, g))
        {
            refs.push((n, g));
        }
    }
    if size > WHOLE_FILE {
        for &r in &refs {
            if !find_objects(&segs, r).is_empty() {
                continue;
            }
            if let Some(off) = xref_lookup(view, r.0)
                && let Ok(buf) = view.read_at(off, OBJECT_READ)
            {
                segs.push(Seg { off, buf });
            }
        }
    }

    // Every Info dictionary: the objects the trailers name, and any
    // dictionary holding a /Producer key.
    let mut dicts: Vec<(usize, usize, Vec<Entry>)> = Vec::new();
    for &r in &refs {
        for (si, at) in find_objects(&segs, r) {
            if let Some((entries, _)) = dict_at(&segs[si].buf, at) {
                dicts.push((si, at, entries));
            }
        }
    }
    for (si, s) in segs.iter().enumerate() {
        for p in key_hits(&s.buf, b"/Producer") {
            if let Some((at, entries)) = enclosing_dict(&s.buf, p) {
                dicts.push((si, at, entries));
            }
        }
    }

    let encrypted = encrypt.is_some();
    let mut found: Vec<Finding> = Vec::new();
    let mut push = |f: Finding| {
        let dup = found
            .iter()
            .any(|g| g.evidence.offset == f.evidence.offset && g.signature_id == f.signature_id);
        if !dup {
            found.push(f);
        }
    };
    for (si, _, entries) in &dicts {
        for e in entries {
            if let Some(f) = entry_finding(&segs[*si], e, encrypted) {
                push(f);
            }
        }
    }
    // Any other /Producer or /Creator string, wherever it sits.
    for s in &segs {
        for key in [&b"/Producer"[..], b"/Creator"] {
            for p in key_hits(&s.buf, key) {
                let key_end = p + key.len();
                let at = skip_ws(&s.buf, key_end);
                let Some((val, val_end)) = parse_value(bounded(&s.buf, at), at, 0) else {
                    continue;
                };
                let e = Entry {
                    key_at: p,
                    key_end,
                    val,
                    val_end,
                };
                if let Some(f) = entry_finding(s, &e, encrypted) {
                    push(f);
                }
            }
        }
    }
    found.sort_by_key(|f| f.evidence.offset);
    out.extend(found);

    incremental(&segs[..windows], linearized, out);
    if let Some((si, e)) = encrypt {
        encrypted_finding(&segs, si, &e, out);
    }
}

fn incremental(segs: &[Seg], linearized: bool, out: &mut Vec<Finding>) {
    let mut eofs: Vec<u64> = segs
        .iter()
        .flat_map(|s| {
            find_all(&s.buf, b"%%EOF")
                .into_iter()
                .map(|p| s.off + p as u64)
        })
        .collect();
    eofs.sort_unstable();
    eofs.dedup();
    // A linearized file closes its first-page section with its own %%EOF.
    let skip = usize::from(linearized && eofs.len() >= 2);
    let revisions = eofs.len() - skip;
    if revisions < 2 {
        return;
    }
    let first = eofs[skip];
    let updates = revisions - 1;
    let later: Vec<String> = eofs[skip + 1..].iter().map(|o| o.to_string()).collect();
    out.push(finding(
        "pdf.incremental",
        Category::Tamper(TamperKind::Patched),
        Confidence::Moderate,
        Severity::Notice,
        format!(
            "PDF saved with {updates} incremental update{}",
            if updates == 1 { "" } else { "s" }
        ),
        Evidence::at(first)
            .with_bytes(b"%%EOF".to_vec())
            .with_note(format!(
                "{revisions} %%EOF markers: the first revision ends at offset {first} and \
                 later revisions end at offset {}, so content was changed or appended \
                 after the document was first written",
                later.join(", ")
            )),
        None,
    ));
}

fn encrypted_finding(segs: &[Seg], si: usize, e: &Entry, out: &mut Vec<Finding>) {
    let Some(seg) = segs.get(si) else {
        return;
    };
    // The encryption dictionary, inline or as an object we can see.
    let dict = match e.val {
        Val::Dict { start } => dict_at(&seg.buf, start).map(|(d, _)| (si, d)),
        Val::Ref(n, g) => find_objects(segs, (n, g))
            .into_iter()
            .find_map(|(s, at)| dict_at(&segs[s].buf, at).map(|(d, _)| (s, d))),
        _ => None,
    };
    let mut parts = Vec::new();
    let mut cipher = None;
    if let Some((ds, entries)) = &dict {
        let buf = &segs[*ds].buf;
        let num = |k: &[u8]| {
            entries
                .iter()
                .find(|x| x.key(buf) == k)
                .and_then(|x| match x.val {
                    Val::Int(v) => Some(v),
                    _ => None,
                })
        };
        if let Some(Val::Name { start, end }) = entries
            .iter()
            .find(|x| x.key(buf) == b"Filter")
            .map(|x| x.val)
        {
            let name = latin1(buf.get(start..end).unwrap_or_default());
            if name == "Standard" {
                parts.push("standard password security handler".to_string());
            } else {
                parts.push(format!("security handler /{}", clip(&name, TITLE_CHARS)));
            }
        }
        if let (Some(v), r) = (num(b"V"), num(b"R")) {
            parts.push(match r {
                Some(r) => format!("V {v}, R {r}"),
                None => format!("V {v}"),
            });
            cipher = match v {
                1 => Some("RC4 40-bit"),
                2 | 3 => Some("RC4"),
                4 => Some("RC4 or AES-128"),
                5 => Some("AES-256"),
                _ => None,
            };
        }
    }
    let mut note = "the trailer names an /Encrypt dictionary, so the document's strings and \
                    streams are encrypted"
        .to_string();
    if !parts.is_empty() {
        note.push_str(&format!("; {}", parts.join(", ")));
    }
    let title = match cipher {
        Some(c) => format!("Encrypted PDF ({c})"),
        None => "Encrypted PDF".to_string(),
    };
    let matched = excerpt(seg.buf.get(e.key_at..e.val_end).unwrap_or_default());
    out.push(finding(
        "pdf.encrypted",
        Category::Integrity(SignatureStatus::Present),
        Confidence::Moderate,
        Severity::Info,
        title,
        Evidence::at(seg.off + e.key_at as u64)
            .with_bytes(matched)
            .with_note(note),
        None,
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::doc::probes;
    use crate::parsers::image::shared::testkit::{apply, garbage, run, with_id};

    /// A PDF under construction: bytes and the offset of each object.
    struct Pdf {
        buf: Vec<u8>,
        objs: Vec<(u32, usize)>,
    }

    impl Pdf {
        fn new() -> Self {
            Pdf {
                buf: b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n".to_vec(),
                objs: Vec::new(),
            }
        }

        fn obj(&mut self, n: u32, body: &[u8]) {
            self.objs.push((n, self.buf.len()));
            self.buf
                .extend_from_slice(format!("{n} 0 obj\n").as_bytes());
            self.buf.extend_from_slice(body);
            self.buf.extend_from_slice(b"\nendobj\n");
        }

        /// A classic xref section for the objects added since the last one,
        /// then the trailer and `%%EOF`. Returns the xref offset.
        fn xref(&mut self, trailer: &str) -> usize {
            let at = self.buf.len();
            self.buf
                .extend_from_slice(b"xref\n0 1\n0000000000 65535 f \n");
            for (n, o) in std::mem::take(&mut self.objs) {
                self.buf
                    .extend_from_slice(format!("{n} 1\n{o:010} 00000 n \n").as_bytes());
            }
            self.buf.extend_from_slice(
                format!("trailer\n{trailer}\nstartxref\n{at}\n%%EOF\n").as_bytes(),
            );
            at
        }
    }

    const INFO: &[u8] =
        b"<< /Producer (LibreOffice 7.6) /Creator <FEFF 0057007200690074 00650072> \
        /Author (Jane \\(JD\\) Doe) /Title (Quarterly report) \
        /CreationDate (D:20240102030405+01'00') /Custom [ (x) 1 << /A 2 >> ] >>";

    /// A two-revision PDF: the original Info dict, then an update that
    /// rewrites it.
    fn updated() -> Vec<u8> {
        let mut p = Pdf::new();
        p.obj(1, b"<< /Type /Catalog /Pages 2 0 R >>");
        p.obj(2, b"<< /Type /Pages /Kids [ ] /Count 0 >>");
        p.obj(3, INFO);
        let x = p.xref("<< /Size 4 /Root 1 0 R /Info 3 0 R >>");
        p.obj(
            3,
            b"<< /Producer (Example PDF Editor 2.1) /ModDate (D:20250607080910Z) >>",
        );
        p.xref(&format!("<< /Size 4 /Root 1 0 R /Info 3 0 R /Prev {x} >>"));
        p.buf
    }

    fn scan(data: &[u8]) -> Vec<Finding> {
        run(probes(), "report.pdf", data, "pdf")
    }

    #[test]
    fn info_strings_and_updates_are_found() {
        let data = updated();
        let fs = scan(&data);
        let producers = with_id(&fs, "pdf.producer");
        assert_eq!(producers.len(), 2);
        assert_eq!(producers[0].title, "PDF producer \"LibreOffice 7.6\"");
        assert_eq!(
            producers[1].title,
            "PDF producer \"Example PDF Editor 2.1\""
        );
        assert_eq!(
            producers[0].category,
            Category::Brand(BrandKind::DocProducer)
        );
        let creator = with_id(&fs, "pdf.creator");
        assert_eq!(creator.len(), 1);
        assert_eq!(creator[0].title, "PDF creator \"Writer\"");
        let m = creator[0].marker.as_ref().unwrap();
        assert_eq!(m.removal, RemovalStrategy::RawBlank { fill: b'0' });
        let s = m.region.offset as usize;
        assert_eq!(data[s - 1], b'<');
        assert_eq!(data[m.region.end() as usize], b'>');

        let info = with_id(&fs, "pdf.info");
        let titles: Vec<&str> = info.iter().map(|f| f.title.as_str()).collect();
        assert_eq!(
            titles,
            [
                "PDF author \"Jane (JD) Doe\"",
                "PDF title \"Quarterly report\"",
                "PDF creation date \"2024-01-02 03:04:05 +01'00'\"",
                "PDF modification date \"2025-06-07 08:09:10 Z\"",
            ]
        );
        for f in &info {
            assert_eq!(f.category, Category::Junk(JunkKind::DocInfo));
            assert_eq!(f.severity, Severity::Notice);
            let at = f.evidence.offset as usize;
            assert_eq!(
                &data[at..at + f.evidence.matched.len()],
                &f.evidence.matched[..]
            );
        }
        let author = info[0].marker.as_ref().unwrap();
        assert_eq!(author.removal, RemovalStrategy::RawBlank { fill: b' ' });
        assert_eq!(
            &data[author.region.offset as usize..author.region.end() as usize],
            b"Jane \\(JD\\) Doe"
        );

        let inc = with_id(&fs, "pdf.incremental");
        assert_eq!(inc.len(), 1);
        assert_eq!(inc[0].title, "PDF saved with 1 incremental update");
        assert_eq!(inc[0].category, Category::Tamper(TamperKind::Patched));
        assert!(with_id(&fs, "pdf.encrypted").is_empty());
        assert_eq!(fs.len(), 8);
    }

    #[test]
    fn every_marker_blanks_and_reparses() {
        let data = updated();
        let fs = scan(&data);
        let removable: Vec<&Finding> = fs.iter().filter(|f| f.marker.is_some()).collect();
        assert_eq!(removable.len(), 7);
        for f in &removable {
            let cleaned = apply(&data, f);
            assert_eq!(cleaned.len(), data.len());
            let again = scan(&cleaned);
            assert_eq!(again.len(), fs.len() - 1, "{} not removed alone", f.title);
            assert!(
                !again
                    .iter()
                    .any(|g| g.title == f.title && g.evidence == f.evidence)
            );
        }
        let mut cur = data;
        while let Some(f) = scan(&cur).into_iter().find(|f| f.marker.is_some()) {
            cur = apply(&cur, &f);
        }
        let left = scan(&cur);
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].signature_id, "pdf.incremental");
        // The xref offsets still point at the objects.
        assert!(xref_lookup(&crate::scan::MemView::new("", cur.clone()), 3).is_some());
    }

    #[test]
    fn encrypted_documents_keep_their_strings() {
        let mut p = Pdf::new();
        p.obj(1, b"<< /Type /Catalog /Pages 2 0 R >>");
        p.obj(3, b"<< /Producer (\x8a\x13\xf0\x01) /Author <9c2e11> >>");
        p.obj(5, b"<< /Filter /Standard /V 5 /R 6 /Length 256 >>");
        p.xref("<< /Size 6 /Root 1 0 R /Info 3 0 R /Encrypt 5 0 R /ID [<00><00>] >>");
        let fs = scan(&p.buf);
        let enc = with_id(&fs, "pdf.encrypted");
        assert_eq!(enc.len(), 1);
        assert_eq!(enc[0].title, "Encrypted PDF (AES-256)");
        assert_eq!(
            enc[0].category,
            Category::Integrity(SignatureStatus::Present)
        );
        assert!(
            enc[0]
                .evidence
                .note
                .as_deref()
                .unwrap()
                .contains("standard password")
        );
        let producer = with_id(&fs, "pdf.producer");
        assert_eq!(producer[0].title, "PDF producer (encrypted value)");
        assert!(fs.iter().all(|f| f.marker.is_none()));
    }

    #[test]
    fn linearized_first_page_trailer_is_not_an_update() {
        let mut p = Pdf::new();
        p.obj(1, b"<< /Linearized 1 /L 2000 /O 3 /E 100 /N 1 /T 500 >>");
        p.xref("<< /Size 2 >>");
        p.obj(2, b"<< /Type /Catalog >>");
        p.xref("<< /Size 3 /Root 2 0 R >>");
        assert!(scan(&p.buf).is_empty());
    }

    #[test]
    fn large_file_resolves_info_through_the_xref() {
        let filler = vec![b'A'; 2_500_000];
        let mut stream = format!("<< /Length {} >>\nstream\n", filler.len()).into_bytes();
        stream.extend_from_slice(&filler);
        stream.extend_from_slice(b"\nendstream");
        let mut p = Pdf::new();
        p.obj(1, b"<< /Type /Catalog /Pages 2 0 R >>");
        p.obj(2, b"<< /Type /Pages /Kids [ ] /Count 0 >>");
        p.obj(4, &stream);
        p.obj(3, b"<< /Producer (Big Scanner 3.0) /Author (Scan Desk) >>");
        p.obj(5, &stream);
        p.xref("<< /Size 6 /Root 1 0 R /Info 3 0 R >>");
        let data = p.buf;
        assert!(data.len() as u64 > WHOLE_FILE);
        let fs = scan(&data);
        assert_eq!(fs.len(), 2);
        let producer = with_id(&fs, "pdf.producer")[0];
        assert_eq!(producer.title, "PDF producer \"Big Scanner 3.0\"");
        let at = producer.evidence.offset as usize;
        assert_eq!(&data[at..at + 9], b"/Producer");
        let cleaned = apply(&data, producer);
        assert_eq!(scan(&cleaned).len(), 1);

        // Without a usable xref the middle of the file is out of reach.
        let mut broken = data.clone();
        let sx = rfind(&broken, b"startxref").unwrap();
        broken[sx] = b'x';
        assert!(scan(&broken).is_empty());
    }

    #[test]
    fn producer_outside_an_info_dict_is_still_a_brand() {
        let mut p = Pdf::new();
        p.obj(
            1,
            b"<< /Type /OCG /Usage << /CreatorInfo << /Creator (Vector Tool 27) >> >> >>",
        );
        p.obj(2, b"<< /Title (outline entry, not document info) >>");
        p.xref("<< /Size 3 >>");
        let fs = scan(&p.buf);
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].title, "PDF creator \"Vector Tool 27\"");
    }

    #[test]
    fn helpers() {
        assert_eq!(
            string_bytes(b"a\\101\\nb\\\nc", 0, 11, false).unwrap(),
            b"aA\nbc"
        );
        assert_eq!(string_bytes(b"4 1 4", 0, 5, true).unwrap(), b"A\x40");
        assert_eq!(decode_text(b"\xFE\xFF\x00H\x00i"), "Hi");
        assert_eq!(pretty_date("D:2024"), "D:2024");
        assert_eq!(pretty_date("D:20240102"), "2024-01-02");
        assert_eq!(literal_end(b"(a(b)c)", 0), Some(6));
        assert_eq!(literal_end(b"(a\\)", 0), None);
        let (d, end) = parse_dict(b"<< /A 1 0 R /B [ 1 2 ] /C /N >>", 0, 0).unwrap();
        assert_eq!(end, 31);
        assert_eq!(d[0].val, Val::Ref(1, 0));
        assert!(parse_dict(b"<< /A (unterminated >>", 0, 0).is_none());
        let deep = format!("{}{}", "[".repeat(100), "]".repeat(100));
        assert!(parse_value(deep.as_bytes(), 0, 0).is_none());
    }

    #[test]
    fn garbage_and_truncation_are_safe() {
        let data = updated();
        for cut in 0..data.len() {
            let fs = scan(&data[..cut]);
            if cut < 5 {
                assert!(fs.is_empty());
            }
        }
        for seed in 0..32 {
            assert!(scan(&garbage(seed, 4096)).is_empty());
            let mut g = b"%PDF-1.4\n".to_vec();
            g.extend(garbage(seed, 4096));
            assert!(scan(&g).is_empty());
        }
        assert!(scan(b"%PDF-1.4\n/Producer (unterminated").is_empty());
        assert!(scan(b"%PDF-1.4\ntrailer << /Info 999999999999 0 R >>").is_empty());
        for i in 0..data.len() {
            for v in [0x00, b'(', b')', b'<', b'>', b'/', b'\\', 0xFF] {
                let mut m = data.clone();
                m[i] = v;
                let _ = scan(&m);
            }
        }
    }
}
