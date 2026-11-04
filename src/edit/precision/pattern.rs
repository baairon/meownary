//! Encoded patterns with explicit boundaries and bounded streaming coverage.

use std::io;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use serde::{Deserialize, Serialize};

use crate::scan::FileView;

pub const WINDOW: u64 = 1024 * 1024;
pub const MAX_PATTERN: usize = 64 * 1024;
const CONTEXT: u64 = 16;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Encoding {
    Ascii,
    #[default]
    Utf8,
    Utf16le,
    Utf16be,
    Windows1252,
}

const C1: [char; 32] = [
    '\u{20ac}', '\u{81}', '\u{201a}', '\u{192}', '\u{201e}', '\u{2026}', '\u{2020}', '\u{2021}',
    '\u{2c6}', '\u{2030}', '\u{160}', '\u{2039}', '\u{152}', '\u{8d}', '\u{17d}', '\u{8f}',
    '\u{90}', '\u{2018}', '\u{2019}', '\u{201c}', '\u{201d}', '\u{2022}', '\u{2013}', '\u{2014}',
    '\u{2dc}', '\u{2122}', '\u{161}', '\u{203a}', '\u{153}', '\u{9d}', '\u{17e}', '\u{178}',
];

impl Encoding {
    /// Decode one scalar without consuming invalid bytes after it. Callers can
    /// skip one code unit on failure and resume at the following valid text.
    pub fn scalar(self, bytes: &[u8]) -> Option<(char, usize)> {
        let width = match self {
            Self::Utf16le | Self::Utf16be => 2,
            _ => 1,
        };
        let max = match self {
            Self::Utf8 => 4,
            Self::Utf16le | Self::Utf16be => 2,
            _ => 1,
        };
        for n in 1..=max {
            if let Some(text) = bytes.get(..n * width).and_then(|part| self.decode(part)) {
                let mut chars = text.chars();
                if let Some(c) = chars.next()
                    && chars.next().is_none()
                {
                    return Some((c, n * width));
                }
            }
        }
        None
    }
    pub const ALL: [Self; 5] = [
        Self::Ascii,
        Self::Utf8,
        Self::Utf16le,
        Self::Utf16be,
        Self::Windows1252,
    ];

    pub fn encode(self, text: &str) -> io::Result<Vec<u8>> {
        match self {
            Self::Ascii if !text.is_ascii() => Err(invalid("text is not ASCII")),
            Self::Ascii | Self::Utf8 => Ok(text.as_bytes().to_vec()),
            Self::Utf16le => Ok(text.encode_utf16().flat_map(u16::to_le_bytes).collect()),
            Self::Utf16be => Ok(text.encode_utf16().flat_map(u16::to_be_bytes).collect()),
            Self::Windows1252 => text
                .chars()
                .map(|c| {
                    if (c as u32) <= 0xff && !(0x80..=0x9f).contains(&(c as u32)) {
                        Ok(c as u8)
                    } else {
                        C1.iter()
                            .position(|&v| v == c)
                            .map(|i| i as u8 + 0x80)
                            .ok_or_else(|| invalid("text is not representable in Windows-1252"))
                    }
                })
                .collect(),
        }
    }

    pub fn decode(self, bytes: &[u8]) -> Option<String> {
        match self {
            Self::Ascii if !bytes.is_ascii() => None,
            Self::Ascii | Self::Utf8 => std::str::from_utf8(bytes).ok().map(str::to_owned),
            Self::Windows1252 => Some(
                bytes
                    .iter()
                    .map(|&b| {
                        if (0x80..=0x9f).contains(&b) {
                            C1[(b - 0x80) as usize]
                        } else {
                            char::from(b)
                        }
                    })
                    .collect(),
            ),
            Self::Utf16le | Self::Utf16be => {
                if !bytes.len().is_multiple_of(2) {
                    return None;
                }
                let units: Vec<u16> = bytes
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|&p| {
                        if self == Self::Utf16le {
                            u16::from_le_bytes(p)
                        } else {
                            u16::from_be_bytes(p)
                        }
                    })
                    .collect();
                String::from_utf16(&units).ok()
            }
        }
    }

    pub fn spaces(self, len: usize) -> Vec<u8> {
        match self {
            Self::Utf16le => [b' ', 0].repeat(len / 2),
            Self::Utf16be => [0, b' '].repeat(len / 2),
            _ => vec![b' '; len],
        }
    }

    fn adjacent(self, bytes: &[u8], at: usize, before: bool) -> Option<char> {
        if (before && at == 0) || (!before && at == bytes.len()) {
            return None;
        }
        let unit = if matches!(self, Self::Utf16le | Self::Utf16be) {
            2
        } else {
            1
        };
        let max = match self {
            Self::Utf8 => 4,
            Self::Utf16le | Self::Utf16be => 2,
            _ => 1,
        };
        for count in 1..=max {
            let n = unit * count;
            let part = if before {
                at.checked_sub(n).and_then(|start| bytes.get(start..at))
            } else {
                at.checked_add(n).and_then(|end| bytes.get(at..end))
            };
            if let Some(text) = part.and_then(|part| self.decode(part)) {
                let mut chars = text.chars();
                let first = chars.next();
                if chars.next().is_none() {
                    return first;
                }
            }
        }
        // Invalid adjacent text must not be mistaken for a textual word boundary.
        Some('\u{fffd}')
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Boundary {
    #[default]
    Substring,
    Word,
    Identifier,
}

fn boundaries(
    boundary: Boundary,
    ends: (char, char),
    neighbors: (Option<char>, Option<char>),
    rtti: bool,
) -> bool {
    let (first, last) = ends;
    let (left, right) = neighbors;
    let identifier = |c: char| c.is_alphanumeric() || c == '_' || c == '\u{fffd}';
    let left_ok = left.is_none_or(|c| !identifier(c))
        || !identifier(first)
        || rtti
        || (boundary == Boundary::Identifier
            && left.is_some_and(|c| c == '_' || (c.is_lowercase() && first.is_uppercase())));
    let right_ok = right.is_none_or(|c| !identifier(c))
        || !identifier(last)
        || (boundary == Boundary::Identifier
            && right.is_some_and(|c| {
                c == '_'
                    || c.is_ascii_digit()
                    || (last.is_lowercase() && c.is_uppercase())
                    || (rtti && last.is_uppercase() && c.is_uppercase())
            }));
    left_ok && right_ok
}

/// Display text and encoded byte matching use the same identifier boundaries.
pub fn text_boundary(text: &str, start: usize, end: usize, boundary: Boundary) -> bool {
    let (Some(prefix), Some(value), Some(suffix)) =
        (text.get(..start), text.get(start..end), text.get(end..))
    else {
        return false;
    };
    let (Some(first), Some(last)) = (value.chars().next(), value.chars().next_back()) else {
        return false;
    };
    if boundary == Boundary::Substring {
        return true;
    }
    let rtti = boundary == Boundary::Identifier
        && [".?AV", ".?AU"].iter().any(|p| {
            prefix.ends_with(p)
                || prefix
                    .len()
                    .checked_sub(2)
                    .and_then(|n| prefix.get(..n).zip(prefix.get(n..)))
                    .is_some_and(|(head, initials)| {
                        head.ends_with(p) && initials.chars().all(|c| c.is_ascii_uppercase())
                    })
        });
    boundaries(
        boundary,
        (first, last),
        (prefix.chars().next_back(), suffix.chars().next()),
        rtti,
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Pattern {
    Text {
        value: String,
        #[serde(default)]
        encoding: Encoding,
        #[serde(default)]
        ignore_ascii_case: bool,
        #[serde(default)]
        boundary: Boundary,
    },
    Hex {
        value: String,
    },
}

#[derive(Debug, Clone)]
struct Needle {
    bytes: Vec<u8>,
    mask: Vec<u8>,
    encoding: Option<Encoding>,
    ignore_case: bool,
    boundary: Boundary,
}

pub fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

/// Hex accepts whitespace and `?` nibbles. Exact replacement bytes reject masks.
pub fn parse_hex(text: &str, masked: bool) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let compact: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if compact.is_empty() || !compact.len().is_multiple_of(2) {
        return Err(invalid("hex needs complete byte pairs"));
    }
    let mut bytes = Vec::new();
    let mut masks = Vec::new();
    for p in compact.as_chunks::<2>().0 {
        let mut value = 0;
        let mut mask = 0;
        for &digit in p {
            value <<= 4;
            mask <<= 4;
            if digit == b'?' && masked {
                continue;
            }
            value |= (digit as char)
                .to_digit(16)
                .ok_or_else(|| invalid("invalid hex digit"))? as u8;
            mask |= 15;
        }
        bytes.push(value);
        masks.push(mask);
    }
    Ok((bytes, masks))
}

impl Needle {
    fn compile(pattern: &Pattern) -> io::Result<Self> {
        let needle = match pattern {
            Pattern::Text {
                value,
                encoding,
                ignore_ascii_case,
                boundary,
            } => {
                let bytes = encoding.encode(value)?;
                Self {
                    mask: vec![255; bytes.len()],
                    bytes,
                    encoding: Some(*encoding),
                    ignore_case: *ignore_ascii_case,
                    boundary: *boundary,
                }
            }
            Pattern::Hex { value } => {
                let (bytes, mask) = parse_hex(value, true)?;
                Self {
                    bytes,
                    mask,
                    encoding: None,
                    ignore_case: false,
                    boundary: Boundary::Substring,
                }
            }
        };
        if needle.bytes.is_empty() || needle.bytes.len() > MAX_PATTERN {
            return Err(invalid("pattern length must be 1..65536 bytes"));
        }
        if !needle.mask.contains(&255) {
            return Err(invalid("masked hex needs at least one exact byte"));
        }
        Ok(needle)
    }

    fn accepts(&self, hay: &[u8], start: usize) -> bool {
        let end = start + self.bytes.len();
        let Some(found) = hay.get(start..end) else {
            return false;
        };
        let equal = if self.ignore_case {
            let encoding = self.encoding.unwrap_or_default();
            match (encoding.decode(found), encoding.decode(&self.bytes)) {
                (Some(a), Some(b)) => a.eq_ignore_ascii_case(&b),
                _ => false,
            }
        } else {
            found
                .iter()
                .zip(&self.bytes)
                .zip(&self.mask)
                .all(|((&a, &b), &m)| (a & m) == b)
        };
        if !equal {
            return false;
        }
        if self.boundary == Boundary::Substring {
            return true;
        }
        let encoding = self.encoding.unwrap_or_default();
        let Some(text) = encoding.decode(found) else {
            return false;
        };
        let left = encoding.adjacent(hay, start, true);
        let right = encoding.adjacent(hay, end, false);
        let first = text.chars().next().unwrap_or_default();
        let last = text.chars().next_back().unwrap_or_default();
        let rtti = self.boundary == Boundary::Identifier
            && [".?AV", ".?AU"].iter().any(|prefix| {
                let bytes = encoding.encode(prefix).unwrap_or_default();
                let width = if matches!(encoding, Encoding::Utf16le | Encoding::Utf16be) {
                    2
                } else {
                    1
                };
                [0, 2].into_iter().any(|initials| {
                    let Some(at) = start.checked_sub(bytes.len() + initials * width) else {
                        return false;
                    };
                    hay.get(at..at + bytes.len()) == Some(bytes.as_slice())
                        && encoding
                            .decode(&hay[at + bytes.len()..start])
                            .is_some_and(|s| s.chars().all(|c| c.is_ascii_uppercase()))
                })
            });
        boundaries(self.boundary, (first, last), (left, right), rtti)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Span {
    pub offset: u64,
    pub len: u64,
}

impl Span {
    pub fn end(&self) -> io::Result<u64> {
        self.offset
            .checked_add(self.len)
            .ok_or_else(|| invalid("range overflow"))
    }

    pub fn overlaps(&self, other: &Self) -> bool {
        self.offset < other.offset.saturating_add(other.len)
            && other.offset < self.offset.saturating_add(self.len)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub max_scan_bytes: u64,
    pub max_matches: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_scan_bytes: 1024 * 1024 * 1024,
            max_matches: 100_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Match {
    pub pattern: usize,
    pub offset: u64,
    pub len: u64,
    pub encoding: Option<Encoding>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SearchReport {
    pub matches: Vec<Match>,
    pub examined: Vec<Span>,
    pub unexamined: Vec<Span>,
    pub complete: bool,
    pub reason: Option<String>,
}

/// One automaton for exact anchors, then mask, case, and boundary checks.
pub struct Matcher {
    ac: AhoCorasick,
    needles: Vec<Needle>,
    anchors: Vec<usize>,
    longest: usize,
}

impl Matcher {
    pub fn new(patterns: &[Pattern]) -> io::Result<Self> {
        if patterns.len() > 10_000 {
            return Err(invalid("at most 10000 patterns are supported"));
        }
        let needles = patterns
            .iter()
            .map(Needle::compile)
            .collect::<io::Result<Vec<_>>>()?;
        let mut anchors = Vec::new();
        let mut pieces = Vec::new();
        let mut longest = 1;
        for needle in &needles {
            let mut best = (0, 0);
            let mut start = 0;
            for i in 0..=needle.mask.len() {
                if i == needle.mask.len() || needle.mask[i] != 255 {
                    if i - start > best.1 {
                        best = (start, i - start);
                    }
                    start = i + 1;
                }
            }
            pieces.push(&needle.bytes[best.0..best.0 + best.1]);
            anchors.push(best.0);
            longest = longest.max(needle.bytes.len());
        }
        let ac = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .build(pieces)
            .map_err(|e| invalid(e.to_string()))?;
        Ok(Self {
            ac,
            needles,
            anchors,
            longest,
        })
    }

    /// The callback sees matches in each window sorted by offset and pattern.
    /// Budget accounting excludes overlap; examined ranges never claim unseen bytes.
    pub fn search(
        &self,
        view: &dyn FileView,
        range: Span,
        limits: &Limits,
    ) -> io::Result<SearchReport> {
        let end = range.end()?;
        if end > view.size() {
            return Err(invalid("search range is past EOF"));
        }
        if limits.max_matches == 0 {
            return Err(invalid("max_matches must be positive"));
        }
        if self.needles.is_empty() {
            return Ok(SearchReport {
                complete: true,
                ..SearchReport::default()
            });
        }
        let stop = range.offset.saturating_add(limits.max_scan_bytes).min(end);
        let mut out = SearchReport::default();
        let mut pos = range.offset;
        while pos < stop {
            let next = (pos + WINDOW).min(stop);
            let from = pos.saturating_sub(CONTEXT).max(range.offset);
            let to = next.saturating_add(self.longest as u64 + 4).min(stop);
            let bytes = read_exact(view, from, (to - from) as usize)?;
            let mut found = Vec::new();
            for hit in self.ac.find_overlapping_iter(&bytes) {
                let index = hit.pattern().as_usize();
                let Some(start) = hit.start().checked_sub(self.anchors[index]) else {
                    continue;
                };
                let absolute = from + start as u64;
                if absolute < pos || absolute >= next {
                    continue;
                }
                let needle = &self.needles[index];
                // A truncated scan is not an end-of-file text boundary.
                if stop < end && absolute.saturating_add(needle.bytes.len() as u64 + 4) > stop {
                    continue;
                }
                if needle.accepts(&bytes, start) {
                    found.push(Match {
                        pattern: index,
                        offset: absolute,
                        len: needle.bytes.len() as u64,
                        encoding: needle.encoding,
                    });
                }
                if found.len() > limits.max_matches {
                    break;
                }
            }
            found.sort_by_key(|m| (m.offset, m.pattern));
            for hit in found {
                if out.matches.len() == limits.max_matches {
                    out.reason = Some("match limit reached".into());
                    // No claim of complete coverage for a partially enumerated window.
                    out.examined.push(Span {
                        offset: range.offset,
                        len: pos - range.offset,
                    });
                    out.unexamined.push(Span {
                        offset: pos,
                        len: end - pos,
                    });
                    return Ok(out);
                }
                out.matches.push(hit);
            }
            pos = next;
        }
        out.examined.push(Span {
            offset: range.offset,
            len: stop - range.offset,
        });
        if stop < end {
            // A budget edge can bisect a pattern, so include its leading context in the gap.
            let from = stop
                .saturating_sub(self.longest as u64 + 3)
                .max(range.offset);
            out.examined[0].len = from - range.offset;
            out.unexamined.push(Span {
                offset: from,
                len: end - from,
            });
            out.reason = Some("scan byte budget reached".into());
        }
        out.complete = out.unexamined.is_empty();
        Ok(out)
    }
}

pub fn read_exact(view: &dyn FileView, offset: u64, len: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(len);
    while bytes.len() < len {
        let part = view.read_at(offset + bytes.len() as u64, len - bytes.len())?;
        if part.is_empty() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        bytes.extend_from_slice(&part);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::MemView;

    #[test]
    fn cross_window_unicode_and_masked_matches_have_exact_offsets() {
        for encoding in Encoding::ALL {
            let text = if encoding == Encoding::Ascii {
                "North Star"
            } else {
                "N\u{f6}rth Star"
            };
            let mut data = vec![0; WINDOW as usize - 3];
            let start = data.len() as u64;
            data.extend(encoding.encode(text).unwrap());
            data.extend([0; 8]);
            let view = MemView::new("sample", data);
            let matcher = Matcher::new(&[Pattern::Text {
                value: text.into(),
                encoding,
                ignore_ascii_case: false,
                boundary: Boundary::Word,
            }])
            .unwrap();
            let report = matcher
                .search(
                    &view,
                    Span {
                        offset: 0,
                        len: view.size(),
                    },
                    &Limits::default(),
                )
                .unwrap();
            assert!(report.complete);
            assert_eq!(report.matches.len(), 1);
            assert_eq!(report.matches[0].offset, start);
        }
        let view = MemView::new("sample", vec![0x41, 0xab, 0xff, 0x41, 0xcd, 0xfe]);
        let matcher = Matcher::new(&[Pattern::Hex {
            value: "41 A? ??".into(),
        }])
        .unwrap();
        assert_eq!(
            matcher
                .search(&view, Span { offset: 0, len: 6 }, &Limits::default())
                .unwrap()
                .matches
                .len(),
            1
        );
    }

    #[test]
    fn budgets_and_boundaries_never_claim_full_coverage() {
        let view = MemView::new("sample", b"earth art art ArtEngine _art_".to_vec());
        let p = Pattern::Text {
            value: "art".into(),
            encoding: Encoding::Utf8,
            ignore_ascii_case: true,
            boundary: Boundary::Word,
        };
        let matcher = Matcher::new(&[p]).unwrap();
        let report = matcher
            .search(
                &view,
                Span {
                    offset: 0,
                    len: view.size(),
                },
                &Limits::default(),
            )
            .unwrap();
        assert_eq!(
            report.matches.iter().map(|m| m.offset).collect::<Vec<_>>(),
            [6, 10]
        );
        let small = matcher
            .search(
                &view,
                Span {
                    offset: 0,
                    len: view.size(),
                },
                &Limits {
                    max_matches: 1,
                    ..Limits::default()
                },
            )
            .unwrap();
        assert!(!small.complete);
        assert!(!small.unexamined.is_empty());
        let small = matcher
            .search(
                &view,
                Span {
                    offset: 0,
                    len: view.size(),
                },
                &Limits {
                    max_scan_bytes: 8,
                    ..Limits::default()
                },
            )
            .unwrap();
        assert!(!small.complete);
        assert_eq!(small.unexamined[0].offset, 2);
    }
}
