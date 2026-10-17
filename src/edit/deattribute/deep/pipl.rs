//! Adobe plug-in property lists in PE and Macintosh resources.

use std::collections::BTreeSet;

use super::super::{Kind, Reason};
use super::{Evidence, Rewrite, Source, candidate, rooted, single_byte};

const MAX_PIPL: usize = 1024 * 1024;

#[derive(Debug)]
struct Field {
    key: [u8; 4],
    off: usize,
    value: Vec<u8>,
}

/// Parsed fields retain their byte offsets and property framing.
#[derive(Debug)]
pub(super) struct Pipl {
    base: u64,
    fields: Vec<Field>,
}

fn number(bytes: &[u8], at: usize, be: bool) -> Option<usize> {
    let raw: [u8; 4] = bytes.get(at..at + 4)?.try_into().ok()?;
    Some(if be {
        u32::from_be_bytes(raw)
    } else {
        u32::from_le_bytes(raw)
    } as usize)
}

fn fourcc(bytes: &[u8], at: usize) -> Option<[u8; 4]> {
    let raw: [u8; 4] = bytes.get(at..at + 4)?.try_into().ok()?;
    raw.iter()
        .all(|&b| (0x20..=0x7e).contains(&b))
        .then_some(raw)
}

impl Pipl {
    /// Parse either resource header and either recorded integer byte order.
    pub(super) fn parse(bytes: &[u8], base: u64) -> Option<Self> {
        if bytes.len() > MAX_PIPL {
            return None;
        }
        for start in [0usize, 2] {
            if start == 2 && bytes.get(..2) != Some(&[1, 0][..]) {
                continue;
            }
            for be in [true, false] {
                if number(bytes, start, be) != Some(0) {
                    continue;
                }
                let Some(count) = number(bytes, start + 4, be).filter(|&n| n > 0 && n <= 1024)
                else {
                    continue;
                };
                let mut at = start + 8;
                let mut fields = Vec::with_capacity(count);
                let mut valid = true;
                for _ in 0..count {
                    let Some(_vendor) = fourcc(bytes, at) else {
                        valid = false;
                        break;
                    };
                    let Some(mut key) = fourcc(bytes, at + 4) else {
                        valid = false;
                        break;
                    };
                    // Windows lists store each code as a little-endian integer.
                    if !be {
                        key.reverse();
                    }
                    let Some(len) = number(bytes, at + 12, be).filter(|&n| n <= MAX_PIPL) else {
                        valid = false;
                        break;
                    };
                    let body = at + 16;
                    let Some(value) = bytes.get(body..body.saturating_add(len)) else {
                        valid = false;
                        break;
                    };
                    fields.push(Field {
                        key,
                        off: body,
                        value: value.to_vec(),
                    });
                    at = body + len;
                    if fields.len() < count && fourcc(bytes, at).is_none() {
                        at = body + ((len + 3) & !3);
                    }
                }
                if valid && !fields.is_empty() {
                    return Some(Self { base, fields });
                }
            }
        }
        None
    }

    fn pascal(field: &Field) -> Option<&[u8]> {
        let len = *field.value.first()? as usize;
        (len > 0 && len < field.value.len()).then(|| &field.value[1..1 + len])
    }

    /// Names in the list can establish the identity used by other fields.
    pub(super) fn evidence(&self) -> Evidence {
        self.fields
            .iter()
            .filter_map(|field| {
                let source = match &field.key {
                    b"eMNA" => Source::MatchName,
                    b"name" | b"catg" => Source::Product,
                    _ => return None,
                };
                let raw = Self::pascal(field)?;
                // A match ID this pass already wrote names nobody.
                if &field.key == b"eMNA" && is_neutral_id(raw) {
                    return None;
                }
                Some((single_byte(raw), source))
            })
            .collect()
    }

    /// Rewrite identity properties. The PE-wide pass can edit entry points later.
    pub(super) fn rewrites(&self, roots: &BTreeSet<String>) -> (Vec<Rewrite>, Vec<Reason>) {
        let mut out = Vec::new();
        let mut skipped = Vec::new();
        let mut ids = BTreeSet::new();
        for field in &self.fields {
            // Entry points are C strings, or Pascal strings on older hosts.
            if functional_key(&field.key) {
                let body = match field.value.first() {
                    Some(&n) if n < 0x20 => &field.value[1..],
                    _ => &field.value[..],
                };
                let end = body.iter().position(|&b| b == 0).unwrap_or(body.len());
                if rooted(&single_byte(&body[..end]), roots) {
                    skipped.push(Reason::FunctionalName);
                }
                continue;
            }
            let Some(raw) = Self::pascal(field) else {
                if matches!(&field.key, b"name" | b"catg" | b"eMNA") {
                    skipped.push(Reason::MalformedMetadata);
                }
                continue;
            };
            let off = self.base + field.off as u64 + 1;
            let text = single_byte(raw);
            let mine = rooted(&text, roots) || candidate(&text).is_some_and(|c| roots.contains(&c));
            let next = match &field.key {
                b"name" => Some(neutral(raw.len(), b"Effect")),
                b"catg" if mine => Some(neutral(raw.len(), b"Effects")),
                b"eMNA" if raw.len() >= 3 && !is_neutral_id(raw) => {
                    let mut id = match_id(raw, 0);
                    let mut salt = 1;
                    while ids.contains(&id) {
                        id = match_id(raw, salt);
                        salt += 1;
                    }
                    ids.insert(id.clone());
                    Some(id)
                }
                b"eMNA" if raw.len() < 3 => {
                    skipped.push(Reason::FunctionalName);
                    None
                }
                _ => None,
            };
            if let Some(next) = next
                && next != raw
            {
                out.push((Kind::Brand, off, next));
            }
        }
        (out, skipped)
    }
}

fn neutral(len: usize, word: &[u8]) -> Vec<u8> {
    let mut out = word.iter().copied().take(len).collect::<Vec<_>>();
    out.resize(len, b' ');
    out
}

fn is_neutral_id(raw: &[u8]) -> bool {
    raw.starts_with(b"de") && raw[2..].iter().all(u8::is_ascii_hexdigit)
}

fn match_id(raw: &[u8], salt: u32) -> Vec<u8> {
    let mut h = blake3::Hasher::new();
    h.update(b"meownary PiPL match name\0");
    h.update(raw);
    h.update(&salt.to_le_bytes());
    let mut bytes = vec![0; (raw.len() - 2).div_ceil(2)];
    h.finalize_xof().fill(&mut bytes);
    let mut out = b"de".to_vec();
    for b in bytes {
        for n in [b >> 4, b & 15] {
            if out.len() == raw.len() {
                break;
            }
            out.push(b"0123456789abcdef"[n as usize]);
        }
    }
    out
}

/// Code descriptors: Win32 and Win64 (`8664`) x86, Intel and ARM Mach-O,
/// PowerPC, Carbon PowerPC and 68k.
fn functional_key(key: &[u8; 4]) -> bool {
    matches!(
        key,
        b"wx86"
            | b"8664"
            | b"mi32"
            | b"mi64"
            | b"ma64"
            | b"mach"
            | b"pwpc"
            | b"ppcb"
            | b"m68k"
            | b"68fp"
    )
}
