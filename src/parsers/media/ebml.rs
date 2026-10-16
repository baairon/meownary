//! Minimal EBML readers shared by identity (the DocType check) and the
//! Matroska/WebM probe. Every reader is bounds-checked and returns `None` on
//! anything malformed.

use crate::util::bytes::slice;

/// EBML header element id.
pub(crate) const EBML_HEADER: u32 = 0x1A45_DFA3;
/// DocType element id inside the EBML header.
pub(crate) const DOC_TYPE: u32 = 0x4282;

/// Read an element id at `off`. Ids keep their length-marker bits, as the
/// Matroska specification writes them (for example `0x1A45DFA3`). Returns the
/// id and its encoded length (1 to 4 bytes).
pub(crate) fn read_id(buf: &[u8], off: usize) -> Option<(u32, usize)> {
    let first = *buf.get(off)?;
    let len = first.leading_zeros() as usize + 1;
    if len > 4 {
        return None;
    }
    let bytes = slice(buf, off, len)?;
    let id = bytes.iter().fold(0u32, |acc, &b| (acc << 8) | u32::from(b));
    Some((id, len))
}

/// Read an element data size at `off`. The size is `None` when every value
/// bit is set, which EBML uses for "unknown size". Returns the size and its
/// encoded length (1 to 8 bytes).
pub(crate) fn read_size(buf: &[u8], off: usize) -> Option<(Option<u64>, usize)> {
    let first = *buf.get(off)?;
    if first == 0 {
        return None;
    }
    let len = first.leading_zeros() as usize + 1;
    let bytes = slice(buf, off, len)?;
    let mask = 0xFFu8.checked_shr(len as u32).unwrap_or(0);
    let mut value = u64::from(first & mask);
    for &b in bytes.iter().skip(1) {
        value = (value << 8) | u64::from(b);
    }
    let all_ones = (1u64 << (7 * len)) - 1;
    Some(((value != all_ones).then_some(value), len))
}

/// One parsed element header: id, data offset (absolute within `buf`), and
/// data size (`None` for unknown size).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Element {
    pub id: u32,
    pub data: usize,
    pub size: Option<u64>,
}

/// Parse the element header at `off`.
pub(crate) fn element(buf: &[u8], off: usize) -> Option<Element> {
    let (id, id_len) = read_id(buf, off)?;
    let (size, size_len) = read_size(buf, off.checked_add(id_len)?)?;
    Some(Element {
        id,
        data: off.checked_add(id_len)?.checked_add(size_len)?,
        size,
    })
}

/// The DocType string of the EBML header at offset 0, if it parses.
pub(crate) fn doc_type(buf: &[u8]) -> Option<&[u8]> {
    let head = element(buf, 0)?;
    if head.id != EBML_HEADER {
        return None;
    }
    let end = match head.size {
        Some(s) => head
            .data
            .saturating_add(usize::try_from(s).ok()?)
            .min(buf.len()),
        None => buf.len().min(head.data.saturating_add(256)),
    };
    let mut off = head.data;
    for _ in 0..32 {
        if off >= end {
            break;
        }
        let el = element(buf, off)?;
        let size = usize::try_from(el.size?).ok()?;
        if el.id == DOC_TYPE {
            let raw = slice(buf, el.data, size)?;
            let trimmed = raw.split(|&b| b == 0).next().unwrap_or(raw);
            return Some(trimmed);
        }
        off = el.data.checked_add(size)?;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_and_sizes() {
        assert_eq!(
            read_id(&[0x1A, 0x45, 0xDF, 0xA3], 0),
            Some((EBML_HEADER, 4))
        );
        assert_eq!(read_id(&[0x42, 0x82], 0), Some((DOC_TYPE, 2)));
        assert_eq!(read_id(&[0x00, 0x01], 0), None);
        assert_eq!(read_id(&[0x1A, 0x45], 0), None);
        assert_eq!(read_size(&[0x84], 0), Some((Some(4), 1)));
        assert_eq!(read_size(&[0x40, 0x02], 0), Some((Some(2), 2)));
        assert_eq!(read_size(&[0xFF], 0), Some((None, 1)));
        assert_eq!(
            read_size(&[0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], 0),
            Some((None, 8))
        );
        assert_eq!(read_size(&[0x00], 0), None);
        assert_eq!(read_size(&[0x01, 0x00], 0), None);
    }

    #[test]
    fn doc_type_found() {
        let buf = [
            0x1A, 0x45, 0xDF, 0xA3, 0x8B, 0x42, 0x86, 0x81, 0x01, 0x42, 0x82, 0x84, b'w', b'e',
            b'b', b'm',
        ];
        assert_eq!(doc_type(&buf), Some(&b"webm"[..]));
        assert_eq!(doc_type(&buf[..12]), None);
        assert_eq!(doc_type(&[]), None);
    }
}
