//! Bounds-checked byte readers shared by every parser. Each reader returns
//! `None` instead of panicking when `off` or `len` falls outside `buf`, so a
//! corrupt length field can never take a probe down.

/// `len` bytes at `off`, if they all lie inside `buf`.
pub fn slice(buf: &[u8], off: usize, len: usize) -> Option<&[u8]> {
    let end = off.checked_add(len)?;
    buf.get(off..end)
}

pub fn u8_at(buf: &[u8], off: usize) -> Option<u8> {
    buf.get(off).copied()
}

pub fn u16_le(buf: &[u8], off: usize) -> Option<u16> {
    slice(buf, off, 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

pub fn u32_le(buf: &[u8], off: usize) -> Option<u32> {
    slice(buf, off, 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

pub fn u64_le(buf: &[u8], off: usize) -> Option<u64> {
    slice(buf, off, 8)
        .and_then(|b| <[u8; 8]>::try_from(b).ok())
        .map(u64::from_le_bytes)
}

pub fn u16_be(buf: &[u8], off: usize) -> Option<u16> {
    slice(buf, off, 2).map(|b| u16::from_be_bytes([b[0], b[1]]))
}

pub fn u32_be(buf: &[u8], off: usize) -> Option<u32> {
    slice(buf, off, 4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

pub fn u64_be(buf: &[u8], off: usize) -> Option<u64> {
    slice(buf, off, 8)
        .and_then(|b| <[u8; 8]>::try_from(b).ok())
        .map(u64::from_be_bytes)
}

/// A NUL-terminated byte string at `off`, at most `max` bytes long (terminator
/// excluded). Without a terminator the string runs to `max` or the buffer end.
pub fn cstr(buf: &[u8], off: usize, max: usize) -> Option<&[u8]> {
    let rest = buf.get(off..)?;
    let rest = &rest[..rest.len().min(max)];
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    Some(&rest[..end])
}

/// Decode UTF-16LE at `off`, stopping at the first NUL or after `max_units`
/// code units. Invalid surrogates become U+FFFD.
pub fn utf16le(buf: &[u8], off: usize, max_units: usize) -> Option<String> {
    let rest = buf.get(off..)?;
    let units: Vec<u16> = rest
        .as_chunks::<2>()
        .0
        .iter()
        .take(max_units)
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|&u| u != 0)
        .collect();
    Some(String::from_utf16_lossy(&units))
}

/// First index of `needle` in `hay`. An empty needle never matches.
pub fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Last index of `needle` in `hay`. An empty needle never matches.
pub fn rfind(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).rposition(|w| w == needle)
}

/// Whether every byte is printable ASCII (space through tilde).
pub fn is_printable_ascii(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| (0x20..0x7f).contains(b))
}

/// Lossy UTF-8 text with trailing NULs and whitespace removed, for notes.
pub fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .trim_end_matches(['\0', ' ', '\n', '\r', '\t'])
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readers_stay_in_bounds() {
        let b = [1u8, 2, 3, 4, 5, 6, 7, 8, 9];
        assert_eq!(u16_le(&b, 0), Some(0x0201));
        assert_eq!(u16_be(&b, 0), Some(0x0102));
        assert_eq!(u32_le(&b, 1), Some(0x0504_0302));
        assert_eq!(u64_be(&b, 1), Some(0x0203_0405_0607_0809));
        assert_eq!(u32_le(&b, 6), None);
        assert_eq!(u64_le(&b, usize::MAX), None);
        assert_eq!(slice(&b, 8, 1), Some(&b[8..9]));
        assert_eq!(slice(&b, 9, 1), None);
    }

    #[test]
    fn strings() {
        let b = b"abc\0def";
        assert_eq!(cstr(b, 0, 10), Some(&b"abc"[..]));
        assert_eq!(cstr(b, 4, 2), Some(&b"de"[..]));
        assert_eq!(cstr(b, 8, 2), None);
        let w = [b'h', 0, b'i', 0, 0, 0, b'x', 0];
        assert_eq!(utf16le(&w, 0, 8).as_deref(), Some("hi"));
        assert_eq!(text(b"name \0\0"), "name");
    }

    #[test]
    fn searching() {
        let h = b"xx-ab-ab-";
        assert_eq!(find(h, b"ab"), Some(3));
        assert_eq!(rfind(h, b"ab"), Some(6));
        assert_eq!(find(h, b""), None);
        assert_eq!(find(b"a", b"ab"), None);
        assert!(is_printable_ascii(b"hello"));
        assert!(!is_printable_ascii(b"he\x01lo"));
    }
}
