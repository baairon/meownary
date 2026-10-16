//! Word boundaries for identity roots inside display strings.

/// Accept an isolated name or a name joined at a case boundary.
pub(super) fn identity_boundary(text: &str, start: usize, end: usize) -> bool {
    let bytes = text.as_bytes();
    let left = start.checked_sub(1).and_then(|i| bytes.get(i)).copied();
    let right = bytes.get(end).copied();
    let first = bytes[start];
    let last = bytes[end - 1];
    let left_ok = left.is_none_or(|b| !identifier(b))
        || left.is_some_and(|b| b.is_ascii_lowercase() && first.is_ascii_uppercase());
    let right_ok = right.is_none_or(|b| !identifier(b))
        || right.is_some_and(|b| last.is_ascii_lowercase() && b.is_ascii_uppercase());
    left_ok && right_ok
}

fn identifier(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}
