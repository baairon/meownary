//! Word boundaries for identity roots inside display strings.

/// Accept an isolated name or a name joined at a case boundary.
pub(super) fn identity_boundary(text: &str, start: usize, end: usize) -> bool {
    crate::edit::precision::pattern::text_boundary(
        text,
        start,
        end,
        crate::edit::precision::pattern::Boundary::Identifier,
    )
}
