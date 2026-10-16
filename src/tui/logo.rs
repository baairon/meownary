//! The wordmark shown in the header and the key panel: "meow" in the animated
//! rainbow, "nary" in the pastel gradient.

#![cfg(feature = "tui")]

/// The wordmark; the first [`RAINBOW_LEN`] letters get the rainbow.
pub const WORDMARK: &str = "meownary";

/// How many leading wordmark letters ("meow") are drawn as a rainbow.
pub const RAINBOW_LEN: usize = 4;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rainbow_covers_meow_only() {
        assert!(WORDMARK.len() > RAINBOW_LEN);
        assert_eq!(&WORDMARK[..RAINBOW_LEN], "meow");
    }
}
