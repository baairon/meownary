//! The cat wordmark shown on the splash and help overlay. A small, friendly
//! mascot; serious output elsewhere stays plain.

#![cfg(feature = "tui")]

/// Three-row ASCII cat + wordmark. Rendered with the accent gradient.
pub const LOGO: &[&str] = &[
    r"  /\_/\     meownary",
    r" ( o.o )    know what a file really is",
    r"  > ^ <",
];
