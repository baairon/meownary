//! The pastel-violet palette, shared across every view. One accent, one
//! gradient, severity and confidence mapped to colors. Mirrors the look of the
//! owner's other terminal apps.

#![cfg(feature = "tui")]

use ratatui::style::Color;

use crate::model::{Confidence, Severity};

pub const ACCENT: Color = Color::Rgb(0xa7, 0x8b, 0xfa);
pub const TEXT: Color = Color::Rgb(0xe9, 0xe4, 0xf5);
pub const ALT: Color = Color::Rgb(0xb9, 0xa7, 0xe6);
pub const GOOD: Color = Color::Rgb(0x86, 0xd6, 0xa2);
pub const WARN: Color = Color::Rgb(0xf0, 0xc5, 0x60);
pub const BAD: Color = Color::Rgb(0xee, 0x7d, 0x92);
pub const BRIGHT: Color = Color::Rgb(0xd8, 0xb4, 0xfe);
pub const RULE: Color = Color::Rgb(0x6b, 0x65, 0x77);

/// Color for a severity (drives the row accent).
pub fn severity_color(s: Severity) -> Color {
    match s {
        Severity::Info => TEXT,
        Severity::Notice => ALT,
        Severity::Warn => WARN,
        Severity::Alert => BAD,
    }
}

/// Color for a confidence badge.
pub fn confidence_color(c: Confidence) -> Color {
    match c {
        Confidence::Strong => GOOD,
        Confidence::Moderate => WARN,
        Confidence::Weak => RULE,
    }
}

/// Two-stop gradient for the wordmark.
pub const ACCENT_RAMP: [Color; 2] = [ACCENT, BRIGHT];

/// Interpolate between two RGB colors (t in 0..=1). Non-RGB inputs return `a`.
pub fn lerp(a: Color, b: Color, t: f32) -> Color {
    if let (Color::Rgb(ar, ag, ab), Color::Rgb(br, bg, bb)) = (a, b) {
        let m = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t).round() as u8;
        Color::Rgb(m(ar, br), m(ag, bg), m(ab, bb))
    } else {
        a
    }
}
