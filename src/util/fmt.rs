//! Formatting helpers shared by the CLI and TUI.

/// A compact human size like `1.4 GB`. Base-1000 so it matches what people see
/// in file managers.
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    if bytes < 1000 {
        return format!("{bytes} B");
    }
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1000.0 && u < UNITS.len() - 1 {
        v /= 1000.0;
        u += 1;
    }
    format!("{v:.1} {}", UNITS[u])
}

/// Render `bytes` as a classic hex+ASCII dump, 16 bytes per row, each row
/// prefixed with its absolute offset (`base` + row start).
pub fn hex_dump(bytes: &[u8], base: u64) -> String {
    let mut out = String::new();
    for (row, chunk) in bytes.chunks(16).enumerate() {
        let off = base + (row as u64) * 16;
        out.push_str(&format!("{off:08x}  "));
        for i in 0..16 {
            if i == 8 {
                out.push(' ');
            }
            match chunk.get(i) {
                Some(b) => out.push_str(&format!("{b:02x} ")),
                None => out.push_str("   "),
            }
        }
        out.push(' ');
        for b in chunk {
            let c = *b;
            out.push(if (0x20..0x7f).contains(&c) {
                c as char
            } else {
                '.'
            });
        }
        out.push('\n');
    }
    out
}
