//! Helpers shared by the container, document and image parsers: CRC-32, bounded
//! fetches, note quoting, and a finding constructor. Kept crate-private so the
//! public parser surface stays exactly `probes()` and `structural_remove()`.

use crate::model::{Category, Confidence, Evidence, Finding, Marker, Severity};
use crate::scan::FileView;
use crate::scan::reader::MAX_READ;

/// Longest excerpt stored in `Evidence::matched`.
pub(crate) const MAX_MATCHED: usize = 64;

/// Longest quoted value placed in a note.
pub(crate) const NOTE_CHARS: usize = 80;

/// Longest quoted value placed in a title.
pub(crate) const TITLE_CHARS: usize = 48;

const CRC_TABLE: [u32; 256] = crc_table();

const fn crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut n = 0;
    while n < 256 {
        let mut c = n as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[n] = c;
        n += 1;
    }
    table
}

/// CRC-32 (IEEE, reflected), as used by PNG, ZIP, gzip, 7z and xz.
pub(crate) fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c = CRC_TABLE[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8);
    }
    c ^ 0xFFFF_FFFF
}

/// Exactly `len` bytes at absolute `off`, or `None` when the read is short,
/// fails, or asks for more than one positioned read may return.
pub(crate) fn fetch(view: &dyn FileView, off: u64, len: usize) -> Option<Vec<u8>> {
    if len > MAX_READ {
        return None;
    }
    let buf = view.read_at(off, len).ok()?;
    (buf.len() == len).then_some(buf)
}

/// Whether `bytes` holds nothing but NULs and spaces (an empty or already
/// scrubbed value). Probes skip such values so a cleaned file reads clean.
pub(crate) fn is_blank(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0 || b == b' ')
}

/// Lossy UTF-8 text, control characters folded to spaces, trimmed and clipped
/// to `max` characters (with a trailing `...` when clipped).
pub(crate) fn quote(bytes: &[u8], max: usize) -> String {
    clip(&String::from_utf8_lossy(bytes), max)
}

/// Fold control characters to spaces, trim, and clip to `max` characters.
pub(crate) fn clip(text: &str, max: usize) -> String {
    let cleaned: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.chars().count() <= max {
        return trimmed.to_string();
    }
    let mut out: String = trimmed.chars().take(max).collect();
    out.push_str("...");
    out
}

/// Bytes read as ISO-8859-1, which never fails and keeps ASCII intact.
pub(crate) fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| b as char).collect()
}

/// The first [`MAX_MATCHED`] bytes of `bytes`.
pub(crate) fn excerpt(bytes: &[u8]) -> Vec<u8> {
    bytes[..bytes.len().min(MAX_MATCHED)].to_vec()
}

/// The file name when it looks like it carries an archive password, the
/// classic lure for an encrypted archive whose contents a scanner cannot open.
/// Matching is case-insensitive: `password` anywhere, or a run of letters
/// that is exactly `pass`, `passwd`, `pw` or `pwd` (so `pass_1234` and
/// `PW-9` match while `passport` and `upward` do not).
pub(crate) fn pw_in_name(view: &dyn FileView) -> Option<String> {
    let name = view.path().file_name()?.to_string_lossy().to_string();
    name_has_password(&name).then_some(name)
}

fn name_has_password(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("password")
        || lower
            .split(|c: char| !c.is_ascii_alphabetic())
            .any(|w| matches!(w, "pass" | "passwd" | "pw" | "pwd"))
}

/// Build a finding. Every probe in these modules goes through here so the
/// field order stays in one place.
pub(crate) fn finding(
    signature_id: &str,
    category: Category,
    confidence: Confidence,
    severity: Severity,
    title: impl Into<String>,
    evidence: Evidence,
    marker: Option<Marker>,
) -> Finding {
    Finding {
        category,
        confidence,
        severity,
        signature_id: signature_id.to_string(),
        title: title.into(),
        evidence,
        marker,
    }
}

/// Render a Unix timestamp as `YYYY-MM-DD HH:MM:SS UTC`.
pub(crate) fn unix_time(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        (rem / 60) % 60,
        rem % 60
    )
}

/// Days since 1970-01-01 to a proleptic Gregorian (year, month, day).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Test helpers: run a module's probes over synthetic bytes, apply a marker the
/// way the edit engine would, and generate deterministic garbage.
#[cfg(test)]
pub(crate) mod testkit {
    use crate::model::{Finding, RemovalStrategy};
    use crate::scan::{MemView, Probe, ProbeCtx};

    /// Run every probe in `probes` whose `formats()` admits `fmt`.
    pub fn run(probes: Vec<Box<dyn Probe>>, name: &str, data: &[u8], fmt: &str) -> Vec<Finding> {
        let view = MemView::new(name, data.to_vec());
        let ctx = ProbeCtx::new(&view, Some(fmt));
        let mut out = Vec::new();
        for p in probes {
            if p.formats().is_empty() || p.formats().contains(&fmt) {
                p.run(&ctx, &mut out);
            }
        }
        assert_sane(&out, data.len() as u64);
        out
    }

    /// Findings with signature `id`.
    pub fn with_id<'a>(fs: &'a [Finding], id: &str) -> Vec<&'a Finding> {
        fs.iter().filter(|f| f.signature_id == id).collect()
    }

    /// Apply `f`'s marker to `data` exactly as the edit engine would.
    pub fn apply(data: &[u8], f: &Finding) -> Vec<u8> {
        let m = f.marker.as_ref().expect("finding has a marker");
        assert!(m.region.offset > 0, "never touch offset 0");
        let mut out = data.to_vec();
        match &m.removal {
            RemovalStrategy::RawBlank { fill } => {
                let s = m.region.offset as usize;
                let e = m.region.end() as usize;
                assert!(e <= out.len() && m.region.len > 0);
                out[s..e].iter_mut().for_each(|b| *b = *fill);
            }
            RemovalStrategy::Truncate { from } => {
                assert!((*from as usize) < out.len());
                out.truncate(*from as usize);
            }
            RemovalStrategy::StructuralRemove => {
                out = crate::edit::structural::remove(m.container, data, m.region)
                    .expect("structural remover accepted the region");
            }
            RemovalStrategy::DeleteFile => panic!("unexpected delete marker"),
        }
        out
    }

    /// Every evidence offset and marker region lies inside the file, and every
    /// excerpt is small.
    pub fn assert_sane(fs: &[Finding], size: u64) {
        for f in fs {
            assert!(
                f.evidence.offset <= size,
                "{}: evidence past EOF",
                f.signature_id
            );
            assert!(
                f.evidence.matched.len() <= 64,
                "{}: excerpt too long",
                f.signature_id
            );
            assert!(!f.title.contains('\u{2014}') && !f.title.contains('\u{2013}'));
            if let Some(m) = &f.marker {
                assert!(
                    m.region.end() <= size,
                    "{}: marker past EOF",
                    f.signature_id
                );
                assert!(
                    m.region.offset > 0,
                    "{}: marker at offset 0",
                    f.signature_id
                );
            }
        }
    }

    /// Deterministic pseudo-random bytes.
    pub fn garbage(seed: u64, len: usize) -> Vec<u8> {
        let mut s = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        (0..len)
            .map(|_| {
                s = s
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                (s >> 33) as u8
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_matches_reference() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn text_helpers() {
        assert!(is_blank(b"  \0 "));
        assert!(!is_blank(b" a "));
        assert_eq!(quote(b" hi\nthere ", 80), "hi there");
        assert_eq!(clip("abcdef", 3), "abc...");
        assert_eq!(unix_time(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(unix_time(1_700_000_000), "2023-11-14 22:13:20 UTC");
    }

    #[test]
    fn password_names() {
        for yes in [
            "invoice_PW_1234.zip",
            "files_pass_hunter2.7z",
            "movie_password_x9.rar",
            "pw.rar",
            "Pass123.zip",
            "mypassword.zip",
            "pwd=abc.zip",
        ] {
            assert!(name_has_password(yes), "{yes}");
        }
        for no in ["passport.zip", "compass.rar", "upward.7z", "photos.zip"] {
            assert!(!name_has_password(no), "{no}");
        }
    }
}
