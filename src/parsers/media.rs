//! Media probes: ISO base media (MP4, MOV), Matroska and WebM, MP3 (ID3v2,
//! ID3v1, encoder tags), FLAC, Ogg, and RIFF (WAV, AVI). They report the
//! encoder that produced a file and the tags it carries, and point markers at
//! the text payloads so a scrub keeps every container's framing intact.
//!
//! Every reader is bounded: box, element, chunk and block counts are capped,
//! large structures are read with capped positioned reads, and anything
//! malformed ends the walk without a finding.

pub(crate) mod ebml;
mod flac;
mod heif;
mod iso;
mod mkv;
mod mp3;
mod ogg;
mod riff;

use crate::model::{
    Category, Confidence, ContainerKind, Evidence, Finding, Marker, Region, RemovalStrategy,
    Severity,
};
use crate::scan::{FileView, Probe, ProbeCtx};

/// Probes contributed by this module.
pub fn probes() -> Vec<Box<dyn Probe>> {
    vec![Box::new(MediaProbe)]
}

struct MediaProbe;

impl Probe for MediaProbe {
    fn id(&self) -> &'static str {
        "media"
    }

    fn formats(&self) -> &'static [&'static str] {
        &[
            "mp4", "matroska", "webm", "mp3", "flac", "ogg", "wav", "avi",
        ]
    }

    fn run(&self, ctx: &ProbeCtx, out: &mut Vec<Finding>) {
        let view = ctx.view;
        match ctx.format {
            Some("mp4") => iso::run(view, out),
            Some("matroska" | "webm") => mkv::run(view, out),
            Some("mp3") => mp3::run(view, out),
            Some("flac") => flac::run(view, out),
            Some("ogg") => ogg::run(view, out),
            Some("wav" | "avi") => riff::run(view, out),
            _ => {}
        }
    }
}

/// Structure-aware removal for the ID3 containers and ISO base media: an ID3v2
/// region drops the whole leading tag, an ID3v1 region drops the 128-byte
/// trailer, and in an ISO file a C2PA or XMP box is turned into free space and
/// an EXIF or XMP item of a HEIC or AVIF image is retyped and zero-filled (see
/// `iso::remove`; the file keeps its size). Any other region (EBML elements,
/// other ISO boxes) has no remover and returns `None`.
pub fn structural_remove(data: &[u8], region: Region) -> Option<Vec<u8>> {
    if let Some(tag_end) = mp3::id3v2_extent(data)
        && region.offset < tag_end as u64
    {
        return data.get(tag_end..).map(<[u8]>::to_vec);
    }
    let len = data.len();
    if len >= 128
        && region.offset == (len - 128) as u64
        && data.get(len - 128..len - 125) == Some(b"TAG")
    {
        return data.get(..len - 128).map(<[u8]>::to_vec);
    }
    iso::remove(data, region)
}

/// Whether a text payload is already empty: only NULs and spaces.
pub(crate) fn is_blank(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0 || b == b' ')
}

/// A short, printable rendering of a text payload for titles and notes.
pub(crate) fn show(bytes: &[u8], max_chars: usize) -> String {
    let text = String::from_utf8_lossy(bytes);
    let trimmed = text.trim_matches(|c: char| c == '\0' || c.is_whitespace());
    let mut out: String = trimmed
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(max_chars)
        .collect();
    if trimmed.chars().count() > max_chars {
        out.push_str("...");
    }
    out
}

/// A four-character code for display (`\xA9nam` shows as `©nam`).
pub(crate) fn fourcc(code: &[u8]) -> String {
    code.iter()
        .map(|&b| match b {
            0xA9 => '\u{A9}',
            0x20..=0x7e => char::from(b),
            _ => '.',
        })
        .collect()
}

/// A length-preserving blank of a text payload with spaces. `None` for an
/// empty region or one that would start at offset 0.
pub(crate) fn text_marker(offset: u64, len: u64, container: ContainerKind) -> Option<Marker> {
    if offset == 0 || len == 0 {
        return None;
    }
    Some(Marker {
        region: Region::new(offset, len),
        removal: RemovalStrategy::RawBlank { fill: 0x20 },
        container,
        reversible: true,
    })
}

/// Evidence at `offset` with up to 64 matched bytes and a note.
pub(crate) fn evidence(offset: u64, bytes: &[u8], note: impl Into<String>) -> Evidence {
    Evidence::at(offset)
        .with_bytes(
            bytes
                .get(..bytes.len().min(64))
                .unwrap_or_default()
                .to_vec(),
        )
        .with_note(note)
}

pub(crate) struct Draft {
    pub category: Category,
    pub confidence: Confidence,
    pub severity: Severity,
    pub id: &'static str,
    pub title: String,
    pub evidence: Evidence,
    pub marker: Option<Marker>,
}

pub(crate) fn push(out: &mut Vec<Finding>, d: Draft) {
    out.push(Finding {
        category: d.category,
        confidence: d.confidence,
        severity: d.severity,
        signature_id: d.id.to_string(),
        title: d.title,
        evidence: d.evidence,
        marker: d.marker,
    });
}

/// Read `len` bytes at `offset`, or `None` on an I/O error.
pub(crate) fn read(view: &dyn FileView, offset: u64, len: usize) -> Option<Vec<u8>> {
    view.read_at(offset, len).ok()
}

#[cfg(test)]
pub(crate) mod testutil {
    use super::*;
    use crate::scan::MemView;

    /// Run the media probe over `data` as `format`.
    pub fn run(name: &str, format: &str, data: &[u8]) -> Vec<Finding> {
        let view = MemView::new(name, data.to_vec());
        let ctx = ProbeCtx::new(&view, Some(format));
        let mut out = Vec::new();
        MediaProbe.run(&ctx, &mut out);
        out
    }

    pub fn ids(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.signature_id.as_str()).collect()
    }

    pub fn find<'a>(findings: &'a [Finding], id: &str) -> &'a Finding {
        findings
            .iter()
            .find(|f| f.signature_id == id)
            .unwrap_or_else(|| panic!("no {id} in {:?}", ids(findings)))
    }

    /// Apply a RawBlank, Truncate or StructuralRemove marker to an in-memory file.
    pub fn apply(data: &mut Vec<u8>, marker: &Marker) {
        match marker.removal {
            RemovalStrategy::RawBlank { fill } => {
                let start = marker.region.offset as usize;
                let end = start + marker.region.len as usize;
                for b in &mut data[start..end] {
                    *b = fill;
                }
            }
            RemovalStrategy::Truncate { from } => data.truncate(from as usize),
            RemovalStrategy::StructuralRemove => {
                *data = crate::edit::structural::remove(marker.container, data, marker.region)
                    .expect("structural remover accepted the region");
            }
            _ => panic!("unexpected removal {:?}", marker.removal),
        }
    }

    /// Identity of `data` as named, for checking a container still parses.
    pub fn format_of(name: &str, data: &[u8]) -> Option<&'static str> {
        crate::parsers::identity::identify(&MemView::new(name, data.to_vec())).0
    }

    /// Feed truncations and corruptions of `data` to the probe: no panics.
    pub fn fuzz(name: &str, format: &str, data: &[u8]) {
        for cut in 0..data.len().min(600) {
            let _ = run(name, format, &data[..cut]);
        }
        let step = (data.len() / 300).max(1);
        for i in (0..data.len()).step_by(step) {
            for v in [0x00, 0xff, 0x7f, 0x80] {
                let mut d = data.to_vec();
                d[i] = v;
                let _ = run(name, format, &d);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;

    #[test]
    fn garbage_produces_nothing() {
        for format in [
            "mp4", "matroska", "webm", "mp3", "flac", "ogg", "wav", "avi",
        ] {
            for data in [
                Vec::new(),
                vec![0u8; 7],
                vec![0xffu8; 4096],
                (0..5000u32).map(|i| (i * 7 + 3) as u8).collect(),
            ] {
                assert!(run("x", format, &data).is_empty(), "{format}");
            }
        }
        assert!(run("x", "png", b"\x89PNG").is_empty());
    }

    #[test]
    fn helpers() {
        assert!(is_blank(b"  \0 "));
        assert!(!is_blank(b" a "));
        assert_eq!(show(b"  Lavf58.76.100\0\0", 40), "Lavf58.76.100");
        assert_eq!(show(b"abcdef", 3), "abc...");
        assert_eq!(fourcc(b"\xa9too"), "\u{A9}too");
        assert!(text_marker(0, 4, ContainerKind::Raw).is_none());
        assert!(text_marker(9, 0, ContainerKind::Raw).is_none());
        assert_eq!(evidence(5, &[1u8; 100], "n").matched.len(), 64);
    }

    #[test]
    fn structural_remove_drops_id3() {
        let mut v2 = mp3::tests_support::id3v2(&[("TIT2", b"\x03Song")]);
        let tag_len = v2.len();
        v2.extend_from_slice(&[0xff, 0xfb, 0x90, 0x64, 1, 2, 3]);
        let out = structural_remove(&v2, Region::new(10, 5)).unwrap();
        assert_eq!(out, &v2[tag_len..]);
        assert_eq!(format_of("a.mp3", &out), Some("mp3"));

        let mut v1 = vec![0xff, 0xfb, 0x90, 0x64, 9, 9];
        v1.extend_from_slice(&mp3::tests_support::id3v1("Title", "Artist"));
        let at = (v1.len() - 128) as u64;
        let out = structural_remove(&v1, Region::new(at, 0)).unwrap();
        assert_eq!(out, &v1[..6]);

        assert!(structural_remove(b"\0\0\0\x18ftypisom", Region::new(8, 4)).is_none());
        assert!(structural_remove(&v1, Region::new(3, 1)).is_none());
        assert!(structural_remove(&[], Region::new(0, 0)).is_none());
    }
}
