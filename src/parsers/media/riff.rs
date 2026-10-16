//! RIFF audio and video (WAV, AVI): walk the chunks to each `LIST` `INFO` and
//! report its text sub-chunks. `ISFT` names the software that wrote the file;
//! the rest (INAM, IART, ICMT, ICRD and others) are tags.
//!
//! Chunk headers are read with positioned reads, so an INFO list placed after
//! a large `data` or `movi` chunk is still found. Markers blank only the text
//! before its NUL terminator, so every chunk keeps its size and padding.

use super::{Draft, evidence, is_blank, push, read, show, text_marker};
use crate::model::{BrandKind, Category, Confidence, ContainerKind, Finding, JunkKind, Severity};
use crate::scan::FileView;
use crate::util::bytes::{slice, u32_le};

/// Most chunk headers read in one file, nested ones included.
const MAX_CHUNKS: usize = 1024;
/// Deepest `LIST` nesting followed.
const MAX_DEPTH: usize = 3;
/// Most bytes of one INFO list read.
const MAX_INFO: usize = 256 * 1024;
/// Most INFO sub-chunks reported per list.
const MAX_TAGS: usize = 64;

/// Readable names for the common INFO ids.
const NAMES: &[(&[u8; 4], &str)] = &[
    (b"INAM", "title"),
    (b"IART", "artist"),
    (b"ICMT", "comment"),
    (b"ICRD", "creation date"),
    (b"IGNR", "genre"),
    (b"ICOP", "copyright"),
    (b"IENG", "engineer"),
    (b"ITCH", "technician"),
    (b"IKEY", "keywords"),
    (b"ISBJ", "subject"),
    (b"ISRC", "source"),
    (b"IPRD", "product"),
    (b"IPRT", "part"),
    (b"ITRK", "track"),
    (b"ILNG", "language"),
    (b"IARL", "archival location"),
    (b"ICMS", "commissioned by"),
];

pub(super) fn run(view: &dyn FileView, out: &mut Vec<Finding>) {
    let h = view.header();
    if slice(h, 0, 4) != Some(b"RIFF") || !matches!(slice(h, 8, 4), Some(b"WAVE" | b"AVI ")) {
        return;
    }
    let size = view.size();
    // Writers that stream sometimes leave the RIFF size at 0 or too small;
    // walk to the end of the file then.
    let declared = u64::from(u32_le(h, 4).unwrap_or(0)) + 8;
    let end = if declared <= 12 || declared > size {
        size
    } else {
        declared
    };
    let mut count = 0usize;
    walk(view, 12, end, 0, &mut count, out);
}

fn walk(
    view: &dyn FileView,
    start: u64,
    end: u64,
    depth: usize,
    count: &mut usize,
    out: &mut Vec<Finding>,
) {
    let mut off = start;
    while off.saturating_add(8) <= end && *count < MAX_CHUNKS {
        *count += 1;
        let Some(hb) = read(view, off, 12) else {
            return;
        };
        let (Some(id), Some(len)) = (slice(&hb, 0, 4), u32_le(&hb, 4)) else {
            return;
        };
        if !id.iter().all(|c| c.is_ascii_graphic() || *c == b' ') {
            return;
        }
        let data = off + 8;
        let chunk_end = data.saturating_add(u64::from(len)).min(end);
        if id == b"LIST" {
            match slice(&hb, 8, 4) {
                Some(b"INFO") => info(view, data + 4, chunk_end, out),
                Some(b"movi" | b"rec ") => {}
                Some(_) if depth < MAX_DEPTH => {
                    walk(view, data + 4, chunk_end, depth + 1, count, out)
                }
                _ => {}
            }
        }
        // Chunks are padded to an even length.
        off = data
            .saturating_add(u64::from(len))
            .saturating_add(u64::from(len & 1));
    }
}

fn info(view: &dyn FileView, start: u64, end: u64, out: &mut Vec<Finding>) {
    let want = usize::try_from(end.saturating_sub(start))
        .unwrap_or(usize::MAX)
        .min(MAX_INFO);
    let Some(buf) = read(view, start, want) else {
        return;
    };
    let mut pos = 0usize;
    let mut reported = 0usize;
    while pos + 8 <= buf.len() && reported < MAX_TAGS {
        let (Some(id), Some(len)) = (slice(&buf, pos, 4), u32_le(&buf, pos + 4)) else {
            return;
        };
        if !id
            .iter()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        {
            return;
        }
        let len = len as usize;
        let vstart = pos + 8;
        let value = buf
            .get(vstart..vstart.saturating_add(len).min(buf.len()))
            .unwrap_or_default();
        let text = value.split(|&b| b == 0).next().unwrap_or_default();
        if !is_blank(text) {
            reported += 1;
            tag(id, start + vstart as u64, text, out);
        }
        pos = vstart.saturating_add(len).saturating_add(len & 1);
    }
}

fn tag(id: &[u8], abs: u64, text: &[u8], out: &mut Vec<Finding>) {
    let code = String::from_utf8_lossy(id).into_owned();
    let marker = text_marker(abs, text.len() as u64, ContainerKind::RiffChunk);
    let keep = "scrubbing fills the text with spaces and keeps the chunk size and NUL terminator";
    if id == b"ISFT" {
        let v = show(text, 60);
        push(
            out,
            Draft {
                category: Category::Brand(BrandKind::MediaEncoder),
                confidence: Confidence::Strong,
                severity: Severity::Info,
                id: "riff.software",
                title: format!("RIFF software {v}"),
                evidence: evidence(
                    abs,
                    text,
                    format!("LIST INFO ISFT (software) = \"{v}\"; {keep}"),
                ),
                marker,
            },
        );
        return;
    }
    let name = NAMES
        .iter()
        .find(|(k, _)| k.as_slice() == id)
        .map_or("tag", |(_, n)| *n);
    let v = show(text, 40);
    push(
        out,
        Draft {
            category: Category::Junk(JunkKind::Comment),
            confidence: Confidence::Moderate,
            severity: Severity::Notice,
            id: "riff.info",
            title: format!("RIFF INFO {name} ({code})"),
            evidence: evidence(
                abs,
                text,
                format!("LIST INFO {code} ({name}) = \"{v}\"; {keep}"),
            ),
            marker,
        },
    );
}

#[cfg(test)]
mod tests {
    use super::super::testutil::{apply, find, format_of, fuzz, ids, run};
    use super::*;
    use crate::model::RemovalStrategy;

    fn chunk(id: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut c = id.to_vec();
        c.extend_from_slice(&(body.len() as u32).to_le_bytes());
        c.extend_from_slice(body);
        if !body.len().is_multiple_of(2) {
            c.push(0);
        }
        c
    }

    fn list(kind: &[u8; 4], children: &[Vec<u8>]) -> Vec<u8> {
        chunk(b"LIST", &[kind.as_slice(), &children.concat()].concat())
    }

    fn riff(form: &[u8; 4], chunks: &[Vec<u8>]) -> Vec<u8> {
        let body = [form.as_slice(), &chunks.concat()].concat();
        chunk(b"RIFF", &body)
    }

    fn info_list() -> Vec<u8> {
        list(
            b"INFO",
            &[
                chunk(b"INAM", b"Night Drive\0"),
                chunk(b"IART", b"Someone\0"),
                chunk(b"ISFT", b"Lavf60.16.100\0"),
                chunk(b"ICRD", b"2024\0"),
                chunk(b"ICMT", b"\0\0"),
            ],
        )
    }

    fn wav() -> Vec<u8> {
        riff(
            b"WAVE",
            &[
                chunk(
                    b"fmt ",
                    &[1, 0, 2, 0, 0x44, 0xac, 0, 0, 0x10, 0xb1, 2, 0, 4, 0, 16, 0],
                ),
                chunk(b"data", &[0x55; 1001]),
                info_list(),
            ],
        )
    }

    #[test]
    fn wav_info_after_odd_data() {
        let data = wav();
        assert_eq!(format_of("a.wav", &data), Some("wav"));
        let f = run("a.wav", "wav", &data);
        assert_eq!(
            ids(&f),
            ["riff.info", "riff.info", "riff.software", "riff.info"]
        );
        let s = find(&f, "riff.software");
        assert_eq!(s.category, Category::Brand(BrandKind::MediaEncoder));
        assert_eq!(s.confidence, Confidence::Strong);
        assert_eq!(s.severity, Severity::Info);
        assert_eq!(s.title, "RIFF software Lavf60.16.100");
        let m = s.marker.as_ref().unwrap();
        assert_eq!(m.container, ContainerKind::RiffChunk);
        assert_eq!(m.removal, RemovalStrategy::RawBlank { fill: 0x20 });
        let at = m.region.offset as usize;
        assert_eq!(&data[at..at + m.region.len as usize], b"Lavf60.16.100");
        assert_eq!(data[at + m.region.len as usize], 0);
        assert_eq!(s.evidence.offset, m.region.offset);

        let i = find(&f, "riff.info");
        assert_eq!(i.category, Category::Junk(JunkKind::Comment));
        assert_eq!(i.confidence, Confidence::Moderate);
        assert_eq!(i.severity, Severity::Notice);
        assert_eq!(i.title, "RIFF INFO title (INAM)");
        let titles: Vec<&str> = f.iter().map(|f| f.title.as_str()).collect();
        assert_eq!(titles[3], "RIFF INFO creation date (ICRD)");
    }

    #[test]
    fn every_marker_scrubs_and_the_file_still_parses() {
        let mut data = wav();
        let len = data.len();
        let f = run("a.wav", "wav", &data);
        for m in f.iter().filter_map(|f| f.marker.as_ref()) {
            apply(&mut data, m);
        }
        assert_eq!(data.len(), len);
        assert!(run("a.wav", "wav", &data).is_empty());
        assert_eq!(format_of("a.wav", &data), Some("wav"));
        // Every chunk header is unchanged: the same INFO list with blank text.
        let blank = list(
            b"INFO",
            &[
                chunk(b"INAM", b"           \0"),
                chunk(b"IART", b"       \0"),
                chunk(b"ISFT", b"             \0"),
                chunk(b"ICRD", b"    \0"),
                chunk(b"ICMT", b"\0\0"),
            ],
        );
        assert!(data.ends_with(&blank));
    }

    #[test]
    fn avi_info_inside_and_after_hdrl() {
        let hdrl = list(
            b"hdrl",
            &[
                chunk(b"avih", &[0u8; 56]),
                list(b"INFO", &[chunk(b"ISFT", b"VirtualDub\0")]),
            ],
        );
        let movi = list(b"movi", &[chunk(b"00dc", &[0u8; 64])]);
        let data = riff(
            b"AVI ",
            &[hdrl, movi, info_list(), chunk(b"idx1", &[0u8; 16])],
        );
        assert_eq!(format_of("a.avi", &data), Some("avi"));
        let f = run("a.avi", "avi", &data);
        assert_eq!(f[0].title, "RIFF software VirtualDub");
        assert_eq!(
            f.iter()
                .filter(|f| f.signature_id == "riff.software")
                .count(),
            2
        );
    }

    #[test]
    fn sizes_and_bounds() {
        // A RIFF size of zero (streamed) still walks to the end of the file.
        let mut data = wav();
        data[4..8].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(run("a.wav", "wav", &data).len(), 4);
        // A huge data chunk ends the walk without reading past EOF.
        let data = riff(
            b"WAVE",
            &[
                chunk(b"fmt ", &[0u8; 16]),
                [b"data".as_slice(), &u32::MAX.to_le_bytes()].concat(),
                info_list(),
            ],
        );
        assert!(run("a.wav", "wav", &data).is_empty());
        // Unknown INFO ids still count as tags; lowercase ids end the list.
        let data = riff(
            b"WAVE",
            &[list(
                b"INFO",
                &[
                    chunk(b"IXYZ", b"v\0"),
                    chunk(b"bad!", b"w\0"),
                    chunk(b"INAM", b"t\0"),
                ],
            )],
        );
        let f = run("a.wav", "wav", &data);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].title, "RIFF INFO tag (IXYZ)");
        // WebP and other RIFF forms are not ours.
        assert!(run("a.webp", "wav", &riff(b"WEBP", &[info_list()])).is_empty());
        // A chunk storm is bounded.
        let storm: Vec<Vec<u8>> = (0..5000).map(|_| chunk(b"JUNK", &[])).collect();
        let data = riff(b"WAVE", &[storm.concat(), info_list()]);
        assert!(run("a.wav", "wav", &data).is_empty());
    }

    #[test]
    fn truncated_and_corrupt_inputs() {
        fuzz("a.wav", "wav", &wav());
    }
}
