//! GIF: walk the block stream (extensions, image descriptors, trailer) through
//! a buffered reader with a byte budget, reporting comment extensions and
//! metadata application extensions.

use crate::model::{
    Category, Confidence, ContainerKind, Evidence, Finding, JunkKind, Marker, Region,
    RemovalStrategy, Severity,
};
use crate::scan::FileView;
use crate::util::fmt::human_size;

use super::jpeg::xmp_creator_tool;
use super::shared::{NOTE_CHARS, TITLE_CHARS, excerpt, finding, is_blank, latin1, quote};

/// Bytes of the file the walk may cover.
const WALK_BUDGET: u64 = 16 * 1024 * 1024;
/// Most blocks (extensions plus images) walked.
const MAX_BLOCKS: usize = 100_000;
/// Most sub-blocks read in one block.
const MAX_SUB_BLOCKS: usize = 1 << 20;
/// Most comment findings per file.
const MAX_COMMENTS: usize = 64;
const CHUNK: usize = 64 * 1024;

/// Sequential reads over a `FileView` in 64 KiB pieces.
struct Reader<'a> {
    view: &'a dyn FileView,
    buf: Vec<u8>,
    start: u64,
}

impl<'a> Reader<'a> {
    fn new(view: &'a dyn FileView) -> Self {
        Self {
            view,
            buf: Vec::new(),
            start: 0,
        }
    }

    fn byte(&mut self, off: u64) -> Option<u8> {
        if off < self.start || off >= self.start + self.buf.len() as u64 {
            self.buf = self.view.read_at(off, CHUNK).ok()?;
            self.start = off;
        }
        self.buf.get((off - self.start) as usize).copied()
    }

    fn bytes(&mut self, off: u64, len: usize) -> Option<Vec<u8>> {
        (0..len as u64).map(|i| self.byte(off + i)).collect()
    }
}

/// A data sub-block: absolute offset of its data and the data length.
type SubBlock = (u64, u8);

/// Read the sub-block chain starting at `pos`, returning the data sub-blocks
/// and the position after the terminator.
fn sub_blocks(r: &mut Reader, mut pos: u64) -> Option<(Vec<SubBlock>, u64)> {
    let mut subs = Vec::new();
    for _ in 0..MAX_SUB_BLOCKS {
        let n = r.byte(pos)?;
        if n == 0 {
            return Some((subs, pos + 1));
        }
        subs.push((pos + 1, n));
        pos += 1 + n as u64;
        if pos > WALK_BUDGET {
            return None;
        }
    }
    None
}

pub(super) fn run(view: &dyn FileView, out: &mut Vec<Finding>) {
    let mut r = Reader::new(view);
    let Some(hdr) = r.bytes(0, 13) else {
        return;
    };
    if &hdr[..6] != b"GIF87a" && &hdr[..6] != b"GIF89a" {
        return;
    }
    let mut pos = 13u64;
    if hdr[10] & 0x80 != 0 {
        pos += 3u64 << ((hdr[10] & 7) + 1);
    }
    let mut comments = 0usize;
    for _ in 0..MAX_BLOCKS {
        match r.byte(pos) {
            Some(0x21) => {
                let Some(label) = r.byte(pos + 1) else {
                    return;
                };
                let Some((subs, next)) = sub_blocks(&mut r, pos + 2) else {
                    return;
                };
                match label {
                    0xFE => comment(&mut r, &subs, &mut comments, out),
                    0xFF => application(&mut r, &subs, out),
                    _ => {}
                }
                pos = next;
            }
            Some(0x2C) => {
                let Some(desc) = r.bytes(pos, 10) else {
                    return;
                };
                pos += 10;
                if desc[9] & 0x80 != 0 {
                    pos += 3u64 << ((desc[9] & 7) + 1);
                }
                let Some((_, next)) = sub_blocks(&mut r, pos + 1) else {
                    return;
                };
                pos = next;
            }
            _ => return,
        }
        if pos > WALK_BUDGET {
            return;
        }
    }
}

fn comment(r: &mut Reader, subs: &[SubBlock], count: &mut usize, out: &mut Vec<Finding>) {
    let mut parts = Vec::new();
    for &(off, n) in subs {
        let Some(data) = r.bytes(off, n as usize) else {
            return;
        };
        if !is_blank(&data) {
            parts.push((off, data));
        }
    }
    let total = parts.len();
    for (i, (off, data)) in parts.into_iter().enumerate() {
        if *count >= MAX_COMMENTS {
            return;
        }
        *count += 1;
        let title = if total > 1 {
            format!(
                "GIF comment \"{}\" (part {} of {total})",
                quote(&data, TITLE_CHARS),
                i + 1
            )
        } else {
            format!("GIF comment \"{}\"", quote(&data, TITLE_CHARS))
        };
        out.push(finding(
            "gif.comment",
            Category::Junk(JunkKind::Comment),
            Confidence::Strong,
            Severity::Notice,
            title,
            Evidence::at(off)
                .with_bytes(excerpt(&data))
                .with_note(format!(
                    "comment extension: \"{}\"",
                    quote(&data, NOTE_CHARS)
                )),
            Some(Marker {
                region: Region::new(off, data.len() as u64),
                removal: RemovalStrategy::RawBlank { fill: b' ' },
                container: ContainerKind::Raw,
                reversible: true,
            }),
        ));
    }
}

fn application(r: &mut Reader, subs: &[SubBlock], out: &mut Vec<Finding>) {
    let Some(&(id_off, 11)) = subs.first() else {
        return;
    };
    let Some(id) = r.bytes(id_off, 11) else {
        return;
    };
    let (kind, what) = match &id[..] {
        b"XMP DataXMP" => (JunkKind::Xmp, "XMP metadata"),
        b"MGKIPTC0000" | b"MGK8BIM0000" => (JunkKind::Iptc, "IPTC metadata"),
        _ => return,
    };
    let data = &subs[1..];
    let Some(&(first_off, _)) = data.first() else {
        return;
    };
    let span: u64 = data.iter().map(|&(_, n)| 1 + n as u64).sum();
    // A single data sub-block can be zeroed in place; XMP is stored as raw
    // text whose bytes double as sub-block lengths, so it gets no marker.
    let marker = match (kind, data) {
        (JunkKind::Iptc, [(off, n)]) => {
            let Some(block) = r.bytes(*off, *n as usize) else {
                return;
            };
            if is_blank(&block) {
                return;
            }
            Some(Marker::blank(
                Region::new(*off, *n as u64),
                ContainerKind::Raw,
            ))
        }
        _ => None,
    };
    let mut note = format!(
        "application extension \"{}\" carrying {}",
        latin1(&id),
        human_size(span)
    );
    if kind == JunkKind::Xmp {
        // The packet starts at the first "length" byte, which is really text.
        let raw = r
            .bytes(first_off - 1, span.min(8192) as usize)
            .unwrap_or_default();
        if let Some(tool) = xmp_creator_tool(&raw) {
            note.push_str(&format!(", CreatorTool \"{tool}\""));
        }
    }
    out.push(finding(
        "gif.app",
        Category::Junk(kind),
        Confidence::Moderate,
        Severity::Notice,
        format!("GIF {what}"),
        Evidence::at(id_off).with_bytes(id.clone()).with_note(note),
        marker,
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::image::probes;
    use crate::parsers::image::shared::testkit::{apply, garbage, run, with_id};

    fn ext(label: u8, blocks: &[&[u8]]) -> Vec<u8> {
        let mut v = vec![0x21, label];
        for b in blocks {
            v.push(b.len() as u8);
            v.extend_from_slice(b);
        }
        v.push(0);
        v
    }

    fn build(blocks: &[Vec<u8>]) -> Vec<u8> {
        let mut v = b"GIF89a\x01\x00\x01\x00\x80\x00\x00".to_vec();
        v.extend_from_slice(&[0, 0, 0, 0xFF, 0xFF, 0xFF]);
        for b in blocks {
            v.extend_from_slice(b);
        }
        v.extend_from_slice(&[0x2C, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0x02, 0x02, 0x44, 0x01, 0]);
        v.push(0x3B);
        v
    }

    fn scan(data: &[u8]) -> Vec<Finding> {
        run(probes(), "anim.gif", data, "gif")
    }

    #[test]
    fn comment_is_found_and_blanked() {
        let data = build(&[
            ext(0xFF, &[b"NETSCAPE2.0", &[1, 0, 0]]),
            ext(0xFE, &[b"made with a test tool"]),
        ]);
        let fs = scan(&data);
        assert_eq!(fs.len(), 1);
        let c = &fs[0];
        assert_eq!(c.signature_id, "gif.comment");
        assert_eq!(c.title, "GIF comment \"made with a test tool\"");
        let m = c.marker.as_ref().unwrap();
        assert_eq!(m.removal, RemovalStrategy::RawBlank { fill: b' ' });
        assert_eq!(m.container, ContainerKind::Raw);
        assert_eq!(data[m.region.offset as usize - 1], 21);
        let cleaned = apply(&data, c);
        assert_eq!(cleaned.len(), data.len());
        assert!(scan(&cleaned).is_empty());
        assert_eq!(*cleaned.last().unwrap(), 0x3B);
    }

    #[test]
    fn multi_block_comment_yields_one_finding_per_block() {
        let data = build(&[ext(0xFE, &[b"part one", b"part two"])]);
        let fs = scan(&data);
        assert_eq!(fs.len(), 2);
        assert!(fs[1].title.ends_with("(part 2 of 2)"));
        let once = apply(&data, &fs[0]);
        let twice = apply(&once, &scan(&once)[0]);
        assert!(scan(&twice).is_empty());
    }

    #[test]
    fn application_extensions() {
        let xmp = ext(0xFF, &[b"XMP DataXMP", b"<x xmp:CreatorTool=\"Tool\"/>"]);
        let iptc = ext(0xFF, &[b"MGKIPTC0000", b"\x1c\x02\x50\x00\x03Bob"]);
        let data = build(&[xmp, iptc]);
        let fs = scan(&data);
        let apps = with_id(&fs, "gif.app");
        assert_eq!(apps.len(), 2);
        assert_eq!(apps[0].category, Category::Junk(JunkKind::Xmp));
        assert!(apps[0].marker.is_none());
        assert!(
            apps[0]
                .evidence
                .note
                .as_deref()
                .unwrap()
                .contains("CreatorTool \"Tool\"")
        );
        assert_eq!(apps[1].category, Category::Junk(JunkKind::Iptc));
        let cleaned = apply(&data, apps[1]);
        let again = scan(&cleaned);
        assert_eq!(with_id(&again, "gif.app").len(), 1);
    }

    #[test]
    fn garbage_and_truncation_are_safe() {
        let data = build(&[ext(0xFE, &[b"hello"])]);
        for cut in 0..data.len() {
            let _ = scan(&data[..cut]);
        }
        for seed in 0..32 {
            assert!(scan(&garbage(seed, 2048)).is_empty());
        }
        let mut g = b"GIF89a".to_vec();
        g.extend(garbage(5, 512));
        let _ = scan(&g);
    }
}
