//! Matroska and WebM: walk the EBML header to the Segment, then the Segment's
//! children to Info, and report MuxingApp, WritingApp and Title.

use super::ebml::{self, EBML_HEADER};
use super::{Draft, evidence, is_blank, push, read, show, text_marker};
use crate::model::{BrandKind, Category, Confidence, ContainerKind, Finding, JunkKind, Severity};
use crate::scan::FileView;

const SEGMENT: u32 = 0x1853_8067;
const INFO: u32 = 0x1549_A966;
const CLUSTER: u32 = 0x1F43_B675;
const MUXING_APP: u32 = 0x4D80;
const WRITING_APP: u32 = 0x5741;
const TITLE: u32 = 0x7BA9;
const CRC32: u32 = 0xBF;

/// Most Segment children walked before giving up on finding Info.
const MAX_CHILDREN: usize = 256;
/// Most bytes of Info read.
const MAX_INFO: u64 = 64 * 1024;

pub(super) fn run(view: &dyn FileView, out: &mut Vec<Finding>) {
    let size = view.size();
    let Some(head) = ebml::element(view.header(), 0) else {
        return;
    };
    let Some(head_size) = head.size else {
        return;
    };
    if head.id != EBML_HEADER {
        return;
    }
    let seg_off = (head.data as u64).saturating_add(head_size);
    let Some(sb) = read(view, seg_off, 16) else {
        return;
    };
    let Some(seg) = ebml::element(&sb, 0) else {
        return;
    };
    if seg.id != SEGMENT {
        return;
    }
    let seg_data = seg_off + seg.data as u64;
    let seg_end = seg
        .size
        .map_or(size, |s| seg_data.saturating_add(s))
        .min(size);
    let mut off = seg_data;
    for _ in 0..MAX_CHILDREN {
        if off >= seg_end {
            return;
        }
        let Some(eb) = read(view, off, 16) else {
            return;
        };
        let Some(el) = ebml::element(&eb, 0) else {
            return;
        };
        let data = off + el.data as u64;
        let avail = seg_end.saturating_sub(data);
        match (el.id, el.size) {
            (CLUSTER, _) => return,
            (INFO, s) => {
                info(view, data, s.unwrap_or(avail).min(avail), out);
                return;
            }
            (_, Some(s)) => off = data.saturating_add(s),
            (_, None) => return,
        }
    }
}

fn info(view: &dyn FileView, data: u64, len: u64, out: &mut Vec<Finding>) {
    let Some(buf) = read(view, data, len.min(MAX_INFO) as usize) else {
        return;
    };
    let mut items = Vec::new();
    let mut crc = false;
    let mut off = 0usize;
    for _ in 0..MAX_CHILDREN {
        let Some(el) = ebml::element(&buf, off) else {
            break;
        };
        let Some(size) = el.size.and_then(|s| usize::try_from(s).ok()) else {
            break;
        };
        let Some(end) = el.data.checked_add(size).filter(|&e| e <= buf.len()) else {
            break;
        };
        match el.id {
            CRC32 => crc = true,
            MUXING_APP | WRITING_APP | TITLE => items.push((el.id, el.data, size)),
            _ => {}
        }
        off = end;
    }
    for (id, start, size) in items {
        let Some(value) = buf.get(start..start + size) else {
            continue;
        };
        if is_blank(value) {
            continue;
        }
        let abs = data + start as u64;
        let v = show(value, 60);
        let (sig, label, category, confidence, severity) = match id {
            MUXING_APP => (
                "mkv.muxing_app",
                "MuxingApp",
                Category::Brand(BrandKind::MediaEncoder),
                Confidence::Strong,
                Severity::Info,
            ),
            WRITING_APP => (
                "mkv.writing_app",
                "WritingApp",
                Category::Brand(BrandKind::MediaEncoder),
                Confidence::Strong,
                Severity::Info,
            ),
            _ => (
                "mkv.title",
                "Title",
                Category::Junk(JunkKind::Comment),
                Confidence::Moderate,
                Severity::Notice,
            ),
        };
        let mut note = format!("Segment Info {label} = \"{v}\"");
        let marker = if crc {
            note.push_str("; Info carries a CRC-32 element, so no marker is offered (blanking would break the checksum)");
            None
        } else {
            text_marker(abs, size as u64, ContainerKind::EbmlElement)
        };
        push(
            out,
            Draft {
                category,
                confidence,
                severity,
                id: sig,
                title: format!("Matroska {label} {v}"),
                evidence: evidence(abs, value, note),
                marker,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::{apply, find, format_of, fuzz, ids, run};
    use super::*;
    use crate::model::RemovalStrategy;

    fn el(id: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut b = id.to_vec();
        let n = payload.len();
        if n < 0x7f {
            b.push(0x80 | n as u8);
        } else {
            b.push(0x01);
            b.extend_from_slice(&(n as u64).to_be_bytes()[1..]);
        }
        b.extend_from_slice(payload);
        b
    }

    fn header(doc: &[u8]) -> Vec<u8> {
        el(
            &[0x1a, 0x45, 0xdf, 0xa3],
            &[el(&[0x42, 0x86], &[1]), el(&[0x42, 0x82], doc)].concat(),
        )
    }

    fn file(doc: &[u8], info_children: &[Vec<u8>], known_size: bool) -> Vec<u8> {
        let body = [
            el(&[0x11, 0x4d, 0x9b, 0x74], &[0u8; 30]),
            el(&[0xec], &[0u8; 10]),
            el(&[0x15, 0x49, 0xa9, 0x66], &info_children.concat()),
            el(&[0x1f, 0x43, 0xb6, 0x75], &[0u8; 64]),
        ]
        .concat();
        let mut seg = vec![0x18, 0x53, 0x80, 0x67];
        if known_size {
            seg.push(0x01);
            seg.extend_from_slice(&(body.len() as u64).to_be_bytes()[1..]);
        } else {
            seg.extend_from_slice(&[0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        }
        seg.extend_from_slice(&body);
        [header(doc), seg].concat()
    }

    fn info_children() -> Vec<Vec<u8>> {
        vec![
            el(&[0x2a, 0xd7, 0xb1], &[0x0f, 0x42, 0x40]),
            el(&[0x4d, 0x80], b"libebml v1.4.5 + libmatroska v1.7.1"),
            el(&[0x57, 0x41], b"mkvmerge v86.0 ('Winter') 64-bit"),
            el(&[0x7b, 0xa9], b"Family trip"),
        ]
    }

    #[test]
    fn info_strings_are_reported() {
        for (doc, fmt) in [(&b"matroska"[..], "matroska"), (b"webm", "webm")] {
            let data = file(doc, &info_children(), false);
            assert_eq!(format_of("a.mkv", &data), Some(fmt));
            let f = run("a.mkv", fmt, &data);
            assert_eq!(ids(&f), ["mkv.muxing_app", "mkv.writing_app", "mkv.title"]);
            let w = find(&f, "mkv.writing_app");
            assert_eq!(w.category, Category::Brand(BrandKind::MediaEncoder));
            assert_eq!(w.confidence, Confidence::Strong);
            assert_eq!(w.severity, Severity::Info);
            let m = w.marker.as_ref().unwrap();
            assert_eq!(m.container, ContainerKind::EbmlElement);
            assert_eq!(m.removal, RemovalStrategy::RawBlank { fill: 0x20 });
            let at = m.region.offset as usize;
            assert_eq!(
                &data[at..at + m.region.len as usize],
                b"mkvmerge v86.0 ('Winter') 64-bit"
            );
            let t = find(&f, "mkv.title");
            assert_eq!(t.category, Category::Junk(JunkKind::Comment));
            assert_eq!(t.confidence, Confidence::Moderate);
            assert_eq!(t.severity, Severity::Notice);
        }
    }

    #[test]
    fn scrubbed_file_still_parses() {
        let mut data = file(b"webm", &info_children(), true);
        let f = run("a.webm", "webm", &data);
        for m in f.iter().filter_map(|f| f.marker.as_ref()) {
            apply(&mut data, m);
        }
        assert!(run("a.webm", "webm", &data).is_empty());
        assert_eq!(format_of("a.webm", &data), Some("webm"));
        // The EBML structure is unchanged: Info and its children still parse.
        let mut kids = info_children();
        kids[1] = el(&[0x4d, 0x80], &[b' '; 35]);
        kids[2] = el(&[0x57, 0x41], &[b' '; 32]);
        kids[3] = el(&[0x7b, 0xa9], &[b' '; 11]);
        assert_eq!(data, file(b"webm", &kids, true));
    }

    #[test]
    fn crc_protected_info_gets_no_marker() {
        let mut kids = vec![el(&[0xbf], &[1, 2, 3, 4])];
        kids.extend(info_children());
        let f = run("a.mkv", "matroska", &file(b"matroska", &kids, false));
        assert_eq!(f.len(), 3);
        assert!(f.iter().all(|f| f.marker.is_none()));
        assert!(f[0].evidence.note.as_deref().unwrap().contains("CRC-32"));
    }

    #[test]
    fn info_after_a_cluster_or_missing_is_ignored() {
        let mut data = header(b"matroska");
        data.extend_from_slice(&[
            0x18, 0x53, 0x80, 0x67, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ]);
        data.extend(el(&[0x1f, 0x43, 0xb6, 0x75], &[0u8; 8]));
        data.extend(el(&[0x15, 0x49, 0xa9, 0x66], &info_children().concat()));
        assert!(run("a.mkv", "matroska", &data).is_empty());
        assert!(run("a.mkv", "matroska", &header(b"matroska")).is_empty());
    }

    #[test]
    fn truncated_and_corrupt_inputs() {
        fuzz(
            "a.mkv",
            "matroska",
            &file(b"matroska", &info_children(), true),
        );
    }
}
