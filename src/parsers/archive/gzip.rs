//! gzip member header: the optional FNAME (original file name) and FCOMMENT
//! fields, plus the MTIME stamp folded into their notes.

use crate::model::{
    Category, Confidence, ContainerKind, Evidence, Finding, JunkKind, Marker, Region,
    RemovalStrategy, Severity,
};
use crate::scan::FileView;
use crate::util::bytes::{cstr, u16_le, u32_le};

use crate::parsers::image::shared::{
    NOTE_CHARS, TITLE_CHARS, clip, crc32, excerpt, finding, is_blank, latin1, unix_time,
};

const FHCRC: u8 = 0x02;
const FEXTRA: u8 = 0x04;
const FNAME: u8 = 0x08;
const FCOMMENT: u8 = 0x10;
const RESERVED: u8 = 0xE0;

/// A NUL-terminated header string: offset of its first byte and its bytes.
fn field(h: &[u8], pos: usize) -> Option<(usize, &[u8])> {
    let s = cstr(h, pos, h.len())?;
    // The terminator must be inside the window, or the field is cut short.
    (h.get(pos + s.len()) == Some(&0)).then_some((pos, s))
}

pub(super) fn run(view: &dyn FileView, out: &mut Vec<Finding>) {
    let h = view.header();
    if h.len() < 10 || h[0] != 0x1F || h[1] != 0x8B || h[2] != 8 {
        return;
    }
    let flg = h[3];
    if flg & RESERVED != 0 {
        return;
    }
    let Some(mtime) = u32_le(h, 4) else {
        return;
    };
    let mut pos = 10usize;
    if flg & FEXTRA != 0 {
        let Some(xlen) = u16_le(h, pos) else {
            return;
        };
        pos += 2 + xlen as usize;
    }
    let mut fields = Vec::new();
    for (flag, sig) in [(FNAME, "gzip.fname"), (FCOMMENT, "gzip.fcomment")] {
        if flg & flag == 0 {
            continue;
        }
        let Some((at, s)) = field(h, pos) else {
            return;
        };
        fields.push((sig, at, s));
        pos = at + s.len() + 1;
    }
    let hcrc = flg & FHCRC != 0;
    if hcrc {
        // The header CRC is the low half of a CRC-32 over everything before it.
        let ok = u16_le(h, pos).is_some_and(|c| c == (crc32(&h[..pos]) & 0xFFFF) as u16);
        if !ok {
            return;
        }
    }
    let mut stamp = (mtime != 0).then(|| format!("; header MTIME {}", unix_time(mtime as u64)));
    for (sig, at, s) in fields {
        if is_blank(s) {
            continue;
        }
        let text = latin1(s);
        let (title, what) = if sig == "gzip.fname" {
            ("gzip original file name", "FNAME")
        } else {
            ("gzip comment", "FCOMMENT")
        };
        let mut note = format!("{what} field: \"{}\"", clip(&text, NOTE_CHARS));
        if let Some(st) = stamp.take() {
            note.push_str(&st);
        }
        let marker = if hcrc {
            note.push_str("; the header CRC (FHCRC) covers it, so it is not blanked in place");
            None
        } else {
            Some(Marker {
                region: Region::new(at as u64, s.len() as u64),
                removal: RemovalStrategy::RawBlank { fill: b' ' },
                container: ContainerKind::GzipHeader,
                reversible: true,
            })
        };
        out.push(finding(
            sig,
            Category::Junk(JunkKind::Comment),
            Confidence::Moderate,
            Severity::Notice,
            format!("{title} \"{}\"", clip(&text, TITLE_CHARS)),
            Evidence::at(at as u64)
                .with_bytes(excerpt(s))
                .with_note(note),
            marker,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::archive::probes;
    use crate::parsers::image::shared::testkit::{apply, garbage, run, with_id};

    pub fn build(flags: u8, mtime: u32, name: &[u8], comment: &[u8]) -> Vec<u8> {
        let mut v = vec![0x1F, 0x8B, 8, flags];
        v.extend_from_slice(&mtime.to_le_bytes());
        v.extend_from_slice(&[0, 3]);
        if flags & FEXTRA != 0 {
            v.extend_from_slice(&[4, 0, b'A', b'B', 0, 0]);
        }
        if flags & FNAME != 0 {
            v.extend_from_slice(name);
            v.push(0);
        }
        if flags & FCOMMENT != 0 {
            v.extend_from_slice(comment);
            v.push(0);
        }
        if flags & FHCRC != 0 {
            let c = (crc32(&v) & 0xFFFF) as u16;
            v.extend_from_slice(&c.to_le_bytes());
        }
        // An empty deflate stream and the CRC/ISIZE trailer.
        v.extend_from_slice(&[0x03, 0x00, 0, 0, 0, 0, 0, 0, 0, 0]);
        v
    }

    fn scan(data: &[u8]) -> Vec<Finding> {
        run(probes(), "x.tar.gz", data, "gzip")
    }

    #[test]
    fn fname_and_fcomment_are_found_and_blanked() {
        let data = build(
            FNAME | FCOMMENT | FEXTRA,
            1_700_000_000,
            b"backup.tar",
            b"nightly",
        );
        let fs = scan(&data);
        assert_eq!(fs.len(), 2);
        let n = with_id(&fs, "gzip.fname")[0];
        assert_eq!(n.title, "gzip original file name \"backup.tar\"");
        assert!(
            n.evidence
                .note
                .as_deref()
                .unwrap()
                .contains("2023-11-14 22:13:20 UTC")
        );
        let c = with_id(&fs, "gzip.fcomment")[0];
        assert!(!c.evidence.note.as_deref().unwrap().contains("MTIME"));
        assert_eq!(&data[c.evidence.offset as usize..][..7], b"nightly");
        let mut cur = data.clone();
        for f in &fs {
            assert_eq!(
                f.marker.as_ref().unwrap().container,
                ContainerKind::GzipHeader
            );
            cur = apply(&cur, f);
        }
        assert_eq!(cur.len(), data.len());
        assert!(scan(&cur).is_empty());
        // Still a well-formed header: both strings remain, now spaces.
        assert_eq!(&cur[16..27], b"          \0");
    }

    #[test]
    fn header_crc_keeps_the_marker_off() {
        let data = build(FNAME | FHCRC, 0, b"a.txt", b"");
        let fs = scan(&data);
        assert_eq!(fs.len(), 1);
        assert!(fs[0].marker.is_none());
        let mut bad = data.clone();
        bad[11] ^= 1;
        assert!(scan(&bad).is_empty());
    }

    #[test]
    fn no_string_field_no_finding() {
        assert!(scan(&build(0, 1_700_000_000, b"", b"")).is_empty());
        assert!(scan(&build(FNAME, 5, b"", b"")).is_empty());
    }

    #[test]
    fn garbage_and_truncation_are_safe() {
        let data = build(FNAME | FCOMMENT, 1, b"name", b"comment");
        for cut in 0..data.len() {
            let _ = scan(&data[..cut]);
        }
        for seed in 0..32 {
            assert!(scan(&garbage(seed, 512)).is_empty());
        }
        let mut g = vec![0x1F, 0x8B, 8, FNAME];
        g.extend(std::iter::repeat_n(b'a', 100));
        assert!(scan(&g).is_empty());
    }
}
