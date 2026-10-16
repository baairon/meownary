//! Single-stream compressors: xz, zstd and bzip2. Each yields one
//! `<fmt>.info` brand finding with the facts its header states.

use crate::model::{BrandKind, Category, Confidence, Evidence, Finding, Severity};
use crate::scan::FileView;
use crate::util::bytes::{slice, u32_le};

use crate::parsers::image::shared::{crc32, excerpt, finding};

fn info(sig: &str, title: String, header: &[u8], note: String) -> Finding {
    finding(
        sig,
        Category::Brand(BrandKind::Toolchain),
        Confidence::Moderate,
        Severity::Info,
        title,
        Evidence::at(0).with_bytes(excerpt(header)).with_note(note),
        None,
    )
}

/// xz: stream flags (check type), verified by the header CRC; and whether the
/// stream footer closes the file.
pub(super) fn xz(view: &dyn FileView, out: &mut Vec<Finding>) {
    let h = view.header();
    let Some(head) = slice(h, 0, 12) else {
        return;
    };
    if &head[..6] != b"\xfd7zXZ\0" || head[6] != 0 || head[7] & 0xF0 != 0 {
        return;
    }
    if u32_le(head, 8) != Some(crc32(&head[6..8])) {
        return;
    }
    let check = match head[7] {
        0 => "no integrity check",
        1 => "CRC32 check",
        4 => "CRC64 check",
        10 => "SHA-256 check",
        _ => "a reserved check type",
    };
    let tail = view.tail();
    let footer =
        tail.len() >= 12 && tail.ends_with(b"YZ") && tail[tail.len() - 4..][..2] == head[6..8];
    let mut note = format!("stream flags declare {check}");
    note.push_str(if footer {
        "; the stream footer closes the file"
    } else {
        "; no matching stream footer at the end (truncated, padded, or multi-stream)"
    });
    out.push(info("xz.info", format!("xz stream ({check})"), head, note));
}

/// zstd: the first frame header (content size, dictionary id, checksum flag).
pub(super) fn zstd(view: &dyn FileView, out: &mut Vec<Finding>) {
    let h = view.header();
    if slice(h, 0, 4) != Some(&[0x28, 0xB5, 0x2F, 0xFD][..]) {
        return;
    }
    let Some(&fhd) = h.get(4) else {
        return;
    };
    if fhd & 0x08 != 0 {
        return;
    }
    let single = fhd & 0x20 != 0;
    let checksum = fhd & 0x04 != 0;
    let mut pos = 5usize;
    let mut window = None;
    if !single {
        let Some(&w) = h.get(pos) else {
            return;
        };
        let exp = (w >> 3) as u32 + 10;
        let base = 1u64 << exp;
        window = Some(base + (base / 8) * (w & 7) as u64);
        pos += 1;
    }
    let did_len = [0usize, 1, 2, 4][(fhd & 3) as usize];
    let Some(did) = slice(h, pos, did_len).map(le) else {
        return;
    };
    pos += did_len;
    let fcs_len = match fhd >> 6 {
        0 if single => 1,
        0 => 0,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    let Some(fcs) = slice(h, pos, fcs_len).map(le) else {
        return;
    };
    let fcs = if fcs_len == 2 { fcs + 256 } else { fcs };
    let mut parts = Vec::new();
    if fcs_len > 0 {
        parts.push(format!("content size {fcs} bytes"));
    } else {
        parts.push("content size not stated".to_string());
    }
    if let Some(w) = window {
        parts.push(format!("window {w} bytes"));
    }
    parts.push(if did_len > 0 && did != 0 {
        format!("dictionary id {did}")
    } else {
        "no dictionary".to_string()
    });
    parts.push(
        if checksum {
            "content checksum"
        } else {
            "no content checksum"
        }
        .to_string(),
    );
    out.push(info(
        "zstd.info",
        "zstd frame".to_string(),
        &h[..pos.min(h.len())],
        parts.join(", "),
    ));
}

fn le(b: &[u8]) -> u64 {
    b.iter().rev().fold(0u64, |acc, &x| (acc << 8) | x as u64)
}

/// bzip2: the block size digit, confirmed by the first block or end magic.
pub(super) fn bzip2(view: &dyn FileView, out: &mut Vec<Finding>) {
    let h = view.header();
    let Some(head) = slice(h, 0, 10) else {
        return;
    };
    if &head[..3] != b"BZh" || !(b'1'..=b'9').contains(&head[3]) {
        return;
    }
    let first = &head[4..10];
    let what = match first {
        [0x31, 0x41, 0x59, 0x26, 0x53, 0x59] => "the first compressed block follows",
        [0x17, 0x72, 0x45, 0x38, 0x50, 0x90] => "an empty stream",
        _ => return,
    };
    let level = head[3] - b'0';
    out.push(info(
        "bzip2.info",
        format!("bzip2 stream ({level}00k blocks)"),
        head,
        format!("block size {level}00 kB; {what}"),
    ));
}

#[cfg(test)]
mod tests {
    use crate::parsers::archive::probes;
    use crate::parsers::image::shared::crc32;
    use crate::parsers::image::shared::testkit::{garbage, run};

    fn xz_bytes(check: u8) -> Vec<u8> {
        let mut v = b"\xfd7zXZ\0\0".to_vec();
        v.push(check);
        v.extend_from_slice(&crc32(&[0, check]).to_le_bytes());
        v.extend_from_slice(&[0u8; 8]);
        v.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, check, b'Y', b'Z']);
        v
    }

    #[test]
    fn xz_check_type() {
        let fs = run(probes(), "a.xz", &xz_bytes(4), "xz");
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].title, "xz stream (CRC64 check)");
        assert!(
            fs[0]
                .evidence
                .note
                .as_deref()
                .unwrap()
                .contains("footer closes")
        );
        let mut bad = xz_bytes(4);
        bad[8] ^= 1;
        assert!(run(probes(), "a.xz", &bad, "xz").is_empty());
    }

    #[test]
    fn zstd_frame_facts() {
        // Single segment, 2-byte content size, 1-byte dictionary id, checksum.
        let data = [0x28, 0xB5, 0x2F, 0xFD, 0x65, 0x07, 0x00, 0x01, 0, 0, 0];
        let fs = run(probes(), "a.zst", &data, "zstd");
        let note = fs[0].evidence.note.clone().unwrap();
        assert_eq!(
            note,
            "content size 512 bytes, dictionary id 7, content checksum"
        );
        let windowed = [0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x50, 1, 2, 3];
        let fs = run(probes(), "a.zst", &windowed, "zstd");
        assert!(
            fs[0]
                .evidence
                .note
                .as_deref()
                .unwrap()
                .contains("window 1048576 bytes")
        );
        assert!(run(probes(), "a.zst", &[0x28, 0xB5, 0x2F, 0xFD, 0x08], "zstd").is_empty());
    }

    #[test]
    fn bzip2_block_size() {
        let fs = run(probes(), "a.bz2", b"BZh91AY&SY\0\0", "bzip2");
        assert_eq!(fs[0].title, "bzip2 stream (900k blocks)");
        assert!(run(probes(), "a.bz2", b"BZh01AY&SY", "bzip2").is_empty());
        assert!(run(probes(), "a.bz2", b"BZh9xxxxxx", "bzip2").is_empty());
    }

    #[test]
    fn garbage_is_quiet() {
        for fmt in ["xz", "zstd", "bzip2"] {
            for seed in 0..16 {
                assert!(run(probes(), "g", &garbage(seed, 64), fmt).is_empty());
            }
            for n in 0..6 {
                assert!(run(probes(), "g", &[0u8; 6][..n], fmt).is_empty());
            }
        }
    }
}
