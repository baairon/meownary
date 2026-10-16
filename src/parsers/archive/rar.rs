//! RAR archives, both the 1.5 to 4.x block format and RAR 5.0: the archive
//! comment (a RAR4 comment block or `CMT` sub-block, or a RAR5 `CMT` service
//! header), header and file encryption, and the archive flags.

use crate::model::{
    BrandKind, Category, Confidence, ContainerKind, DeceptionKind, Evidence, Finding, JunkKind,
    Marker, Region, RemovalStrategy, Severity,
};
use crate::scan::FileView;
use crate::util::bytes::{slice, u16_le, u32_le};

use crate::parsers::image::shared::{
    NOTE_CHARS, TITLE_CHARS, crc32, excerpt, fetch, finding, is_blank, pw_in_name, quote,
};

const SIG4: &[u8] = b"Rar!\x1a\x07\x00";
const SIG5: &[u8] = b"Rar!\x1a\x07\x01\x00";
/// Most blocks walked.
const MAX_BLOCKS: usize = 64;
/// Largest RAR5 header accepted (the format caps it at 2 MiB).
const MAX_HEADER5: u64 = 2 * 1024 * 1024;
/// Most comment bytes read to quote and blank-check.
const MAX_COMMENT: u64 = 64 * 1024;

/// What a walk learned.
#[derive(Debug, Default)]
struct Rar {
    version: &'static str,
    /// Offset of the main archive header.
    main_off: Option<u64>,
    flags: Vec<&'static str>,
    headers_encrypted: Option<u64>,
    /// Offset of the first file header whose data is encrypted.
    file_encrypted: Option<u64>,
    files: usize,
    unpack_ver: Option<u8>,
    comment: Option<Comment>,
}

#[derive(Debug, Clone, Copy)]
struct Comment {
    /// Absolute offset and length of the comment data.
    off: u64,
    len: u64,
    stored: bool,
}

pub(super) fn run(view: &dyn FileView, out: &mut Vec<Finding>) {
    let Some(head) = fetch(view, 0, 8) else {
        return;
    };
    let rar = if head.starts_with(SIG5) {
        walk5(view)
    } else if head.starts_with(SIG4) {
        walk4(view)
    } else {
        return;
    };
    let Some(main_off) = rar.main_off else {
        return;
    };
    if let Some(c) = rar.comment {
        comment_finding(view, c, out);
    }
    let pw = pw_in_name(view);
    if let (Some(off), Some(name)) = (rar.headers_encrypted, pw.as_ref()) {
        out.push(pw_finding(
            "rar.encrypted_headers",
            off,
            &format!(
                "the archive headers are encrypted, hiding even the file names, and the file \
                 name \"{}\" appears to carry the password",
                quote(name.as_bytes(), NOTE_CHARS)
            ),
        ));
    } else if let (Some(off), Some(name)) = (rar.file_encrypted, pw.as_ref()) {
        out.push(pw_finding(
            "rar.encrypted",
            off,
            &format!(
                "file data is encrypted and the file name \"{}\" appears to carry the password",
                quote(name.as_bytes(), NOTE_CHARS)
            ),
        ));
    }
    let mut note = format!("RAR {} format", rar.version);
    if let Some(v) = rar.unpack_ver {
        note.push_str(&format!(
            ", version {}.{} needed to extract",
            v / 10,
            v % 10
        ));
    }
    if rar.files > 0 {
        note.push_str(&format!(", {} file headers read", rar.files));
    }
    let mut flags = rar.flags.clone();
    if rar.headers_encrypted.is_some() {
        flags.push("encrypted headers");
    } else if rar.file_encrypted.is_some() {
        flags.push("encrypted file data");
    }
    if !flags.is_empty() {
        note.push_str(&format!("; {}", flags.join(", ")));
    }
    out.push(finding(
        "rar.info",
        Category::Brand(BrandKind::Toolchain),
        Confidence::Moderate,
        Severity::Info,
        format!("RAR {} archive", rar.version),
        Evidence::at(main_off).with_note(note),
        None,
    ));
}

fn pw_finding(sig: &str, off: u64, note: &str) -> Finding {
    finding(
        sig,
        Category::Deception(DeceptionKind::PwInFilename),
        Confidence::Strong,
        Severity::Warn,
        "Encrypted RAR with a password in its file name",
        Evidence::at(off).with_note(note),
        None,
    )
}

fn comment_finding(view: &dyn FileView, c: Comment, out: &mut Vec<Finding>) {
    if c.len == 0 {
        return;
    }
    let shown = fetch(view, c.off, c.len.min(MAX_COMMENT) as usize).unwrap_or_default();
    let (title, note, marker) = if c.stored {
        if is_blank(&shown) {
            return;
        }
        (
            format!("RAR comment \"{}\"", quote(&shown, TITLE_CHARS)),
            format!("stored comment: \"{}\"", quote(&shown, NOTE_CHARS)),
            (c.len <= MAX_COMMENT).then_some(Marker {
                region: Region::new(c.off, c.len),
                removal: RemovalStrategy::RawBlank { fill: b' ' },
                container: ContainerKind::RarBlock,
                reversible: true,
            }),
        )
    } else {
        (
            "RAR comment (compressed)".to_string(),
            format!(
                "{} bytes of compressed comment data; it cannot be blanked in place",
                c.len
            ),
            None,
        )
    };
    out.push(finding(
        "rar.comment",
        Category::Junk(JunkKind::ArchiveComment),
        Confidence::Strong,
        Severity::Notice,
        title,
        Evidence::at(c.off)
            .with_bytes(excerpt(&shown))
            .with_note(note),
        marker,
    ));
}

/// Walk RAR 1.5 to 4.x blocks from offset 7.
fn walk4(view: &dyn FileView) -> Rar {
    let mut rar = Rar {
        version: "1.5-4.x",
        ..Rar::default()
    };
    let size = view.size();
    let mut pos = SIG4.len() as u64;
    for _ in 0..MAX_BLOCKS {
        let Some(h) = fetch(view, pos, 7) else {
            break;
        };
        let ty = h[2];
        let flags = u16_le(&h, 3).unwrap_or(0);
        let hsize = u16_le(&h, 5).unwrap_or(0) as u64;
        if hsize < 7 || pos + hsize > size {
            break;
        }
        let Some(block) = fetch(view, pos, hsize as usize) else {
            break;
        };
        let add = if flags & 0x8000 != 0 {
            u32_le(&block, 7).unwrap_or(0) as u64
        } else {
            0
        };
        match ty {
            0x73 => {
                if rar.main_off.is_some() {
                    break;
                }
                rar.main_off = Some(pos);
                for (bit, label) in [
                    (0x0001, "multi-volume"),
                    (0x0004, "locked"),
                    (0x0008, "solid"),
                    (0x0040, "recovery record"),
                ] {
                    if flags & bit != 0 {
                        rar.flags.push(label);
                    }
                }
                if flags & 0x0002 != 0 && hsize >= 13 + 13 {
                    rar.comment = comment_block4(&block, 13, pos);
                }
                if flags & 0x0080 != 0 {
                    rar.headers_encrypted = Some(pos);
                    break;
                }
            }
            0x75 if rar.comment.is_none() => rar.comment = comment_block4(&block, 0, pos),
            0x74 | 0x7A => {
                let name_size = u16_le(&block, 26).unwrap_or(0) as usize;
                let name_at = if flags & 0x0100 != 0 { 40 } else { 32 };
                let name = slice(&block, name_at, name_size).unwrap_or_default();
                if ty == 0x74 {
                    rar.files += 1;
                    if rar.unpack_ver.is_none() {
                        rar.unpack_ver = block.get(24).copied();
                    }
                    if flags & 0x0004 != 0 && rar.file_encrypted.is_none() {
                        rar.file_encrypted = Some(pos);
                    }
                } else if name == b"CMT" && rar.comment.is_none() {
                    rar.comment = Some(Comment {
                        off: pos + hsize,
                        len: add.min(size.saturating_sub(pos + hsize)),
                        stored: block.get(25) == Some(&0x30) && flags & 0x0004 == 0,
                    });
                }
            }
            0x7B => break,
            _ => {}
        }
        if rar.main_off.is_none() && ty != 0x72 {
            break;
        }
        pos += hsize + add;
    }
    rar
}

/// An old-style comment block (`0x75`) at `at` inside `block` (whose file
/// offset is `base`).
fn comment_block4(block: &[u8], at: usize, base: u64) -> Option<Comment> {
    if *block.get(at + 2)? != 0x75 {
        return None;
    }
    let size = u16_le(block, at + 5)? as usize;
    if size < 13 || at + size > block.len() {
        return None;
    }
    Some(Comment {
        off: base + at as u64 + 13,
        len: (size - 13) as u64,
        stored: *block.get(at + 10)? == 0x30,
    })
}

/// A RAR5 variable-length integer at `pos`: the value and its byte length.
fn vint(buf: &[u8], pos: usize) -> Option<(u64, usize)> {
    let mut v = 0u64;
    for i in 0..10 {
        let b = *buf.get(pos + i)?;
        v |= ((b & 0x7F) as u64) << (7 * i);
        if b & 0x80 == 0 {
            return Some((v, i + 1));
        }
    }
    None
}

/// A cursor over one RAR5 header.
struct Cur<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl Cur<'_> {
    fn vint(&mut self) -> Option<u64> {
        let (v, n) = vint(self.buf, self.pos)?;
        self.pos += n;
        Some(v)
    }

    fn skip(&mut self, n: usize) -> Option<()> {
        self.pos = self.pos.checked_add(n)?;
        (self.pos <= self.buf.len()).then_some(())
    }
}

/// Walk RAR 5.0 headers from offset 8, verifying each header CRC.
fn walk5(view: &dyn FileView) -> Rar {
    let mut rar = Rar {
        version: "5.0",
        ..Rar::default()
    };
    let size = view.size();
    let mut pos = SIG5.len() as u64;
    for _ in 0..MAX_BLOCKS {
        let Some(pre) = view.read_at(pos, 16).ok().filter(|b| b.len() >= 5) else {
            break;
        };
        let Some((hsize, vlen)) = vint(&pre, 4) else {
            break;
        };
        let total = 4 + vlen as u64 + hsize;
        if hsize == 0 || hsize > MAX_HEADER5 || pos + total > size {
            break;
        }
        let Some(block) = fetch(view, pos, total as usize) else {
            break;
        };
        if u32_le(&block, 0) != Some(crc32(&block[4..])) {
            break;
        }
        let Some(info) = header5(&block, 4 + vlen) else {
            break;
        };
        let data_off = pos + total;
        match info.ty {
            1 => {
                rar.main_off = Some(pos);
                for (bit, label) in [
                    (0x0001, "multi-volume"),
                    (0x0004, "solid"),
                    (0x0008, "recovery record"),
                    (0x0010, "locked"),
                ] {
                    if info.archive_flags & bit != 0 {
                        rar.flags.push(label);
                    }
                }
            }
            2 => {
                rar.files += 1;
                if info.encrypted && rar.file_encrypted.is_none() {
                    rar.file_encrypted = Some(pos);
                }
            }
            3 if info.name == b"CMT" && rar.comment.is_none() => {
                rar.comment = Some(Comment {
                    off: data_off,
                    len: info.data_size.min(size.saturating_sub(data_off)),
                    stored: info.method == 0 && !info.encrypted,
                });
            }
            4 => {
                // An archive encryption header: everything after it is ciphertext.
                if rar.main_off.is_none() {
                    rar.main_off = Some(pos);
                }
                rar.headers_encrypted = Some(pos);
                break;
            }
            5 => break,
            _ => {}
        }
        if rar.main_off.is_none() {
            break;
        }
        pos = data_off.saturating_add(info.data_size);
    }
    rar
}

#[derive(Debug, Default)]
struct Header5 {
    ty: u64,
    data_size: u64,
    archive_flags: u64,
    name: Vec<u8>,
    method: u64,
    encrypted: bool,
}

/// Parse the common and type-specific fields of a RAR5 header whose type
/// field starts at `start` in `block`.
fn header5(block: &[u8], start: usize) -> Option<Header5> {
    let mut c = Cur {
        buf: block,
        pos: start,
    };
    let mut h = Header5 {
        ty: c.vint()?,
        ..Header5::default()
    };
    let flags = c.vint()?;
    let extra = if flags & 1 != 0 { c.vint()? } else { 0 };
    if flags & 2 != 0 {
        h.data_size = c.vint()?;
    }
    match h.ty {
        1 => h.archive_flags = c.vint()?,
        2 | 3 => {
            let file_flags = c.vint()?;
            c.vint()?;
            c.vint()?;
            if file_flags & 2 != 0 {
                c.skip(4)?;
            }
            if file_flags & 4 != 0 {
                c.skip(4)?;
            }
            let comp = c.vint()?;
            h.method = (comp >> 7) & 7;
            c.vint()?;
            let name_len = c.vint()? as usize;
            h.name = slice(block, c.pos, name_len)?.to_vec();
            c.skip(name_len)?;
            // The extra area closes the header; record type 1 is encryption.
            let extra_start = block.len().checked_sub(extra as usize)?;
            let mut x = Cur {
                buf: block,
                pos: extra_start,
            };
            while x.pos < block.len() {
                let Some(rec_size) = x.vint() else {
                    break;
                };
                let rec_at = x.pos;
                if x.vint() == Some(1) {
                    h.encrypted = true;
                }
                x.pos = rec_at;
                if x.skip(rec_size as usize).is_none() {
                    break;
                }
            }
        }
        _ => {}
    }
    Some(h)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::parsers::archive::probes;
    use crate::parsers::image::shared::testkit::{apply, garbage, run, with_id};

    fn v(mut n: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let b = (n & 0x7F) as u8;
            n >>= 7;
            if n == 0 {
                out.push(b);
                return out;
            }
            out.push(b | 0x80);
        }
    }

    /// A RAR5 header block from its fields after the size vint.
    fn block5(fields: &[u8], data: &[u8]) -> Vec<u8> {
        let mut body = v(fields.len() as u64);
        body.extend_from_slice(fields);
        let mut out = crc32(&body).to_le_bytes().to_vec();
        out.extend(body);
        out.extend_from_slice(data);
        out
    }

    fn service5(name: &[u8], data: &[u8], method: u64) -> Vec<u8> {
        let mut f = v(3);
        f.extend(v(2));
        f.extend(v(data.len() as u64));
        f.extend(v(0));
        f.extend(v(data.len() as u64));
        f.extend(v(0));
        f.extend(v(method << 7));
        f.extend(v(0));
        f.extend(v(name.len() as u64));
        f.extend_from_slice(name);
        block5(&f, data)
    }

    pub fn build5(comment: Option<&[u8]>, encrypt_headers: bool) -> Vec<u8> {
        let mut out = SIG5.to_vec();
        if encrypt_headers {
            out.extend(block5(&[4, 0, 0, 0, 0], &[]));
            out.extend_from_slice(&[0xAA; 32]);
            return out;
        }
        out.extend(block5(&[1, 0, 0x04], &[]));
        if let Some(c) = comment {
            out.extend(service5(b"CMT", c, 0));
        }
        let mut f = v(2);
        f.extend(v(2));
        f.extend(v(5));
        f.extend(v(0));
        f.extend(v(5));
        f.extend(v(0x20));
        f.extend(v(0));
        f.extend(v(0));
        f.extend(v(5));
        f.extend_from_slice(b"a.txt");
        out.extend(block5(&f, b"hello"));
        out.extend(block5(&[5, 0, 0], &[]));
        out
    }

    fn block4(ty: u8, flags: u16, fields: &[u8], data: &[u8]) -> Vec<u8> {
        let mut out = vec![0, 0, ty];
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&((7 + fields.len()) as u16).to_le_bytes());
        out.extend_from_slice(fields);
        out.extend_from_slice(data);
        out
    }

    fn sub4(name: &[u8], data: &[u8], method: u8) -> Vec<u8> {
        let mut f = (data.len() as u32).to_le_bytes().to_vec();
        f.extend_from_slice(&(data.len() as u32).to_le_bytes());
        f.extend_from_slice(&[2, 0, 0, 0, 0, 0, 0, 0, 0, 29, method]);
        f.extend_from_slice(&(name.len() as u16).to_le_bytes());
        f.extend_from_slice(&[0; 4]);
        f.extend_from_slice(name);
        block4(0x7A, 0x8000, &f, data)
    }

    pub fn build4(comment: Option<&[u8]>, main_flags: u16) -> Vec<u8> {
        let mut out = SIG4.to_vec();
        out.extend(block4(0x73, main_flags, &[0; 6], &[]));
        if let Some(c) = comment {
            out.extend(sub4(b"CMT", c, 0x30));
        }
        let mut f = 5u32.to_le_bytes().to_vec();
        f.extend_from_slice(&5u32.to_le_bytes());
        f.extend_from_slice(&[2, 0, 0, 0, 0, 0, 0, 0, 0, 29, 0x30]);
        f.extend_from_slice(&5u16.to_le_bytes());
        f.extend_from_slice(&[0x20, 0, 0, 0]);
        f.extend_from_slice(b"a.txt");
        out.extend(block4(0x74, 0x8000, &f, b"hello"));
        out.extend(block4(0x7B, 0x4000, &[], &[]));
        out
    }

    fn scan(name: &str, data: &[u8]) -> Vec<Finding> {
        run(probes(), name, data, "rar")
    }

    #[test]
    fn rar5_comment_found_and_blanked() {
        let data = build5(Some(b"Visit example.test for more"), false);
        let fs = scan("a.rar", &data);
        let c = with_id(&fs, "rar.comment");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].title, "RAR comment \"Visit example.test for more\"");
        let m = c[0].marker.as_ref().unwrap();
        assert_eq!(m.container, ContainerKind::RarBlock);
        let info = with_id(&fs, "rar.info")[0];
        assert_eq!(info.title, "RAR 5.0 archive");
        assert!(info.evidence.note.as_deref().unwrap().contains("solid"));
        let cleaned = apply(&data, c[0]);
        let again = scan("a.rar", &cleaned);
        assert!(with_id(&again, "rar.comment").is_empty());
        assert_eq!(with_id(&again, "rar.info").len(), 1);
    }

    #[test]
    fn rar4_comment_found_and_blanked() {
        let data = build4(Some(b"old style"), 0x0008);
        let fs = scan("a.rar", &data);
        let c = with_id(&fs, "rar.comment")[0];
        assert_eq!(&data[c.evidence.offset as usize..][..9], b"old style");
        let info = with_id(&fs, "rar.info")[0];
        let note = info.evidence.note.clone().unwrap();
        assert!(note.contains("version 2.9 needed") && note.contains("1 file headers"));
        let cleaned = apply(&data, c);
        assert!(with_id(&scan("a.rar", &cleaned), "rar.comment").is_empty());
    }

    #[test]
    fn encrypted_headers_with_password_name() {
        let data = build5(None, true);
        let fs = scan("movie_password_x9.rar", &data);
        let d = with_id(&fs, "rar.encrypted_headers");
        assert_eq!(d.len(), 1);
        assert_eq!(
            d[0].category,
            Category::Deception(DeceptionKind::PwInFilename)
        );
        let fs = scan("movie.rar", &data);
        assert!(with_id(&fs, "rar.encrypted_headers").is_empty());
        let note = with_id(&fs, "rar.info")[0].evidence.note.clone().unwrap();
        assert!(note.contains("encrypted headers"));

        let data4 = build4(None, 0x0080);
        let fs = scan("pw.rar", &data4);
        assert_eq!(with_id(&fs, "rar.encrypted_headers").len(), 1);
    }

    #[test]
    fn bad_crc_stops_the_walk() {
        let mut data = build5(Some(b"comment"), false);
        data[8] ^= 0xFF;
        assert!(scan("a.rar", &data).is_empty());
    }

    #[test]
    fn garbage_and_truncation_are_safe() {
        for data in [build5(Some(b"c5"), false), build4(Some(b"c4"), 0)] {
            for cut in 0..data.len() {
                let _ = scan("a.rar", &data[..cut]);
            }
        }
        for seed in 0..32 {
            assert!(scan("g.rar", &garbage(seed, 512)).is_empty());
            let mut g = SIG5.to_vec();
            g.extend(garbage(seed, 256));
            assert!(scan("g.rar", &g).is_empty());
        }
    }
}
