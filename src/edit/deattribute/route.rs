//! Which archive handler a file goes to, and how many files an archive holds.
//! A plain zip, a tar, and a gzip whose payload is a tar are handled through
//! their contents; everything else keeps the per-file path.

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use miniz_oxide::inflate::decompress_to_vec_with_limit;

use crate::util::bytes::u16_le;

use super::zip::zip_file_count;

/// Archives deattributed through the files inside them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveKind {
    /// A plain `.zip` (not a jar, apk or office document).
    Zip,
    /// A `.tar`.
    Tar,
    /// A gzip whose payload is a tar.
    TarGz,
}

/// How an identified file is handled: `Some` for an archive that is cleaned
/// through its contents, `None` for the per-file path. `format` is the scan's
/// identity label, so a docx, jar or apk (all zip containers) is not an archive
/// here, and a gzip counts only when its payload is a tar.
pub fn archive_kind(path: &Path, format: Option<&str>) -> Option<ArchiveKind> {
    match format? {
        "zip" => Some(ArchiveKind::Zip),
        "tar" => Some(ArchiveKind::Tar),
        "gzip" if gzip_holds_tar(path) => Some(ArchiveKind::TarGz),
        _ => None,
    }
}

/// How many files (not folders or tar bookkeeping) the archive holds, or `None`
/// when it cannot be read. Called only to word the saved line.
pub fn archive_file_count(original: &Path, kind: ArchiveKind) -> Option<usize> {
    match kind {
        ArchiveKind::Zip => zip_file_count(original),
        ArchiveKind::Tar => {
            let mut file = File::open(original).ok()?;
            let len = file.metadata().ok()?.len();
            Some(count_tar(&mut file, len))
        }
        ArchiveKind::TarGz => {
            let data = fs::read(original).ok()?;
            let body = data.get(gzip_body_start(&data)?..)?;
            let tar = inflate(body, MAX_COUNT)?;
            let len = tar.len() as u64;
            Some(count_tar(&mut std::io::Cursor::new(tar), len))
        }
    }
}

/// Most uncompressed bytes read to count a tar.gz.
const MAX_COUNT: usize = 1024 * 1024 * 1024;

/// Where the deflate stream starts, after the gzip header and its optional
/// fields.
fn gzip_body_start(h: &[u8]) -> Option<usize> {
    if h.len() < 10 || h[..3] != [0x1f, 0x8b, 8] {
        return None;
    }
    let flags = h[3];
    let mut pos = 10usize;
    if flags & 4 != 0 {
        pos = pos.checked_add(2 + usize::from(u16_le(h, pos)?))?;
    }
    for bit in [8, 16] {
        if flags & bit != 0 {
            pos += h.get(pos..)?.iter().position(|&b| b == 0)? + 1;
        }
    }
    if flags & 2 != 0 {
        pos += 2;
    }
    (pos <= h.len()).then_some(pos)
}

/// The decompressed bytes of a raw deflate stream, up to `limit`; whatever was
/// produced before a limit or a truncated input is kept when `partial`.
fn inflate(body: &[u8], limit: usize) -> Option<Vec<u8>> {
    decompress_to_vec_with_limit(body, limit).ok()
}

/// Whether the file is a gzip whose first 512 decompressed bytes are a tar
/// header.
fn gzip_holds_tar(path: &Path) -> bool {
    let mut head = Vec::new();
    let Ok(file) = File::open(path) else {
        return false;
    };
    if file.take(64 * 1024).read_to_end(&mut head).is_err() {
        return false;
    }
    let Some(body) = gzip_body_start(&head).and_then(|at| head.get(at..)) else {
        return false;
    };
    let first = match decompress_to_vec_with_limit(body, 512) {
        Ok(out) => out,
        Err(e) => e.output,
    };
    first.get(257..262) == Some(b"ustar".as_slice())
}

/// An octal header field, or a base-256 one when the top bit is set.
fn number(field: &[u8]) -> Option<u64> {
    if field.first().is_some_and(|b| b & 0x80 != 0) {
        let mut n = u64::from(field[0] & 0x7f);
        for &b in &field[1..] {
            n = n.checked_mul(256)?.checked_add(u64::from(b))?;
        }
        return Some(n);
    }
    let text: Vec<u8> = field
        .iter()
        .copied()
        .skip_while(|&b| b == b' ')
        .take_while(|b| (b'0'..=b'7').contains(b))
        .collect();
    if text.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(std::str::from_utf8(&text).ok()?, 8).ok()
}

/// Count the regular files by walking tar headers, stopping at the end marker
/// or the first header that does not check out.
fn count_tar<R: Read + Seek>(src: &mut R, len: u64) -> usize {
    let mut count = 0;
    let mut pos = 0u64;
    let mut header = [0u8; 512];
    while pos + 512 <= len {
        if src.seek(SeekFrom::Start(pos)).is_err() || src.read_exact(&mut header).is_err() {
            break;
        }
        if header.iter().all(|&b| b == 0) {
            break;
        }
        let sum: u64 = header
            .iter()
            .enumerate()
            .map(|(i, &b)| u64::from(if (148..156).contains(&i) { b' ' } else { b }))
            .sum();
        if number(&header[148..156]) != Some(sum) {
            break;
        }
        if matches!(header[156], b'0' | 0 | b'7') {
            count += 1;
        }
        let Some(size) = number(&header[124..136]) else {
            break;
        };
        pos = match size
            .checked_add(511)
            .and_then(|s| (s / 512).checked_mul(512))
            .and_then(|s| pos.checked_add(512)?.checked_add(s))
        {
            Some(next) => next,
            None => break,
        };
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use miniz_oxide::deflate::compress_to_vec;

    /// A ustar header for a regular file called `name` of `size` bytes.
    fn header(name: &str, size: usize, flag: u8) -> [u8; 512] {
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..107].copy_from_slice(b"0000644");
        h[124..135].copy_from_slice(format!("{size:011o}").as_bytes());
        h[156] = flag;
        h[257..262].copy_from_slice(b"ustar");
        let sum: u32 = h
            .iter()
            .enumerate()
            .map(|(i, &b)| u32::from(if (148..156).contains(&i) { b' ' } else { b }))
            .sum();
        h[148..155].copy_from_slice(format!("{sum:07o}\0").as_bytes()[..7].as_ref());
        h[155] = b' ';
        h
    }

    pub(super) fn tar_of(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, data) in files {
            out.extend_from_slice(&header(name, data.len(), b'0'));
            out.extend_from_slice(data);
            out.resize(out.len().next_multiple_of(512), 0);
        }
        out.extend_from_slice(&[0; 1024]);
        out
    }

    fn gzip_of(tar: &[u8], name: Option<&str>) -> Vec<u8> {
        let mut out = vec![
            0x1f,
            0x8b,
            8,
            if name.is_some() { 8 } else { 0 },
            0,
            0,
            0,
            0,
            0,
            3,
        ];
        if let Some(name) = name {
            out.extend_from_slice(name.as_bytes());
            out.push(0);
        }
        out.extend_from_slice(&compress_to_vec(tar, 6));
        out.extend_from_slice(&[0; 8]);
        out
    }

    #[test]
    fn tar_and_tar_gz_files_are_counted_and_routed() {
        let dir = tempfile::tempdir().unwrap();
        let tar = tar_of(&[
            ("a.txt", b"hello"),
            ("b/c.txt", b""),
            ("d.txt", &[7u8; 700]),
        ]);
        let plain = dir.path().join("x.tar");
        fs::write(&plain, &tar).unwrap();
        assert_eq!(archive_file_count(&plain, ArchiveKind::Tar), Some(3));
        assert_eq!(archive_kind(&plain, Some("tar")), Some(ArchiveKind::Tar));

        let gz = dir.path().join("x.tar.gz");
        fs::write(&gz, gzip_of(&tar, Some("x.tar"))).unwrap();
        assert_eq!(archive_kind(&gz, Some("gzip")), Some(ArchiveKind::TarGz));
        assert_eq!(archive_file_count(&gz, ArchiveKind::TarGz), Some(3));
    }

    #[test]
    fn a_gzip_of_something_else_is_not_an_archive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notes.txt.gz");
        fs::write(&path, gzip_of(&[b'x'; 2000], None)).unwrap();
        assert_eq!(archive_kind(&path, Some("gzip")), None);
        assert_eq!(archive_kind(&path, Some("jar")), None);
        assert_eq!(archive_kind(&path, Some("ooxml")), None);
        assert_eq!(archive_kind(&path, None), None);
        assert_eq!(archive_kind(&path, Some("zip")), Some(ArchiveKind::Zip));
    }
}
