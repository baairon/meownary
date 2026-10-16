//! Which archive handler a file goes to, and how many files an archive holds.
//! A plain zip, a tar, and a gzip whose payload is a tar are handled through
//! their contents; everything else keeps the per-file path.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::path::Path;

use miniz_oxide::inflate::stream::{InflateState, inflate};
use miniz_oxide::{DataFormat, MZFlush, MZStatus};

use super::tar::{Seekable, Stream, header_ok, walk};
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

/// How many files (not folders, links or tar bookkeeping) the archive holds,
/// or `None` when it cannot be read. Called only to word the saved line. A
/// tar.gz is inflated as it is walked, so nothing but one header is ever held
/// in memory.
pub fn archive_file_count(original: &Path, kind: ArchiveKind) -> Option<usize> {
    match kind {
        ArchiveKind::Zip => zip_file_count(original),
        ArchiveKind::Tar => {
            let file = File::open(original).ok()?;
            let len = file.metadata().ok()?.len();
            count_tar(&mut Seekable::new(file, len).ok()?)
        }
        ArchiveKind::TarGz => {
            let file = File::open(original).ok()?;
            let gz = Gunzip::new(BufReader::with_capacity(64 * 1024, file), MAX_COUNT);
            count_tar(&mut Stream::new(gz))
        }
    }
}

/// Most uncompressed bytes walked to count a tar.gz.
const MAX_COUNT: u64 = 1024 * 1024 * 1024;

/// Count the files by walking tar headers, stopping at the end marker or the
/// first header that does not check out. `None` when the input is not a tar or
/// cannot be read.
fn count_tar<S: super::tar::Source>(src: &mut S) -> Option<usize> {
    let mut count = 0;
    walk(src, |entry, _| {
        if entry.is_file() {
            count += 1;
        }
        Ok(false)
    })
    .ok()??;
    Some(count)
}

/// Whether the file is a gzip whose first 512 decompressed bytes are a tar
/// header, ustar or the older V7 form, by its checksum.
fn gzip_holds_tar(path: &Path) -> bool {
    let Ok(file) = File::open(path) else {
        return false;
    };
    let mut gz = Gunzip::new(BufReader::new(file), 512);
    let mut first = [0u8; 512];
    let mut got = 0;
    while got < first.len() {
        match gz.read(&mut first[got..]) {
            Ok(0) | Err(_) => return false,
            Ok(n) => got += n,
        }
    }
    first.iter().any(|&b| b != 0) && header_ok(&first)
}

/// A gzip file inflated as it is read, every member in turn. Checksums are not
/// checked: this only counts and sniffs, and the cleaner checks them itself.
struct Gunzip<R> {
    src: R,
    state: Box<InflateState>,
    /// Inside a member's deflate stream, past its header.
    in_member: bool,
    done: bool,
    /// Bytes produced so far, and the most allowed.
    produced: u64,
    limit: u64,
}

impl<R: BufRead> Gunzip<R> {
    fn new(src: R, limit: u64) -> Self {
        Self {
            src,
            state: InflateState::new_boxed(DataFormat::Raw),
            in_member: false,
            done: false,
            produced: 0,
            limit,
        }
    }

    /// Step past one member header, or return `false` at the end of the file
    /// (or the NUL padding some writers leave after the last member).
    fn member_header(&mut self) -> io::Result<bool> {
        let next = self.src.fill_buf()?;
        if next.is_empty() || (self.produced > 0 && next[0] == 0) {
            return Ok(false);
        }
        let mut fixed = [0u8; 10];
        self.src.read_exact(&mut fixed)?;
        if fixed[..3] != [0x1F, 0x8B, 8] || fixed[3] & 0xE0 != 0 {
            return Err(invalid("not a gzip member"));
        }
        let flags = fixed[3];
        if flags & 0x04 != 0 {
            let mut len = [0u8; 2];
            self.src.read_exact(&mut len)?;
            self.skip(u64::from(u16::from_le_bytes(len)))?;
        }
        for bit in [0x08, 0x10] {
            if flags & bit != 0 {
                // A stored name or comment, ended by a NUL.
                let mut text = Vec::new();
                (&mut self.src).take(64 * 1024).read_until(0, &mut text)?;
                if text.last() != Some(&0) {
                    return Err(invalid("unterminated gzip header field"));
                }
            }
        }
        if flags & 0x02 != 0 {
            self.skip(2)?;
        }
        Ok(true)
    }

    fn skip(&mut self, len: u64) -> io::Result<()> {
        let n = io::copy(&mut (&mut self.src).take(len), &mut io::sink())?;
        if n == len {
            Ok(())
        } else {
            Err(io::ErrorKind::UnexpectedEof.into())
        }
    }
}

impl<R: BufRead> Read for Gunzip<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.done {
                return Ok(0);
            }
            if !self.in_member {
                if !self.member_header()? {
                    self.done = true;
                    continue;
                }
                self.state.reset(DataFormat::Raw);
                self.in_member = true;
            }
            let input = self.src.fill_buf()?;
            let ran_dry = input.is_empty();
            let r = inflate(&mut self.state, input, buf, MZFlush::None);
            self.src.consume(r.bytes_consumed);
            self.produced += r.bytes_written as u64;
            if self.produced > self.limit {
                return Err(io::Error::other("past the inflate limit"));
            }
            match r.status {
                Ok(MZStatus::StreamEnd) => {
                    // The member's CRC32 and ISIZE.
                    self.skip(8)?;
                    self.in_member = false;
                }
                Ok(_) if r.bytes_written > 0 || r.bytes_consumed > 0 => {}
                _ if ran_dry => return Err(io::ErrorKind::UnexpectedEof.into()),
                _ => return Err(invalid("bad deflate stream")),
            }
            if r.bytes_written > 0 {
                return Ok(r.bytes_written);
            }
        }
    }
}

fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use miniz_oxide::deflate::compress_to_vec;
    use std::fs;

    /// Write the checksum of `h` in its field, summed signed when `signed`.
    fn seal(h: &mut [u8; 512], signed: bool) {
        h[148..156].fill(b' ');
        let sum: i64 = h
            .iter()
            .map(|&b| {
                if signed {
                    i64::from(b as i8)
                } else {
                    i64::from(b)
                }
            })
            .sum();
        h[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
    }

    /// A ustar header for a regular file called `name` of `size` bytes.
    fn header(name: &[u8], size: usize, flag: u8) -> [u8; 512] {
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name);
        h[100..107].copy_from_slice(b"0000644");
        h[124..135].copy_from_slice(format!("{size:011o}").as_bytes());
        h[156] = flag;
        h[257..262].copy_from_slice(b"ustar");
        seal(&mut h, false);
        h
    }

    fn push(out: &mut Vec<u8>, h: [u8; 512], data: &[u8]) {
        out.extend_from_slice(&h);
        out.extend_from_slice(data);
        out.resize(out.len().next_multiple_of(512), 0);
    }

    pub(super) fn tar_of(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, data) in files {
            push(&mut out, header(name.as_bytes(), data.len(), b'0'), data);
        }
        out.extend_from_slice(&[0; 1024]);
        out
    }

    fn gzip_of(data: &[u8], name: Option<&str>) -> Vec<u8> {
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
        out.extend_from_slice(&compress_to_vec(data, 6));
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
        let zeros = dir.path().join("zeros.gz");
        fs::write(&zeros, gzip_of(&[0; 2048], None)).unwrap();
        assert_eq!(archive_kind(&zeros, Some("gzip")), None);
    }

    #[test]
    fn counting_accepts_the_header_forms_the_cleaner_accepts() {
        let dir = tempfile::tempdir().unwrap();
        let mut t = Vec::new();
        // Old tars summed the checksum over signed bytes.
        let mut signed = header(b"caf\xe9\xff.txt", 3, b'0');
        seal(&mut signed, true);
        push(&mut t, signed, b"abc");
        // A size led by NULs instead of zeros.
        let mut nuls = header(b"nuls.txt", 0, b'0');
        nuls[124..136].copy_from_slice(&[&[0u8; 9][..], b"12\0"].concat());
        seal(&mut nuls, false);
        push(&mut t, nuls, &[1; 10]);
        // A GNU base-256 size.
        let mut big = header(b"base256.txt", 0, b'0');
        big[124..136].fill(0);
        big[124] = 0x80;
        big[135] = 20;
        seal(&mut big, false);
        push(&mut t, big, &[2; 20]);
        // A hard link carrying a size is not a file, and its data is skipped.
        push(&mut t, header(b"link.txt", 600, b'1'), &[3; 600]);
        push(&mut t, header(b"last.txt", 1, b'0'), b"z");
        t.extend_from_slice(&[0; 1024]);
        let path = dir.path().join("forms.tar");
        fs::write(&path, &t).unwrap();
        assert_eq!(archive_file_count(&path, ArchiveKind::Tar), Some(4));
        let gz = dir.path().join("forms.tar.gz");
        fs::write(&gz, gzip_of(&t, None)).unwrap();
        assert_eq!(archive_file_count(&gz, ArchiveKind::TarGz), Some(4));
    }

    #[test]
    fn a_v7_tar_inside_a_gzip_is_routed() {
        let dir = tempfile::tempdir().unwrap();
        let mut h = header(b"old.txt", 5, b'0');
        h[257..263].fill(0);
        seal(&mut h, false);
        let mut t = Vec::new();
        push(&mut t, h, b"hello");
        t.extend_from_slice(&[0; 1024]);
        let path = dir.path().join("old.tar.gz");
        fs::write(&path, gzip_of(&t, Some("old.tar"))).unwrap();
        assert_eq!(archive_kind(&path, Some("gzip")), Some(ArchiveKind::TarGz));
        assert_eq!(archive_file_count(&path, ArchiveKind::TarGz), Some(1));
    }

    #[test]
    fn a_multi_member_gzip_is_counted_as_one_stream() {
        let dir = tempfile::tempdir().unwrap();
        let tar = tar_of(&[("a.txt", b"hello"), ("b.txt", &[9u8; 900])]);
        let mut gz = gzip_of(&tar[..700], Some("part.tar"));
        gz.extend_from_slice(&gzip_of(&tar[700..], None));
        gz.extend_from_slice(&[0; 16]);
        let path = dir.path().join("multi.tar.gz");
        fs::write(&path, &gz).unwrap();
        assert_eq!(archive_kind(&path, Some("gzip")), Some(ArchiveKind::TarGz));
        assert_eq!(archive_file_count(&path, ArchiveKind::TarGz), Some(2));
    }

    #[test]
    fn counting_stops_at_a_broken_header_and_a_broken_gzip_reads_as_none() {
        let dir = tempfile::tempdir().unwrap();
        let mut tar = tar_of(&[("a.txt", b"hello"), ("b.txt", b"world")]);
        tar[1024] ^= 0x20;
        let path = dir.path().join("broken.tar");
        fs::write(&path, &tar).unwrap();
        assert_eq!(archive_file_count(&path, ArchiveKind::Tar), Some(1));

        let mut gz = gzip_of(&[7u8; 4096], None);
        gz[3] = 0xE0;
        let path = dir.path().join("bad.tar.gz");
        fs::write(&path, &gz).unwrap();
        assert_eq!(archive_file_count(&path, ArchiveKind::TarGz), None);
    }
}
