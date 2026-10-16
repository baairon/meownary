//! tar and tar.gz deattribution. Each regular file inside is handed to
//! [`deattribute_bytes`]; an entry that comes back changed has its data region
//! overwritten in place, and since the length never changes the header, the
//! padding and every other entry stay byte for byte as they were. A `.tar.gz`
//! is inflated, cleaned the same way and deflated again into one member.
//!
//! The original is only ever read. The copy goes through a temp file beside it
//! and is renamed over the copy path, so a failure leaves nothing behind.

use std::fs::{self, File};
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use miniz_oxide::deflate::compress_to_vec;
use miniz_oxide::inflate::stream::{InflateState, inflate};
use miniz_oxide::{DataFormat, MZFlush, MZStatus};

use crate::edit::engine::EditError;
use crate::edit::fsio;

use super::Reason;
use super::mem::{ArchiveOutcome, deattribute_bytes};

const BLOCK: u64 = 512;
const CHKSUM: usize = 148;
/// Largest pax or GNU long-name record read into memory.
const META_MAX: u64 = 1024 * 1024;
const MIB: u64 = 1024 * 1024;
const DEFLATE_LEVEL: u8 = 6;

#[derive(Debug, Clone, Copy)]
struct Limits {
    /// Entries larger than this are left alone.
    entry: u64,
    /// Archives whose uncompressed size exceeds this are refused.
    total: u64,
}

const LIMITS: Limits = Limits {
    entry: 256 * MIB,
    total: 1024 * MIB,
};

/// The deattributed copy's name for an archive: `name.deattributed.tar` or
/// `name.deattributed.tar.gz`. Other names (`.tgz`, say) fall back to the shared
/// single-extension rule.
pub fn copy_name(original: &Path) -> PathBuf {
    let name = original
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let lower = name.to_ascii_lowercase();
    let stem_len = lower
        .strip_suffix(".tar.gz")
        .or_else(|| lower.strip_suffix(".tar"))
        .map(str::len)
        .filter(|&n| n > 0);
    match stem_len {
        Some(n) => original.with_file_name(format!("{}.deattributed{}", &name[..n], &name[n..])),
        None => super::deattributed_name(original),
    }
}

/// Whether a file name already carries the copy tag in any position.
fn is_copy(path: &Path) -> bool {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    super::is_deattributed(path)
        || name.contains(".deattributed.")
        || name.ends_with(".deattributed")
}

/// Write the deattributed copy of the tar (`gz` false) or tar.gz (`gz` true) at
/// `original` to `out`. `Ok(None)` means nothing inside had anything to blank
/// (or the input is not a tar), and nothing is written.
pub fn deattribute_tar(
    original: &Path,
    gz: bool,
    out: &Path,
) -> Result<Option<ArchiveOutcome>, EditError> {
    run(original, gz, Some(out), LIMITS)
}

/// The same work as [`deattribute_tar`] without writing anything. The outcome's
/// `output` is [`copy_name`] of the original.
pub fn plan_tar(original: &Path, gz: bool) -> Result<Option<ArchiveOutcome>, EditError> {
    run(original, gz, None, LIMITS)
}

/// One entry's replacement data and where it goes in the (uncompressed) tar.
struct Patch {
    offset: u64,
    bytes: Vec<u8>,
}

#[derive(Default)]
struct Scan {
    patches: Vec<Patch>,
    brand: usize,
    patch: usize,
    skipped: Vec<(String, Reason)>,
}

impl Scan {
    fn outcome(self, output: PathBuf) -> Option<ArchiveOutcome> {
        if self.patches.is_empty() {
            return None;
        }
        Some(ArchiveOutcome {
            output,
            entries_cleaned: self.patches.len(),
            brand: self.brand,
            patch: self.patch,
            skipped: self.skipped,
        })
    }
}

fn run(
    original: &Path,
    gz: bool,
    out: Option<&Path>,
    limits: Limits,
) -> Result<Option<ArchiveOutcome>, EditError> {
    if is_copy(original) {
        return Err(EditError::Refused(
            "the file is already a deattributed copy".into(),
        ));
    }
    let meta = fs::symlink_metadata(original)?;
    if meta.file_type().is_symlink() {
        return Err(EditError::Symlink(original.to_path_buf()));
    }
    if !meta.is_file() {
        return Err(EditError::Refused("not a regular file".into()));
    }
    if let Some(out) = out {
        match fs::symlink_metadata(out) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(EditError::Symlink(out.to_path_buf()));
            }
            Ok(m) if !m.is_file() => {
                return Err(EditError::Refused(
                    "the copy's path is taken by something that is not a file".into(),
                ));
            }
            _ => {}
        }
    }
    let output = out.map_or_else(|| copy_name(original), Path::to_path_buf);
    if gz {
        run_gz(original, &meta, out, output, limits)
    } else {
        run_plain(original, &meta, out, output, limits)
    }
}

fn run_plain(
    original: &Path,
    meta: &fs::Metadata,
    out: Option<&Path>,
    output: PathBuf,
    limits: Limits,
) -> Result<Option<ArchiveOutcome>, EditError> {
    let size = meta.len();
    if size > limits.total {
        return Err(too_big(limits));
    }
    let mut src = File::open(original)?;
    let Some(scan) = scan(&mut src, size, limits)? else {
        return Ok(None);
    };
    let Some(out) = out else {
        return Ok(scan.outcome(output));
    };
    if scan.patches.is_empty() {
        return Ok(None);
    }
    let (tmp, file) = fsio::create_temp_beside(out)?;
    let result = (|| {
        copy_plain(&mut src, file, &scan.patches, size)?;
        finish(&tmp, out, meta)
    })();
    match result {
        Ok(()) => Ok(scan.outcome(output)),
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Stream the original into `file`, lay the patches over it and fsync.
fn copy_plain(
    src: &mut File,
    mut file: File,
    patches: &[Patch],
    size: u64,
) -> Result<(), EditError> {
    src.seek(SeekFrom::Start(0))?;
    let copied = io::copy(&mut src.take(size.saturating_add(1)), &mut file)?;
    if copied != size {
        return Err(EditError::Changed);
    }
    for p in patches {
        fsio::write_at(&file, p.offset, &p.bytes)?;
    }
    file.sync_all()?;
    Ok(())
}

fn run_gz(
    original: &Path,
    meta: &fs::Metadata,
    out: Option<&Path>,
    output: PathBuf,
    limits: Limits,
) -> Result<Option<ArchiveOutcome>, EditError> {
    if meta.len() > limits.total {
        return Err(too_big(limits));
    }
    let data = fs::read(original)?;
    if data.len() as u64 != meta.len() {
        return Err(EditError::Changed);
    }
    let (head, mut tar) = gunzip(&data, limits)?;
    drop(data);
    let tar_len = tar.len() as u64;
    let Some(scan) = scan(&mut Cursor::new(&tar), tar_len, limits)? else {
        return Ok(None);
    };
    let Some(out) = out else {
        return Ok(scan.outcome(output));
    };
    if scan.patches.is_empty() {
        return Ok(None);
    }
    for p in &scan.patches {
        let at = p.offset as usize;
        tar[at..at + p.bytes.len()].copy_from_slice(&p.bytes);
    }
    let packed = gzip(&head, &tar);
    drop(tar);
    let (tmp, mut file) = fsio::create_temp_beside(out)?;
    let result = (|| {
        file.write_all(&packed)?;
        file.sync_all()?;
        drop(file);
        finish(&tmp, out, meta)
    })();
    match result {
        Ok(()) => Ok(scan.outcome(output)),
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Keep the original's mode, rename the temp file over the copy and sync the
/// folder.
fn finish(tmp: &Path, out: &Path, meta: &fs::Metadata) -> Result<(), EditError> {
    // Keep the original's mode (an executable stays executable). Windows only
    // has a read-only bit, which would block the next run's replace, so it is
    // left clear there.
    #[cfg(unix)]
    fs::set_permissions(tmp, meta.permissions())?;
    #[cfg(not(unix))]
    let _ = meta;
    fs::rename(tmp, out)?;
    if let Some(dir) = out.parent() {
        fsio::sync_dir(dir);
    }
    Ok(())
}

fn too_big(limits: Limits) -> EditError {
    EditError::Refused(format!(
        "archive is larger than {} MiB uncompressed",
        limits.total / MIB
    ))
}

fn corrupt(what: &str) -> EditError {
    EditError::Io(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("corrupt gzip: {what}"),
    ))
}

// ---- tar walking ----------------------------------------------------------

/// A numeric header field: octal digits (leading spaces or NULs, ended by a
/// space or NUL), or the GNU base-256 form when the high bit is set.
fn number(field: &[u8]) -> Option<u64> {
    let first = *field.first()?;
    if first & 0x80 != 0 {
        let mut v = (first & 0x7F) as u64;
        for &b in &field[1..] {
            v = v.checked_mul(256)?.checked_add(b as u64)?;
        }
        return Some(v);
    }
    let digits = field
        .iter()
        .copied()
        .skip_while(|&b| b == b' ' || b == 0)
        .take_while(|&b| b != b' ' && b != 0);
    let mut v = 0u64;
    for d in digits {
        if !(b'0'..=b'7').contains(&d) {
            return None;
        }
        v = v.checked_mul(8)?.checked_add((d - b'0') as u64)?;
    }
    Some(v)
}

/// Whether the stored checksum matches the sum of the header bytes with the
/// checksum field read as spaces, summed unsigned or (as old tars did) signed.
fn header_ok(h: &[u8; 512]) -> bool {
    let Some(stored) = number(&h[CHKSUM..CHKSUM + 8]) else {
        return false;
    };
    let mut unsigned = 0u64;
    let mut signed = 0i64;
    for (i, &b) in h.iter().enumerate() {
        let b = if (CHKSUM..CHKSUM + 8).contains(&i) {
            b' '
        } else {
            b
        };
        unsigned += b as u64;
        signed += b as i8 as i64;
    }
    stored == unsigned || i64::try_from(stored).is_ok_and(|s| s == signed)
}

fn cstr_lossy(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

/// The path in a ustar header, with its prefix when the magic is POSIX.
fn header_name(h: &[u8; 512]) -> String {
    let name = cstr_lossy(&h[..100]);
    if &h[257..263] == b"ustar\0" {
        let prefix = cstr_lossy(&h[345..500]);
        if !prefix.is_empty() {
            return format!("{prefix}/{name}");
        }
    }
    name
}

/// The pax keys that matter here.
#[derive(Default, Clone)]
struct Pax {
    path: Option<String>,
    size: Option<u64>,
}

impl Pax {
    /// Parse `<len> <key>=<value>\n` records, where `len` counts the whole
    /// record. A malformed record ends the parse.
    fn parse(&mut self, data: &[u8]) {
        let mut rest = data;
        while !rest.is_empty() {
            let Some(sp) = rest.iter().position(|&b| b == b' ') else {
                return;
            };
            let Some(len) = std::str::from_utf8(&rest[..sp])
                .ok()
                .and_then(|s| s.parse::<usize>().ok())
            else {
                return;
            };
            if len <= sp + 1 || len > rest.len() {
                return;
            }
            let body = &rest[sp + 1..len];
            let record = body.strip_suffix(b"\n").unwrap_or(body);
            rest = &rest[len..];
            let Some(eq) = record.iter().position(|&b| b == b'=') else {
                continue;
            };
            let value = &record[eq + 1..];
            match &record[..eq] {
                b"path" => self.path = Some(String::from_utf8_lossy(value).into_owned()),
                b"size" => {
                    self.size = std::str::from_utf8(value)
                        .ok()
                        .and_then(|s| s.trim().parse().ok());
                }
                _ => {}
            }
        }
    }
}

fn read_at<R: Read + Seek>(r: &mut R, offset: u64, len: usize) -> io::Result<Vec<u8>> {
    r.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// Offset of the next header after `size` data bytes at `data_off`, or `None`
/// when the data runs past the end or the arithmetic overflows.
fn skip_to(data_off: u64, size: u64, total: u64) -> Option<u64> {
    let end = data_off.checked_add(size)?;
    if end > total {
        return None;
    }
    size.checked_add(BLOCK - 1)
        .map(|s| s / BLOCK * BLOCK)
        .and_then(|padded| data_off.checked_add(padded))
}

/// Walk the headers of a tar `total` bytes long and collect the replacement data
/// for every regular file that has a credit. `Ok(None)` when the first block is
/// not a tar header. A bad checksum, a truncated entry or the end-of-archive
/// block stops the walk; everything before it still counts.
fn scan<R: Read + Seek>(r: &mut R, total: u64, limits: Limits) -> Result<Option<Scan>, EditError> {
    let mut scan = Scan::default();
    let mut global = Pax::default();
    let mut next_pax = Pax::default();
    let mut long_name: Option<String> = None;
    let mut off = 0u64;
    let mut first = true;
    while off.checked_add(BLOCK).is_some_and(|end| end <= total) {
        let h: [u8; 512] = read_at(r, off, BLOCK as usize)?
            .try_into()
            .map_err(|_| io::Error::other("short tar block"))?;
        if h.iter().all(|&b| b == 0) || !header_ok(&h) {
            if first {
                return Ok(None);
            }
            break;
        }
        first = false;
        let Some(hsize) = number(&h[124..136]) else {
            break;
        };
        let flag = h[156];
        let data_off = off + BLOCK;
        if matches!(flag, b'L' | b'K' | b'x' | b'g') {
            let Some(next) = skip_to(data_off, hsize, total) else {
                break;
            };
            if hsize <= META_MAX {
                let data = read_at(r, data_off, hsize as usize)?;
                match flag {
                    b'L' => long_name = Some(cstr_lossy(&data)),
                    b'x' => next_pax.parse(&data),
                    b'g' => global.parse(&data),
                    _ => {}
                }
            }
            off = next;
            continue;
        }
        let pax = std::mem::take(&mut next_pax);
        let size = match flag {
            b'1' | b'2' | b'5' => 0,
            _ => pax.size.or(global.size).unwrap_or(hsize),
        };
        let name = pax
            .path
            .or_else(|| long_name.take())
            .or_else(|| global.path.clone())
            .unwrap_or_else(|| header_name(&h));
        long_name = None;
        let Some(next) = skip_to(data_off, size, total) else {
            break;
        };
        let regular = matches!(flag, 0 | b'0' | b'7') && !name.ends_with('/');
        if regular && size > 0 {
            if size > limits.entry {
                scan.skipped.push((name, Reason::EntryTooLarge));
            } else {
                let data = read_at(r, data_off, size as usize)?;
                let outcome = deattribute_bytes(&name, &data);
                scan.skipped.extend(
                    outcome
                        .skipped
                        .into_iter()
                        .map(|reason| (name.clone(), reason)),
                );
                if let Some(bytes) = outcome.bytes
                    && bytes.len() == data.len()
                {
                    scan.brand += outcome.brand;
                    scan.patch += outcome.patch;
                    scan.patches.push(Patch {
                        offset: data_off,
                        bytes,
                    });
                }
            }
        }
        off = next;
    }
    Ok(Some(scan))
}

// ---- gzip -----------------------------------------------------------------

/// The parts of the first gzip header the rewritten member keeps.
struct GzHead {
    mtime: [u8; 4],
    os: u8,
}

/// Parse one member header; returns the kept fields and the header's length.
/// FEXTRA, FNAME, FCOMMENT and FHCRC are skipped over, not kept.
fn gz_header(d: &[u8]) -> Option<(GzHead, usize)> {
    if d.len() < 10 || d[0] != 0x1F || d[1] != 0x8B || d[2] != 8 || d[3] & 0xE0 != 0 {
        return None;
    }
    let flg = d[3];
    let mut pos = 10usize;
    if flg & 0x04 != 0 {
        let xlen = u16::from_le_bytes([*d.get(pos)?, *d.get(pos + 1)?]) as usize;
        pos = pos.checked_add(2 + xlen)?;
    }
    for flag in [0x08, 0x10] {
        if flg & flag != 0 {
            let nul = d.get(pos..)?.iter().position(|&b| b == 0)?;
            pos += nul + 1;
        }
    }
    if flg & 0x02 != 0 {
        pos = pos.checked_add(2)?;
    }
    (pos <= d.len()).then(|| {
        (
            GzHead {
                mtime: [d[4], d[5], d[6], d[7]],
                os: d[9],
            },
            pos,
        )
    })
}

/// Inflate every member of a gzip file into one buffer, checking each member's
/// CRC32 and ISIZE. Anything after the last member other than NUL padding is an
/// error, since the rewritten file would silently drop it.
fn gunzip(data: &[u8], limits: Limits) -> Result<(GzHead, Vec<u8>), EditError> {
    let mut out = Vec::new();
    let mut head = None;
    let mut pos = 0usize;
    while pos < data.len() {
        let rest = &data[pos..];
        if head.is_some() && rest.iter().all(|&b| b == 0) {
            break;
        }
        let (h, hlen) = gz_header(rest).ok_or_else(|| corrupt("bad member header"))?;
        head.get_or_insert(h);
        let body = &rest[hlen..];
        let start = out.len();
        let used = inflate_raw(body, &mut out, limits.total as usize)?;
        let trailer = body
            .get(used..used + 8)
            .ok_or_else(|| corrupt("missing trailer"))?;
        let crc = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
        let isize = u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);
        let member = &out[start..];
        if crc != crc32(member) || isize != member.len() as u32 {
            return Err(corrupt("checksum mismatch"));
        }
        pos += hlen + used + 8;
    }
    head.map(|h| (h, out)).ok_or_else(|| corrupt("empty file"))
}

/// Inflate one raw deflate stream from the start of `input`, appending to
/// `out`; returns how many input bytes it used.
fn inflate_raw(input: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<usize, EditError> {
    let mut state = InflateState::new_boxed(DataFormat::Raw);
    let mut chunk = vec![0u8; 64 * 1024];
    let mut pos = 0usize;
    loop {
        let r = inflate(&mut state, &input[pos..], &mut chunk, MZFlush::None);
        out.extend_from_slice(&chunk[..r.bytes_written]);
        pos += r.bytes_consumed;
        if out.len() > limit {
            return Err(EditError::Refused(format!(
                "archive is larger than {} MiB uncompressed",
                limit as u64 / MIB
            )));
        }
        match r.status {
            Ok(MZStatus::StreamEnd) => return Ok(pos),
            Ok(_) if r.bytes_consumed > 0 || r.bytes_written > 0 => {}
            _ => return Err(corrupt("bad deflate stream")),
        }
    }
}

/// One gzip member: the kept mtime and OS byte, no optional fields.
fn gzip(head: &GzHead, tar: &[u8]) -> Vec<u8> {
    let body = compress_to_vec(tar, DEFLATE_LEVEL);
    let mut out = Vec::with_capacity(body.len() + 18);
    out.extend_from_slice(&[0x1F, 0x8B, 8, 0]);
    out.extend_from_slice(&head.mtime);
    out.extend_from_slice(&[0, head.os]);
    out.extend_from_slice(&body);
    out.extend_from_slice(&crc32(tar).to_le_bytes());
    out.extend_from_slice(&(tar.len() as u32).to_le_bytes());
    out
}

const CRC_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
};

/// CRC-32 (IEEE, reflected), as gzip stores it.
fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c = CRC_TABLE[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8);
    }
    c ^ 0xFFFF_FFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    const CREDIT: &[u8] = b"patched by Invented\0";

    fn octal(v: u64, width: usize) -> Vec<u8> {
        format!("{v:0w$o}\0", w = width - 1).into_bytes()
    }

    fn header(name: &str, flag: u8, size: u64) -> [u8; 512] {
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..108].copy_from_slice(&octal(0o644, 8));
        h[108..116].copy_from_slice(&octal(0, 8));
        h[116..124].copy_from_slice(&octal(0, 8));
        h[124..136].copy_from_slice(&octal(size, 12));
        h[136..148].copy_from_slice(&octal(1_700_000_000, 12));
        h[148..156].fill(b' ');
        h[156] = flag;
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        let sum: u64 = h.iter().map(|&b| b as u64).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        h
    }

    fn entry(out: &mut Vec<u8>, name: &str, flag: u8, data: &[u8]) {
        out.extend_from_slice(&header(name, flag, data.len() as u64));
        out.extend_from_slice(data);
        out.resize(out.len().next_multiple_of(512), 0);
    }

    fn pax_record(key: &str, value: &str) -> Vec<u8> {
        let base = key.len() + value.len() + 3;
        let mut len = base;
        while format!("{len}").len() + base != len {
            len = format!("{len}").len() + base;
        }
        format!("{len} {key}={value}\n").into_bytes()
    }

    fn fake_pe() -> Vec<u8> {
        let mut v = vec![0u8; 256];
        v[..16].copy_from_slice(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00");
        v.extend_from_slice(CREDIT);
        v
    }

    fn end(out: &mut Vec<u8>) {
        out.resize(out.len() + 1024, 0);
    }

    /// A tar with four fake PEs (plain name, GNU long name, pax path, and one
    /// more plain) among a text file and a directory.
    fn sample_tar() -> Vec<u8> {
        let mut t = Vec::new();
        entry(&mut t, "src/", b'5', b"");
        entry(&mut t, "src/tool.exe", b'0', &fake_pe());
        entry(&mut t, "notes.txt", b'0', b"plain notes\n");
        let long = format!("{}/longtool.exe", "d".repeat(120));
        let mut l = long.clone().into_bytes();
        l.push(0);
        entry(&mut t, "././@LongLink", b'L', &l);
        entry(&mut t, &long[..100], b'0', &fake_pe());
        entry(
            &mut t,
            "PaxHeader/x",
            b'x',
            &pax_record("path", "pax/dir/paxed.dll"),
        );
        entry(&mut t, "paxshort", b'0', &fake_pe());
        end(&mut t);
        t
    }

    fn clean_tar() -> Vec<u8> {
        let mut t = Vec::new();
        entry(&mut t, "notes.txt", b'0', b"plain notes\n");
        entry(&mut t, "dir/", b'5', b"");
        end(&mut t);
        t
    }

    /// Every header in `t` as (typeflag, size, data offset), checking checksums.
    fn walk(t: &[u8]) -> Vec<(u8, u64, usize)> {
        let mut out = Vec::new();
        let mut off = 0usize;
        while off + 512 <= t.len() {
            let h: [u8; 512] = t[off..off + 512].try_into().unwrap();
            if h.iter().all(|&b| b == 0) {
                break;
            }
            assert!(header_ok(&h), "bad checksum at {off}");
            let size = number(&h[124..136]).unwrap();
            out.push((h[156], size, off + 512));
            off += 512 + (size as usize).next_multiple_of(512);
        }
        out
    }

    fn gz_member(chunk: &[u8], extras: bool) -> Vec<u8> {
        let mut m = vec![0x1F, 0x8B, 8];
        m.push(if extras { 0x08 | 0x10 } else { 0 });
        m.extend_from_slice(&0x1234_5678u32.to_le_bytes());
        m.extend_from_slice(&[0, 3]);
        if extras {
            m.extend_from_slice(b"leak-by-Invented.tar\0made by Invented\0");
        }
        m.extend_from_slice(&compress_to_vec(chunk, 6));
        m.extend_from_slice(&crc32(chunk).to_le_bytes());
        m.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
        m
    }

    fn count(dir: &Path) -> usize {
        fs::read_dir(dir).unwrap().count()
    }

    fn find(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn crc32_matches_the_reference_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn copy_names_keep_the_tar_suffix_whole() {
        assert_eq!(
            copy_name(Path::new("dir/a.tar")),
            Path::new("dir/a.deattributed.tar")
        );
        assert_eq!(
            copy_name(Path::new("dir/a.b.TAR.GZ")),
            Path::new("dir/a.b.deattributed.TAR.GZ")
        );
        assert_eq!(
            copy_name(Path::new("a.tgz")),
            Path::new("a.deattributed.tgz")
        );
        for p in ["a.deattributed.tar", "a.deattributed.tar.gz"] {
            assert!(is_copy(Path::new(p)));
        }
        assert!(!is_copy(Path::new("a.tar.gz")));
    }

    #[test]
    fn a_tar_copy_is_valid_and_loses_only_the_credit() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("a.tar");
        let tar = sample_tar();
        fs::write(&src, &tar).unwrap();
        let out = copy_name(&src);

        let plan = plan_tar(&src, false).unwrap().expect("credits found");
        assert_eq!(plan.entries_cleaned, 3);
        assert_eq!(plan.output, out);
        assert_eq!(count(dir.path()), 1, "a plan writes nothing");

        let done = deattribute_tar(&src, false, &out).unwrap().unwrap();
        assert_eq!(done.entries_cleaned, 3);
        assert!(done.brand + done.patch > 0);
        assert_eq!(count(dir.path()), 2, "no temp file is left");
        assert_eq!(fs::read(&src).unwrap(), tar, "the original is untouched");

        let copy = fs::read(&out).unwrap();
        assert_eq!(copy.len(), tar.len());
        assert!(!find(&copy, CREDIT));
        assert!(find(&tar, CREDIT));
        let before = walk(&tar);
        assert_eq!(walk(&copy), before, "same headers and sizes");
        let pes: Vec<_> = before
            .iter()
            .filter(|e| e.1 == 276 && e.0 == b'0')
            .map(|e| e.2..e.2 + 276)
            .collect();
        assert_eq!(pes.len(), 3);
        for (i, (a, b)) in tar.iter().zip(&copy).enumerate() {
            if a != b {
                assert!(pes.iter().any(|r| r.contains(&i)), "stray change at {i}");
            }
        }
        assert!(tar != copy);
    }

    #[test]
    fn a_targz_copy_inflates_to_the_cleaned_tar() {
        let dir = tempfile::tempdir().unwrap();
        let tar = sample_tar();
        let plain = dir.path().join("p.tar");
        fs::write(&plain, &tar).unwrap();
        let plain_out = copy_name(&plain);
        deattribute_tar(&plain, false, &plain_out).unwrap().unwrap();
        let want = fs::read(&plain_out).unwrap();

        // Two members, the first with FNAME and FCOMMENT leaks.
        let cut = 3 * 512 + 512;
        let mut gz = gz_member(&tar[..cut], true);
        gz.extend_from_slice(&gz_member(&tar[cut..], false));
        let src = dir.path().join("a.tar.gz");
        fs::write(&src, &gz).unwrap();
        let out = copy_name(&src);
        assert_eq!(out.file_name().unwrap(), "a.deattributed.tar.gz");

        let done = deattribute_tar(&src, true, &out).unwrap().unwrap();
        assert_eq!(done.entries_cleaned, 3);
        assert_eq!(fs::read(&src).unwrap(), gz, "the original is untouched");
        assert_eq!(count(dir.path()), 4);

        let copy = fs::read(&out).unwrap();
        assert_eq!(&copy[..4], &[0x1F, 0x8B, 8, 0], "no FNAME or FCOMMENT");
        assert_eq!(&copy[4..8], &0x1234_5678u32.to_le_bytes(), "mtime kept");
        assert_eq!(copy[9], 3, "OS byte kept");
        assert!(!find(&copy, b"Invented"));
        let (_, inflated) = gunzip(&copy, LIMITS).unwrap();
        assert_eq!(inflated, want);
        assert_eq!(walk(&inflated), walk(&tar));
    }

    #[test]
    fn nothing_to_blank_returns_none_and_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let tar = clean_tar();
        let a = dir.path().join("a.tar");
        let b = dir.path().join("b.tar.gz");
        let c = dir.path().join("c.gz");
        fs::write(&a, &tar).unwrap();
        fs::write(&b, gz_member(&tar, false)).unwrap();
        fs::write(
            &c,
            gz_member(b"just some text, not a tar archive at all", false),
        )
        .unwrap();
        assert!(
            deattribute_tar(&a, false, &copy_name(&a))
                .unwrap()
                .is_none()
        );
        assert!(deattribute_tar(&b, true, &copy_name(&b)).unwrap().is_none());
        assert!(deattribute_tar(&c, true, &copy_name(&c)).unwrap().is_none());
        assert!(plan_tar(&b, true).unwrap().is_none());
        assert_eq!(count(dir.path()), 3);
    }

    #[test]
    fn oversized_entries_are_skipped_and_named() {
        let tar = sample_tar();
        let limits = Limits {
            entry: 275,
            total: LIMITS.total,
        };
        let s = scan(&mut Cursor::new(&tar), tar.len() as u64, limits)
            .unwrap()
            .unwrap();
        assert!(s.patches.is_empty());
        assert_eq!(s.skipped.len(), 3);
        assert!(s.skipped.iter().all(|(_, r)| *r == Reason::EntryTooLarge));
        assert!(s.skipped[2].0.starts_with("pax/dir/paxed.dll"));

        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("a.tar");
        fs::write(&src, &tar).unwrap();
        let out = copy_name(&src);
        assert!(run(&src, false, Some(&out), limits).unwrap().is_none());
        assert!(!out.exists());
    }

    #[test]
    fn the_total_size_cap_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let tar = sample_tar();
        let a = dir.path().join("a.tar");
        let b = dir.path().join("b.tar.gz");
        fs::write(&a, &tar).unwrap();
        fs::write(&b, gz_member(&tar, false)).unwrap();
        let limits = Limits {
            entry: LIMITS.entry,
            total: 4096,
        };
        let out = dir.path().join("out");
        assert!(matches!(
            run(&a, false, Some(&out), limits),
            Err(EditError::Refused(_))
        ));
        let limits = Limits {
            entry: LIMITS.entry,
            total: 4000,
        };
        assert!(matches!(
            run(&b, true, Some(&out), limits),
            Err(EditError::Refused(_))
        ));
        assert_eq!(count(dir.path()), 2);
    }

    #[test]
    fn a_corrupt_gzip_is_an_error_and_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let good = gz_member(&sample_tar(), false);
        let mut bad_crc = good.clone();
        let n = bad_crc.len();
        bad_crc[n - 8] ^= 0xFF;
        let mut bad_stream = good[..10].to_vec();
        bad_stream.extend_from_slice(&[0xFF; 40]);
        let truncated = good[..good.len() / 2].to_vec();
        let mut trailing = good.clone();
        trailing.extend_from_slice(b"junk after the member");
        for (i, data) in [bad_crc, bad_stream, truncated, trailing]
            .iter()
            .enumerate()
        {
            let src = dir.path().join(format!("c{i}.tar.gz"));
            fs::write(&src, data).unwrap();
            let out = copy_name(&src);
            assert!(deattribute_tar(&src, true, &out).is_err(), "case {i}");
            assert!(!out.exists());
        }
        assert_eq!(count(dir.path()), 4, "only the originals remain");
    }

    #[test]
    fn a_copy_is_not_deattributed_again() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("a.deattributed.tar");
        fs::write(&src, sample_tar()).unwrap();
        let out = dir.path().join("a.deattributed.deattributed.tar");
        assert!(matches!(
            deattribute_tar(&src, false, &out),
            Err(EditError::Refused(_))
        ));
    }

    #[test]
    fn pax_size_overrides_the_header_size() {
        let mut t = Vec::new();
        let pe = fake_pe();
        entry(
            &mut t,
            "PaxHeader/x",
            b'x',
            &pax_record("size", &pe.len().to_string()),
        );
        // The header claims 0 bytes; the pax record carries the real length.
        t.extend_from_slice(&header("big.exe", b'0', 0));
        t.extend_from_slice(&pe);
        t.resize(t.len().next_multiple_of(512), 0);
        end(&mut t);
        let s = scan(&mut Cursor::new(&t), t.len() as u64, LIMITS)
            .unwrap()
            .unwrap();
        assert_eq!(s.patches.len(), 1);
    }

    #[test]
    fn garbage_is_not_a_tar() {
        let junk = vec![7u8; 2048];
        assert!(
            scan(&mut Cursor::new(&junk), 2048, LIMITS)
                .unwrap()
                .is_none()
        );
    }
}
