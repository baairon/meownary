//! Deattribution of a plain ZIP archive through its contents. The archive
//! carries no attribution itself, so every file inside is cleaned like a file
//! on disk and the copy is rebuilt around the result:
//!
//! * a changed entry is re-deflated (or stored again if it was stored), with
//!   its CRC and sizes recomputed in the local header, the data descriptor if
//!   it has one, and the central directory;
//! * every other byte of the archive is copied untouched, so unchanged entries
//!   keep their compressed data, and entry order, names, timestamps, external
//!   attributes, extra fields and the archive comment all survive;
//! * stored offsets after a changed entry are shifted, nothing else moves.
//!
//! The original is only read. Encrypted entries, methods other than stored and
//! deflate, and ZIP64 entries are skipped as `unsupported entry`, an entry over
//! 256 MiB uncompressed is skipped as `entry too large`, and an archive that
//! would expand past 1 GiB is refused. Nested archives are never opened.

use std::cell::Cell;
use std::fs;
use std::io::{self, BufWriter, Write};
use std::path::Path;

use miniz_oxide::deflate::compress_to_vec;
use miniz_oxide::inflate::decompress_to_vec_with_limit;

use crate::parsers;
use crate::scan::WindowedFile;
use crate::util::bytes::{slice, u16_le, u32_le};

use super::mem::{ArchiveOutcome, SliceView, deattribute_with};
use super::{Reason, check_output, is_deattributed};
use crate::edit::{EditError, fsio};

const LOCAL_SIG: &[u8] = b"PK\x03\x04";
const CENTRAL_SIG: &[u8] = b"PK\x01\x02";
const DESCRIPTOR_SIG: &[u8] = b"PK\x07\x08";
const EOCD_LEN: usize = 22;
const LOCAL_LEN: usize = 30;
const CENTRAL_LEN: usize = 46;
const STORED: u16 = 0;
const DEFLATED: u16 = 8;
const ENCRYPTED: u16 = 1;
const STRONG_ENCRYPTION: u16 = 1 << 6;
const HAS_DESCRIPTOR: u16 = 1 << 3;
/// An entry larger than this (uncompressed) is skipped.
const MAX_ENTRY: u64 = 256 * 1024 * 1024;
/// An archive larger than this (compressed, or uncompressed in total) is refused.
const MAX_TOTAL: u64 = 1024 * 1024 * 1024;
/// Deflate effort for re-compressed entries.
const LEVEL: u8 = 6;

/// One central-directory entry, as far as deattribution needs it.
struct Entry {
    /// Entry path, decoded lossily.
    name: String,
    /// Offset of the central record in the archive bytes.
    rec: usize,
    flags: u16,
    method: u16,
    crc: u32,
    csize: u64,
    size: u64,
    /// Offset of the local header as stored in the central record.
    stored_offset: u32,
    /// Absolute offset of the local header.
    local: usize,
    dir: bool,
}

impl Entry {
    /// The file name without its folders, used for identity hints.
    fn file_name(&self) -> &str {
        self.name.rsplit('/').next().unwrap_or(&self.name)
    }
}

/// Where one entry's pieces sit in the archive bytes.
struct Span {
    data_start: usize,
    data_end: usize,
    /// Length of the data descriptor after the data, 0 when there is none.
    descriptor: usize,
    /// Length of the local header with its name and extra field.
    header: usize,
}

/// An entry whose bytes are replaced in the copy.
struct Change {
    index: usize,
    start: usize,
    end: usize,
    bytes: Vec<u8>,
    crc: u32,
    csize: u32,
    size: u32,
}

/// What reading the archive found.
struct Analysis {
    arch: parsers::zip::ZipArchive,
    entries: Vec<Entry>,
    changes: Vec<Change>,
    brand: usize,
    patch: usize,
    skipped: Vec<(String, Reason)>,
}

/// CRC-32 (IEEE) of `data`.
fn crc32(data: &[u8]) -> u32 {
    const TABLE: [u32; 256] = {
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
    let mut crc = !0u32;
    for &b in data {
        crc = TABLE[((crc ^ u32::from(b)) & 0xFF) as usize] ^ (crc >> 8);
    }
    !crc
}

fn refuse(why: &str) -> EditError {
    EditError::Refused(why.to_string())
}

/// Deattribute every file inside the ZIP at `original`, writing the result to
/// `out` unless `dry_run`. The outcome always carries the entry skips;
/// `entries_cleaned == 0` means no copy was (or would be) written.
pub fn deattribute_zip(
    original: &Path,
    out: &Path,
    dry_run: bool,
) -> Result<ArchiveOutcome, EditError> {
    if is_deattributed(original) {
        return Err(refuse("the file is already a deattributed copy"));
    }
    let meta = fs::symlink_metadata(original)?;
    if meta.file_type().is_symlink() {
        return Err(EditError::Symlink(original.to_path_buf()));
    }
    if !meta.is_file() {
        return Err(refuse("not a regular file"));
    }
    if meta.len() > MAX_TOTAL {
        return Err(refuse("the archive is too large"));
    }
    let data = fs::read(original)?;
    if data.len() as u64 != meta.len() {
        return Err(EditError::Changed);
    }
    let found = analyze(&data)?;
    let outcome = ArchiveOutcome {
        output: out.to_path_buf(),
        entries_cleaned: found.changes.len(),
        brand: found.brand,
        patch: found.patch,
        skipped: found.skipped.clone(),
    };
    if found.changes.is_empty() {
        return Ok(outcome);
    }
    if dry_run {
        assemble(&data, &found, &mut io::sink())?;
        return Ok(outcome);
    }
    check_output(out)?;
    let modified = meta.modified().ok();
    let moved = Cell::new(false);
    let written = fsio::replace_atomic_with(out, |file| {
        #[cfg(unix)]
        file.set_permissions(meta.permissions())?;
        let mut w = BufWriter::new(&*file);
        assemble(&data, &found, &mut w).map_err(|e| match e {
            EditError::Io(e) => e,
            other => io::Error::other(other.to_string()),
        })?;
        w.flush()?;
        let same = fs::metadata(original)
            .is_ok_and(|m| m.len() == meta.len() && m.modified().ok() == modified);
        if !same {
            moved.set(true);
            return Err(io::Error::other("changed while it was being copied"));
        }
        Ok(())
    });
    if moved.get() {
        return Err(EditError::Changed);
    }
    written?;
    Ok(outcome)
}

/// How many files (not folders) the ZIP at `path` holds.
pub fn zip_file_count(path: &Path) -> Option<usize> {
    let view = WindowedFile::open(path).ok()?;
    let arch = parsers::zip::parse(&view)?;
    Some(
        arch.entries
            .iter()
            .filter(|e| !e.name.ends_with(b"/"))
            .count(),
    )
}

/// Read the archive, clean every supported entry in memory and collect the
/// replacements.
fn analyze(data: &[u8]) -> Result<Analysis, EditError> {
    let view = SliceView::new("archive.zip", data);
    let arch = parsers::zip::parse(&view).ok_or_else(|| refuse("not a readable zip"))?;
    if arch.zip64 {
        return Err(refuse("zip64 archives are not supported"));
    }
    let entries = read_central(data, &arch)?;
    let total: u64 = entries.iter().filter(|e| !e.dir).map(|e| e.size).sum();
    if total > MAX_TOTAL {
        return Err(refuse("the archive would expand past its size limit"));
    }

    let registry = parsers::registry();
    let cd = arch.cd_offset as usize;
    let mut out = Analysis {
        arch,
        entries: Vec::new(),
        changes: Vec::new(),
        brand: 0,
        patch: 0,
        skipped: Vec::new(),
    };
    for (index, e) in entries.iter().enumerate() {
        if e.dir {
            continue;
        }
        if unsupported(e) {
            out.skipped.push((e.name.clone(), Reason::UnsupportedEntry));
            continue;
        }
        let Some(span) = span_of(data, e, cd) else {
            out.skipped.push((e.name.clone(), Reason::UnsupportedEntry));
            continue;
        };
        if e.size == 0 {
            continue;
        }
        if e.size > MAX_ENTRY {
            out.skipped.push((e.name.clone(), Reason::EntryTooLarge));
            continue;
        }
        let Some(plain) = unpack(data, e, &span) else {
            out.skipped.push((e.name.clone(), Reason::UnsupportedEntry));
            continue;
        };
        let cleaned = deattribute_with(e.file_name(), &plain, &registry);
        for reason in cleaned.skipped {
            out.skipped.push((e.name.clone(), reason));
        }
        let Some(blanked) = cleaned.bytes else {
            continue;
        };
        match rebuild(data, e, &span, index, &blanked) {
            Some(change) => {
                out.brand += cleaned.brand;
                out.patch += cleaned.patch;
                out.changes.push(change);
            }
            None => out.skipped.push((e.name.clone(), Reason::UnsupportedEntry)),
        }
    }
    out.entries = entries;
    out.changes.sort_by_key(|c| c.start);
    let mut edge = 0usize;
    for c in &out.changes {
        if c.start < edge || c.end > cd {
            return Err(refuse("the archive's entries overlap"));
        }
        edge = c.end;
    }
    Ok(out)
}

/// Walk the central directory into entries, keeping every record's offset.
fn read_central(data: &[u8], arch: &parsers::zip::ZipArchive) -> Result<Vec<Entry>, EditError> {
    let bad = || refuse("the central directory is unreadable");
    let cd = usize::try_from(arch.cd_offset).map_err(|_| bad())?;
    let cd_end = cd
        .checked_add(usize::try_from(arch.cd_size).map_err(|_| bad())?)
        .filter(|&end| end <= data.len())
        .ok_or_else(bad)?;
    let shift = usize::try_from(arch.shift).map_err(|_| bad())?;
    let mut entries = Vec::new();
    let mut pos = cd;
    for _ in 0..arch.declared_entries {
        let head = slice(data, pos, CENTRAL_LEN).ok_or_else(bad)?;
        if &head[..4] != CENTRAL_SIG {
            return Err(bad());
        }
        let name_len = usize::from(u16_le(head, 28).ok_or_else(bad)?);
        let extra_len = usize::from(u16_le(head, 30).ok_or_else(bad)?);
        let comment_len = usize::from(u16_le(head, 32).ok_or_else(bad)?);
        let end = pos + CENTRAL_LEN + name_len + extra_len + comment_len;
        if end > cd_end {
            return Err(bad());
        }
        let name = &data[pos + CENTRAL_LEN..pos + CENTRAL_LEN + name_len];
        let stored_offset = u32_le(head, 42).ok_or_else(bad)?;
        entries.push(Entry {
            name: String::from_utf8_lossy(name).into_owned(),
            rec: pos,
            flags: u16_le(head, 8).ok_or_else(bad)?,
            method: u16_le(head, 10).ok_or_else(bad)?,
            crc: u32_le(head, 16).ok_or_else(bad)?,
            csize: u64::from(u32_le(head, 20).ok_or_else(bad)?),
            size: u64::from(u32_le(head, 24).ok_or_else(bad)?),
            stored_offset,
            local: usize::try_from(stored_offset)
                .ok()
                .and_then(|o| o.checked_add(shift))
                .ok_or_else(bad)?,
            dir: name.ends_with(b"/"),
        });
        pos = end;
    }
    Ok(entries)
}

/// Whether the entry cannot be read: encrypted, an unknown method, or ZIP64.
fn unsupported(e: &Entry) -> bool {
    e.flags & (ENCRYPTED | STRONG_ENCRYPTION) != 0
        || !matches!(e.method, STORED | DEFLATED)
        || e.csize == u64::from(u32::MAX)
        || e.size == u64::from(u32::MAX)
        || e.stored_offset == u32::MAX
}

/// Locate the entry's local header, data and descriptor, or `None` when the
/// layout does not hold together.
fn span_of(data: &[u8], e: &Entry, cd: usize) -> Option<Span> {
    let head = slice(data, e.local, LOCAL_LEN)?;
    if &head[..4] != LOCAL_SIG || u16_le(head, 8)? != e.method {
        return None;
    }
    if u32_le(head, 18)? == u32::MAX || u32_le(head, 22)? == u32::MAX {
        return None;
    }
    let header = LOCAL_LEN + usize::from(u16_le(head, 26)?) + usize::from(u16_le(head, 28)?);
    let data_start = e.local.checked_add(header)?;
    let data_end = data_start.checked_add(usize::try_from(e.csize).ok()?)?;
    if data_end > cd {
        return None;
    }
    let descriptor = if e.flags & HAS_DESCRIPTOR != 0 {
        descriptor_len(data, e, data_end, cd)?
    } else {
        0
    };
    Some(Span {
        data_start,
        data_end,
        descriptor,
        header,
    })
}

/// Length of the data descriptor at `at`: with or without its signature, and
/// agreeing with the central record.
fn descriptor_len(data: &[u8], e: &Entry, at: usize, cd: usize) -> Option<usize> {
    let (len, body) = if slice(data, at, 4)? == DESCRIPTOR_SIG {
        (16, at + 4)
    } else {
        (12, at)
    };
    if at + len > cd
        || u32_le(data, body)? != e.crc
        || u64::from(u32_le(data, body + 4)?) != e.csize
        || u64::from(u32_le(data, body + 8)?) != e.size
    {
        return None;
    }
    Some(len)
}

/// The entry's uncompressed bytes, checked against its recorded size and CRC.
fn unpack(data: &[u8], e: &Entry, span: &Span) -> Option<Vec<u8>> {
    let packed = data.get(span.data_start..span.data_end)?;
    let size = usize::try_from(e.size).ok()?;
    let plain = match e.method {
        STORED => packed.to_vec(),
        _ => decompress_to_vec_with_limit(packed, size).ok()?,
    };
    (plain.len() == size && crc32(&plain) == e.crc).then_some(plain)
}

/// The replacement bytes for one entry: its local header with the new CRC and
/// sizes, the new data, and a data descriptor if the entry had one.
fn rebuild(data: &[u8], e: &Entry, span: &Span, index: usize, plain: &[u8]) -> Option<Change> {
    let packed = match e.method {
        STORED => plain.to_vec(),
        _ => compress_to_vec(plain, LEVEL),
    };
    let crc = crc32(plain);
    let csize = u32::try_from(packed.len()).ok()?;
    let size = u32::try_from(plain.len()).ok()?;
    let mut bytes = data.get(e.local..e.local + span.header)?.to_vec();
    bytes[14..18].copy_from_slice(&crc.to_le_bytes());
    bytes[18..22].copy_from_slice(&csize.to_le_bytes());
    bytes[22..26].copy_from_slice(&size.to_le_bytes());
    bytes.extend_from_slice(&packed);
    if span.descriptor > 0 {
        if span.descriptor == 16 {
            bytes.extend_from_slice(DESCRIPTOR_SIG);
        }
        bytes.extend_from_slice(&crc.to_le_bytes());
        bytes.extend_from_slice(&csize.to_le_bytes());
        bytes.extend_from_slice(&size.to_le_bytes());
    }
    Some(Change {
        index,
        start: e.local,
        end: span.data_end + span.descriptor,
        bytes,
        crc,
        csize,
        size,
    })
}

/// Write the copy: the original with each changed entry replaced, the central
/// directory patched to match, and the end record pointing at it.
fn assemble(data: &[u8], found: &Analysis, w: &mut dyn Write) -> Result<(), EditError> {
    let arch = &found.arch;
    let cd = arch.cd_offset as usize;
    let cd_end = cd + arch.cd_size as usize;
    let eocd = (arch.comment_offset as usize)
        .checked_sub(EOCD_LEN)
        .filter(|&at| at >= cd_end)
        .ok_or_else(|| refuse("the end record is unreadable"))?;

    // After each change, how far later offsets have moved.
    let mut shifts: Vec<(usize, i64)> = Vec::with_capacity(found.changes.len());
    let mut moved = 0i64;
    for c in &found.changes {
        moved += c.bytes.len() as i64 - (c.end - c.start) as i64;
        shifts.push((c.start, moved));
    }
    let moved_before = |pos: usize| -> i64 {
        match shifts.partition_point(|&(start, _)| start < pos) {
            0 => 0,
            n => shifts[n - 1].1,
        }
    };

    let mut central = data[cd..cd_end].to_vec();
    for e in &found.entries {
        let rec = e.rec - cd;
        let offset = i64::from(e.stored_offset) + moved_before(e.local);
        let offset = u32::try_from(offset).map_err(|_| refuse("the copy would be too large"))?;
        central[rec + 42..rec + 46].copy_from_slice(&offset.to_le_bytes());
    }
    for c in &found.changes {
        let rec = found.entries[c.index].rec - cd;
        central[rec + 16..rec + 20].copy_from_slice(&c.crc.to_le_bytes());
        central[rec + 20..rec + 24].copy_from_slice(&c.csize.to_le_bytes());
        central[rec + 24..rec + 28].copy_from_slice(&c.size.to_le_bytes());
    }

    let mut cursor = 0usize;
    for c in &found.changes {
        w.write_all(&data[cursor..c.start])?;
        w.write_all(&c.bytes)?;
        cursor = c.end;
    }
    w.write_all(&data[cursor..cd])?;
    w.write_all(&central)?;
    w.write_all(&data[cd_end..eocd])?;
    let mut end_record = data[eocd..].to_vec();
    let stored_cd =
        u32_le(&end_record, 16).ok_or_else(|| refuse("the end record is unreadable"))?;
    let stored_cd = u32::try_from(i64::from(stored_cd) + moved)
        .map_err(|_| refuse("the copy would be too large"))?;
    end_record[16..20].copy_from_slice(&stored_cd.to_le_bytes());
    w.write_all(&end_record)?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::mem::tests::fake_pe;
    use super::*;
    use crate::parsers::zip::parse;
    use crate::scan::MemView;

    /// One entry of a synthetic archive.
    pub(crate) struct Item<'a> {
        pub name: &'a str,
        pub data: &'a [u8],
        pub deflate: bool,
        pub flags: u16,
    }

    pub(crate) fn item<'a>(name: &'a str, data: &'a [u8], deflate: bool) -> Item<'a> {
        Item {
            name,
            data,
            deflate,
            flags: 0,
        }
    }

    /// Build a ZIP with stored and deflated entries, a data descriptor on
    /// entries flagged for one, and an archive comment.
    pub(crate) fn build(items: &[Item], comment: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for it in items {
            let packed = if it.deflate {
                compress_to_vec(it.data, 6)
            } else {
                it.data.to_vec()
            };
            let method: u16 = if it.deflate { DEFLATED } else { STORED };
            let crc = crc32(it.data);
            let offset = out.len() as u32;
            let descriptor = it.flags & HAS_DESCRIPTOR != 0;
            let (lcrc, lc, lu) = if descriptor {
                (0, 0, 0)
            } else {
                (crc, packed.len() as u32, it.data.len() as u32)
            };
            out.extend_from_slice(LOCAL_SIG);
            out.extend_from_slice(&20u16.to_le_bytes());
            out.extend_from_slice(&it.flags.to_le_bytes());
            out.extend_from_slice(&method.to_le_bytes());
            out.extend_from_slice(&[0x21, 0x08, 0x4a, 0x5b]);
            out.extend_from_slice(&lcrc.to_le_bytes());
            out.extend_from_slice(&lc.to_le_bytes());
            out.extend_from_slice(&lu.to_le_bytes());
            out.extend_from_slice(&(it.name.len() as u16).to_le_bytes());
            out.extend_from_slice(&4u16.to_le_bytes());
            out.extend_from_slice(it.name.as_bytes());
            out.extend_from_slice(b"\xfe\xca\x00\x00");
            out.extend_from_slice(&packed);
            if descriptor {
                out.extend_from_slice(DESCRIPTOR_SIG);
                out.extend_from_slice(&crc.to_le_bytes());
                out.extend_from_slice(&(packed.len() as u32).to_le_bytes());
                out.extend_from_slice(&(it.data.len() as u32).to_le_bytes());
            }

            central.extend_from_slice(CENTRAL_SIG);
            central.extend_from_slice(&0x031eu16.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&it.flags.to_le_bytes());
            central.extend_from_slice(&method.to_le_bytes());
            central.extend_from_slice(&[0x21, 0x08, 0x4a, 0x5b]);
            central.extend_from_slice(&crc.to_le_bytes());
            central.extend_from_slice(&(packed.len() as u32).to_le_bytes());
            central.extend_from_slice(&(it.data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(it.name.len() as u16).to_le_bytes());
            central.extend_from_slice(&4u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&[0; 4]);
            central.extend_from_slice(&0x81a4_0000u32.to_le_bytes());
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(it.name.as_bytes());
            central.extend_from_slice(b"\xfe\xca\x00\x00");
        }
        let cd_off = out.len() as u32;
        out.extend_from_slice(&central);
        out.extend_from_slice(b"PK\x05\x06");
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&(items.len() as u16).to_le_bytes());
        out.extend_from_slice(&(items.len() as u16).to_le_bytes());
        out.extend_from_slice(&(central.len() as u32).to_le_bytes());
        out.extend_from_slice(&cd_off.to_le_bytes());
        out.extend_from_slice(&(comment.len() as u16).to_le_bytes());
        out.extend_from_slice(comment);
        out
    }

    /// An entry as read back from a copy: record bytes plus uncompressed data.
    struct Back {
        name: String,
        record: Vec<u8>,
        packed: Vec<u8>,
        plain: Vec<u8>,
        method: u16,
    }

    /// Re-parse `bytes` as a ZIP and check every CRC and size.
    fn read_back(bytes: &[u8]) -> (Vec<Back>, Vec<u8>) {
        let view = MemView::new("x.zip", bytes.to_vec());
        let arch = parse(&view).expect("valid zip");
        let entries = read_central(bytes, &arch).expect("central directory");
        assert_eq!(entries.len() as u64, arch.declared_entries);
        let mut back = Vec::new();
        for e in &entries {
            let span = span_of(bytes, e, arch.cd_offset as usize).expect("local entry");
            let packed = bytes[span.data_start..span.data_end].to_vec();
            let plain = unpack(bytes, e, &span).expect("crc and size match");
            let local = &bytes[e.local..e.local + span.header];
            if span.descriptor == 0 {
                assert_eq!(u32_le(local, 14), Some(crc32(&plain)));
                assert_eq!(u32_le(local, 18), Some(packed.len() as u32));
                assert_eq!(u32_le(local, 22), Some(plain.len() as u32));
            }
            let len = CENTRAL_LEN + e.name.len() + 4;
            back.push(Back {
                name: e.name.clone(),
                record: bytes[e.rec..e.rec + len].to_vec(),
                packed,
                plain,
                method: e.method,
            });
        }
        let comment = bytes[arch.comment_offset as usize..arch.end as usize].to_vec();
        (back, comment)
    }

    fn fixture() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let exe = fake_pe(b"patched by Invented");
        let text = b"nothing to see here, just plain words repeated repeated repeated".to_vec();
        (exe.clone(), exe, text)
    }

    #[test]
    fn crc32_matches_the_standard_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn credits_inside_stored_and_deflated_entries_are_blanked() {
        let dir = tempfile::tempdir().unwrap();
        let (stored_exe, deflated_exe, text) = fixture();
        let original = build(
            &[
                item("bin/stored.exe", &stored_exe, false),
                item("notes.txt", &text, true),
                item("bin/deflated.exe", &deflated_exe, true),
            ],
            b"an invented comment",
        );
        let path = dir.path().join("bundle.zip");
        fs::write(&path, &original).unwrap();
        let out = dir.path().join("bundle.deattributed.zip");

        let done = deattribute_zip(&path, &out, false).unwrap();
        assert_eq!((done.entries_cleaned, done.brand, done.patch), (2, 0, 2));
        assert!(done.skipped.is_empty(), "{:?}", done.skipped);
        assert_eq!(done.output, out);
        assert_eq!(fs::read(&path).unwrap(), original, "original untouched");

        let copy = fs::read(&out).unwrap();
        let (before, comment_before) = read_back(&original);
        let (after, comment_after) = read_back(&copy);
        assert_eq!(comment_before, comment_after);
        assert_eq!(before.len(), after.len());
        for (b, a) in before.iter().zip(&after) {
            assert_eq!(b.name, a.name);
            assert_eq!(b.method, a.method);
            assert_eq!(b.plain.len(), a.plain.len());
        }
        for i in [0, 2] {
            assert!(!after[i].plain.windows(10).any(|w| w == b"patched by"));
            assert!(before[i].plain.windows(10).any(|w| w == b"patched by"));
        }
        assert_eq!(after[1].plain, text);
        assert_eq!(after[1].packed, before[1].packed, "untouched entry kept");
        assert_eq!(after[1].record[..42], before[1].record[..42]);
    }

    #[test]
    fn entry_order_timestamps_attributes_and_descriptors_survive() {
        let dir = tempfile::tempdir().unwrap();
        let (_, exe, text) = fixture();
        let mut with_descriptor = item("late.exe", &exe, true);
        with_descriptor.flags = HAS_DESCRIPTOR;
        let original = build(
            &[
                item("first.txt", &text, true),
                with_descriptor,
                item("last.txt", &text, false),
            ],
            b"",
        );
        let path = dir.path().join("a.zip");
        fs::write(&path, &original).unwrap();
        let out = dir.path().join("a.deattributed.zip");
        let done = deattribute_zip(&path, &out, false).unwrap();
        assert_eq!(done.entries_cleaned, 1);

        let (before, _) = read_back(&original);
        let (after, _) = read_back(&fs::read(&out).unwrap());
        let names: Vec<_> = after.iter().map(|b| b.name.as_str()).collect();
        assert_eq!(names, ["first.txt", "late.exe", "last.txt"]);
        for (b, a) in before.iter().zip(&after) {
            // Version, flags, method, time and date, then attributes.
            assert_eq!(b.record[4..16], a.record[4..16]);
            assert_eq!(b.record[28..42], a.record[28..42]);
            assert_eq!(b.record[42 + 4..], a.record[42 + 4..]);
        }
        assert!(!after[1].plain.windows(10).any(|w| w == b"patched by"));
        assert_eq!(after[0].packed, before[0].packed);
        assert_eq!(after[2].packed, before[2].packed);
    }

    #[test]
    fn a_dry_run_computes_everything_and_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (_, exe, _) = fixture();
        let original = build(&[item("x.exe", &exe, true)], b"");
        let path = dir.path().join("d.zip");
        fs::write(&path, &original).unwrap();
        let out = dir.path().join("d.deattributed.zip");
        let done = deattribute_zip(&path, &out, true).unwrap();
        assert_eq!((done.entries_cleaned, done.patch), (1, 1));
        assert!(!out.exists());
        assert_eq!(fs::read(&path).unwrap(), original);
        let names: Vec<_> = fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(names.len(), 1, "no temp file left");
    }

    #[test]
    fn an_archive_with_nothing_inside_to_blank_writes_no_copy() {
        let dir = tempfile::tempdir().unwrap();
        let (_, _, text) = fixture();
        let original = build(
            &[item("a.txt", &text, true), item("b.txt", &text, false)],
            b"",
        );
        let path = dir.path().join("plain.zip");
        fs::write(&path, &original).unwrap();
        let out = dir.path().join("plain.deattributed.zip");
        let done = deattribute_zip(&path, &out, false).unwrap();
        assert_eq!(done.entries_cleaned, 0);
        assert!(!out.exists());
    }

    #[test]
    fn encrypted_and_unknown_method_entries_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let (_, exe, _) = fixture();
        let mut secret = item("secret.exe", &exe, false);
        secret.flags = ENCRYPTED;
        let mut odd = build(&[item("odd.exe", &exe, false)], b"");
        // Method 12 (bzip2) in both headers.
        odd[8] = 12;
        let cd = u32_le(&odd, odd.len() - 6).unwrap() as usize;
        odd[cd + 10] = 12;

        let original = build(&[secret, item("ok.exe", &exe, false)], b"");
        let path = dir.path().join("e.zip");
        fs::write(&path, &original).unwrap();
        let out = dir.path().join("e.deattributed.zip");
        let done = deattribute_zip(&path, &out, false).unwrap();
        assert_eq!(done.entries_cleaned, 1);
        assert_eq!(
            done.skipped,
            vec![("secret.exe".to_string(), Reason::UnsupportedEntry)]
        );
        let (after, _) = read_back(&fs::read(&out).unwrap());
        assert!(after[0].plain.windows(10).any(|w| w == b"patched by"));
        assert!(!after[1].plain.windows(10).any(|w| w == b"patched by"));

        let path = dir.path().join("o.zip");
        fs::write(&path, &odd).unwrap();
        let out = dir.path().join("o.deattributed.zip");
        let done = deattribute_zip(&path, &out, false).unwrap();
        assert_eq!(done.entries_cleaned, 0);
        assert_eq!(
            done.skipped,
            vec![("odd.exe".to_string(), Reason::UnsupportedEntry)]
        );
        assert!(!out.exists());
    }

    #[test]
    fn a_rerun_replaces_the_copy() {
        let dir = tempfile::tempdir().unwrap();
        let (_, exe, _) = fixture();
        let original = build(&[item("x.exe", &exe, true)], b"");
        let path = dir.path().join("r.zip");
        fs::write(&path, &original).unwrap();
        let out = dir.path().join("r.deattributed.zip");
        fs::write(&out, b"stale").unwrap();
        deattribute_zip(&path, &out, false).unwrap();
        let first = fs::read(&out).unwrap();
        assert_ne!(first, b"stale");
        deattribute_zip(&path, &out, false).unwrap();
        assert_eq!(fs::read(&out).unwrap(), first);
        let entries = fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(entries, 2, "the copy is replaced, not stacked");
    }

    #[test]
    fn a_nested_archive_is_not_opened() {
        let dir = tempfile::tempdir().unwrap();
        let (_, exe, _) = fixture();
        let inner = build(&[item("deep.exe", &exe, true)], b"");
        let original = build(&[item("inner.zip", &inner, false)], b"");
        let path = dir.path().join("n.zip");
        fs::write(&path, &original).unwrap();
        let out = dir.path().join("n.deattributed.zip");
        let done = deattribute_zip(&path, &out, false).unwrap();
        assert_eq!(done.entries_cleaned, 0);
        assert!(done.skipped.is_empty());
        assert!(!out.exists());
    }

    #[test]
    fn garbage_and_copies_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("g.zip");
        fs::write(&path, b"PK\x03\x04 but not really a zip").unwrap();
        let out = dir.path().join("g.deattributed.zip");
        assert!(matches!(
            deattribute_zip(&path, &out, false),
            Err(EditError::Refused(_))
        ));
        let copy = dir.path().join("h.deattributed.zip");
        fs::write(&copy, b"x").unwrap();
        assert!(matches!(
            deattribute_zip(&copy, &out, false),
            Err(EditError::Refused(_))
        ));
        assert_eq!(zip_file_count(&path), None);
    }

    #[test]
    fn file_counts_leave_folders_out() {
        let dir = tempfile::tempdir().unwrap();
        let (_, _, text) = fixture();
        let original = build(
            &[
                item("folder/", b"", false),
                item("folder/a.txt", &text, true),
                item("b.txt", &text, false),
            ],
            b"",
        );
        let path = dir.path().join("c.zip");
        fs::write(&path, &original).unwrap();
        assert_eq!(zip_file_count(&path), Some(2));
    }
}
