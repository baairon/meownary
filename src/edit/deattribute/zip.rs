//! Deattribution of a plain ZIP archive through its contents. The archive
//! carries no attribution itself, so every file inside is cleaned like a file
//! on disk and the copy is rebuilt around the result:
//!
//! * a changed entry is re-deflated (or stored again if it was stored), with
//!   its CRC and sizes recomputed in the local header (unless a data
//!   descriptor left them zero there), the data descriptor if it has one, and
//!   the central directory;
//! * every other byte of the archive is copied untouched, so unchanged entries
//!   keep their compressed data, and entry order, names, timestamps, external
//!   attributes, extra fields and the archive comment all survive;
//! * stored offsets after a changed entry are shifted, including those in a
//!   ZIP64 end record and locator that some writers add without needing them;
//!   nothing else moves.
//!
//! The original is only read. Encrypted entries and methods other than stored
//! and deflate are skipped as `unsupported entry`, an entry over 256 MiB
//! uncompressed is skipped as `entry too large`, and a nested archive is named
//! and never opened. A ZIP64 or multi-disk archive, one whose changed entry
//! shares bytes with another entry, and one that would expand past 1 GiB are
//! refused. A signed package (a signed JAR layout, an APK signing block, a
//! wheel's RECORD, a NuGet signature) is left alone whole, as any change would
//! break its signature.

use std::fs;
use std::io::{self, BufWriter, Write};
use std::path::Path;

use miniz_oxide::deflate::compress_to_vec;
use miniz_oxide::inflate::decompress_to_vec_with_limit;

use crate::parsers;
use crate::scan::{WindowedFile, guard};
use crate::util::bytes::{slice, u16_le, u32_le, u64_le};

use super::mem::{ArchiveOutcome, MemOutcome, SliceView, deattribute_with_mode, is_container};
use super::{Mode, Reason, check_output, is_deattributed};
use crate::edit::{EditError, fsio};

const LOCAL_SIG: &[u8] = b"PK\x03\x04";
const CENTRAL_SIG: &[u8] = b"PK\x01\x02";
const DESCRIPTOR_SIG: &[u8] = b"PK\x07\x08";
const ZIP64_END_SIG: &[u8] = b"PK\x06\x06";
const ZIP64_LOCATOR_SIG: &[u8] = b"PK\x06\x07";
const APK_SIG_BLOCK: &[u8] = b"APK Sig Block 42";
const EOCD_LEN: usize = 22;
const LOCAL_LEN: usize = 30;
const CENTRAL_LEN: usize = 46;
const ZIP64_END_LEN: usize = 56;
const ZIP64_LOCATOR_LEN: usize = 20;
const ZIP64_EXTRA: u16 = 0x0001;
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
    /// Offset of the classic end record.
    eocd: usize,
    /// Offsets of a ZIP64 end record and its locator, when the archive has them.
    zip64_end: Option<(usize, usize)>,
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

fn multi_disk() -> EditError {
    refuse("archives split over several disks are not supported")
}

/// Deattribute every file inside the ZIP at `original`, writing the result to
/// `out` unless `dry_run`. The outcome always carries the entry skips;
/// `entries_cleaned == 0` means no copy was (or would be) written. A signed
/// package comes back that way too, with the entry that signs it skipped as
/// `signed package`.
pub fn deattribute_zip(
    original: &Path,
    out: &Path,
    dry_run: bool,
) -> Result<ArchiveOutcome, EditError> {
    deattribute_zip_mode(original, out, dry_run, Mode::Basic)
}

pub fn deattribute_zip_mode(
    original: &Path,
    out: &Path,
    dry_run: bool,
    mode: Mode,
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
    let found = analyze_mode(&data, mode)?;
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
    let (tmp, file) = fsio::create_temp_beside(out)?;
    let result = (|| {
        let mut w = BufWriter::new(&file);
        assemble(&data, &found, &mut w)?;
        w.flush()?;
        drop(w);
        file.sync_all()?;
        drop(file);
        let same = fs::metadata(original)
            .is_ok_and(|m| m.len() == meta.len() && m.modified().ok() == modified);
        if !same {
            return Err(EditError::Changed);
        }
        super::tar::finish(&tmp, out, &meta)
    })();
    match result {
        Ok(()) => Ok(outcome),
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
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

/// Whether cleaning the copy at `output` again in `mode` would change no entry.
pub fn verify_copy(output: &Path, mode: Mode) -> bool {
    let Ok(data) = fs::read(output) else {
        return false;
    };
    analyze_mode(&data, mode).is_ok_and(|found| found.changes.is_empty())
}

/// Whether an entry that came back with nothing to blank is itself an archive,
/// which is then named as a nested archive instead of passing as clean. The
/// tar walker asks the same question of its entries.
pub(super) fn nested(cleaned: &MemOutcome, name: &str, data: &[u8]) -> bool {
    if cleaned.bytes.is_some() || !cleaned.skipped.is_empty() {
        return false;
    }
    let view = SliceView::new(name, data);
    guard::guarded(|| parsers::identify(&view).0).is_ok_and(is_container)
}

/// Read the archive, clean every supported entry in memory and collect the
/// replacements.
#[cfg(test)]
fn analyze(data: &[u8]) -> Result<Analysis, EditError> {
    analyze_mode(data, Mode::Basic)
}

fn analyze_mode(data: &[u8], mode: Mode) -> Result<Analysis, EditError> {
    let view = SliceView::new("archive.zip", data);
    let arch = parsers::zip::parse(&view).ok_or_else(|| refuse("not a readable zip"))?;
    if arch.zip64 {
        return Err(refuse("zip64 archives are not supported"));
    }
    let cd = arch.cd_offset as usize;
    let cd_end = cd + arch.cd_size as usize;
    let eocd = end_record(data, &arch, cd_end)?;
    let zip64_end = zip64_end(data, &arch, cd_end, eocd)?;
    let entries = read_central(data, &arch)?;
    let mut out = Analysis {
        arch,
        entries: Vec::new(),
        changes: Vec::new(),
        brand: 0,
        patch: 0,
        skipped: Vec::new(),
        eocd,
        zip64_end,
    };
    if let Some(name) = signature(data, cd, &entries) {
        out.skipped.push((name, Reason::SignedContainer));
        out.entries = entries;
        return Ok(out);
    }

    let spans: Vec<Option<Span>> = entries.iter().map(|e| span_of(data, e, cd)).collect();
    let total: u64 = entries
        .iter()
        .zip(&spans)
        .filter(|(e, span)| !e.dir && !unsupported(e) && span.is_some() && e.size <= MAX_ENTRY)
        .map(|(e, _)| e.size)
        .sum();
    if total > MAX_TOTAL {
        return Err(refuse("the archive would expand past its size limit"));
    }

    let registry = parsers::registry();
    for (index, (e, span)) in entries.iter().zip(&spans).enumerate() {
        if e.dir {
            continue;
        }
        if unsupported(e) {
            out.skipped.push((e.name.clone(), Reason::UnsupportedEntry));
            continue;
        }
        let Some(span) = span else {
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
        let Some(plain) = unpack(data, e, span) else {
            out.skipped.push((e.name.clone(), Reason::UnsupportedEntry));
            continue;
        };
        let cleaned = deattribute_with_mode(e.file_name(), &plain, &registry, mode);
        if nested(&cleaned, e.file_name(), &plain) {
            out.skipped.push((e.name.clone(), Reason::NestedArchive));
        }
        for &reason in &cleaned.skipped {
            out.skipped.push((e.name.clone(), reason));
        }
        let Some(blanked) = cleaned.bytes else {
            continue;
        };
        match rebuild(data, e, span, index, &blanked) {
            Some(change) => {
                out.brand += cleaned.brand;
                out.patch += cleaned.patch;
                out.changes.push(change);
            }
            None => out.skipped.push((e.name.clone(), Reason::UnsupportedEntry)),
        }
    }
    out.changes.sort_by_key(|c| c.start);
    check_overlap(&entries, &spans, &out.changes, cd)?;
    out.entries = entries;
    Ok(out)
}

/// Offset of the classic end record, refusing an archive split over disks.
fn end_record(
    data: &[u8],
    arch: &parsers::zip::ZipArchive,
    cd_end: usize,
) -> Result<usize, EditError> {
    let bad = || refuse("the end record is unreadable");
    let eocd = (arch.comment_offset as usize)
        .checked_sub(EOCD_LEN)
        .filter(|&at| at >= cd_end)
        .ok_or_else(bad)?;
    let rec = slice(data, eocd, EOCD_LEN).ok_or_else(bad)?;
    let field = |at| u16_le(rec, at).ok_or_else(bad);
    let (disk, cd_disk, on_disk, total) = (field(4)?, field(6)?, field(8)?, field(10)?);
    if disk != 0 || cd_disk != 0 || on_disk != total {
        return Err(multi_disk());
    }
    Ok(eocd)
}

/// The ZIP64 end record and locator some writers (`zip -fz`, streaming ones)
/// add even when no classic field is saturated, as (record, locator) offsets.
/// Readers that find a locator trust the record over the classic fields, so it
/// must agree with them now and is shifted along with them in the copy.
fn zip64_end(
    data: &[u8],
    arch: &parsers::zip::ZipArchive,
    cd_end: usize,
    eocd: usize,
) -> Result<Option<(usize, usize)>, EditError> {
    let Some(loc) = eocd
        .checked_sub(ZIP64_LOCATOR_LEN)
        .filter(|&at| at >= cd_end && slice(data, at, 4) == Some(ZIP64_LOCATOR_SIG))
    else {
        return Ok(None);
    };
    let bad = || refuse("the zip64 end record is unreadable");
    let l = slice(data, loc, ZIP64_LOCATOR_LEN).ok_or_else(bad)?;
    let (rec_disk, stored, disks) = (
        u32_le(l, 4).ok_or_else(bad)?,
        u64_le(l, 8).ok_or_else(bad)?,
        u32_le(l, 16).ok_or_else(bad)?,
    );
    if rec_disk != 0 || disks > 1 {
        return Err(multi_disk());
    }
    let rec = usize::try_from(stored)
        .ok()
        .and_then(|at| at.checked_add(usize::try_from(arch.shift).ok()?))
        .filter(|&at| at >= cd_end && at.saturating_add(ZIP64_END_LEN) <= loc)
        .ok_or_else(bad)?;
    let r = slice(data, rec, ZIP64_END_LEN).ok_or_else(bad)?;
    if &r[..4] != ZIP64_END_SIG {
        return Err(bad());
    }
    if u32_le(r, 16) != Some(0) || u32_le(r, 20) != Some(0) {
        return Err(multi_disk());
    }
    let on_disk = u64_le(r, 24).ok_or_else(bad)?;
    let total = u64_le(r, 32).ok_or_else(bad)?;
    let size = u64_le(r, 40).ok_or_else(bad)?;
    let offset = u64_le(r, 48).ok_or_else(bad)?;
    if on_disk != total
        || total != arch.declared_entries
        || size != arch.cd_size
        || offset.checked_add(arch.shift) != Some(arch.cd_offset)
    {
        return Err(refuse("the zip64 end record disagrees with the end record"));
    }
    Ok(Some((rec, loc)))
}

/// The entry (or block) that marks the archive as a signed package, whose
/// signature or hash list any changed entry would break.
fn signature(data: &[u8], cd: usize, entries: &[Entry]) -> Option<String> {
    if cd >= APK_SIG_BLOCK.len() && data.get(cd - APK_SIG_BLOCK.len()..cd) == Some(APK_SIG_BLOCK) {
        return Some("<apk signing block>".into());
    }
    entries
        .iter()
        .find(|e| signs(&e.name))
        .map(|e| e.name.clone())
}

/// Whether an entry path is a signature or a signed hash list: JAR signature
/// files, a wheel's RECORD, or a NuGet package signature.
fn signs(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    if let Some(file) = upper.strip_prefix("META-INF/")
        && !file.contains('/')
        && [".SF", ".RSA", ".DSA", ".EC"]
            .iter()
            .any(|ext| file.len() > ext.len() && file.ends_with(ext))
    {
        return true;
    }
    upper == ".SIGNATURE.P7S"
        || (upper.ends_with(".DIST-INFO/RECORD") && upper.matches('/').count() == 1)
}

/// Refuse when a changed entry's bytes are shared with any other entry: two
/// records naming one local header, or a local header inside another entry's
/// data. Rewriting such bytes would corrupt the other entry, or leave it
/// holding the very credit that was blanked here.
fn check_overlap(
    entries: &[Entry],
    spans: &[Option<Span>],
    changes: &[Change],
    cd: usize,
) -> Result<(), EditError> {
    let overlap = || refuse("the archive's entries overlap");
    let mut ranges: Vec<(usize, usize)> = entries
        .iter()
        .zip(spans)
        .map(|(e, span)| {
            let end = span
                .as_ref()
                .map_or(e.local.saturating_add(LOCAL_LEN), |s| {
                    s.data_end + s.descriptor
                });
            (e.local, end)
        })
        .collect();
    ranges.sort_unstable();
    // The furthest any range reaches among those sorted before each index.
    let reach: Vec<usize> = ranges
        .iter()
        .scan(0usize, |far, r| {
            *far = (*far).max(r.1);
            Some(*far)
        })
        .collect();
    for c in changes {
        if c.end > cd {
            return Err(overlap());
        }
        let before = ranges.partition_point(|r| r.0 < c.start);
        if before > 0 && reach[before - 1] > c.start {
            return Err(overlap());
        }
        // The change's own range starts at `c.start`; any other one starting
        // inside it overlaps.
        if ranges.partition_point(|r| r.0 < c.end) - before > 1 {
            return Err(overlap());
        }
    }
    Ok(())
}

/// Whether an extra field carries a ZIP64 record.
fn has_zip64_extra(extra: &[u8]) -> bool {
    let mut i = 0usize;
    while let (Some(id), Some(len)) = (u16_le(extra, i), u16_le(extra, i + 2)) {
        if id == ZIP64_EXTRA {
            return true;
        }
        i += 4 + usize::from(len);
    }
    false
}

/// Walk the central directory into entries, keeping every record's offset. A
/// record on another disk or with any ZIP64 field refuses the archive, since
/// the offsets rewritten here would no longer be the ones readers use.
fn read_central(data: &[u8], arch: &parsers::zip::ZipArchive) -> Result<Vec<Entry>, EditError> {
    let bad = || refuse("the central directory is unreadable");
    let zip64 = || refuse("zip64 entries are not supported");
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
        if u16_le(head, 34) != Some(0) {
            return Err(multi_disk());
        }
        let name = &data[pos + CENTRAL_LEN..pos + CENTRAL_LEN + name_len];
        let extra = &data[pos + CENTRAL_LEN + name_len..pos + CENTRAL_LEN + name_len + extra_len];
        let csize = u32_le(head, 20).ok_or_else(bad)?;
        let size = u32_le(head, 24).ok_or_else(bad)?;
        let stored_offset = u32_le(head, 42).ok_or_else(bad)?;
        if [csize, size, stored_offset].contains(&u32::MAX) || has_zip64_extra(extra) {
            return Err(zip64());
        }
        entries.push(Entry {
            name: String::from_utf8_lossy(name).into_owned(),
            rec: pos,
            flags: u16_le(head, 8).ok_or_else(bad)?,
            method: u16_le(head, 10).ok_or_else(bad)?,
            crc: u32_le(head, 16).ok_or_else(bad)?,
            csize: u64::from(csize),
            size: u64::from(size),
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

/// Whether the entry cannot be read: encrypted or an unknown method.
fn unsupported(e: &Entry) -> bool {
    e.flags & (ENCRYPTED | STRONG_ENCRYPTION) != 0 || !matches!(e.method, STORED | DEFLATED)
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
/// sizes, the new data, and a data descriptor if the entry had one. `None` when
/// the local header carries a ZIP64 extra, whose sizes would go stale.
fn rebuild(data: &[u8], e: &Entry, span: &Span, index: usize, plain: &[u8]) -> Option<Change> {
    let packed = match e.method {
        STORED => plain.to_vec(),
        _ => compress_to_vec(plain, LEVEL),
    };
    let crc = crc32(plain);
    let csize = u32::try_from(packed.len()).ok()?;
    let size = u32::try_from(plain.len()).ok()?;
    let mut bytes = data.get(e.local..e.local + span.header)?.to_vec();
    let name_len = usize::from(u16_le(&bytes, 26)?);
    if has_zip64_extra(bytes.get(LOCAL_LEN + name_len..)?) {
        return None;
    }
    // With a data descriptor the local fields are normally zero and readers
    // take the values from the descriptor and the central record; they stay
    // zero then, and are only rewritten when the writer filled them in.
    let zeroed = e.flags & HAS_DESCRIPTOR != 0 && bytes[14..26].iter().all(|&b| b == 0);
    if !zeroed {
        bytes[14..18].copy_from_slice(&crc.to_le_bytes());
        bytes[18..22].copy_from_slice(&csize.to_le_bytes());
        bytes[22..26].copy_from_slice(&size.to_le_bytes());
    }
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

/// Add `moved` to the little-endian u64 at `at` in `buf`.
fn shift_u64(buf: &mut [u8], at: usize, moved: i64) -> Result<(), EditError> {
    let bad = || refuse("the zip64 end record is unreadable");
    let old = u64_le(buf, at).ok_or_else(bad)?;
    let new = old
        .checked_add_signed(moved)
        .ok_or_else(|| refuse("the copy would be too large"))?;
    buf[at..at + 8].copy_from_slice(&new.to_le_bytes());
    Ok(())
}

/// Write the copy: the original with each changed entry replaced, the central
/// directory patched to match, and the end records pointing at it.
fn assemble(data: &[u8], found: &Analysis, w: &mut dyn Write) -> Result<(), EditError> {
    let arch = &found.arch;
    let cd = arch.cd_offset as usize;
    let cd_end = cd + arch.cd_size as usize;
    let eocd = found.eocd;

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
    // Between the central directory and the end record: a ZIP64 end record
    // (central directory offset at byte 48) and its locator (record offset at
    // byte 8) both move with everything else.
    let mut between = data[cd_end..eocd].to_vec();
    if let Some((rec, loc)) = found.zip64_end {
        shift_u64(&mut between, rec - cd_end + 48, moved)?;
        shift_u64(&mut between, loc - cd_end + 8, moved)?;
    }

    let mut cursor = 0usize;
    for c in &found.changes {
        w.write_all(&data[cursor..c.start])?;
        w.write_all(&c.bytes)?;
        cursor = c.end;
    }
    w.write_all(&data[cursor..cd])?;
    w.write_all(&central)?;
    w.write_all(&between)?;
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
    fn a_nested_archive_is_named_and_not_opened() {
        let dir = tempfile::tempdir().unwrap();
        let (_, exe, _) = fixture();
        let inner = build(&[item("deep.exe", &exe, true)], b"");
        let original = build(&[item("inner.zip", &inner, false)], b"");
        let path = dir.path().join("n.zip");
        fs::write(&path, &original).unwrap();
        let out = dir.path().join("n.deattributed.zip");
        let done = deattribute_zip(&path, &out, false).unwrap();
        assert_eq!(done.entries_cleaned, 0);
        assert_eq!(
            done.skipped,
            vec![("inner.zip".to_string(), Reason::NestedArchive)]
        );
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

    /// Offsets of the classic end record and the central directory in a
    /// synthetic archive with no comment.
    fn ends(zip: &[u8]) -> (usize, usize) {
        let eocd = zip.len() - EOCD_LEN;
        (eocd, u32_le(zip, eocd + 16).unwrap() as usize)
    }

    /// Put an unsaturated ZIP64 end record and locator between the central
    /// directory and the end record, as `zip -fz` does.
    fn with_zip64_end(zip: &[u8]) -> Vec<u8> {
        let (eocd, cd) = ends(zip);
        let entries = u64::from(u16_le(zip, eocd + 10).unwrap());
        let cd_size = u64::from(u32_le(zip, eocd + 12).unwrap());
        let mut out = zip[..eocd].to_vec();
        let rec = out.len() as u64;
        out.extend_from_slice(ZIP64_END_SIG);
        out.extend_from_slice(&44u64.to_le_bytes());
        out.extend_from_slice(&45u16.to_le_bytes());
        out.extend_from_slice(&45u16.to_le_bytes());
        out.extend_from_slice(&[0; 8]);
        out.extend_from_slice(&entries.to_le_bytes());
        out.extend_from_slice(&entries.to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&(cd as u64).to_le_bytes());
        out.extend_from_slice(ZIP64_LOCATOR_SIG);
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&rec.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&zip[eocd..]);
        out
    }

    /// Insert `bytes` right before the central directory, shifting its offset.
    fn before_central(zip: &[u8], bytes: &[u8]) -> Vec<u8> {
        let (eocd, cd) = ends(zip);
        let mut out = zip[..cd].to_vec();
        out.extend_from_slice(bytes);
        out.extend_from_slice(&zip[cd..]);
        let moved = (cd + bytes.len()) as u32;
        out[eocd + bytes.len() + 16..eocd + bytes.len() + 20].copy_from_slice(&moved.to_le_bytes());
        out
    }

    /// The central record offsets of every entry.
    fn records(zip: &[u8]) -> Vec<usize> {
        let view = MemView::new("x.zip", zip.to_vec());
        let arch = parse(&view).unwrap();
        read_central(zip, &arch)
            .unwrap()
            .iter()
            .map(|e| e.rec)
            .collect()
    }

    fn clean_bytes(path: &Path, bytes: &[u8]) -> Result<ArchiveOutcome, EditError> {
        fs::write(path, bytes).unwrap();
        let out = path.with_extension("deattributed.zip");
        deattribute_zip(path, &out, false)
    }

    #[test]
    fn an_unsaturated_zip64_end_record_moves_with_the_central_directory() {
        let dir = tempfile::tempdir().unwrap();
        let (_, exe, text) = fixture();
        let plain = build(
            &[item("a.txt", &text, true), item("tool.exe", &exe, true)],
            b"",
        );
        let original = with_zip64_end(&plain);
        let view = MemView::new("x.zip", original.clone());
        assert!(
            !parse(&view).unwrap().zip64,
            "the classic fields are not saturated"
        );
        let path = dir.path().join("z.zip");
        fs::write(&path, &original).unwrap();
        let out = dir.path().join("z.deattributed.zip");
        assert_eq!(
            deattribute_zip(&path, &out, false).unwrap().entries_cleaned,
            1
        );

        let copy = fs::read(&out).unwrap();
        let (eocd, cd) = ends(&copy);
        let (_, old_cd) = ends(&original);
        assert_ne!(cd, old_cd, "the change moved the central directory");
        let loc = eocd - ZIP64_LOCATOR_LEN;
        assert_eq!(&copy[loc..loc + 4], ZIP64_LOCATOR_SIG);
        let rec = u64_le(&copy, loc + 8).unwrap() as usize;
        assert_eq!(&copy[rec..rec + 4], ZIP64_END_SIG);
        assert_eq!(u64_le(&copy, rec + 48), Some(cd as u64));
        assert_eq!(rec, cd + u32_le(&copy, eocd + 12).unwrap() as usize);
        let (after, _) = read_back(&copy);
        assert!(!after[1].plain.windows(10).any(|w| w == b"patched by"));
        assert!(verify_copy(&out, Mode::Basic));
    }

    #[test]
    fn a_zip64_end_record_that_disagrees_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (_, exe, _) = fixture();
        let mut original = with_zip64_end(&build(&[item("tool.exe", &exe, true)], b""));
        let (eocd, _) = ends(&original);
        let rec = u64_le(&original, eocd - ZIP64_LOCATOR_LEN + 8).unwrap() as usize;
        original[rec + 48] ^= 1;
        let path = dir.path().join("d.zip");
        assert!(matches!(
            clean_bytes(&path, &original),
            Err(EditError::Refused(_))
        ));
    }

    #[test]
    fn a_change_sharing_bytes_with_another_entry_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (_, exe, text) = fixture();
        let mut original = build(
            &[item("tool.exe", &exe, true), item("b.txt", &text, false)],
            b"",
        );
        // A second record naming the first entry's local header.
        let recs = records(&original);
        original[recs[1] + 42..recs[1] + 46].copy_from_slice(&0u32.to_le_bytes());
        let path = dir.path().join("o.zip");
        assert!(matches!(
            clean_bytes(&path, &original),
            Err(EditError::Refused(_))
        ));
        assert!(!dir.path().join("o.deattributed.zip").exists());

        // A local header inside the changed entry's data.
        let mut inside = build(
            &[item("tool.exe", &exe, false), item("b.txt", &text, false)],
            b"",
        );
        let recs = records(&inside);
        inside[recs[1] + 42..recs[1] + 46].copy_from_slice(&100u32.to_le_bytes());
        let path = dir.path().join("i.zip");
        assert!(matches!(
            clean_bytes(&path, &inside),
            Err(EditError::Refused(_))
        ));
    }

    #[test]
    fn signed_packages_are_left_alone_whole() {
        let dir = tempfile::tempdir().unwrap();
        let (_, exe, _) = fixture();
        for signer in [
            "META-INF/CERT.SF",
            "meta-inf/release.rsa",
            "pkg-1.0.dist-info/RECORD",
            ".signature.p7s",
        ] {
            let original = build(
                &[
                    item(signer, b"invented signature", false),
                    item("tool.exe", &exe, true),
                ],
                b"",
            );
            let path = dir.path().join("s.zip");
            let done = clean_bytes(&path, &original).unwrap();
            assert_eq!(done.entries_cleaned, 0, "{signer}");
            assert_eq!(
                done.skipped,
                vec![(signer.to_string(), Reason::SignedContainer)]
            );
            assert!(!dir.path().join("s.deattributed.zip").exists());
        }
        for unsigned in ["META-INF/MANIFEST.MF", "META-INF/sub/x.SF", "docs/RECORD"] {
            let original = build(
                &[
                    item(unsigned, b"plain", false),
                    item("tool.exe", &exe, true),
                ],
                b"",
            );
            let found = analyze(&original).unwrap();
            assert_eq!(found.changes.len(), 1, "{unsigned}");
        }

        let apk = before_central(
            &build(&[item("tool.exe", &exe, true)], b""),
            b"\0\0\0\0\0\0\0\0APK Sig Block 42",
        );
        let found = analyze(&apk).unwrap();
        assert!(found.changes.is_empty());
        assert_eq!(found.skipped[0].1, Reason::SignedContainer);
    }

    #[test]
    fn a_descriptor_entry_keeps_zero_local_fields() {
        let dir = tempfile::tempdir().unwrap();
        let (_, exe, _) = fixture();
        let mut streamed = item("late.exe", &exe, true);
        streamed.flags = HAS_DESCRIPTOR;
        let original = build(&[streamed], b"");
        let path = dir.path().join("b.zip");
        assert_eq!(clean_bytes(&path, &original).unwrap().entries_cleaned, 1);
        let copy = fs::read(dir.path().join("b.deattributed.zip")).unwrap();
        assert_eq!(
            copy[14..26],
            [0; 12],
            "crc and sizes stay in the descriptor"
        );
        let (after, _) = read_back(&copy);
        assert!(!after[0].plain.windows(10).any(|w| w == b"patched by"));
        let csize = after[0].packed.len();
        let desc = LOCAL_LEN + "late.exe".len() + 4 + csize;
        assert_eq!(&copy[desc..desc + 4], DESCRIPTOR_SIG);
        assert_eq!(u32_le(&copy, desc + 4), Some(crc32(&after[0].plain)));
        assert_eq!(u32_le(&copy, desc + 8), Some(csize as u32));
    }

    #[test]
    fn multi_disk_and_zip64_archives_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (_, exe, _) = fixture();
        let base = build(
            &[item("tool.exe", &exe, true), item("b.exe", &exe, false)],
            b"",
        );
        let (eocd, _) = ends(&base);
        let rec = records(&base)[1];
        let name_len = "b.exe".len();
        type Edit = Box<dyn Fn(&mut Vec<u8>)>;
        let cases: Vec<(&str, Edit)> = vec![
            ("entries on this disk", Box::new(move |z| z[eocd + 8] = 1)),
            ("record on disk 1", Box::new(move |z| z[rec + 34] = 1)),
            (
                "saturated size",
                Box::new(move |z| z[rec + 24..rec + 28].fill(0xFF)),
            ),
            (
                "zip64 extra",
                Box::new(move |z| {
                    let at = rec + CENTRAL_LEN + name_len;
                    z[at..at + 2].copy_from_slice(&ZIP64_EXTRA.to_le_bytes());
                }),
            ),
        ];
        for (what, edit) in cases {
            let mut z = base.clone();
            edit(&mut z);
            let path = dir.path().join("m.zip");
            assert!(
                matches!(clean_bytes(&path, &z), Err(EditError::Refused(_))),
                "{what}"
            );
        }
    }

    #[test]
    fn skipped_entries_do_not_count_toward_the_size_budget() {
        let dir = tempfile::tempdir().unwrap();
        let (_, exe, _) = fixture();
        let mut secret = item("secret.exe", &exe, false);
        secret.flags = ENCRYPTED;
        let mut original = build(&[secret, item("ok.exe", &exe, false)], b"");
        let rec = records(&original)[0];
        original[rec + 24..rec + 28].copy_from_slice(&0xF000_0000u32.to_le_bytes());
        let path = dir.path().join("big.zip");
        let done = clean_bytes(&path, &original).unwrap();
        assert_eq!(done.entries_cleaned, 1);
        assert_eq!(
            done.skipped,
            vec![("secret.exe".to_string(), Reason::UnsupportedEntry)]
        );
    }

    #[test]
    fn a_read_only_stale_copy_is_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let (_, exe, _) = fixture();
        let original = build(&[item("x.exe", &exe, true)], b"");
        let path = dir.path().join("ro.zip");
        fs::write(&path, &original).unwrap();
        let out = dir.path().join("ro.deattributed.zip");
        fs::write(&out, b"stale").unwrap();
        let mut perms = fs::metadata(&out).unwrap().permissions();
        perms.set_readonly(true);
        fs::set_permissions(&out, perms).unwrap();

        deattribute_zip(&path, &out, false).unwrap();
        let (after, _) = read_back(&fs::read(&out).unwrap());
        assert!(!after[0].plain.windows(10).any(|w| w == b"patched by"));
        let entries = fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(entries, 2, "no temp file is left");
    }

    #[test]
    fn a_fresh_copy_verifies_and_the_original_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let (_, exe, text) = fixture();
        let original = build(
            &[item("a.exe", &exe, true), item("b.txt", &text, false)],
            b"",
        );
        let path = dir.path().join("v.zip");
        fs::write(&path, &original).unwrap();
        let out = dir.path().join("v.deattributed.zip");
        for mode in [Mode::Basic, Mode::Deep] {
            deattribute_zip_mode(&path, &out, false, mode).unwrap();
            assert!(verify_copy(&out, mode));
            assert!(!verify_copy(&path, mode));
        }
    }

    #[test]
    fn an_entry_cleans_to_the_same_bytes_alone_in_a_zip_and_in_a_targz() {
        use super::super::mem::deattribute_bytes_mode;
        use super::super::tar::tests::{end, entry, gz_member, headers, inflate_copy};
        use super::super::tar::{copy_name, deattribute_tar_mode};
        let dir = tempfile::tempdir().unwrap();
        let (_, exe, _) = fixture();
        for mode in [Mode::Basic, Mode::Deep] {
            let alone = deattribute_bytes_mode("tool.exe", &exe, mode)
                .bytes
                .expect("blanked");

            let zip = dir.path().join("same.zip");
            fs::write(&zip, build(&[item("bin/tool.exe", &exe, true)], b"")).unwrap();
            let out = dir.path().join("same.deattributed.zip");
            deattribute_zip_mode(&zip, &out, false, mode).unwrap();
            let (after, _) = read_back(&fs::read(&out).unwrap());
            assert_eq!(after[0].plain, alone);

            let mut t = Vec::new();
            entry(&mut t, "bin/tool.exe", b'0', &exe);
            end(&mut t);
            let gz = dir.path().join("same.tar.gz");
            fs::write(&gz, gz_member(&t, false)).unwrap();
            let out = copy_name(&gz);
            deattribute_tar_mode(&gz, true, &out, mode)
                .unwrap()
                .unwrap();
            let inflated = inflate_copy(&fs::read(&out).unwrap());
            let (_, size, at) = headers(&inflated)[0];
            assert_eq!(inflated[at..at + size as usize], alone[..]);
        }
    }
}
