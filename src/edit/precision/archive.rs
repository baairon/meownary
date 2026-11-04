//! Bounded archive inventory and packaging. Files are data, never programs.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{
    pattern::invalid,
    plan::{self, Hashes},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Limits {
    pub entries: usize,
    pub entry_bytes: u64,
    pub total_bytes: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            entries: 100_000,
            entry_bytes: 256 * 1024 * 1024,
            total_bytes: 1024 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub path: String,
    pub directory: bool,
    pub hashes: Option<Hashes>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: u32,
    pub entries: Vec<Entry>,
}

fn safe_name(name: &str, directory: bool) -> io::Result<String> {
    let name = if directory {
        name.trim_end_matches('/')
    } else {
        name
    };
    if name.is_empty()
        || name.len() > 4096
        || name.contains(['\\', ':'])
        || name.chars().any(char::is_control)
    {
        return Err(invalid("archive path is empty, too long, or not portable"));
    }
    for part in name.split('/') {
        let stem = part.split('.').next().unwrap_or("").to_ascii_uppercase();
        if part.is_empty()
            || part == "."
            || part == ".."
            || part.ends_with(['.', ' '])
            || part.contains(['<', '>', '"', '|', '?', '*'])
            || ["CON", "PRN", "AUX", "NUL"].contains(&stem.as_str())
            || ((stem.starts_with("COM") || stem.starts_with("LPT"))
                && stem.len() == 4
                && stem.as_bytes()[3].is_ascii_digit())
        {
            return Err(invalid(format!("unsafe archive path: {name}")));
        }
    }
    Ok(name.to_owned())
}

struct Walk<'a> {
    root: &'a Path,
    limits: &'a Limits,
    total: u64,
    entries: Vec<Entry>,
    names: BTreeMap<String, bool>,
    metadata: Vec<(String, Option<u32>, Option<u64>)>,
}

struct BudgetReader<R> {
    inner: R,
    left: u64,
}
impl<R: Read> Read for BudgetReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.left == 0 {
            let mut probe = [0];
            return if self.inner.read(&mut probe)? == 0 {
                Ok(0)
            } else {
                Err(invalid("archive stream budget exceeded"))
            };
        }
        let len = buf.len().min(self.left.min(usize::MAX as u64) as usize);
        let n = self.inner.read(&mut buf[..len])?;
        self.left -= n as u64;
        Ok(n)
    }
}

impl Walk<'_> {
    fn entry(
        &mut self,
        name: &str,
        directory: bool,
        size: u64,
        reader: &mut dyn Read,
        mode: Option<u32>,
        mtime: Option<u64>,
    ) -> io::Result<()> {
        if self.entries.len() >= self.limits.entries || size > self.limits.entry_bytes {
            return Err(invalid("archive entry limit exceeded"));
        }
        self.total = self
            .total
            .checked_add(size)
            .ok_or_else(|| invalid("archive size overflow"))?;
        if self.total > self.limits.total_bytes {
            return Err(invalid("archive expansion budget exceeded"));
        }
        let name = safe_name(name, directory)?;
        let key = name.to_lowercase();
        if self.names.insert(key.clone(), directory).is_some() {
            return Err(invalid("duplicate or case-colliding archive path"));
        }
        for (at, _) in key.match_indices('/') {
            if self.names.get(&key[..at]) == Some(&false) {
                return Err(invalid("archive file and directory paths conflict"));
            }
        }
        let prefix = format!("{key}/");
        if !directory
            && self
                .names
                .range(prefix.clone()..)
                .next()
                .is_some_and(|(other, _)| other.starts_with(&prefix))
        {
            return Err(invalid("archive file and directory paths conflict"));
        }
        let output = self.root.join(&name);
        let hashes = if directory {
            if size != 0 {
                return Err(invalid("directory entry carries payload bytes"));
            }
            fs::create_dir_all(&output)?;
            None
        } else {
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output)?;
            let got = io::copy(&mut reader.take(size.saturating_add(1)), &mut file)?;
            if got != size {
                return Err(invalid("archive payload length differs from its header"));
            }
            file.sync_all()?;
            Some(plan::hash(&output)?)
        };
        self.entries.push(Entry {
            path: name.clone(),
            directory,
            hashes,
        });
        self.metadata.push((name, mode, mtime));
        Ok(())
    }
}

fn read_archive(
    path: &Path,
    root: &Path,
    limits: &Limits,
    preserve_metadata: bool,
) -> io::Result<Manifest> {
    plan::regular(path)?;
    let mut walk = Walk {
        root,
        limits,
        total: 0,
        entries: Vec::new(),
        names: BTreeMap::new(),
        metadata: Vec::new(),
    };
    let mut magic = [0; 4];
    let n = File::open(path)?.read(&mut magic)?;
    if n >= 2 && &magic[..2] == b"PK" {
        let mut archive = zip::ZipArchive::new(File::open(path)?).map_err(io::Error::other)?;
        if archive.len() > limits.entries {
            return Err(invalid("archive entry count exceeds budget"));
        }
        for index in 0..archive.len() {
            let mut entry = archive.by_index(index).map_err(io::Error::other)?;
            let mode = entry.unix_mode().unwrap_or(0) & 0o170000;
            if entry.encrypted() || !matches!(mode, 0 | 0o100000 | 0o040000) {
                return Err(invalid(
                    "encrypted entries and special files are not extracted",
                ));
            }
            if entry.size() > entry.compressed_size().max(1).saturating_mul(1000) {
                return Err(invalid("archive compression ratio exceeds 1000"));
            }
            let name = entry.name().map_err(io::Error::other)?.into_owned();
            let permissions = entry.unix_mode();
            let mtime = entry.last_modified().and_then(|dt| {
                let month = time::Month::try_from(dt.month()).ok()?;
                let date =
                    time::Date::from_calendar_date(i32::from(dt.year()), month, dt.day()).ok()?;
                let clock = time::Time::from_hms(dt.hour(), dt.minute(), dt.second()).ok()?;
                u64::try_from(
                    time::PrimitiveDateTime::new(date, clock)
                        .assume_utc()
                        .unix_timestamp(),
                )
                .ok()
            });
            walk.entry(
                &name,
                entry.is_dir(),
                entry.size(),
                &mut entry,
                permissions,
                mtime,
            )?;
        }
    } else {
        let source: Box<dyn Read> = if magic[..2] == [0x1f, 0x8b] {
            Box::new(flate2::read::MultiGzDecoder::new(File::open(path)?))
        } else {
            Box::new(File::open(path)?)
        };
        // Bound padding and extension records as well as ordinary payloads.
        let mut archive = tar::Archive::new(BudgetReader {
            inner: source,
            left: limits.total_bytes.saturating_add(16 * 1024 * 1024),
        });
        for entry in archive.entries()? {
            let mut entry = entry?;
            let kind = entry.header().entry_type();
            if !kind.is_file() && !kind.is_dir() {
                return Err(invalid(
                    "links, sparse files, and special tar entries are not extracted",
                ));
            }
            let bytes = entry.path_bytes();
            let name = std::str::from_utf8(&bytes)
                .map_err(|_| invalid("archive name is not UTF-8"))?
                .to_owned();
            let mode = entry.header().mode().ok();
            let mtime = entry.header().mtime().ok();
            walk.entry(&name, kind.is_dir(), entry.size(), &mut entry, mode, mtime)?;
        }
        io::copy(&mut archive.into_inner(), &mut io::sink())?;
    }
    for (name, mode, mtime) in walk.metadata.iter().rev() {
        if !preserve_metadata {
            break;
        }
        let target = root.join(name);
        if let Some(seconds) = mtime {
            let stamp = std::time::UNIX_EPOCH
                .checked_add(std::time::Duration::from_secs(*seconds))
                .ok_or_else(|| invalid("archive timestamp overflow"))?;
            set_timestamp(&target, stamp)?;
        }
        #[cfg(unix)]
        if let Some(mode) = mode {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&target, fs::Permissions::from_mode(mode & 0o777))?;
        }
        #[cfg(not(unix))]
        let _ = mode;
    }
    Ok(Manifest {
        version: 1,
        entries: walk.entries,
    })
}

pub fn inventory(path: &Path, limits: &Limits) -> io::Result<Manifest> {
    let scratch = tempfile::tempdir()?;
    read_archive(path, scratch.path(), limits, false)
}

pub fn extract(path: &Path, output: &Path, limits: &Limits) -> io::Result<Manifest> {
    let destination = plan::output_path(output)?;
    if destination.exists() {
        return Err(invalid("extraction requires a new destination directory"));
    }
    let parent = destination
        .parent()
        .ok_or_else(|| invalid("destination has no parent"))?;
    let scratch = tempfile::tempdir_in(parent)?;
    let manifest = read_archive(path, scratch.path(), limits, true)?;
    fs::rename(scratch.path(), &destination)?;
    crate::edit::fsio::sync_dir(parent);
    Ok(manifest)
}

fn set_timestamp(path: &Path, stamp: std::time::SystemTime) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.access_mode(0x100).custom_flags(0x02000000);
    }
    options.open(path)?.set_modified(stamp)
}

pub fn folder_manifest(root: &Path, limits: &Limits) -> io::Result<Manifest> {
    if !root.is_dir() || fs::symlink_metadata(root)?.file_type().is_symlink() {
        return Err(invalid("pack needs a real directory"));
    }
    let mut entries = Vec::new();
    let mut names = BTreeMap::new();
    let mut total = 0u64;
    for item in walkdir::WalkDir::new(root)
        .min_depth(1)
        .follow_links(false)
        .sort_by_file_name()
    {
        let item = item.map_err(io::Error::other)?;
        if !item.file_type().is_dir() && !item.file_type().is_file() {
            return Err(invalid("links and special files cannot be packed"));
        }
        let relative = item.path().strip_prefix(root).map_err(io::Error::other)?;
        let name = relative
            .to_str()
            .ok_or_else(|| invalid("archive paths must be UTF-8"))?
            .replace('\\', "/");
        let name = safe_name(&name, item.file_type().is_dir())?;
        if names.insert(name.to_lowercase(), ()).is_some() {
            return Err(invalid("case-colliding archive names"));
        }
        let hashes = if item.file_type().is_file() {
            plan::regular(item.path())?;
            Some(plan::hash(item.path())?)
        } else {
            None
        };
        let size = hashes.as_ref().map_or(0, |h| h.size);
        total = total
            .checked_add(size)
            .ok_or_else(|| invalid("archive size overflow"))?;
        if size > limits.entry_bytes
            || total > limits.total_bytes
            || entries.len() >= limits.entries
        {
            return Err(invalid("archive budget exceeded"));
        }
        entries.push(Entry {
            path: name,
            directory: item.file_type().is_dir(),
            hashes,
        });
    }
    Ok(Manifest {
        version: 1,
        entries,
    })
}

fn write_tar(
    writer: &mut dyn Write,
    root: &Path,
    manifest: &Manifest,
    normalize: bool,
) -> io::Result<()> {
    let mut archive = tar::Builder::new(writer);
    for entry in &manifest.entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(entry.hashes.as_ref().map_or(0, |h| h.size));
        let path = root.join(&entry.path);
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(invalid("source became a symbolic link"));
        }
        header.set_mode(source_mode(&metadata, entry.directory, normalize));
        header.set_entry_type(if entry.directory {
            tar::EntryType::Directory
        } else {
            tar::EntryType::Regular
        });
        header.set_mtime(source_mtime(&metadata, normalize)?);
        header.set_uid(0);
        header.set_gid(0);
        header.set_cksum();
        if entry.directory {
            archive.append_data(&mut header, &entry.path, io::empty())?;
        } else {
            archive.append_data(
                &mut header,
                &entry.path,
                File::open(root.join(&entry.path))?,
            )?;
        }
    }
    archive.finish()
}

pub fn pack(
    root: &Path,
    output: &Path,
    format: &str,
    overwrite: bool,
    limits: &Limits,
) -> io::Result<Manifest> {
    pack_with_metadata(root, output, format, overwrite, limits, false)
}

fn source_mtime(metadata: &fs::Metadata, normalize: bool) -> io::Result<u64> {
    if normalize {
        return Ok(0);
    }
    Ok(metadata
        .modified()?
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| invalid("timestamp predates Unix epoch; use --normalize-metadata"))?
        .as_secs())
}

fn source_mode(metadata: &fs::Metadata, directory: bool, normalize: bool) -> u32 {
    #[cfg(unix)]
    if !normalize {
        use std::os::unix::fs::PermissionsExt;
        return metadata.permissions().mode() & 0o777;
    }
    let _ = (metadata, normalize);
    if directory { 0o755 } else { 0o644 }
}

pub fn pack_with_metadata(
    root: &Path,
    output: &Path,
    format: &str,
    overwrite: bool,
    limits: &Limits,
    normalize: bool,
) -> io::Result<Manifest> {
    let destination = plan::output_path(output)?;
    for ancestor in std::path::absolute(root)?.ancestors() {
        if fs::symlink_metadata(ancestor)?.file_type().is_symlink() {
            return Err(invalid("pack input cannot contain symbolic links"));
        }
    }
    let root = crate::edit::fsio::canonical(root)?;
    if destination.starts_with(&root) {
        return Err(invalid(
            "archive output must be outside its input directory",
        ));
    }
    let manifest = folder_manifest(&root, limits)?;
    let temp = tempfile::NamedTempFile::new_in(
        destination
            .parent()
            .ok_or_else(|| invalid("output has no parent"))?,
    )?;
    let file = temp.reopen()?;
    match format {
        "zip" => {
            let mut archive = zip::ZipWriter::new(file);
            for entry in &manifest.entries {
                let path = root.join(&entry.path);
                let metadata = fs::symlink_metadata(&path)?;
                if metadata.file_type().is_symlink() {
                    return Err(invalid("source became a symbolic link"));
                }
                let seconds = source_mtime(&metadata, normalize)?;
                let stamp = if normalize {
                    zip::DateTime::default()
                } else {
                    let date = time::OffsetDateTime::from_unix_timestamp(
                        i64::try_from(seconds).map_err(|_| invalid("timestamp out of range"))?,
                    )
                    .map_err(io::Error::other)?;
                    zip::DateTime::from_date_and_time(
                        u16::try_from(date.year())
                            .map_err(|_| invalid("ZIP timestamp out of range"))?,
                        date.month() as u8,
                        date.day(),
                        date.hour(),
                        date.minute(),
                        date.second(),
                    )
                    .map_err(|_| {
                        invalid("ZIP timestamp outside 1980..2107; use --normalize-metadata")
                    })?
                };
                let options = zip::write::SimpleFileOptions::default()
                    .unix_permissions(source_mode(&metadata, entry.directory, normalize))
                    .last_modified_time(stamp)
                    .compression_method(zip::CompressionMethod::Deflated)
                    .large_file(
                        entry
                            .hashes
                            .as_ref()
                            .is_some_and(|h| h.size >= u32::MAX as u64),
                    );
                if entry.directory {
                    archive
                        .add_directory(&entry.path, options)
                        .map_err(io::Error::other)?;
                } else {
                    archive
                        .start_file(&entry.path, options)
                        .map_err(io::Error::other)?;
                    let file = File::open(&path)?;
                    let expected = entry.hashes.as_ref().map_or(0, |h| h.size);
                    if io::copy(&mut file.take(expected.saturating_add(1)), &mut archive)?
                        != expected
                    {
                        return Err(invalid("source changed during packaging"));
                    }
                }
            }
            archive.finish().map_err(io::Error::other)?.sync_all()?;
        }
        "tar" => {
            let mut file = file;
            write_tar(&mut file, &root, &manifest, normalize)?;
            file.sync_all()?;
        }
        "tar.gz" => {
            let mut gzip = flate2::write::GzEncoder::new(file, flate2::Compression::default());
            write_tar(&mut gzip, &root, &manifest, normalize)?;
            gzip.finish()?.sync_all()?;
        }
        _ => return Err(invalid("pack format must be zip, tar, or tar.gz")),
    }
    let check = inventory(temp.path(), limits)?;
    if check.entries != manifest.entries
        || folder_manifest(&root, limits)?.entries != manifest.entries
    {
        return Err(invalid(
            "archive content or source changed during packaging",
        ));
    }
    plan::publish(temp.path(), &destination, overwrite)?;
    Ok(manifest)
}

pub fn verify(path: &Path, expected: &Manifest, limits: &Limits) -> io::Result<bool> {
    if expected.version != 1 {
        return Err(invalid("unsupported manifest version"));
    }
    Ok(inventory(path, limits)?.entries == expected.entries)
}

/// Database tables describe installation intent. Reading them never installs
/// a package or runs a custom action.
pub fn inspect_msi(path: &Path, limit: usize) -> io::Result<Value> {
    plan::regular(path)?;
    let mut package = msi::open(path)?;
    let names: Vec<String> = package.tables().map(|t| t.name().to_owned()).collect();
    let mut tables = serde_json::Map::new();
    let mut remaining = limit;
    let mut complete = true;
    for name in ["File", "Component", "Directory", "Media", "Property"] {
        if !names.iter().any(|n| n == name) {
            continue;
        }
        let rows = package.select_rows(msi::Select::table(name))?;
        let mut values = Vec::new();
        for row in rows {
            if remaining == 0 {
                complete = false;
                break;
            }
            remaining -= 1;
            let mut value = serde_json::Map::new();
            for (index, column) in row.columns().iter().enumerate() {
                value.insert(
                    column.name().into(),
                    match &row[index] {
                        msi::Value::Null => Value::Null,
                        msi::Value::Int(n) => json!(n),
                        msi::Value::Str(s) => json!(s),
                        msi::Value::Binary => json!({"binary_stream":true}),
                    },
                );
            }
            values.push(Value::Object(value));
        }
        tables.insert(name.into(), json!(values));
    }
    Ok(
        json!({"tables":tables,"complete":complete,"payloads_extracted":false,
        "note":"File, Component, Directory and Media keys describe payload placement; properties and external cabinets can leave paths unresolved."}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_ambiguous_paths() {
        for name in [
            "../escape",
            "/root",
            "C:/file",
            "a\\b",
            "a/./b",
            "AUX.txt",
            "x:stream",
            "a./b",
            "a//b",
        ] {
            assert!(safe_name(name, false).is_err(), "{name}");
        }
        assert_eq!(safe_name("a/b.bin", false).unwrap(), "a/b.bin");
    }
    #[test]
    fn roundtrip_preserves_every_file_and_empty_directory() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("input");
        fs::create_dir_all(root.join("empty")).unwrap();
        fs::write(root.join("one.bin"), [0, 255, 40, 42]).unwrap();
        fs::write(root.join("two.txt"), b"North Star fixture").unwrap();
        for format in ["zip", "tar", "tar.gz"] {
            let output = temp.path().join(format!("bundle.{format}"));
            let manifest = pack(&root, &output, format, false, &Limits::default()).unwrap();
            assert_eq!(manifest.entries.len(), 3);
            assert!(verify(&output, &manifest, &Limits::default()).unwrap());
            let destination = temp.path().join(format!("unpacked-{format}"));
            extract(&output, &destination, &Limits::default()).unwrap();
            assert_eq!(
                fs::read(destination.join("one.bin")).unwrap(),
                [0, 255, 40, 42]
            );
            assert!(destination.join("empty").is_dir());
        }
    }

    #[test]
    fn corrupt_or_over_budget_extract_never_publishes_a_directory() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("input");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("data.bin"), [1; 128]).unwrap();
        let output = temp.path().join("bundle.zip");
        pack(&root, &output, "zip", false, &Limits::default()).unwrap();
        let destination = temp.path().join("extracted");
        assert!(
            extract(
                &output,
                &destination,
                &Limits {
                    entry_bytes: 64,
                    ..Limits::default()
                }
            )
            .is_err()
        );
        assert!(!destination.exists());
        fs::write(&output, b"PK broken").unwrap();
        assert!(extract(&output, &destination, &Limits::default()).is_err());
        assert!(!destination.exists());
        assert!(
            pack(
                &root,
                &root.join("nested.zip"),
                "zip",
                false,
                &Limits::default()
            )
            .is_err()
        );
    }

    #[test]
    fn timestamps_are_preserved_or_explicitly_normalized() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("input");
        fs::create_dir(&root).unwrap();
        let input = root.join("data.bin");
        fs::write(&input, b"fixture").unwrap();
        let stamp = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        set_timestamp(&input, stamp).unwrap();
        for format in ["zip", "tar", "tar.gz"] {
            let output = temp.path().join(format!("bundle.{format}"));
            pack(&root, &output, format, false, &Limits::default()).unwrap();
            let destination = temp.path().join(format!("out-{format}"));
            extract(&output, &destination, &Limits::default()).unwrap();
            assert_eq!(
                fs::metadata(destination.join("data.bin"))
                    .unwrap()
                    .modified()
                    .unwrap(),
                stamp
            );
            let normalized = temp.path().join(format!("normalized.{format}"));
            pack_with_metadata(&root, &normalized, format, false, &Limits::default(), true)
                .unwrap();
            let second = temp.path().join(format!("normalized2.{format}"));
            pack_with_metadata(&root, &second, format, false, &Limits::default(), true).unwrap();
            assert_eq!(fs::read(normalized).unwrap(), fs::read(second).unwrap());
        }
    }
}
