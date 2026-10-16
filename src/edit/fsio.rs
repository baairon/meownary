//! Low-level file helpers private to the edit engine: positioned reads and
//! writes, chunked range copies and hashes, path cleanup, unique names, and an
//! atomic replace that keeps the original permissions. Every loop here works in
//! bounded chunks, so no edit ever pulls a whole large file into memory.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf, Prefix};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Chunk size for streamed copies, fills and hashes.
pub(crate) const CHUNK: usize = 1024 * 1024;

static UNIQUE: AtomicU64 = AtomicU64::new(0);

/// Seconds since the Unix epoch (0 if the clock is before it).
pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A name fragment that is unique within this process and very likely across
/// processes: pid, wall-clock nanos, and a process-wide counter.
pub(crate) fn unique_tag() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = UNIQUE.fetch_add(1, Ordering::Relaxed);
    format!("{}-{nanos}-{n}", std::process::id())
}

/// Strip the Windows verbatim prefix (`\\?\C:\...`) from a plain drive path so
/// stored paths look like the ones people type. UNC and other verbatim forms
/// are left alone. A no-op elsewhere.
pub(crate) fn clean_path(p: PathBuf) -> PathBuf {
    let mut comps = p.components();
    if let Some(Component::Prefix(pre)) = comps.next()
        && let Prefix::VerbatimDisk(letter) = pre.kind()
    {
        let mut out = PathBuf::from(format!("{}:\\", letter as char));
        for c in comps {
            if !matches!(c, Component::RootDir) {
                out.push(c.as_os_str());
            }
        }
        return out;
    }
    p
}

/// Canonical absolute form of an existing path, falling back to a plain
/// absolute path where canonicalization is unsupported.
pub(crate) fn canonical(p: &Path) -> io::Result<PathBuf> {
    match fs::canonicalize(p) {
        Ok(c) => Ok(clean_path(c)),
        Err(_) => std::path::absolute(p).map(clean_path),
    }
}

/// Whether `p` is absolute and free of `.` and `..` components.
pub(crate) fn is_plain_absolute(p: &Path) -> bool {
    p.is_absolute()
        && !p
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
}

/// One positioned read; returns how many bytes landed (short near EOF).
pub(crate) fn read_at(file: &File, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.read_at(buf, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        file.seek_read(buf, offset)
    }
    #[cfg(not(any(unix, windows)))]
    {
        use std::io::{Seek, SeekFrom};
        let mut f = file.try_clone()?;
        f.seek(SeekFrom::Start(offset))?;
        f.read(buf)
    }
}

/// Fill `buf` from `offset`, failing with `UnexpectedEof` if the file is short.
pub(crate) fn read_exact_at(file: &File, mut offset: u64, mut buf: &mut [u8]) -> io::Result<()> {
    while !buf.is_empty() {
        match read_at(file, offset, buf) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => {
                offset += n as u64;
                buf = &mut buf[n..];
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Positioned write of the whole buffer at `offset`.
pub(crate) fn write_at(file: &File, offset: u64, buf: &[u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.write_all_at(buf, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let mut written = 0usize;
        while written < buf.len() {
            match file.seek_write(&buf[written..], offset + written as u64) {
                Ok(0) => return Err(io::Error::other("short write")),
                Ok(n) => written += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        use std::io::{Seek, SeekFrom};
        let mut f = file.try_clone()?;
        f.seek(SeekFrom::Start(offset))?;
        f.write_all(buf)
    }
}

/// Overwrite `len` bytes at `offset` with `fill`, in chunks.
pub(crate) fn write_fill(file: &File, offset: u64, len: u64, fill: u8) -> io::Result<()> {
    let chunk = vec![fill; (len.min(CHUNK as u64)) as usize];
    let mut done = 0u64;
    while done < len {
        let n = (len - done).min(chunk.len() as u64) as usize;
        write_at(file, offset + done, &chunk[..n])?;
        done += n as u64;
    }
    Ok(())
}

/// blake3 (lowercase hex) of `len` bytes at `offset`, streamed. A file shorter
/// than the span is an `UnexpectedEof` error.
pub(crate) fn hash_range(file: &File, offset: u64, len: u64) -> io::Result<String> {
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; (len.min(CHUNK as u64)) as usize];
    let mut done = 0u64;
    while done < len {
        let n = (len - done).min(buf.len() as u64) as usize;
        read_exact_at(file, offset + done, &mut buf[..n])?;
        hasher.update(&buf[..n]);
        done += n as u64;
    }
    Ok(hasher.finalize().to_hex().to_string())
}

/// blake3 of `len` repetitions of `fill`, without allocating `len` bytes.
pub(crate) fn hash_fill(fill: u8, len: u64) -> String {
    let mut hasher = blake3::Hasher::new();
    let chunk = vec![fill; (len.min(CHUNK as u64)) as usize];
    let mut done = 0u64;
    while done < len {
        let n = (len - done).min(chunk.len() as u64) as usize;
        hasher.update(&chunk[..n]);
        done += n as u64;
    }
    hasher.finalize().to_hex().to_string()
}

/// blake3 of a whole file, streamed.
pub(crate) fn hash_file(path: &Path) -> io::Result<(u64, String)> {
    let file = File::open(path)?;
    let len = file.metadata()?.len();
    Ok((len, hash_range(&file, 0, len)?))
}

/// Copy `len` bytes at `offset` in `src` to a new file at `dst` (which must not
/// exist), fsync it, and return the copy's blake3.
pub(crate) fn copy_range_to_new(
    src: &File,
    offset: u64,
    len: u64,
    dst: &Path,
) -> io::Result<String> {
    let mut out = OpenOptions::new().write(true).create_new(true).open(dst)?;
    let result = (|| {
        let mut hasher = blake3::Hasher::new();
        let mut buf = vec![0u8; (len.min(CHUNK as u64)) as usize];
        let mut done = 0u64;
        while done < len {
            let n = (len - done).min(buf.len() as u64) as usize;
            read_exact_at(src, offset + done, &mut buf[..n])?;
            hasher.update(&buf[..n]);
            out.write_all(&buf[..n])?;
            done += n as u64;
        }
        out.sync_all()?;
        Ok(hasher.finalize().to_hex().to_string())
    })();
    if result.is_err() {
        drop(out);
        let _ = fs::remove_file(dst);
    }
    result
}

/// Write the whole of `src_path` into `dst` at `offset`, in chunks. Returns the
/// number of bytes written.
pub(crate) fn copy_file_into(src_path: &Path, dst: &File, offset: u64) -> io::Result<u64> {
    let mut src = File::open(src_path)?;
    let mut buf = vec![0u8; CHUNK];
    let mut done = 0u64;
    loop {
        let n = match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        write_at(dst, offset + done, &buf[..n])?;
        done += n as u64;
    }
    Ok(done)
}

/// Copy a whole file to a new path that must not exist yet, fsync, and remove
/// the partial copy on failure.
pub(crate) fn copy_to_new(src_path: &Path, dst: &Path) -> io::Result<u64> {
    let src = File::open(src_path)?;
    let len = src.metadata()?.len();
    copy_range_to_new(&src, 0, len, dst)?;
    Ok(len)
}

/// fsync a directory so a rename inside it is durable (unix only; elsewhere a
/// no-op, since Windows cannot open directories this way).
pub(crate) fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    {
        if let Ok(d) = File::open(dir) {
            let _ = d.sync_all();
        }
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
}

/// A unique temp path next to `target`, created with `create_new` (open for
/// reading and writing) so it can never clobber anything.
pub(crate) fn create_temp_beside(target: &Path) -> io::Result<(PathBuf, File)> {
    let dir = target.parent().unwrap_or_else(|| Path::new("."));
    let base = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_string());
    let mut last = None;
    for _ in 0..8 {
        let tmp = dir.join(format!(".{base}.meownary-{}.tmp", unique_tag()));
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&tmp)
        {
            Ok(f) => return Ok((tmp, f)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::other("could not create a temp file")))
}

/// Replace `target` atomically with bytes produced by `fill`: write a unique
/// temp sibling, fsync, copy the original permissions, rename over the target,
/// then fsync the parent directory. On any failure the temp file is removed and
/// the target is untouched.
pub(crate) fn replace_atomic_with(
    target: &Path,
    fill: impl FnOnce(&mut File) -> io::Result<()>,
) -> io::Result<()> {
    let perms = fs::metadata(target).ok().map(|m| m.permissions());
    let (tmp, mut file) = create_temp_beside(target)?;
    let result = (|| {
        fill(&mut file)?;
        file.sync_all()?;
        drop(file);
        if let Some(p) = perms {
            fs::set_permissions(&tmp, p)?;
        }
        fs::rename(&tmp, target)
    })();
    match result {
        Ok(()) => {
            if let Some(dir) = target.parent() {
                sync_dir(dir);
            }
            Ok(())
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Replace `target` atomically with `data`.
pub(crate) fn replace_atomic(target: &Path, data: &[u8]) -> io::Result<()> {
    replace_atomic_with(target, |f| f.write_all(data))
}

/// Replace `target` atomically with the contents of the file at `src`.
pub(crate) fn replace_atomic_from(target: &Path, src: &Path) -> io::Result<()> {
    replace_atomic_with(target, |f| {
        let mut s = File::open(src)?;
        io::copy(&mut s, f).map(|_| ())
    })
}

/// Encode bytes as lowercase hex.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0xf) as usize] as char);
    }
    s
}

/// Decode lowercase or uppercase hex; `None` on odd length or a bad digit.
pub(crate) fn from_hex(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    let digit = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    b.as_chunks::<2>()
        .0
        .iter()
        .map(|p| Some((digit(p[0])? << 4) | digit(p[1])?))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let data = [0u8, 1, 0x7f, 0x80, 0xff];
        assert_eq!(to_hex(&data), "00017f80ff");
        assert_eq!(from_hex("00017F80ff").as_deref(), Some(&data[..]));
        assert_eq!(from_hex("abc"), None);
        assert_eq!(from_hex("zz"), None);
    }

    #[test]
    fn fill_hash_matches_slice_hash() {
        let len = CHUNK as u64 + 17;
        let direct = crate::util::hash::hash_hex(&vec![0x20u8; len as usize]);
        assert_eq!(hash_fill(0x20, len), direct);
        assert_eq!(hash_fill(0, 0), crate::util::hash::hash_hex(&[]));
    }

    #[cfg(windows)]
    #[test]
    fn verbatim_drive_prefix_is_stripped() {
        let p = clean_path(PathBuf::from(r"\\?\C:\Users\x\file.bin"));
        assert_eq!(p, PathBuf::from(r"C:\Users\x\file.bin"));
        let unc = PathBuf::from(r"\\?\UNC\server\share\f");
        assert_eq!(clean_path(unc.clone()), unc);
    }

    #[test]
    fn plain_absolute_rejects_dots() {
        let base = std::env::temp_dir();
        assert!(is_plain_absolute(&base.join("a")));
        assert!(!is_plain_absolute(&base.join("..").join("a")));
        assert!(!is_plain_absolute(Path::new("relative/a")));
    }

    #[test]
    fn atomic_replace_and_ranges() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f.bin");
        fs::write(&p, b"hello world").unwrap();
        replace_atomic(&p, b"bye").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"bye");
        let leftovers: Vec<_> = fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(leftovers.len(), 1, "no temp files left behind");

        let f = OpenOptions::new().read(true).write(true).open(&p).unwrap();
        write_fill(&f, 1, 2, b'x').unwrap();
        drop(f);
        assert_eq!(fs::read(&p).unwrap(), b"bxx");
        let f = File::open(&p).unwrap();
        let copy = dir.path().join("c.bin");
        let h = copy_range_to_new(&f, 1, 2, &copy).unwrap();
        assert_eq!(fs::read(&copy).unwrap(), b"xx");
        assert_eq!(h, crate::util::hash::hash_hex(b"xx"));
        assert!(
            copy_range_to_new(&f, 0, 1, &copy).is_err(),
            "never clobbers"
        );
        assert!(hash_range(&f, 2, 5).is_err(), "short file is an error");
    }
}
