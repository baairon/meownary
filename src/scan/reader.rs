//! Bounded file access. A `FileView` gives probes a header window, a tail
//! window, and positioned reads for structural points, but never hands them the
//! whole file. A 20 GB file is identified from a few kilobytes in milliseconds.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

/// Size of the eagerly-read front window.
pub const HEADER_WINDOW: usize = 64 * 1024;
/// Size of the eagerly-read back window (overlays, EOCD, ID3v1, appended sigs).
pub const TAIL_WINDOW: usize = 64 * 1024;
/// Hard cap on any single positioned read, so a corrupt length field can never
/// make us allocate gigabytes.
pub const MAX_READ: usize = 16 * 1024 * 1024;

/// Read-only, bounded access to one file. Parsers are written against this
/// trait and never see whether the bytes came from a cache, a seek, or an mmap.
pub trait FileView {
    fn path(&self) -> &Path;
    /// The file's size in bytes at open time.
    fn size(&self) -> u64;
    /// The eagerly-read front window (up to [`HEADER_WINDOW`], shorter for tiny files).
    fn header(&self) -> &[u8];
    /// The eagerly-read back window (up to [`TAIL_WINDOW`]).
    fn tail(&self) -> &[u8];
    /// File offset at which [`FileView::tail`] begins.
    fn tail_start(&self) -> u64;
    /// Read up to `len` bytes at absolute `offset`. Serves from a cached window
    /// when fully contained, else does one positioned read. Returns fewer bytes
    /// near EOF; `len` is clamped to [`MAX_READ`].
    fn read_at(&self, offset: u64, len: usize) -> io::Result<Vec<u8>>;
}

/// A `FileView` backed by an open handle plus the two cached windows.
pub struct WindowedFile {
    path: PathBuf,
    file: File,
    size: u64,
    header: Vec<u8>,
    tail: Vec<u8>,
    tail_start: u64,
}

impl WindowedFile {
    pub fn open(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        let file = File::open(&path)?;
        let size = file.metadata()?.len();

        let header_len = size.min(HEADER_WINDOW as u64) as usize;
        let mut header = vec![0u8; header_len];
        read_exact_at(&file, 0, &mut header)?;

        let tail_start = size.saturating_sub(TAIL_WINDOW as u64);
        let tail_len = (size - tail_start) as usize;
        let mut tail = vec![0u8; tail_len];
        read_exact_at(&file, tail_start, &mut tail)?;

        Ok(Self {
            path,
            file,
            size,
            header,
            tail,
            tail_start,
        })
    }
}

impl FileView for WindowedFile {
    fn path(&self) -> &Path {
        &self.path
    }
    fn size(&self) -> u64 {
        self.size
    }
    fn header(&self) -> &[u8] {
        &self.header
    }
    fn tail(&self) -> &[u8] {
        &self.tail
    }
    fn tail_start(&self) -> u64 {
        self.tail_start
    }

    fn read_at(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        if offset >= self.size || len == 0 {
            return Ok(Vec::new());
        }
        let avail = (self.size - offset) as usize;
        let want = len.min(avail).min(MAX_READ);

        // Serve from the header cache when fully contained.
        if offset + want as u64 <= self.header.len() as u64 {
            let o = offset as usize;
            return Ok(self.header[o..o + want].to_vec());
        }
        // Serve from the tail cache when fully contained.
        if offset >= self.tail_start {
            let o = (offset - self.tail_start) as usize;
            if o + want <= self.tail.len() {
                return Ok(self.tail[o..o + want].to_vec());
            }
        }
        // Otherwise one positioned read straight off the handle.
        let mut buf = vec![0u8; want];
        let got = read_at(&self.file, offset, &mut buf)?;
        buf.truncate(got);
        Ok(buf)
    }
}

/// An in-memory `FileView` with the same windowing as [`WindowedFile`]. Used by
/// probe tests, and by callers that already hold a file's bytes.
pub struct MemView {
    path: PathBuf,
    data: Vec<u8>,
    tail_start: u64,
}

impl MemView {
    pub fn new(path: impl Into<PathBuf>, data: impl Into<Vec<u8>>) -> Self {
        let data = data.into();
        let tail_start = (data.len() as u64).saturating_sub(TAIL_WINDOW as u64);
        Self {
            path: path.into(),
            data,
            tail_start,
        }
    }
}

impl FileView for MemView {
    fn path(&self) -> &Path {
        &self.path
    }
    fn size(&self) -> u64 {
        self.data.len() as u64
    }
    fn header(&self) -> &[u8] {
        &self.data[..self.data.len().min(HEADER_WINDOW)]
    }
    fn tail(&self) -> &[u8] {
        &self.data[self.tail_start as usize..]
    }
    fn tail_start(&self) -> u64 {
        self.tail_start
    }
    fn read_at(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        if offset >= self.data.len() as u64 || len == 0 {
            return Ok(Vec::new());
        }
        let start = offset as usize;
        let want = len.min(self.data.len() - start).min(MAX_READ);
        Ok(self.data[start..start + want].to_vec())
    }
}

/// One positioned read. Returns the number of bytes read (may be short).
fn read_at(file: &File, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
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
        use std::io::{Read, Seek, SeekFrom};
        let mut f = file.try_clone()?;
        f.seek(SeekFrom::Start(offset))?;
        f.read(buf)
    }
}

/// Positioned read that keeps going until `buf` is full or EOF. Tolerates a
/// short final read; a window near EOF is simply shorter than requested.
fn read_exact_at(file: &File, mut offset: u64, mut buf: &mut [u8]) -> io::Result<()> {
    while !buf.is_empty() {
        match read_at(file, offset, buf)? {
            0 => break,
            n => {
                offset += n as u64;
                buf = &mut buf[n..];
            }
        }
    }
    Ok(())
}
