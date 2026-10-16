//! PE header parsing: the DOS header, the `PE\0\0` signature, the COFF and
//! optional headers, the section table and the data directories, plus the RVA
//! to file offset mapping every other PE probe relies on.

use std::borrow::Cow;

use crate::scan::FileView;
use crate::util::bytes::{slice, u16_le, u32_le};

/// Hard cap on the section table walk.
pub const MAX_SECTIONS: usize = 96;

pub const DIR_RESOURCE: usize = 2;
pub const DIR_EXPORT: usize = 0;
pub const DIR_SECURITY: usize = 4;
pub const DIR_DEBUG: usize = 6;
pub const DIR_CLR: usize = 14;

/// Up to `len` bytes at `off`, borrowed from the header window when it covers
/// the range, otherwise one bounded positioned read. Short near EOF.
pub fn read(view: &dyn FileView, off: u64, len: usize) -> Option<Cow<'_, [u8]>> {
    let header = view.header();
    if let Some(end) = off.checked_add(len as u64)
        && end <= header.len() as u64
    {
        return header.get(off as usize..end as usize).map(Cow::Borrowed);
    }
    view.read_at(off, len).ok().map(Cow::Owned)
}

/// Exactly `len` bytes at `off`, or `None` when the file is shorter.
pub fn read_exact(view: &dyn FileView, off: u64, len: usize) -> Option<Cow<'_, [u8]>> {
    let bytes = read(view, off, len)?;
    (bytes.len() == len).then_some(bytes)
}

/// One section header.
#[derive(Debug, Clone)]
pub struct Section {
    pub name: [u8; 8],
    pub vsize: u32,
    pub va: u32,
    pub raw_size: u32,
    pub raw_ptr: u32,
    pub characteristics: u32,
    /// Absolute file offset of this 40-byte section header.
    pub header_off: u64,
}

impl Section {
    /// The name up to its first NUL.
    pub fn name_bytes(&self) -> &[u8] {
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(8);
        self.name.get(..end).unwrap_or(&[])
    }

    pub fn name_str(&self) -> String {
        String::from_utf8_lossy(self.name_bytes()).into_owned()
    }

    /// Whether `rva` falls inside this section's virtual span.
    pub fn contains_rva(&self, rva: u32) -> bool {
        let span = self.vsize.max(self.raw_size);
        rva >= self.va && rva - self.va < span
    }
}

/// One data directory slot.
#[derive(Debug, Clone, Copy, Default)]
pub struct DataDir {
    pub rva: u32,
    pub size: u32,
}

/// The parsed headers of a PE image.
#[derive(Debug, Clone)]
pub struct PeImage {
    pub e_lfanew: u64,
    pub is64: bool,
    pub entry_rva: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    /// Absolute file offset of the optional header CheckSum field.
    pub checksum_off: u64,
    pub sym_ptr: u32,
    pub sym_count: u32,
    pub sections: Vec<Section>,
    pub dirs: Vec<DataDir>,
    /// Absolute file offset of the first data directory slot.
    pub dirs_off: u64,
    pub file_size: u64,
    /// Absolute file offset just past the declared section table.
    pub table_end: u64,
}

impl PeImage {
    /// Parse the headers, or `None` when this is not a PE image (a bare DOS
    /// executable, garbage after `MZ`, or a truncated header).
    pub fn parse(view: &dyn FileView) -> Option<Self> {
        let header = view.header();
        if slice(header, 0, 2)? != b"MZ" {
            return None;
        }
        let file_size = view.size();
        let e_lfanew = u64::from(u32_le(header, 0x3c)?);
        if e_lfanew < 4 || e_lfanew.checked_add(24)? > file_size {
            return None;
        }
        let fixed = read_exact(view, e_lfanew, 24)?;
        if slice(&fixed, 0, 4)? != b"PE\0\0" {
            return None;
        }
        let nsec = usize::from(u16_le(&fixed, 6)?);
        let sym_ptr = u32_le(&fixed, 12)?;
        let sym_count = u32_le(&fixed, 16)?;
        let opt_size = usize::from(u16_le(&fixed, 20)?);

        let opt_off = e_lfanew + 24;
        let opt = read_exact(view, opt_off, opt_size)?;
        let (is64, dir_base, nrva_off) = match u16_le(&opt, 0)? {
            0x10b => (false, 96usize, 92usize),
            0x20b => (true, 112, 108),
            _ => return None,
        };
        if opt_size < dir_base {
            return None;
        }
        let entry_rva = u32_le(&opt, 16)?;
        let size_of_headers = u32_le(&opt, 60)?;
        let checksum = u32_le(&opt, 64)?;
        let nrva = (u32_le(&opt, nrva_off)? as usize)
            .min(16)
            .min((opt_size - dir_base) / 8);
        let dirs = (0..nrva)
            .filter_map(|i| {
                let at = dir_base + i * 8;
                Some(DataDir {
                    rva: u32_le(&opt, at)?,
                    size: u32_le(&opt, at + 4)?,
                })
            })
            .collect();

        let table_off = opt_off + opt_size as u64;
        let table_end = table_off + (nsec as u64) * 40;
        let nsec = nsec.min(MAX_SECTIONS);
        let table = read(view, table_off, nsec * 40)?;
        let sections = table
            .as_chunks::<40>()
            .0
            .iter()
            .enumerate()
            .filter_map(|(i, raw)| {
                let mut name = [0u8; 8];
                name.copy_from_slice(slice(raw, 0, 8)?);
                Some(Section {
                    name,
                    vsize: u32_le(raw, 8)?,
                    va: u32_le(raw, 12)?,
                    raw_size: u32_le(raw, 16)?,
                    raw_ptr: u32_le(raw, 20)?,
                    characteristics: u32_le(raw, 36)?,
                    header_off: table_off + (i as u64) * 40,
                })
            })
            .collect();

        Some(Self {
            e_lfanew,
            is64,
            entry_rva,
            size_of_headers,
            checksum,
            checksum_off: opt_off + 64,
            sym_ptr,
            sym_count,
            sections,
            dirs,
            dirs_off: opt_off + dir_base as u64,
            file_size,
            table_end,
        })
    }

    /// A data directory, when present and non-empty.
    pub fn dir(&self, index: usize) -> Option<DataDir> {
        self.dirs
            .get(index)
            .copied()
            .filter(|d| d.rva != 0 && d.size != 0)
    }

    /// Map an RVA to an absolute file offset through the section table.
    pub fn rva_to_off(&self, rva: u32) -> Option<u64> {
        for s in &self.sections {
            if s.raw_size == 0 || !s.contains_rva(rva) {
                continue;
            }
            let delta = rva - s.va;
            if delta >= s.raw_size {
                return None;
            }
            let off = u64::from(s.raw_ptr) + u64::from(delta);
            return (off < self.file_size).then_some(off);
        }
        let rva = u64::from(rva);
        (rva < u64::from(self.size_of_headers) && rva < self.file_size).then_some(rva)
    }

    /// End of the raw data the headers and section table describe: at least
    /// SizeOfHeaders, the end of the section table, and the end of every
    /// section's raw data.
    pub fn image_end(&self) -> u64 {
        self.sections
            .iter()
            .filter(|s| s.raw_size != 0)
            .map(|s| u64::from(s.raw_ptr) + u64::from(s.raw_size))
            .fold(
                u64::from(self.size_of_headers).max(self.table_end),
                u64::max,
            )
    }

    /// Whether the headers lay out the file consistently enough to say where
    /// the image ends: SizeOfHeaders covers the section table, at least one
    /// section has raw data, and that data lies past the headers.
    pub fn layout_ok(&self) -> bool {
        let headers = u64::from(self.size_of_headers);
        if headers == 0 || headers < self.table_end {
            return false;
        }
        let data_end = self
            .sections
            .iter()
            .filter(|s| s.raw_size != 0 && s.raw_ptr != 0)
            .map(|s| u64::from(s.raw_ptr) + u64::from(s.raw_size))
            .max();
        data_end.is_some_and(|end| end > headers)
    }
}
