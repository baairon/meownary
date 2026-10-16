//! The RT_VERSION resource: walk the resource directory down to the version
//! leaf, then read the StringFileInfo name and value pairs out of
//! VS_VERSIONINFO, remembering where each value's UTF-16 bytes live.

use crate::scan::FileView;
use crate::util::bytes::u16_le;
use crate::util::bytes::u32_le;

use super::image::{DIR_RESOURCE, PeImage, read, read_exact};

const RT_VERSION: u32 = 16;
/// Cap on entries read from one resource directory.
const MAX_ENTRIES: usize = 256;
/// Cap on the version leaf size.
const MAX_LEAF: usize = 64 * 1024;
/// Cap on blocks visited at any one level of VS_VERSIONINFO.
const MAX_BLOCKS: usize = 256;
/// Cap on UTF-16 units in a block key.
const MAX_KEY_UNITS: usize = 64;

/// One StringFileInfo pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionString {
    pub key: String,
    pub value: String,
    /// Absolute file offset of the value's first UTF-16 unit.
    pub value_off: u64,
    /// Length of the value in bytes, excluding its NUL terminator.
    pub value_len: u64,
}

/// The parsed version resource.
#[derive(Debug, Clone)]
pub struct VersionInfo {
    /// Absolute file offset of the VS_VERSIONINFO block.
    pub leaf_off: u64,
    pub strings: Vec<VersionString>,
}

impl VersionInfo {
    /// The first non-empty value for `key`.
    pub fn get(&self, key: &str) -> Option<&VersionString> {
        self.strings
            .iter()
            .find(|s| s.key == key && !s.value.trim().is_empty())
    }
}

enum Entry {
    Dir(u64),
    Data(u64),
}

/// Find and parse the version resource, if the image has one.
pub fn find(img: &PeImage, view: &dyn FileView) -> Option<VersionInfo> {
    let dir = img.dir(DIR_RESOURCE)?;
    let base = img.rva_to_off(dir.rva)?;
    let Entry::Dir(names) = entry(view, base, 0, Some(RT_VERSION))? else {
        return None;
    };
    let Entry::Dir(langs) = entry(view, base, names, None)? else {
        return None;
    };
    let Entry::Data(data) = entry(view, base, langs, None)? else {
        return None;
    };
    let data_entry = read_exact(view, base.checked_add(data)?, 16)?;
    let leaf_rva = u32_le(&data_entry, 0)?;
    let leaf_size = u32_le(&data_entry, 4)? as usize;
    let leaf_off = img.rva_to_off(leaf_rva)?;
    let leaf = read(view, leaf_off, leaf_size.min(MAX_LEAF))?;
    let strings = parse(&leaf, leaf_off)?;
    Some(VersionInfo { leaf_off, strings })
}

/// Pick an entry from the resource directory at `base + rel`: the id entry
/// equal to `want`, or the first entry when `want` is `None`.
fn entry(view: &dyn FileView, base: u64, rel: u64, want: Option<u32>) -> Option<Entry> {
    let at = base.checked_add(rel)?;
    let head = read_exact(view, at, 16)?;
    let named = usize::from(u16_le(&head, 12)?);
    let ids = usize::from(u16_le(&head, 14)?);
    let total = (named + ids).min(MAX_ENTRIES);
    let table = read(view, at + 16, total * 8)?;
    for raw in table.as_chunks::<8>().0 {
        let name = u32_le(raw, 0)?;
        let target = u32_le(raw, 4)?;
        if let Some(id) = want
            && name != id
        {
            continue;
        }
        let rel = u64::from(target & 0x7fff_ffff);
        return Some(if target & 0x8000_0000 != 0 {
            Entry::Dir(rel)
        } else {
            Entry::Data(rel)
        });
    }
    None
}

/// A block header inside VS_VERSIONINFO.
struct Block {
    /// Offset just past the block, clamped to its parent.
    end: usize,
    /// Declared length, used to step to the next sibling.
    len: usize,
    value_len: usize,
    is_text: bool,
    key: String,
    value_off: usize,
}

fn align4(v: usize) -> usize {
    v.saturating_add(3) & !3
}

fn block(buf: &[u8], off: usize, parent_end: usize) -> Option<Block> {
    let len = usize::from(u16_le(buf, off)?);
    if len < 6 {
        return None;
    }
    let end = off.checked_add(len)?.min(parent_end);
    let value_len = usize::from(u16_le(buf, off + 2)?);
    let is_text = u16_le(buf, off + 4)? == 1;
    let mut p = off + 6;
    let mut units = Vec::new();
    loop {
        if p + 2 > end || units.len() > MAX_KEY_UNITS {
            return None;
        }
        let u = u16_le(buf, p)?;
        p += 2;
        if u == 0 {
            break;
        }
        units.push(u);
    }
    Some(Block {
        end,
        len,
        value_len,
        is_text,
        key: String::from_utf16_lossy(&units),
        value_off: align4(p),
    })
}

/// The children of a block whose children start at `start` and stop at `end`.
fn children(buf: &[u8], start: usize, end: usize) -> Vec<Block> {
    let mut out = Vec::new();
    let mut pos = align4(start);
    while pos + 6 <= end && out.len() < MAX_BLOCKS {
        let Some(b) = block(buf, pos, end) else {
            break;
        };
        pos = align4(pos + b.len);
        out.push(b);
    }
    out
}

/// Parse VS_VERSIONINFO in `leaf`, which sits at absolute offset `leaf_off`.
fn parse(leaf: &[u8], leaf_off: u64) -> Option<Vec<VersionString>> {
    let root = block(leaf, 0, leaf.len())?;
    if root.key != "VS_VERSION_INFO" {
        return None;
    }
    let mut strings = Vec::new();
    let root_kids = align4(root.value_off + root.value_len);
    for sfi in children(leaf, root_kids, root.end) {
        if sfi.key != "StringFileInfo" {
            continue;
        }
        let sfi_kids = align4(sfi.value_off + value_bytes(&sfi));
        for table in children(leaf, sfi_kids, sfi.end) {
            let table_kids = align4(table.value_off + value_bytes(&table));
            for s in children(leaf, table_kids, table.end) {
                if strings.len() >= MAX_BLOCKS {
                    return Some(strings);
                }
                let (value, units) = utf16_value(leaf, s.value_off, s.end);
                strings.push(VersionString {
                    key: s.key,
                    value,
                    value_off: leaf_off + s.value_off as u64,
                    value_len: (units * 2) as u64,
                });
            }
        }
    }
    Some(strings)
}

/// Byte length of a block's value. Text values count UTF-16 units.
fn value_bytes(b: &Block) -> usize {
    if b.is_text {
        b.value_len * 2
    } else {
        b.value_len
    }
}

/// A NUL-terminated UTF-16LE value in `[off, end)`, and its unit count.
fn utf16_value(buf: &[u8], off: usize, end: usize) -> (String, usize) {
    let mut units = Vec::new();
    let mut p = off;
    while p + 2 <= end {
        match u16_le(buf, p) {
            Some(0) | None => break,
            Some(u) => units.push(u),
        }
        p += 2;
    }
    (String::from_utf16_lossy(&units), units.len())
}
