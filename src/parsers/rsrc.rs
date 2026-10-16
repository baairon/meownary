//! Macintosh resource forks and AppleDouble resource entries.

use crate::scan::FileView;

const MAX_TYPES: usize = 1024;
const MAX_REFS: usize = 65_536;

#[derive(Debug, Clone)]
pub(crate) struct Resource {
    pub kind: [u8; 4],
    pub off: u64,
    pub len: u64,
    pub name: Option<(u64, usize)>,
}

#[derive(Debug)]
pub(crate) struct Fork {
    pub resources: Vec<Resource>,
    pub apple_double: bool,
}

fn read(view: &dyn FileView, at: u64, len: usize) -> Option<Vec<u8>> {
    if at.checked_add(len as u64)? > view.size() {
        return None;
    }
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        let part = view.read_at(at + out.len() as u64, len - out.len()).ok()?;
        if part.is_empty() {
            return None;
        }
        out.extend_from_slice(&part);
    }
    Some(out)
}

fn u16_at(raw: &[u8], at: usize) -> Option<usize> {
    Some(u16::from_be_bytes(raw.get(at..at + 2)?.try_into().ok()?) as usize)
}

fn u32_at(raw: &[u8], at: usize) -> Option<u64> {
    Some(u32::from_be_bytes(raw.get(at..at + 4)?.try_into().ok()?) as u64)
}

/// Parse one fork, including its map, reference lists and data records.
pub(crate) fn parse(view: &dyn FileView) -> Option<Fork> {
    let head = read(view, 0, 26.min(view.size() as usize))?;
    let (base, size, apple_double) = if head.get(..4) == Some(&[0, 5, 0x16, 7][..]) {
        if u32_at(&head, 4)? != 0x0002_0000 {
            return None;
        }
        let count = u16_at(&head, 24)?.min(1024);
        let desc = read(view, 26, count * 12)?;
        let mut fork = None;
        for i in 0..count {
            if u32_at(&desc, i * 12) == Some(2) {
                let off = u32_at(&desc, i * 12 + 4)?;
                let len = u32_at(&desc, i * 12 + 8)?;
                if off.checked_add(len)? > view.size() {
                    return None;
                }
                fork = Some((off, len));
                break;
            }
        }
        let (off, len) = fork?;
        (off, len, true)
    } else {
        (0, view.size(), false)
    };
    let hdr = read(view, base, 16)?;
    let data_off = u32_at(&hdr, 0)?;
    let map_off = u32_at(&hdr, 4)?;
    let data_len = u32_at(&hdr, 8)?;
    let map_len = u32_at(&hdr, 12)?;
    if data_off < 16
        || map_off < data_off + data_len
        || map_off.checked_add(map_len)? > size
        || map_len < 30
    {
        return None;
    }
    let map = read(view, base + map_off, 30)?;
    let types_rel = u16_at(&map, 24)? as u64;
    let names_rel = u16_at(&map, 26)? as u64;
    if types_rel + 2 > map_len || names_rel > map_len {
        return None;
    }
    let count = u16_at(&read(view, base + map_off + types_rel, 2)?, 0)? + 1;
    if count > MAX_TYPES || types_rel + 2 + (count as u64) * 8 > map_len {
        return None;
    }
    let types = read(view, base + map_off + types_rel + 2, count * 8)?;
    let mut resources = Vec::new();
    for i in 0..count {
        let at = i * 8;
        let kind: [u8; 4] = types[at..at + 4].try_into().ok()?;
        let refs = u16_at(&types, at + 4)? + 1;
        let refs_rel = u16_at(&types, at + 6)? as u64;
        if refs > MAX_REFS || types_rel + refs_rel + (refs as u64) * 12 > map_len {
            return None;
        }
        let table = read(view, base + map_off + types_rel + refs_rel, refs * 12)?;
        for j in 0..refs {
            let at = j * 12;
            let name_rel = u16_at(&table, at + 2)?;
            let name = if name_rel == 0xffff {
                None
            } else {
                let at = base + map_off + names_rel + name_rel as u64;
                let len = read(view, at, 1)?[0] as usize;
                if names_rel + name_rel as u64 + 1 + len as u64 > map_len {
                    return None;
                }
                Some((at + 1, len))
            };
            let data_rel = u32_at(&table, at + 4)? & 0x00ff_ffff;
            if data_rel + 4 > data_len {
                return None;
            }
            let data_at = base + data_off + data_rel;
            let len = u32_at(&read(view, data_at, 4)?, 0)?;
            if data_rel + 4 + len > data_len {
                return None;
            }
            resources.push(Resource {
                kind,
                off: data_at + 4,
                len,
                name,
            });
        }
    }
    Some(Fork {
        resources,
        apple_double,
    })
}
