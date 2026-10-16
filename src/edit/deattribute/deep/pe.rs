//! The PE part of the deep pass. The sweep reads only initialized data
//! sections, and inside them never touches a byte the loader or a
//! disassembler resolves by content: import and delay-import names and thunk
//! tables, export names and their arrays, TLS, load config, relocations,
//! exception data, the resource directory, version and manifest resources,
//! and .NET metadata other than the user string heap. Version and manifest
//! values can still identify a vendor, and RT_STRING leaves have their own
//! length-prefixed parser. The rewrites are fixed
//! fields: the export module name, COFF, export, resource and debug
//! timestamps, CodeView PDB paths and GUIDs, POGO, VC feature and repro
//! records, and the Authenticode directory slot and detached certificate.

use std::collections::BTreeSet;

use crate::model::{ContainerKind, Marker, Region};
use crate::parsers::pe::image::{
    DIR_CLR, DIR_DEBUG, DIR_EXPORT, DIR_RESOURCE, DIR_SECURITY, PeImage,
};
use crate::parsers::pe::version;
use crate::scan::FileView;
use crate::util::hash::hash_hex;

use super::super::{Caveat, Kind, Reason, Target};
use super::{
    Deep, Encoding, Evidence, Hit, Protected, Source, fill_marker, read_full, redact_hits,
    region_strings, roots,
};

const DIR_IMPORT: usize = 1;
const DIR_EXCEPTION: usize = 3;
const DIR_BASERELOC: usize = 5;
const DIR_TLS: usize = 9;
const DIR_LOAD_CONFIG: usize = 10;
const DIR_BOUND_IMPORT: usize = 11;
const DIR_IAT: usize = 12;
const DIR_DELAY_IMPORT: usize = 13;

const RT_VERSION: u32 = 16;
const RT_MANIFEST: u32 = 24;
const RT_STRING: u32 = 6;

const IMAGE_SCN_CNT_CODE: u32 = 0x20;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x40;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

const DEBUG_CODEVIEW: u32 = 2;
const DEBUG_VC_FEATURE: u32 = 12;
const DEBUG_POGO: u32 = 13;
const DEBUG_REPRO: u32 = 16;

/// Cap on import descriptors, thunks, export names and resource entries.
const MAX_ENTRIES: usize = 65_536;
/// Longest import, export or module name read.
const MAX_NAME: usize = 512;
/// Largest debug record body rewritten.
const MAX_DEBUG_BODY: usize = 64 * 1024;
const MAX_RESOURCE_STRING: usize = 256 * 1024;
const MAX_CERT_BODY: usize = 4 * 1024 * 1024;

/// The neutral stem a deep copy's export module name is rewritten to.
pub(super) const NEUTRAL_MODULE: &[u8] = b"module";

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

/// RT_STRING has sixteen length-prefixed UTF-16 values and no terminators.
fn string_table(view: &dyn FileView, off: u64, size: usize) -> Vec<Hit> {
    if size > MAX_RESOURCE_STRING {
        return Vec::new();
    }
    let Some(bytes) = read_full(view, off, size) else {
        return Vec::new();
    };
    let mut hits = Vec::new();
    let mut at = 0usize;
    for _ in 0..16 {
        let Some(units) = u16_at(&bytes, at).map(usize::from) else {
            break;
        };
        at += 2;
        let Some(end) = at.checked_add(units * 2).filter(|&n| n <= bytes.len()) else {
            break;
        };
        if (4..=super::MAX_STRING).contains(&units) {
            let raw: Vec<u16> = bytes[at..end]
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect();
            if let Ok(text) = String::from_utf16(&raw) {
                hits.push(Hit {
                    off: off + at as u64,
                    len: end - at,
                    text,
                    encoding: Encoding::Utf16,
                });
            }
        }
        at = end;
    }
    hits
}

/// Only assembly identities are used as evidence. The XML bytes stay intact.
fn manifest_names(view: &dyn FileView, off: u64, size: usize) -> Vec<String> {
    if size > MAX_RESOURCE_STRING {
        return Vec::new();
    }
    let Some(bytes) = read_full(view, off, size) else {
        return Vec::new();
    };
    let utf16 =
        bytes.starts_with(&[0xff, 0xfe]) || (bytes.len() >= 4 && bytes[1] == 0 && bytes[3] == 0);
    let text = if utf16 {
        let start = if bytes.starts_with(&[0xff, 0xfe]) {
            2
        } else {
            0
        };
        let units: Vec<u16> = bytes[start..]
            .chunks_exact(2)
            .map(|p| u16::from_le_bytes([p[0], p[1]]))
            .collect();
        String::from_utf16(&units).ok()
    } else {
        std::str::from_utf8(&bytes).ok().map(str::to_string)
    };
    let Some(text) = text else { return Vec::new() };
    let lower = text.to_ascii_lowercase();
    let mut names = Vec::new();
    let mut from = 0;
    while let Some(rel) = lower[from..].find("<assemblyidentity") {
        let begin = from + rel;
        let Some(end) = lower[begin..].find('>').map(|n| begin + n) else {
            break;
        };
        let tag = &text[begin..end];
        let tag_lower = &lower[begin..end];
        let name_at = tag_lower
            .match_indices("name")
            .map(|(at, _)| at)
            .find(|&at| {
                at.checked_sub(1)
                    .and_then(|before| tag.as_bytes().get(before))
                    .is_some_and(u8::is_ascii_whitespace)
                    && tag
                        .as_bytes()
                        .get(at + 4)
                        .is_some_and(|b| b.is_ascii_whitespace() || *b == b'=')
            });
        if let Some(at) = name_at {
            let mut value = at + 4;
            while tag
                .as_bytes()
                .get(value)
                .is_some_and(u8::is_ascii_whitespace)
            {
                value += 1;
            }
            if tag.as_bytes().get(value) == Some(&b'=') {
                value += 1;
                while tag
                    .as_bytes()
                    .get(value)
                    .is_some_and(u8::is_ascii_whitespace)
                {
                    value += 1;
                }
                if let Some(&quote @ (b'"' | b'\'')) = tag.as_bytes().get(value) {
                    value += 1;
                    if let Some(close) = tag[value..].find(char::from(quote)) {
                        names.push(
                            tag[value..value + close]
                                .split('.')
                                .next()
                                .unwrap_or("")
                                .to_string(),
                        );
                    }
                }
            }
        }
        from = end + 1;
    }
    names
}

/// Read O and CN name attributes from bounded DER in PKCS#7. These are weak
/// evidence because a certificate table may also contain CA certificates.
fn certificate_names(table: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at + 8 <= table.len() {
        let Some(len) = u32_at(table, at).map(|n| n as usize) else {
            break;
        };
        if len < 8 || at + len > table.len() {
            break;
        }
        if u16_at(table, at + 6) == Some(2) {
            let der = &table[at + 8..at + len];
            for pos in 0..der.len().saturating_sub(6) {
                if der.get(pos..pos + 4) != Some(&[6, 3, 0x55, 4][..])
                    || !matches!(der.get(pos + 4), Some(3 | 10))
                {
                    continue;
                }
                let tag = der[pos + 5];
                if !matches!(tag, 0x0c | 0x13 | 0x16 | 0x1e) {
                    continue;
                }
                let len0 = der[pos + 6];
                let (body, size) = if len0 & 0x80 == 0 {
                    (pos + 7, len0 as usize)
                } else if len0 == 0x81 && pos + 7 < der.len() {
                    (pos + 8, der[pos + 7] as usize)
                } else if len0 == 0x82 && pos + 8 < der.len() {
                    (
                        pos + 9,
                        u16::from_be_bytes([der[pos + 7], der[pos + 8]]) as usize,
                    )
                } else {
                    continue;
                };
                if size == 0 || size > 512 {
                    continue;
                }
                let Some(value) = der.get(body..body + size) else {
                    continue;
                };
                let name = if tag == 0x1e {
                    let units: Vec<u16> = value
                        .chunks_exact(2)
                        .map(|p| u16::from_be_bytes([p[0], p[1]]))
                        .collect();
                    String::from_utf16(&units).ok()
                } else {
                    std::str::from_utf8(value).ok().map(str::to_string)
                };
                if let Some(name) = name {
                    out.push(name);
                }
            }
        }
        at = (at + len + 7) & !7;
    }
    out
}

struct Walk<'a> {
    view: &'a dyn FileView,
    img: &'a PeImage,
    protected: Protected,
    rewrites: Vec<(Kind, u64, Vec<u8>)>,
    caveats: Vec<Caveat>,
    resource_hits: Vec<Hit>,
    evidence: Evidence,
    skipped: Vec<Reason>,
}

impl Walk<'_> {
    fn safe_resource_leaf(&self, rva: u32, size: u32) -> Option<u64> {
        let section = self.img.sections.iter().find(|s| s.contains_rva(rva))?;
        let delta = rva.checked_sub(section.va)?;
        if section.characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE) != 0
            || section.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA == 0
            || delta.checked_add(size)? > section.raw_size
        {
            return None;
        }
        let off = u64::from(section.raw_ptr) + u64::from(delta);
        off.checked_add(u64::from(size))
            .filter(|&end| end <= self.view.size())
            .map(|_| off)
    }

    /// Protect a data directory's whole range.
    fn dir_range(&mut self, index: usize) {
        if let Some(d) = self.img.dir(index)
            && let Some(off) = self.img.rva_to_off(d.rva)
        {
            self.protected.add(off, u64::from(d.size));
        }
    }

    /// Protect the NUL-terminated name at `rva`, returning its offset and bytes.
    fn name_at(&mut self, rva: u32) -> Option<(u64, Vec<u8>)> {
        let off = self.img.rva_to_off(rva)?;
        let bytes = self.view.read_at(off, MAX_NAME).ok()?;
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        self.protected.add(off, end as u64 + 1);
        Some((off, bytes[..end].to_vec()))
    }

    /// Protect a thunk array at `rva` and every hint/name entry it points to.
    fn thunks(&mut self, rva: u32) {
        let Some(mut at) = self.img.rva_to_off(rva) else {
            return;
        };
        let width = if self.img.is64 { 8usize } else { 4 };
        for _ in 0..MAX_ENTRIES {
            let Some(raw) = read_full(self.view, at, width) else {
                return;
            };
            let value = if self.img.is64 {
                u64_at(&raw, 0)
            } else {
                u32_at(&raw, 0).map(u64::from)
            };
            let Some(value) = value.filter(|&v| v != 0) else {
                return;
            };
            self.protected.add(at, width as u64);
            let ordinal = value >> (width * 8 - 1) != 0;
            if !ordinal && let Ok(name_rva) = u32::try_from(value & 0x7fff_ffff) {
                // A hint/name entry: a two-byte hint, then the name.
                self.name_at(name_rva.wrapping_add(2));
                if let Some(off) = self.img.rva_to_off(name_rva) {
                    self.protected.add(off, 2);
                }
            }
            at += width as u64;
        }
    }

    fn imports(&mut self) {
        let Some(d) = self.img.dir(DIR_IMPORT) else {
            return;
        };
        let Some(mut at) = self.img.rva_to_off(d.rva) else {
            return;
        };
        for _ in 0..MAX_ENTRIES {
            let Some(desc) = read_full(self.view, at, 20) else {
                return;
            };
            if desc.iter().all(|&b| b == 0) {
                return;
            }
            let (Some(lookup), Some(name), Some(iat)) =
                (u32_at(&desc, 0), u32_at(&desc, 12), u32_at(&desc, 16))
            else {
                return;
            };
            self.name_at(name);
            self.thunks(if lookup != 0 { lookup } else { iat });
            at += 20;
        }
    }

    fn delay_imports(&mut self) {
        let Some(d) = self.img.dir(DIR_DELAY_IMPORT) else {
            return;
        };
        let Some(mut at) = self.img.rva_to_off(d.rva) else {
            return;
        };
        for _ in 0..MAX_ENTRIES {
            let Some(desc) = read_full(self.view, at, 32) else {
                return;
            };
            if desc.iter().all(|&b| b == 0) {
                return;
            }
            let (Some(attrs), Some(name), Some(names)) =
                (u32_at(&desc, 0), u32_at(&desc, 4), u32_at(&desc, 16))
            else {
                return;
            };
            // Version 1 descriptors hold RVAs; the older form holds VAs.
            if attrs & 1 != 0 {
                self.name_at(name);
                self.thunks(names);
            }
            at += 32;
        }
    }

    /// Protect the export name arrays and names, returning the module name.
    fn exports(&mut self) -> Option<(u64, Vec<u8>)> {
        let d = self.img.dir(DIR_EXPORT)?;
        let at = self.img.rva_to_off(d.rva)?;
        let dir = read_full(self.view, at, 40)?;
        let name_rva = u32_at(&dir, 12)?;
        let functions = (u32_at(&dir, 20)? as usize).min(MAX_ENTRIES);
        let names = (u32_at(&dir, 24)? as usize).min(MAX_ENTRIES);
        let (Some(funcs_rva), Some(names_rva), Some(ords_rva)) =
            (u32_at(&dir, 28), u32_at(&dir, 32), u32_at(&dir, 36))
        else {
            return None;
        };
        if let Some(off) = self.img.rva_to_off(funcs_rva) {
            self.protected.add(off, functions as u64 * 4);
        }
        if let Some(off) = self.img.rva_to_off(ords_rva) {
            self.protected.add(off, names as u64 * 2);
        }
        if let Some(off) = self.img.rva_to_off(names_rva) {
            self.protected.add(off, names as u64 * 4);
            if let Some(table) = read_full(self.view, off, names * 4) {
                for i in 0..names {
                    if let Some(rva) = u32_at(&table, i * 4) {
                        self.name_at(rva);
                    }
                }
            }
        }
        if let Some(stamp) = at.checked_add(4) {
            self.zero(stamp, 4);
        }
        let module = self.name_at(name_rva)?;
        (module.1.len() >= 4 && module.1.iter().all(|b| (0x20..=0x7e).contains(b)))
            .then_some(module)
    }

    /// Queue a same-length zero rewrite when the field is not zero already.
    fn zero(&mut self, off: u64, len: usize) {
        if let Some(cur) = read_full(self.view, off, len)
            && cur.iter().any(|&b| b != 0)
        {
            self.rewrites.push((Kind::Brand, off, vec![0; len]));
        }
    }

    /// Walk the resource tree: protect every directory node, entry, name and
    /// data entry, plus version and manifest leaves whole; zero node stamps.
    fn resources(&mut self) {
        let Some(d) = self.img.dir(DIR_RESOURCE) else {
            return;
        };
        let Some(base) = self.img.rva_to_off(d.rva) else {
            return;
        };
        let mut seen = BTreeSet::new();
        let mut budget = 4096usize;
        self.node(base, 0, 0, None, &mut seen, &mut budget);
    }

    fn node(
        &mut self,
        base: u64,
        rel: u64,
        depth: usize,
        kind: Option<u32>,
        seen: &mut BTreeSet<u64>,
        budget: &mut usize,
    ) {
        if depth > 3 || *budget == 0 || !seen.insert(rel) {
            return;
        }
        *budget -= 1;
        let Some(at) = base.checked_add(rel) else {
            return;
        };
        let Some(head) = read_full(self.view, at, 16) else {
            return;
        };
        self.protected.add(at, 16);
        self.zero(at + 4, 4);
        let (Some(named), Some(ids)) = (u16_at(&head, 12), u16_at(&head, 14)) else {
            return;
        };
        let total = (usize::from(named) + usize::from(ids)).min(1024);
        let Some(table) = read_full(self.view, at + 16, total * 8) else {
            return;
        };
        self.protected.add(at + 16, total as u64 * 8);
        for i in 0..total {
            let (Some(name), Some(target)) = (u32_at(&table, i * 8), u32_at(&table, i * 8 + 4))
            else {
                continue;
            };
            if name & 0x8000_0000 != 0 {
                let off = base + u64::from(name & 0x7fff_ffff);
                if let Some(len) = read_full(self.view, off, 2).and_then(|b| u16_at(&b, 0)) {
                    self.protected.add(off, 2 + u64::from(len) * 2);
                }
            }
            let kind = if depth == 0 {
                (name & 0x8000_0000 == 0).then_some(name)
            } else {
                kind
            };
            let child = u64::from(target & 0x7fff_ffff);
            if target & 0x8000_0000 != 0 {
                self.node(base, child, depth + 1, kind, seen, budget);
                continue;
            }
            let Some(entry_off) = base.checked_add(child) else {
                continue;
            };
            self.protected.add(entry_off, 16);
            if let Some(entry) = read_full(self.view, entry_off, 16)
                && let (Some(rva), Some(size)) = (u32_at(&entry, 0), u32_at(&entry, 4))
                && let Some(off) = self.safe_resource_leaf(rva, size)
            {
                match kind {
                    Some(RT_VERSION) => self.protected.add(off, u64::from(size)),
                    Some(RT_MANIFEST) => {
                        self.protected.add(off, u64::from(size));
                        self.evidence.extend(
                            manifest_names(self.view, off, size as usize)
                                .into_iter()
                                .map(|name| (name, Source::Manifest)),
                        );
                    }
                    Some(RT_STRING) => {
                        self.resource_hits
                            .extend(string_table(self.view, off, size as usize))
                    }
                    _ => {}
                }
            }
        }
    }

    /// Protect .NET metadata and return the strings of its user string heap,
    /// the one heap the runtime reads as text rather than resolving by name.
    fn dotnet(&mut self) -> Vec<Hit> {
        let Some(d) = self.img.dir(DIR_CLR) else {
            return Vec::new();
        };
        let Some(off) = self.img.rva_to_off(d.rva) else {
            return Vec::new();
        };
        let Some(h) = read_full(self.view, off, 72) else {
            return Vec::new();
        };
        let (Some(md_rva), Some(md_size), Some(flags)) =
            (u32_at(&h, 8), u32_at(&h, 12), u32_at(&h, 16))
        else {
            return Vec::new();
        };
        if flags & 0x8 != 0 {
            self.caveats.push(Caveat::SignatureInvalidated);
        }
        for (rva_at, size_at) in [(24, 28), (32, 36)] {
            if let (Some(rva), Some(size)) = (u32_at(&h, rva_at), u32_at(&h, size_at))
                && let Some(o) = self.img.rva_to_off(rva)
            {
                self.protected.add(o, u64::from(size));
            }
        }
        let Some(md) = self.img.rva_to_off(md_rva) else {
            return Vec::new();
        };
        self.protected.add(md, u64::from(md_size));
        user_strings(self.view, md, u64::from(md_size)).unwrap_or_default()
    }

    fn debug(&mut self) {
        let Some(d) = self.img.dir(DIR_DEBUG) else {
            return;
        };
        let Some(dir) = self.img.rva_to_off(d.rva) else {
            return;
        };
        for i in 0..(u64::from(d.size) / 28).min(1024) {
            let at = dir + i * 28;
            let Some(entry) = read_full(self.view, at, 28) else {
                return;
            };
            self.zero(at + 4, 4);
            let (Some(kind), Some(size), Some(ptr)) =
                (u32_at(&entry, 12), u32_at(&entry, 16), u32_at(&entry, 24))
            else {
                continue;
            };
            let (ptr, size) = (u64::from(ptr), size as usize);
            if ptr == 0 || size == 0 || size > MAX_DEBUG_BODY {
                continue;
            }
            self.protected.add(ptr, size as u64);
            match kind {
                DEBUG_CODEVIEW => self.codeview(ptr, size),
                DEBUG_VC_FEATURE | DEBUG_POGO | DEBUG_REPRO => self.zero(ptr, size),
                _ => {}
            }
        }
    }

    /// Zero a CodeView record's PDB path, and for RSDS its GUID (the age stays).
    fn codeview(&mut self, ptr: u64, size: usize) {
        let Some(data) = read_full(self.view, ptr, size) else {
            return;
        };
        let path_at = match data.get(..4) {
            Some(b"RSDS") => {
                self.zero(ptr + 4, 16);
                24
            }
            Some(b"NB10") => 16,
            _ => return,
        };
        if let Some(end) = data
            .get(path_at..)
            .and_then(|b| b.iter().position(|&x| x == 0))
            .filter(|&e| e > 0)
        {
            let path = String::from_utf8_lossy(&data[path_at..path_at + end]);
            let file = path.rsplit(['\\', '/']).next().unwrap_or("");
            if let Some(stem) = file.to_ascii_lowercase().strip_suffix(".pdb") {
                self.evidence.push((stem.to_string(), Source::Pdb));
            }
            self.zero(ptr + path_at as u64, end);
        }
    }

    /// The certificate is outside the loaded image. Mine its names before
    /// clearing the detached payload and the directory slot.
    fn certificate(&mut self) -> Option<Marker> {
        let d = self.img.dir(DIR_SECURITY)?;
        let off = u64::from(d.rva);
        let len = d.size as usize;
        if len < 8
            || len > MAX_CERT_BODY
            || off < self.img.image_end()
            || off
                .checked_add(len as u64)
                .is_none_or(|end| end > self.view.size())
        {
            self.skipped.push(Reason::Unsafe);
            return None;
        }
        let Some(table) = read_full(self.view, off, len) else {
            self.skipped.push(Reason::Io);
            return None;
        };
        if u32_at(&table, 0).is_none_or(|n| n < 8 || n as usize > len) {
            self.skipped.push(Reason::Unsafe);
            return None;
        }
        self.evidence.extend(
            certificate_names(&table)
                .into_iter()
                .map(|name| (name, Source::Certificate)),
        );
        Some(fill_marker(off, len as u64, 0))
    }

    /// Initialized data sections past the headers that hold no code.
    fn data_regions(&self) -> Vec<(u64, u64)> {
        let headers = u64::from(self.img.size_of_headers).max(self.img.table_end);
        let mut out: Vec<(u64, u64)> = self
            .img
            .sections
            .iter()
            .filter(|s| {
                s.characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE) == 0
                    && s.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA != 0
                    && s.raw_size != 0
                    && u64::from(s.raw_ptr) >= headers
                    && u64::from(s.raw_ptr) + u64::from(s.raw_size) <= self.view.size()
            })
            .map(|s| (u64::from(s.raw_ptr), u64::from(s.raw_size)))
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }
}

/// The strings of a .NET `#US` heap: length-prefixed UTF-16 with a trailing
/// flag byte, reported without the prefix and flag so a blank keeps both.
fn user_strings(view: &dyn FileView, md: u64, md_size: u64) -> Option<Vec<Hit>> {
    let root = read_full(view, md, 16)?;
    if root.get(..4)? != b"BSJB" {
        return None;
    }
    let ver_len = u64::from(u32_at(&root, 12)?);
    let streams_at = md.checked_add(16)?.checked_add(ver_len)?;
    let head = read_full(view, streams_at, 4)?;
    let count = usize::from(u16_at(&head, 2)?).min(16);
    let mut at = streams_at + 4;
    for _ in 0..count {
        let h = read_full(view, at, 8 + 32)?;
        let offset = u64::from(u32_at(&h, 0)?);
        let size = u64::from(u32_at(&h, 4)?);
        let name_end = h[8..].iter().position(|&b| b == 0)?;
        let name = &h[8..8 + name_end];
        at += 8 + (name_end as u64 + 4) / 4 * 4;
        if name != b"#US" {
            continue;
        }
        if offset.checked_add(size)? > md_size || size > 64 * 1024 * 1024 {
            return None;
        }
        let heap_off = md + offset;
        let heap = read_full(view, heap_off, size as usize)?;
        let mut hits = Vec::new();
        let mut pos = 1usize;
        while pos < heap.len() {
            let b0 = heap[pos];
            let (len, hdr) = if b0 & 0x80 == 0 {
                (usize::from(b0), 1)
            } else if b0 & 0xc0 == 0x80 {
                (
                    usize::from(b0 & 0x3f) << 8 | usize::from(*heap.get(pos + 1)?),
                    2,
                )
            } else {
                let b = heap.get(pos..pos + 4)?;
                (
                    usize::from(b[0] & 0x1f) << 24
                        | usize::from(b[1]) << 16
                        | usize::from(b[2]) << 8
                        | usize::from(b[3]),
                    4,
                )
            };
            let body = pos + hdr;
            let chars = len.saturating_sub(1);
            if len == 0 {
                pos = body;
                continue;
            }
            if body + len > heap.len() {
                break;
            }
            let bytes = &heap[body..body + chars];
            if chars >= 8
                && chars % 2 == 0
                && bytes
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .all(|p| p[1] == 0 && (0x20..=0x7e).contains(&p[0]))
            {
                hits.push(Hit {
                    off: heap_off + body as u64,
                    len: chars,
                    text: bytes.iter().step_by(2).map(|&b| char::from(b)).collect(),
                    encoding: Encoding::Utf16,
                });
            }
            pos = body + len;
        }
        return Some(hits);
    }
    None
}

pub(super) fn sweep(view: &dyn FileView) -> Deep {
    let Some(img) = PeImage::parse(view) else {
        return Deep::default();
    };
    let mut w = Walk {
        view,
        img: &img,
        protected: Protected::default(),
        rewrites: Vec::new(),
        caveats: Vec::new(),
        resource_hits: Vec::new(),
        evidence: Vec::new(),
        skipped: Vec::new(),
    };
    w.protected
        .add(0, u64::from(img.size_of_headers).max(img.table_end));
    for dir in [
        DIR_EXPORT,
        DIR_IMPORT,
        DIR_EXCEPTION,
        DIR_BASERELOC,
        DIR_DEBUG,
        DIR_TLS,
        DIR_LOAD_CONFIG,
        DIR_BOUND_IMPORT,
        DIR_IAT,
        DIR_DELAY_IMPORT,
        DIR_CLR,
    ] {
        w.dir_range(dir);
    }
    w.imports();
    w.delay_imports();
    let module = w.exports();
    w.resources();
    let user = w.dotnet();
    w.debug();
    let certificate = w.certificate();
    if let Some(info) = version::find(&img, view) {
        for item in info.strings {
            let source = match item.key.as_str() {
                "CompanyName" => Some(Source::Company),
                "ProductName" | "InternalName" | "OriginalFilename" => Some(Source::Product),
                _ => None,
            };
            if let Some(source) = source {
                let value = if item.key == "OriginalFilename" {
                    item.value.split('.').next().unwrap_or("").to_string()
                } else {
                    item.value
                };
                w.evidence.push((value, source));
            }
        }
    }

    // COFF header TimeDateStamp.
    w.zero(img.e_lfanew + 8, 4);
    // A cleared security slot leaves the copy unsigned rather than carrying a
    // signature that no longer matches.
    if img.dir(DIR_SECURITY).is_some() {
        w.zero(img.dirs_off + DIR_SECURITY as u64 * 8, 8);
        w.caveats.push(Caveat::SignatureInvalidated);
    }

    let regions = w.data_regions();
    let mut hits = region_strings(view, &regions);
    hits.extend(w.resource_hits.iter().cloned());
    hits.sort();
    hits.dedup();
    let mut all_hits = hits.clone();
    all_hits.extend(user.iter().cloned());
    let stem = module.as_ref().and_then(|(_, name)| {
        let name = std::str::from_utf8(name).ok()?;
        name.split(['.', '_']).next()
    });
    let roots = roots(&all_hits, stem, &w.evidence);
    let mut rewrites = redact_hits(&hits, &roots, &w.protected);
    rewrites.extend(redact_hits(&user, &roots, &Protected::default()));
    let blanks = certificate
        .into_iter()
        .map(|marker| (Kind::Brand, marker))
        .collect();

    if let Some((off, old)) = module {
        let suffix = old
            .iter()
            .rposition(|&b| b == b'.')
            .map_or(&[][..], |i| &old[i..]);
        let room = old.len() - suffix.len();
        let mut name: Vec<u8> = NEUTRAL_MODULE.iter().copied().take(room).collect();
        name.resize(room, b'_');
        name.extend_from_slice(suffix);
        if name != old {
            w.rewrites.push((Kind::Brand, off, name));
        }
    }

    Deep {
        blanks,
        rewrites: w.rewrites.into_iter().chain(rewrites).collect(),
        caveats: w.caveats,
        skipped: w.skipped,
    }
}

/// Whether the PE carries an Authenticode signature.
pub(in super::super) fn signed(view: &dyn FileView) -> bool {
    PeImage::parse(view).is_some_and(|img| img.dir(DIR_SECURITY).is_some())
}

/// The checksum the PE will need once `targets` are applied, as one more
/// target, when the original carries a non-zero checksum that would change.
/// It is computed from the planned bytes, so the copy on disk and the same
/// file cleaned inside an archive get the same value.
pub(in super::super) fn checksum_target(view: &dyn FileView, targets: &[Target]) -> Option<Target> {
    if targets.is_empty() {
        return None;
    }
    let img = PeImage::parse(view)?;
    let field = img.checksum_off;
    if img.checksum == 0
        || targets
            .iter()
            .any(|t| t.marker.region.offset < field + 4 && t.marker.region.end() > field)
    {
        return None;
    }
    let size = view.size();
    let overlays: Vec<(u64, Vec<u8>)> = targets
        .iter()
        .map(|t| (t.marker.region.offset, t.new_bytes()))
        .collect();
    const CHUNK: u64 = 1 << 20;
    let mut sum: u64 = 0;
    let mut pos = 0u64;
    while pos < size {
        let n = CHUNK.min(size - pos);
        let mut buf = read_full(view, pos, n as usize)?;
        let end = pos + n;
        for (off, bytes) in &overlays {
            let o_end = off + bytes.len() as u64;
            if o_end <= pos || *off >= end {
                continue;
            }
            let from = (*off).max(pos);
            let to = o_end.min(end);
            buf[(from - pos) as usize..(to - pos) as usize]
                .copy_from_slice(&bytes[(from - off) as usize..(to - off) as usize]);
        }
        for f in field..field + 4 {
            if f >= pos && f < end {
                buf[(f - pos) as usize] = 0;
            }
        }
        for w in buf.chunks(2) {
            let word = match *w {
                [lo, hi] => u16::from_le_bytes([lo, hi]),
                [lo] => u16::from(lo),
                _ => 0,
            };
            sum += u64::from(word);
            sum = (sum & 0xffff) + (sum >> 16);
        }
        pos = end;
    }
    let folded = ((sum & 0xffff) + (sum >> 16)) & 0xffff;
    let value = (folded as u32).wrapping_add(size as u32);
    if value == img.checksum {
        return None;
    }
    let original = read_full(view, field, 4)?;
    Some(Target {
        kind: Kind::Brand,
        marker: Marker::blank(Region::new(field, 4), ContainerKind::Raw),
        expected_hash: hash_hex(&original),
        replacement: Some(value.to_le_bytes().to_vec()),
    })
}
