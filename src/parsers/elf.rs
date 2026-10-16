//! Probes for ELF objects (32 and 64-bit, either byte order): toolchain
//! strings in `.comment`, the GNU and Go build ids, the program interpreter,
//! and build paths left in `.comment` or the dynamic RPATH and RUNPATH.
//!
//! Every marker here is a RawBlank, so `structural_remove` stays `None`.

#[cfg(test)]
mod tests;

use std::borrow::Cow;

use crate::model::{
    BrandKind, Category, Confidence, ContainerKind, Evidence, Finding, JunkKind, Marker, Region,
    Severity, SignatureStatus,
};
use crate::scan::{FileView, Probe, ProbeCtx};
use crate::util::bytes::{cstr, is_printable_ascii, slice};

/// Probes contributed by this module.
pub fn probes() -> Vec<Box<dyn Probe>> {
    vec![Box::new(ElfProbe)]
}

/// Structure-aware removal for the containers this module owns. Every ELF
/// marker is a RawBlank, so there is nothing to rewrite.
pub fn structural_remove(_data: &[u8], _region: Region) -> Option<Vec<u8>> {
    None
}

struct ElfProbe;

impl Probe for ElfProbe {
    fn id(&self) -> &'static str {
        "elf"
    }

    fn formats(&self) -> &'static [&'static str] {
        &["elf"]
    }

    fn run(&self, ctx: &ProbeCtx, out: &mut Vec<Finding>) {
        let Some(elf) = Elf::parse(ctx.view) else {
            return;
        };
        comment(ctx.view, &elf, out);
        build_id(ctx.view, &elf, out);
        go_build_id(ctx.view, &elf, out);
        interp(ctx.view, &elf, out);
        rpath(ctx.view, &elf, out);
    }
}

/// Cap on section headers read.
const MAX_SECTIONS: usize = 512;
/// Cap on program headers read.
const MAX_PHDRS: usize = 256;
/// Cap on any one section body read.
const MAX_SECTION_READ: usize = 64 * 1024;
/// Cap on one string read out of a string table.
const MAX_STR: usize = 4096;

const SHT_SYMTAB: u32 = 2;
const SHT_DYNAMIC: u32 = 6;
const SHT_NOBITS: u32 = 8;
const PT_INTERP: u32 = 3;
const DT_RPATH: u64 = 15;
const DT_RUNPATH: u64 = 29;

// ---------------------------------------------------------------------------
// Shared helpers (also used by the PE and Mach-O probes)

/// Whether `s` names a user, temporary or build directory: the kind of path
/// that leaks who built a binary and where.
pub(crate) fn names_user_path(s: &str) -> bool {
    const NEEDLES: [&str; 14] = [
        "/home/",
        "/users/",
        "/tmp/",
        "/var/folders/",
        "/private/var/",
        "/build/",
        "/builds/",
        "/builddir/",
        "/_build/",
        "/runner/work/",
        "/workspace/",
        "/jenkins/",
        "/target/debug",
        "/target/release",
    ];
    let lower = s.to_ascii_lowercase().replace('\\', "/");
    NEEDLES.iter().any(|n| lower.contains(n)) || has_drive_path(s)
}

/// Whether `s` holds a Windows drive path such as `C:\` or `d:/`.
pub(crate) fn has_drive_path(s: &str) -> bool {
    let b = s.as_bytes();
    b.windows(3).enumerate().any(|(i, w)| {
        w[0].is_ascii_alphabetic()
            && w[1] == b':'
            && (w[2] == b'\\' || w[2] == b'/')
            && (i == 0 || !b[i - 1].is_ascii_alphanumeric())
    })
}

/// Whether a free-form string contains a filesystem path (URLs excluded).
fn contains_fs_path(s: &str) -> bool {
    s.split(|c: char| c.is_whitespace() || "()[]'\",;".contains(c))
        .filter(|tok| !tok.contains("://"))
        .any(|tok| {
            let unix = tok.len() > 3
                && tok.starts_with('/')
                && tok[1..].contains('/')
                && tok[1..].starts_with(|c: char| c.is_ascii_alphanumeric() || "._-~".contains(c));
            unix || tok.starts_with("~/") || has_drive_path(tok)
        })
}

/// Up to `len` bytes at `off`, borrowed from the header window when possible.
fn read(view: &dyn FileView, off: u64, len: usize) -> Option<Cow<'_, [u8]>> {
    let header = view.header();
    if let Some(end) = off.checked_add(len as u64)
        && end <= header.len() as u64
    {
        return header.get(off as usize..end as usize).map(Cow::Borrowed);
    }
    view.read_at(off, len).ok().map(Cow::Owned)
}

/// Printable, length-capped text for titles and notes.
fn clean(s: &str, max: usize) -> String {
    let mut out: String = s
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .take(max)
        .collect();
    if s.chars().count() > max {
        out.push_str("...");
    }
    out.trim().to_string()
}

fn finding(
    category: Category,
    confidence: Confidence,
    severity: Severity,
    id: &str,
    title: String,
    evidence: Evidence,
    marker: Option<Marker>,
) -> Finding {
    Finding {
        category,
        confidence,
        severity,
        signature_id: id.to_string(),
        title,
        evidence,
        marker,
    }
}

// ---------------------------------------------------------------------------
// Header parsing

/// Byte order and word size of one ELF file.
#[derive(Debug, Clone, Copy)]
struct Order {
    le: bool,
    is64: bool,
}

impl Order {
    fn u16(&self, b: &[u8], off: usize) -> Option<u16> {
        let a: [u8; 2] = slice(b, off, 2)?.try_into().ok()?;
        Some(if self.le {
            u16::from_le_bytes(a)
        } else {
            u16::from_be_bytes(a)
        })
    }

    fn u32(&self, b: &[u8], off: usize) -> Option<u32> {
        let a: [u8; 4] = slice(b, off, 4)?.try_into().ok()?;
        Some(if self.le {
            u32::from_le_bytes(a)
        } else {
            u32::from_be_bytes(a)
        })
    }

    fn u64(&self, b: &[u8], off: usize) -> Option<u64> {
        let a: [u8; 8] = slice(b, off, 8)?.try_into().ok()?;
        Some(if self.le {
            u64::from_le_bytes(a)
        } else {
            u64::from_be_bytes(a)
        })
    }

    /// A class-sized word (4 bytes for ELF32, 8 for ELF64).
    fn word(&self, b: &[u8], off: usize) -> Option<u64> {
        if self.is64 {
            self.u64(b, off)
        } else {
            self.u32(b, off).map(u64::from)
        }
    }
}

#[derive(Debug, Clone)]
struct Shdr {
    name: String,
    kind: u32,
    flags: u64,
    offset: u64,
    size: u64,
    link: u32,
}

#[derive(Debug, Clone, Copy)]
struct Phdr {
    kind: u32,
    offset: u64,
    filesz: u64,
}

struct Elf {
    order: Order,
    sections: Vec<Shdr>,
    phdrs: Vec<Phdr>,
}

impl Elf {
    fn parse(view: &dyn FileView) -> Option<Self> {
        let h = view.header();
        if slice(h, 0, 4)? != b"\x7fELF" {
            return None;
        }
        let is64 = match *h.get(4)? {
            1 => false,
            2 => true,
            _ => return None,
        };
        let le = match *h.get(5)? {
            1 => true,
            2 => false,
            _ => return None,
        };
        let o = Order { le, is64 };
        let (phoff, shoff, rest) = if is64 {
            (o.u64(h, 32)?, o.u64(h, 40)?, 52usize)
        } else {
            (u64::from(o.u32(h, 28)?), u64::from(o.u32(h, 32)?), 40usize)
        };
        let phentsize = usize::from(o.u16(h, rest + 2)?);
        let phnum = usize::from(o.u16(h, rest + 4)?);
        let shentsize = usize::from(o.u16(h, rest + 6)?);
        let shnum = usize::from(o.u16(h, rest + 8)?);
        let shstrndx = usize::from(o.u16(h, rest + 10)?);

        let phdrs = Self::phdrs(view, o, phoff, phentsize, phnum);
        let sections = Self::sections(view, o, shoff, shentsize, shnum, shstrndx);
        Some(Elf {
            order: o,
            sections,
            phdrs,
        })
    }

    fn phdrs(view: &dyn FileView, o: Order, off: u64, entsize: usize, num: usize) -> Vec<Phdr> {
        let min = if o.is64 { 56 } else { 32 };
        if off == 0 || num == 0 || entsize < min || entsize > 256 {
            return Vec::new();
        }
        let num = num.min(MAX_PHDRS);
        let Some(table) = read(view, off, num * entsize) else {
            return Vec::new();
        };
        table
            .chunks_exact(entsize)
            .filter_map(|p| {
                Some(if o.is64 {
                    Phdr {
                        kind: o.u32(p, 0)?,
                        offset: o.u64(p, 8)?,
                        filesz: o.u64(p, 32)?,
                    }
                } else {
                    Phdr {
                        kind: o.u32(p, 0)?,
                        offset: u64::from(o.u32(p, 4)?),
                        filesz: u64::from(o.u32(p, 16)?),
                    }
                })
            })
            .collect()
    }

    fn sections(
        view: &dyn FileView,
        o: Order,
        off: u64,
        entsize: usize,
        num: usize,
        strndx: usize,
    ) -> Vec<Shdr> {
        let min = if o.is64 { 64 } else { 40 };
        if off == 0 || entsize < min || entsize > 256 {
            return Vec::new();
        }
        // Raw headers: (name offset, type, offset, size, link, flags).
        let raw = |b: &[u8]| -> Option<(u32, u32, u64, u64, u32, u64)> {
            Some(if o.is64 {
                (
                    o.u32(b, 0)?,
                    o.u32(b, 4)?,
                    o.u64(b, 24)?,
                    o.u64(b, 32)?,
                    o.u32(b, 40)?,
                    o.u64(b, 8)?,
                )
            } else {
                (
                    o.u32(b, 0)?,
                    o.u32(b, 4)?,
                    u64::from(o.u32(b, 16)?),
                    u64::from(o.u32(b, 20)?),
                    o.u32(b, 24)?,
                    u64::from(o.u32(b, 8)?),
                )
            })
        };
        // Extended numbering keeps the real count and string index in
        // section 0 when they overflow the 16-bit header fields.
        let (mut num, mut strndx) = (num, strndx);
        if num == 0 || strndx == 0xffff {
            let Some(first) = read(view, off, entsize) else {
                return Vec::new();
            };
            let Some((_, _, _, size0, link0, _)) = raw(&first) else {
                return Vec::new();
            };
            if num == 0 {
                num = usize::try_from(size0).unwrap_or(0);
            }
            if strndx == 0xffff {
                strndx = link0 as usize;
            }
        }
        let num = num.min(MAX_SECTIONS);
        if num == 0 {
            return Vec::new();
        }
        let Some(table) = read(view, off, num * entsize) else {
            return Vec::new();
        };
        let raws: Vec<_> = table.chunks_exact(entsize).filter_map(raw).collect();
        let names = raws
            .get(strndx)
            .filter(|r| r.1 != SHT_NOBITS)
            .and_then(|r| read(view, r.2, r.3.min(MAX_SECTION_READ as u64) as usize));
        raws.iter()
            .map(|&(name, kind, offset, size, link, flags)| {
                let name = names
                    .as_deref()
                    .and_then(|n| cstr(n, name as usize, 256))
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .unwrap_or_default();
                Shdr {
                    name,
                    kind,
                    flags,
                    offset,
                    size,
                    link,
                }
            })
            .collect()
    }

    fn section(&self, name: &str) -> Option<&Shdr> {
        self.sections
            .iter()
            .find(|s| s.name == name && s.kind != SHT_NOBITS && s.size != 0)
    }

    /// A section's bytes, capped at [`MAX_SECTION_READ`].
    fn body<'a>(&self, view: &'a dyn FileView, s: &Shdr) -> Option<Cow<'a, [u8]>> {
        if s.kind == SHT_NOBITS {
            return None;
        }
        read(view, s.offset, s.size.min(MAX_SECTION_READ as u64) as usize)
    }
}

// ---------------------------------------------------------------------------
// Deep deattribution regions

const SHT_PROGBITS: u32 = 1;
const SHF_EXECINSTR: u64 = 0x4;

/// Sections whose bytes the loader or linker resolves by content, never swept
/// even when they are plain data.
const LOAD_BEARING_SECTIONS: &[&str] = &[
    ".interp",
    ".dynstr",
    ".dynsym",
    ".strtab",
    ".symtab",
    ".shstrtab",
    ".dynamic",
    ".gnu.version",
    ".gnu.version_r",
    ".gnu.version_d",
    ".gnu.hash",
    ".hash",
    ".got",
    ".got.plt",
    ".init_array",
    ".fini_array",
    ".go.buildinfo",
    ".gopclntab",
    ".typelink",
    ".itablink",
];

/// File ranges of the data sections a deep sweep may read: allocated or
/// `.comment` PROGBITS sections that hold no code and are not resolved by
/// content (string tables, symbol tables, version and dynamic tables, notes,
/// unwind data). Sorted, as `(offset, len)`.
pub(crate) fn data_regions(view: &dyn FileView) -> Vec<(u64, u64)> {
    let Some(elf) = Elf::parse(view) else {
        return Vec::new();
    };
    let size = view.size();
    let mut out: Vec<(u64, u64)> = elf
        .sections
        .iter()
        .filter(|s| {
            s.kind == SHT_PROGBITS
                && s.flags & SHF_EXECINSTR == 0
                && s.size != 0
                && !LOAD_BEARING_SECTIONS.contains(&s.name.as_str())
                && !s.name.starts_with(".note")
                && !s.name.starts_with(".eh_frame")
                && !s.name.starts_with(".debug")
                && !s.name.starts_with(".rela")
                && !s.name.starts_with(".rel.")
                && (s.name == ".comment"
                    || s.name.starts_with(".rodata")
                    || s.name.starts_with(".data"))
                && s.offset >= 64
                && s.offset.checked_add(s.size).is_some_and(|end| end <= size)
        })
        .map(|s| (s.offset, s.size))
        .collect();
    out.sort_unstable();
    out
}

// ---------------------------------------------------------------------------
// .comment

/// Toolchain strings in `.comment`, without unrelated build paths.
pub(crate) fn deattribute_comment(view: &dyn FileView) -> Vec<Marker> {
    let Some(elf) = Elf::parse(view) else {
        return Vec::new();
    };
    let Some(sec) = elf.section(".comment") else {
        return Vec::new();
    };
    let Some(body) = elf.body(view, sec) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut at = 0usize;
    for part in body.split(|&b| b == 0) {
        let start = at;
        at += part.len() + 1;
        if part.is_empty() || !is_printable_ascii(part) {
            continue;
        }
        let value = String::from_utf8_lossy(part);
        if contains_fs_path(&value) || value.trim().is_empty() {
            continue;
        }
        out.push(Marker::blank(
            Region::new(sec.offset + start as u64, part.len() as u64),
            ContainerKind::ElfSection,
        ));
        if out.len() >= 32 {
            break;
        }
    }
    out
}

fn comment(view: &dyn FileView, elf: &Elf, out: &mut Vec<Finding>) {
    const MAX_STRINGS: usize = 32;
    let Some(sec) = elf.section(".comment") else {
        return;
    };
    let Some(body) = elf.body(view, sec) else {
        return;
    };
    // (offset inside the section, text)
    let mut strings: Vec<(usize, String)> = Vec::new();
    let mut at = 0usize;
    for part in body.split(|&b| b == 0) {
        let start = at;
        at += part.len() + 1;
        if part.is_empty() || !is_printable_ascii(part) {
            continue;
        }
        let text = String::from_utf8_lossy(part).trim().to_string();
        if !text.is_empty() {
            strings.push((start, text));
        }
        if strings.len() >= MAX_STRINGS {
            break;
        }
    }
    if strings.is_empty() {
        return;
    }
    let mut unique: Vec<&str> = Vec::new();
    for (_, s) in &strings {
        if !unique.contains(&s.as_str()) {
            unique.push(s);
        }
    }
    let symtab = elf
        .sections
        .iter()
        .any(|s| s.kind == SHT_SYMTAB || s.name == ".symtab");
    let note = format!(
        "{}; {}",
        unique
            .iter()
            .map(|s| clean(s, 160))
            .collect::<Vec<_>>()
            .join("; "),
        if symtab {
            ".symtab present (not stripped)"
        } else {
            "no .symtab (stripped)"
        }
    );
    out.push(finding(
        Category::Brand(BrandKind::Toolchain),
        Confidence::Strong,
        Severity::Info,
        "elf.comment",
        clean(&unique.join(", "), 96),
        Evidence::at(sec.offset)
            .with_note(note)
            .with_bytes(body.get(..body.len().min(64)).unwrap_or(&[]).to_vec()),
        None,
    ));

    for (start, text) in &strings {
        if !contains_fs_path(text) {
            continue;
        }
        let Some(raw) = body.get(*start..) else {
            continue;
        };
        let len = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        let off = sec.offset + *start as u64;
        out.push(finding(
            Category::Junk(JunkKind::BuildPath),
            Confidence::Strong,
            Severity::Notice,
            "elf.comment.junk",
            format!("Build path in .comment: {}", clean(text, 72)),
            Evidence::at(off)
                .with_note(format!(".comment string \"{}\"", clean(text, 200)))
                .with_bytes(raw.get(..len.min(64)).unwrap_or(&[]).to_vec()),
            Some(Marker::blank(
                Region::new(off, len as u64),
                ContainerKind::ElfSection,
            )),
        ));
    }
}

// ---------------------------------------------------------------------------
// Notes

/// One parsed ELF note.
struct Note<'a> {
    name: &'a [u8],
    kind: u32,
    desc: &'a [u8],
}

/// Walk the notes in a SHT_NOTE body. Name and desc are 4-byte aligned.
fn notes(o: Order, body: &[u8]) -> Vec<Note<'_>> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at + 12 <= body.len() && out.len() < 16 {
        let (Some(namesz), Some(descsz), Some(kind)) =
            (o.u32(body, at), o.u32(body, at + 4), o.u32(body, at + 8))
        else {
            break;
        };
        let namesz = namesz as usize;
        let descsz = descsz as usize;
        let name_at = at + 12;
        let desc_at = name_at.saturating_add(namesz.saturating_add(3) & !3);
        let next = desc_at.saturating_add(descsz.saturating_add(3) & !3);
        let (Some(name), Some(desc)) = (slice(body, name_at, namesz), slice(body, desc_at, descsz))
        else {
            break;
        };
        let name_len = name.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
        let name = name.get(..name_len).unwrap_or(&[]);
        out.push(Note { name, kind, desc });
        if next <= at {
            break;
        }
        at = next;
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn build_id(view: &dyn FileView, elf: &Elf, out: &mut Vec<Finding>) {
    const NT_GNU_BUILD_ID: u32 = 3;
    let Some(sec) = elf.section(".note.gnu.build-id") else {
        return;
    };
    let Some(body) = elf.body(view, sec) else {
        return;
    };
    let Some(note) = notes(elf.order, &body)
        .into_iter()
        .find(|n| n.kind == NT_GNU_BUILD_ID && n.name == b"GNU" && !n.desc.is_empty())
    else {
        return;
    };
    let id = hex(note.desc.get(..note.desc.len().min(64)).unwrap_or(&[]));
    out.push(finding(
        Category::Integrity(SignatureStatus::Present),
        Confidence::Strong,
        Severity::Info,
        "elf.build_id",
        "GNU build id present".to_string(),
        Evidence::at(sec.offset).with_note(format!("build id {id}")),
        None,
    ));
}

fn go_build_id(view: &dyn FileView, elf: &Elf, out: &mut Vec<Finding>) {
    const NT_GO_BUILDID: u32 = 4;
    let Some(sec) = elf.section(".note.go.buildid") else {
        return;
    };
    let Some(body) = elf.body(view, sec) else {
        return;
    };
    let Some(note) = notes(elf.order, &body)
        .into_iter()
        .find(|n| n.kind == NT_GO_BUILDID && n.name == b"Go")
    else {
        return;
    };
    let id = clean(&String::from_utf8_lossy(note.desc), 120);
    out.push(finding(
        Category::Brand(BrandKind::Toolchain),
        Confidence::Strong,
        Severity::Info,
        "elf.go_buildid",
        "Go".to_string(),
        Evidence::at(sec.offset).with_note(format!("Go build id {id}")),
        None,
    ));
}

// ---------------------------------------------------------------------------
// Interpreter

fn interp(view: &dyn FileView, elf: &Elf, out: &mut Vec<Finding>) {
    let from_phdr = elf
        .phdrs
        .iter()
        .find(|p| p.kind == PT_INTERP && p.filesz > 0)
        .map(|p| (p.offset, p.filesz));
    let from_section = || elf.section(".interp").map(|s| (s.offset, s.size));
    let Some((off, size)) = from_phdr.or_else(from_section) else {
        return;
    };
    let Some(raw) = read(view, off, size.min(MAX_STR as u64) as usize) else {
        return;
    };
    let Some(path) = cstr(&raw, 0, raw.len()) else {
        return;
    };
    if path.is_empty() || !is_printable_ascii(path) {
        return;
    }
    let path = String::from_utf8_lossy(path).into_owned();
    let family = if path.contains("ld-musl") {
        Some("musl")
    } else if path.contains("ld-linux") {
        Some("glibc")
    } else if path.starts_with("/system/bin/linker") {
        Some("Android bionic")
    } else if path.contains("ld-elf.so") {
        Some("FreeBSD")
    } else {
        None
    };
    let mut note = format!("program interpreter {}", clean(&path, 200));
    if let Some(f) = family {
        note.push_str(&format!(" ({f})"));
    }
    out.push(finding(
        Category::Brand(BrandKind::Toolchain),
        Confidence::Moderate,
        Severity::Info,
        "elf.interp",
        format!("Loader {}", clean(&path, 80)),
        Evidence::at(off).with_note(note),
        None,
    ));
}

// ---------------------------------------------------------------------------
// RPATH and RUNPATH

fn rpath(view: &dyn FileView, elf: &Elf, out: &mut Vec<Finding>) {
    const MAX_DYN: usize = 4096;
    let o = elf.order;
    let entsize = if o.is64 { 16 } else { 8 };
    for dynamic in elf.sections.iter().filter(|s| s.kind == SHT_DYNAMIC) {
        let Some(strtab) = elf.sections.get(dynamic.link as usize) else {
            continue;
        };
        if strtab.kind == SHT_NOBITS {
            continue;
        }
        let Some(body) = elf.body(view, dynamic) else {
            continue;
        };
        for e in body.chunks_exact(entsize).take(MAX_DYN) {
            let (Some(tag), Some(val)) = (o.word(e, 0), o.word(e, entsize / 2)) else {
                break;
            };
            if tag == 0 {
                break;
            }
            if tag != DT_RPATH && tag != DT_RUNPATH {
                continue;
            }
            let name = if tag == DT_RPATH {
                "DT_RPATH"
            } else {
                "DT_RUNPATH"
            };
            if let Some(f) = rpath_entry(view, strtab, val, name) {
                out.push(f);
            }
        }
    }
}

fn rpath_entry(view: &dyn FileView, strtab: &Shdr, val: u64, name: &str) -> Option<Finding> {
    if val >= strtab.size {
        return None;
    }
    let off = strtab.offset.checked_add(val)?;
    let max = (strtab.size - val).min(MAX_STR as u64) as usize;
    let raw = read(view, off, max)?;
    let bytes = cstr(&raw, 0, raw.len())?;
    if bytes.is_empty() {
        return None;
    }
    let text = String::from_utf8_lossy(bytes).into_owned();

    // Blank from the first offending entry to the end of the string, taking
    // its leading ':' along so the entries before it stay intact. Positions
    // come from the raw bytes, since lossy decoding can change lengths.
    let mut pos = 0usize;
    let mut first_bad: Option<(usize, String)> = None;
    let mut kept_after: Vec<String> = Vec::new();
    for (i, part) in bytes.split(|&b| b == b':').enumerate() {
        let part_text = String::from_utf8_lossy(part);
        if first_bad.is_some() {
            if !part.is_empty() && !names_user_path(&part_text) {
                kept_after.push(part_text.into_owned());
            }
        } else if names_user_path(&part_text) {
            let start = if i == 0 { 0 } else { pos.saturating_sub(1) };
            first_bad = Some((start, part_text.into_owned()));
        }
        pos += part.len() + 1;
    }
    let (start, bad) = first_bad?;
    let len = bytes.len().checked_sub(start)?;
    let region = Region::new(off + start as u64, len as u64);
    let mut note = format!("{name} = {}", clean(&text, 240));
    if !kept_after.is_empty() {
        note.push_str(&format!(
            "; scrubbing also clears the later entries {}",
            clean(&kept_after.join(":"), 120)
        ));
    }
    Some(finding(
        Category::Junk(JunkKind::BuildPath),
        Confidence::Strong,
        Severity::Notice,
        "elf.rpath",
        format!("Build path in {name}: {}", clean(&bad, 72)),
        Evidence::at(off)
            .with_note(note)
            .with_bytes(bytes.get(..bytes.len().min(64)).unwrap_or(&[]).to_vec()),
        Some(Marker::blank(region, ContainerKind::ElfSection)),
    ))
}
