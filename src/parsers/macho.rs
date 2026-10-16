//! Probes for Mach-O binaries: thin 32 and 64-bit files in either byte order
//! and universal (fat) files. Reports the code signature state, the build
//! platform and SDK, the image UUID, user paths in LC_RPATH and App Store
//! encryption. Findings for a fat slice carry absolute file offsets and an
//! arch prefix in the title.
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
use crate::util::bytes::{cstr, slice, u32_be, u64_be};

use super::elf::names_user_path;

/// Probes contributed by this module.
pub fn probes() -> Vec<Box<dyn Probe>> {
    vec![Box::new(MachoProbe)]
}

/// Structure-aware removal for the containers this module owns. Every
/// Mach-O marker is a RawBlank, so there is nothing to rewrite.
pub fn structural_remove(_data: &[u8], _region: Region) -> Option<Vec<u8>> {
    None
}

struct MachoProbe;

impl Probe for MachoProbe {
    fn id(&self) -> &'static str {
        "macho"
    }

    fn formats(&self) -> &'static [&'static str] {
        &["macho"]
    }

    fn run(&self, ctx: &ProbeCtx, out: &mut Vec<Finding>) {
        let view = ctx.view;
        match fat_slices(view) {
            Some(slices) => {
                for s in slices {
                    thin(view, s.base, s.size, Some(&s.arch), out);
                }
            }
            None => thin(view, 0, view.size(), None, out),
        }
    }
}

/// Cap on fat arches visited.
const MAX_ARCHES: usize = 16;
/// Cap on load commands walked per slice.
const MAX_CMDS: usize = 256;
/// Cap on the load command area read per slice.
const MAX_CMDS_BYTES: u64 = 2 * 1024 * 1024;
/// Cap on SuperBlob index entries.
const MAX_BLOBS: usize = 64;

const LC_UUID: u32 = 0x1b;
const LC_CODE_SIGNATURE: u32 = 0x1d;
const LC_SYMTAB: u32 = 0x2;
const LC_ENCRYPTION_INFO: u32 = 0x21;
const LC_VERSION_MIN_MACOSX: u32 = 0x24;
const LC_VERSION_MIN_IPHONEOS: u32 = 0x25;
const LC_ENCRYPTION_INFO_64: u32 = 0x2c;
const LC_VERSION_MIN_TVOS: u32 = 0x2f;
const LC_VERSION_MIN_WATCHOS: u32 = 0x30;
const LC_BUILD_VERSION: u32 = 0x32;
const LC_RPATH: u32 = 0x8000_001c;

const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
const CSMAGIC_CODEDIRECTORY: u32 = 0xfade_0c02;
const CS_ADHOC: u32 = 0x2;

// ---------------------------------------------------------------------------
// Helpers

fn read(view: &dyn FileView, off: u64, len: usize) -> Option<Cow<'_, [u8]>> {
    let header = view.header();
    if let Some(end) = off.checked_add(len as u64)
        && end <= header.len() as u64
    {
        return header.get(off as usize..end as usize).map(Cow::Borrowed);
    }
    view.read_at(off, len).ok().map(Cow::Owned)
}

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

/// `xxxx.yy.zz` nibble-packed version.
fn version(v: u32) -> String {
    let (major, minor, patch) = (v >> 16, (v >> 8) & 0xff, v & 0xff);
    if patch == 0 {
        format!("{major}.{minor}")
    } else {
        format!("{major}.{minor}.{patch}")
    }
}

// ---------------------------------------------------------------------------
// Fat files

struct Slice {
    base: u64,
    size: u64,
    arch: String,
}

fn arch_name(cputype: u32, subtype: u32) -> String {
    match (cputype, subtype & 0x00ff_ffff) {
        (0x0100_000c, 2) => "arm64e".to_string(),
        (0x0100_000c, _) => "arm64".to_string(),
        (0x0200_000c, _) => "arm64_32".to_string(),
        (0x0000_000c, _) => "arm".to_string(),
        (0x0100_0007, 8) => "x86_64h".to_string(),
        (0x0100_0007, _) => "x86_64".to_string(),
        (0x0000_0007, _) => "i386".to_string(),
        (0x0000_0012, _) => "ppc".to_string(),
        (0x0100_0012, _) => "ppc64".to_string(),
        (t, _) => format!("cpu 0x{t:x}"),
    }
}

/// The slices of a fat file, or `None` when the file is not fat.
fn fat_slices(view: &dyn FileView) -> Option<Vec<Slice>> {
    let h = view.header();
    let magic = u32_be(h, 0)?;
    let is64 = match magic {
        0xcafe_babe => false,
        0xcafe_babf => true,
        _ => return None,
    };
    let count = (u32_be(h, 4)? as usize).min(MAX_ARCHES);
    let entsize = if is64 { 32 } else { 20 };
    let table = read(view, 8, count * entsize)?;
    let size = view.size();
    let slices = table
        .chunks_exact(entsize)
        .filter_map(|a| {
            let cputype = u32_be(a, 0)?;
            let subtype = u32_be(a, 4)?;
            let (base, len) = if is64 {
                (u64_be(a, 8)?, u64_be(a, 16)?)
            } else {
                (u64::from(u32_be(a, 8)?), u64::from(u32_be(a, 12)?))
            };
            let end = base.checked_add(len)?;
            (base >= 8 && end <= size && len >= 28).then(|| Slice {
                base,
                size: len,
                arch: arch_name(cputype, subtype),
            })
        })
        .collect();
    Some(slices)
}

// ---------------------------------------------------------------------------
// Thin images

#[derive(Debug, Clone, Copy)]
struct Order {
    le: bool,
}

impl Order {
    fn u32(&self, b: &[u8], off: usize) -> Option<u32> {
        let a: [u8; 4] = slice(b, off, 4)?.try_into().ok()?;
        Some(if self.le {
            u32::from_le_bytes(a)
        } else {
            u32::from_be_bytes(a)
        })
    }
}

/// One thin image at `base`, with its arch name when it is a fat slice.
struct Ctx<'a> {
    view: &'a dyn FileView,
    base: u64,
    size: u64,
    arch: Option<&'a str>,
    o: Order,
}

impl Ctx<'_> {
    fn title(&self, t: String) -> String {
        match self.arch {
            Some(a) => format!("[{a}] {t}"),
            None => t,
        }
    }
}

fn thin(view: &dyn FileView, base: u64, size: u64, arch: Option<&str>, out: &mut Vec<Finding>) {
    let Some(h) = read(view, base, 32) else {
        return;
    };
    let (le, is64) = match (u32_be(&h, 0), h.get(..4)) {
        (Some(0xfeed_face), _) => (false, false),
        (Some(0xfeed_facf), _) => (false, true),
        (_, Some([0xce, 0xfa, 0xed, 0xfe])) => (true, false),
        (_, Some([0xcf, 0xfa, 0xed, 0xfe])) => (true, true),
        _ => return,
    };
    let o = Order { le };
    let (Some(ncmds), Some(sizeofcmds)) = (o.u32(&h, 16), o.u32(&h, 20)) else {
        return;
    };
    let hdr = if is64 { 32u64 } else { 28 };
    // A load command area that runs past the slice means a truncated or
    // corrupt header: report nothing rather than guess.
    if h.len() < hdr as usize || hdr + u64::from(sizeofcmds) > size {
        return;
    }
    let want = u64::from(sizeofcmds).min(MAX_CMDS_BYTES) as usize;
    let Some(cmds) = read(view, base + hdr, want) else {
        return;
    };
    let ctx = Ctx {
        view,
        base,
        size,
        arch,
        o,
    };

    // Collect the commands first: whether the slice is signed shapes the
    // notes of the junk findings that come before LC_CODE_SIGNATURE.
    let mut lcs: Vec<(u32, &[u8], u64)> = Vec::new();
    let mut pos = 0usize;
    let walk = (ncmds as usize).min(MAX_CMDS);
    for _ in 0..walk {
        let (Some(cmd), Some(cmdsize)) = (o.u32(&cmds, pos), o.u32(&cmds, pos + 4)) else {
            break;
        };
        let cmdsize = cmdsize as usize;
        if cmdsize < 8 {
            break;
        }
        let Some(lc) = slice(&cmds, pos, cmdsize) else {
            break;
        };
        lcs.push((cmd, lc, base + hdr + pos as u64));
        pos += cmdsize;
    }
    let signed = lcs.iter().any(|&(cmd, _, _)| cmd == LC_CODE_SIGNATURE);
    // Only a fully walked command table can prove the signature is absent.
    let complete = lcs.len() == ncmds as usize;

    let mut versioned = false;
    for &(cmd, lc, lc_off) in &lcs {
        match cmd {
            LC_CODE_SIGNATURE => code_signature(&ctx, lc, lc_off, out),
            LC_BUILD_VERSION if !versioned => {
                versioned = build_version(&ctx, lc, lc_off, out);
            }
            LC_VERSION_MIN_MACOSX
            | LC_VERSION_MIN_IPHONEOS
            | LC_VERSION_MIN_TVOS
            | LC_VERSION_MIN_WATCHOS
                if !versioned =>
            {
                versioned = version_min(&ctx, cmd, lc, lc_off, out);
            }
            LC_UUID => uuid(&ctx, lc, lc_off, out),
            LC_RPATH => rpath(&ctx, lc, lc_off, signed, out),
            LC_ENCRYPTION_INFO | LC_ENCRYPTION_INFO_64 => encryption(&ctx, lc, lc_off, out),
            _ => {}
        }
    }

    if !signed && complete {
        out.push(finding(
            Category::Integrity(SignatureStatus::NoEmbedded),
            Confidence::Strong,
            Severity::Info,
            "macho.code_signature",
            ctx.title("No embedded code signature".to_string()),
            Evidence::at(base).with_note("no LC_CODE_SIGNATURE load command"),
            None,
        ));
    }
}

// ---------------------------------------------------------------------------
// Deep deattribution regions

const LC_SEGMENT: u32 = 0x1;
const LC_SEGMENT_64: u32 = 0x19;
const S_ZEROFILL: u32 = 0x1;
const S_GB_ZEROFILL: u32 = 0xc;
const S_THREAD_LOCAL_ZEROFILL: u32 = 0x12;
const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x400;

/// What a deep sweep may read in a Mach-O file.
#[derive(Debug, Default)]
pub(crate) struct DeepRegions {
    /// Absolute `(offset, len)` file ranges, sorted.
    pub regions: Vec<(u64, u64)>,
    /// Any slice carries `LC_CODE_SIGNATURE`.
    pub signed: bool,
    pub signatures: Vec<DeepSignature>,
}

#[derive(Debug)]
pub(crate) struct DeepSignature {
    pub off: u64,
    pub len: u64,
    pub command_off: u64,
    pub ident: Option<String>,
    pub team: Option<String>,
}

/// String sections a deep sweep may read, by `(segment prefix, section)`.
/// Objective-C class and selector names, symbol and string tables and
/// everything in `__LINKEDIT` are resolved by content and never listed.
const DEEP_SECTIONS: &[(&str, &str)] = &[
    ("__TEXT", "__cstring"),
    ("__TEXT", "__const"),
    ("__TEXT", "__ustring"),
    ("__TEXT", "__oslogstring"),
    ("__DATA", "__const"),
    ("__DATA", "__data"),
];

pub(crate) fn deep_regions(view: &dyn FileView) -> DeepRegions {
    let mut out = DeepRegions::default();
    match fat_slices(view) {
        Some(slices) => {
            for s in slices {
                thin_regions(view, s.base, s.size, &mut out);
            }
        }
        None => thin_regions(view, 0, view.size(), &mut out),
    }
    out.regions.sort_unstable();
    out.regions.dedup();
    out
}

fn fixed_name(b: &[u8]) -> &[u8] {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    &b[..end]
}

fn thin_regions(view: &dyn FileView, base: u64, size: u64, out: &mut DeepRegions) {
    let Some(h) = read(view, base, 32) else {
        return;
    };
    let (le, is64) = match (u32_be(&h, 0), h.get(..4)) {
        (Some(0xfeed_face), _) => (false, false),
        (Some(0xfeed_facf), _) => (false, true),
        (_, Some([0xce, 0xfa, 0xed, 0xfe])) => (true, false),
        (_, Some([0xcf, 0xfa, 0xed, 0xfe])) => (true, true),
        _ => return,
    };
    let o = Order { le };
    let u64o = |b: &[u8], at: usize| -> Option<u64> {
        let lo = u64::from(o.u32(b, at)?);
        let hi = u64::from(o.u32(b, at + 4)?);
        Some(if le { lo | (hi << 32) } else { (lo << 32) | hi })
    };
    let (Some(ncmds), Some(sizeofcmds)) = (o.u32(&h, 16), o.u32(&h, 20)) else {
        return;
    };
    let hdr = if is64 { 32u64 } else { 28 };
    if hdr + u64::from(sizeofcmds) > size {
        return;
    }
    let want = u64::from(sizeofcmds).min(MAX_CMDS_BYTES) as usize;
    let Some(cmds) = read(view, base + hdr, want) else {
        return;
    };
    let mut pos = 0usize;
    for _ in 0..(ncmds as usize).min(MAX_CMDS) {
        let (Some(cmd), Some(cmdsize)) = (o.u32(&cmds, pos), o.u32(&cmds, pos + 4)) else {
            break;
        };
        let cmdsize = cmdsize as usize;
        let Some(lc) = slice(&cmds, pos, cmdsize).filter(|_| cmdsize >= 8) else {
            break;
        };
        pos += cmdsize;
        if cmd == LC_CODE_SIGNATURE {
            let (Some(dataoff), Some(datasize)) = (o.u32(lc, 8), o.u32(lc, 12)) else {
                continue;
            };
            if datasize == 0 {
                continue;
            }
            out.signed = true;
            if u64::from(dataoff)
                .checked_add(u64::from(datasize))
                .is_some_and(|end| end <= size)
            {
                let ctx = Ctx {
                    view,
                    base,
                    size,
                    arch: None,
                    o,
                };
                let cd = superblob(&ctx, u64::from(dataoff), u64::from(datasize));
                out.signatures.push(DeepSignature {
                    off: base + u64::from(dataoff),
                    len: u64::from(datasize),
                    command_off: base + hdr + pos as u64 - cmdsize as u64,
                    ident: cd.as_ref().and_then(|c| c.ident.clone()),
                    team: cd.and_then(|c| c.team),
                });
            }
            continue;
        }
        if cmd == LC_SYMTAB {
            let (Some(symoff), Some(nsyms), Some(stroff), Some(strsize)) =
                (o.u32(lc, 8), o.u32(lc, 12), o.u32(lc, 16), o.u32(lc, 20))
            else {
                continue;
            };
            let ent = if is64 { 16u64 } else { 12 };
            if nsyms > 65_536
                || strsize > 64 * 1024 * 1024
                || u64::from(symoff) + u64::from(nsyms) * ent > size
                || u64::from(stroff) + u64::from(strsize) > size
            {
                continue;
            }
            for i in 0..nsyms {
                let Some(sym) = read(
                    view,
                    base + u64::from(symoff) + u64::from(i) * ent,
                    ent as usize,
                ) else {
                    break;
                };
                if !matches!(sym[4], 0x64 | 0x66 | 0x84) {
                    continue;
                }
                let Some(strx) = o.u32(&sym, 0) else {
                    continue;
                };
                if strx == 0 || strx >= strsize {
                    continue;
                }
                let off = base + u64::from(stroff) + u64::from(strx);
                let limit = (strsize - strx).min(4096) as usize;
                let Some(raw) = read(view, off, limit) else {
                    continue;
                };
                if let Some(end) = raw.iter().position(|&b| b == 0)
                    && end >= 4
                    && raw[..end].iter().all(|&b| b >= 0x20)
                {
                    out.regions.push((off, end as u64 + 1));
                }
            }
            continue;
        }
        let (nsects_at, first, entsize) = match cmd {
            LC_SEGMENT => (48usize, 56usize, 68usize),
            LC_SEGMENT_64 => (64, 72, 80),
            _ => continue,
        };
        let Some(nsects) = o.u32(lc, nsects_at) else {
            continue;
        };
        for i in 0..(nsects as usize).min(256) {
            let Some(sec) = slice(lc, first + i * entsize, entsize) else {
                break;
            };
            let sect = fixed_name(&sec[..16]);
            let seg = fixed_name(&sec[16..32]);
            let listed = DEEP_SECTIONS
                .iter()
                .any(|(s, n)| seg.starts_with(s.as_bytes()) && sect == n.as_bytes());
            if !listed {
                continue;
            }
            let (sz, off, flags) = if cmd == LC_SEGMENT_64 {
                (u64o(sec, 40), o.u32(sec, 48), o.u32(sec, 64))
            } else {
                (
                    o.u32(sec, 36).map(u64::from),
                    o.u32(sec, 40),
                    o.u32(sec, 56),
                )
            };
            let (Some(sz), Some(off), Some(flags)) = (sz, off, flags) else {
                continue;
            };
            let kind = flags & 0xff;
            if matches!(kind, S_ZEROFILL | S_GB_ZEROFILL | S_THREAD_LOCAL_ZEROFILL)
                || flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS) != 0
                || sz == 0
                || u64::from(off) < hdr + u64::from(sizeofcmds)
                || u64::from(off).checked_add(sz).is_none_or(|end| end > size)
            {
                continue;
            }
            out.regions.push((base + u64::from(off), sz));
        }
    }
}

// ---------------------------------------------------------------------------
// Code signature

fn code_signature(ctx: &Ctx, lc: &[u8], lc_off: u64, out: &mut Vec<Finding>) {
    let (Some(dataoff), Some(datasize)) = (ctx.o.u32(lc, 8), ctx.o.u32(lc, 12)) else {
        return;
    };
    if dataoff == 0 && datasize == 0 {
        out.push(finding(
            Category::Integrity(SignatureStatus::Absent),
            Confidence::Strong,
            Severity::Info,
            "macho.code_signature",
            ctx.title("No embedded code signature".to_string()),
            Evidence::at(lc_off).with_note("LC_CODE_SIGNATURE has no data"),
            None,
        ));
        return;
    }
    let parsed = superblob(ctx, u64::from(dataoff), u64::from(datasize));
    let f = match parsed {
        Some(cd) => {
            let mut note = match &cd.ident {
                Some(id) => format!("identifier {}", clean(id, 120)),
                None => "no identifier".to_string(),
            };
            if let Some(team) = &cd.team {
                note.push_str(&format!(", team {}", clean(team, 40)));
            }
            note.push_str(&format!(
                ", CodeDirectory flags 0x{:x}; trust is not checked",
                cd.flags
            ));
            if cd.flags & CS_ADHOC != 0 {
                finding(
                    Category::Integrity(SignatureStatus::AdHoc),
                    Confidence::Strong,
                    Severity::Notice,
                    "macho.code_signature",
                    ctx.title("Ad hoc code signature".to_string()),
                    Evidence::at(cd.off).with_note(note),
                    None,
                )
            } else {
                finding(
                    Category::Integrity(SignatureStatus::Present),
                    Confidence::Strong,
                    Severity::Info,
                    "macho.code_signature",
                    ctx.title("Code signature present (not verified)".to_string()),
                    Evidence::at(cd.off).with_note(note),
                    None,
                )
            }
        }
        None => finding(
            Category::Integrity(SignatureStatus::Absent),
            Confidence::Moderate,
            Severity::Warn,
            "macho.code_signature",
            ctx.title("Code signature is damaged or truncated".to_string()),
            Evidence::at(lc_off).with_note(format!(
                "LC_CODE_SIGNATURE points at offset {dataoff} for {datasize} bytes, which holds no readable CodeDirectory"
            )),
            None,
        ),
    };
    out.push(f);
}

struct CodeDirectory {
    /// Absolute offset of the CodeDirectory blob.
    off: u64,
    flags: u32,
    ident: Option<String>,
    team: Option<String>,
}

/// Parse the SuperBlob at slice offset `dataoff` and pick its CodeDirectory.
/// Signature blobs are always big-endian.
fn superblob(ctx: &Ctx, dataoff: u64, datasize: u64) -> Option<CodeDirectory> {
    if dataoff.checked_add(datasize)? > ctx.size || datasize < 12 {
        return None;
    }
    let sb_off = ctx.base + dataoff;
    let head = read(ctx.view, sb_off, 12)?;
    if u32_be(&head, 0)? != CSMAGIC_EMBEDDED_SIGNATURE {
        return None;
    }
    let count = (u32_be(&head, 8)? as usize).min(MAX_BLOBS);
    let index = read(ctx.view, sb_off + 12, count * 8)?;
    let mut best: Option<u64> = None;
    for e in index.as_chunks::<8>().0 {
        let (Some(slot), Some(rel)) = (u32_be(e, 0), u32_be(e, 4)) else {
            break;
        };
        let rel = u64::from(rel);
        if rel + 8 > datasize {
            continue;
        }
        let magic = read(ctx.view, sb_off + rel, 4).and_then(|m| u32_be(&m, 0));
        if magic != Some(CSMAGIC_CODEDIRECTORY) {
            continue;
        }
        if slot == 0 || best.is_none() {
            best = Some(rel);
        }
        if slot == 0 {
            break;
        }
    }
    let rel = best?;
    let cd_off = sb_off + rel;
    let cd = read(ctx.view, cd_off, 64)?;
    let cd_len = u64::from(u32_be(&cd, 4)?).min(datasize - rel);
    let version = u32_be(&cd, 8)?;
    let flags = u32_be(&cd, 12)?;
    let string_at = |field: usize| -> Option<String> {
        let at = u64::from(u32_be(&cd, field)?);
        if at == 0 || at >= cd_len {
            return None;
        }
        let raw = read(ctx.view, cd_off + at, (cd_len - at).min(512) as usize)?;
        let s = cstr(&raw, 0, raw.len())?;
        (!s.is_empty()).then(|| String::from_utf8_lossy(s).into_owned())
    };
    let ident = string_at(20);
    let team = if version >= 0x20200 {
        string_at(48)
    } else {
        None
    };
    Some(CodeDirectory {
        off: cd_off,
        flags,
        ident,
        team,
    })
}

// ---------------------------------------------------------------------------
// Build version

fn platform_name(p: u32) -> String {
    match p {
        1 => "macOS".to_string(),
        2 => "iOS".to_string(),
        3 => "tvOS".to_string(),
        4 => "watchOS".to_string(),
        5 => "bridgeOS".to_string(),
        6 => "Mac Catalyst".to_string(),
        7 => "iOS Simulator".to_string(),
        8 => "tvOS Simulator".to_string(),
        9 => "watchOS Simulator".to_string(),
        10 => "DriverKit".to_string(),
        11 => "visionOS".to_string(),
        12 => "visionOS Simulator".to_string(),
        n => format!("platform {n}"),
    }
}

fn tool_name(t: u32) -> String {
    match t {
        1 => "clang".to_string(),
        2 => "swift".to_string(),
        3 => "ld".to_string(),
        4 => "lld".to_string(),
        1024 => "metal".to_string(),
        n => format!("tool {n}"),
    }
}

fn build_version(ctx: &Ctx, lc: &[u8], lc_off: u64, out: &mut Vec<Finding>) -> bool {
    const MAX_TOOLS: usize = 8;
    let o = ctx.o;
    let (Some(platform), Some(minos), Some(sdk), Some(ntools)) =
        (o.u32(lc, 8), o.u32(lc, 12), o.u32(lc, 16), o.u32(lc, 20))
    else {
        return false;
    };
    let tools: Vec<String> = (0..(ntools as usize).min(MAX_TOOLS))
        .map_while(|i| {
            let at = 24 + i * 8;
            Some(format!(
                "{} {}",
                tool_name(o.u32(lc, at)?),
                version(o.u32(lc, at + 4)?)
            ))
        })
        .collect();
    let name = platform_name(platform);
    let mut note = format!(
        "platform {name}, minos {}, sdk {}",
        version(minos),
        version(sdk)
    );
    if !tools.is_empty() {
        note.push_str(&format!(", tools: {}", tools.join(", ")));
    }
    out.push(finding(
        Category::Brand(BrandKind::Toolchain),
        Confidence::Strong,
        Severity::Info,
        "macho.build_version",
        ctx.title(format!("{name} {} (SDK {})", version(minos), version(sdk))),
        Evidence::at(lc_off).with_note(note),
        None,
    ));
    true
}

fn version_min(ctx: &Ctx, cmd: u32, lc: &[u8], lc_off: u64, out: &mut Vec<Finding>) -> bool {
    let (Some(v), Some(sdk)) = (ctx.o.u32(lc, 8), ctx.o.u32(lc, 12)) else {
        return false;
    };
    let name = match cmd {
        LC_VERSION_MIN_MACOSX => "macOS",
        LC_VERSION_MIN_IPHONEOS => "iOS",
        LC_VERSION_MIN_TVOS => "tvOS",
        _ => "watchOS",
    };
    out.push(finding(
        Category::Brand(BrandKind::Toolchain),
        Confidence::Strong,
        Severity::Info,
        "macho.build_version",
        ctx.title(format!("{name} {} (SDK {})", version(v), version(sdk))),
        Evidence::at(lc_off).with_note(format!(
            "LC_VERSION_MIN for {name}: minimum {}, sdk {}",
            version(v),
            version(sdk)
        )),
        None,
    ));
    true
}

// ---------------------------------------------------------------------------
// UUID, RPATH, encryption

fn uuid(ctx: &Ctx, lc: &[u8], lc_off: u64, out: &mut Vec<Finding>) {
    let Some(u) = slice(lc, 8, 16) else {
        return;
    };
    let hex: Vec<String> = u.iter().map(|b| format!("{b:02X}")).collect();
    let text = format!(
        "{}-{}-{}-{}-{}",
        hex[0..4].concat(),
        hex[4..6].concat(),
        hex[6..8].concat(),
        hex[8..10].concat(),
        hex[10..16].concat()
    );
    out.push(finding(
        Category::Brand(BrandKind::Toolchain),
        Confidence::Moderate,
        Severity::Info,
        "macho.uuid",
        ctx.title(format!("Image UUID {text}")),
        Evidence::at(lc_off + 8)
            .with_note(format!("LC_UUID {text}"))
            .with_bytes(u.to_vec()),
        None,
    ));
}

fn rpath(ctx: &Ctx, lc: &[u8], lc_off: u64, signed: bool, out: &mut Vec<Finding>) {
    let Some(rel) = ctx.o.u32(lc, 8).map(|v| v as usize) else {
        return;
    };
    if rel < 12 || rel >= lc.len() {
        return;
    }
    let Some(path) = cstr(lc, rel, lc.len() - rel) else {
        return;
    };
    if path.is_empty() {
        return;
    }
    let text = String::from_utf8_lossy(path).into_owned();
    if !names_user_path(&text) {
        return;
    }
    let off = lc_off + rel as u64;
    let mut note = format!("LC_RPATH {}", clean(&text, 240));
    if signed {
        note.push_str("; scrubbing changes signed bytes, so re-sign the binary afterwards");
    }
    out.push(finding(
        Category::Junk(JunkKind::BuildPath),
        Confidence::Strong,
        Severity::Notice,
        "macho.rpath",
        ctx.title(format!("Build path in LC_RPATH: {}", clean(&text, 72))),
        Evidence::at(off)
            .with_note(note)
            .with_bytes(path.get(..path.len().min(64)).unwrap_or(&[]).to_vec()),
        Some(Marker::blank(
            Region::new(off, path.len() as u64),
            ContainerKind::MachoLoadCmd,
        )),
    ));
}

fn encryption(ctx: &Ctx, lc: &[u8], lc_off: u64, out: &mut Vec<Finding>) {
    let (Some(cryptoff), Some(cryptsize), Some(cryptid)) =
        (ctx.o.u32(lc, 8), ctx.o.u32(lc, 12), ctx.o.u32(lc, 16))
    else {
        return;
    };
    if cryptid == 0 {
        return;
    }
    out.push(finding(
        Category::Brand(BrandKind::Vendor),
        Confidence::Moderate,
        Severity::Info,
        "macho.encrypted",
        ctx.title("App Store encrypted binary".to_string()),
        Evidence::at(lc_off).with_note(format!(
            "cryptid {cryptid}, {cryptsize} encrypted bytes at slice offset {cryptoff}"
        )),
        None,
    ));
}
