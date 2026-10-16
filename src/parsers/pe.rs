//! Probes for PE (Portable Executable) images: the MSVC Rich header, PDB
//! paths, version resources, Authenticode presence, overlays, the header
//! checksum, .NET metadata and packer section names.
//!
//! Every marker here is a RawBlank or a Truncate, so `structural_remove`
//! stays `None`.

pub(crate) mod image;
mod rich;
pub(crate) mod version;

#[cfg(test)]
mod tests;

use crate::model::{
    BrandKind, Category, Confidence, ContainerKind, DeceptionKind, Evidence, Finding, JunkKind,
    Marker, Region, Severity, SignatureStatus, TamperKind,
};
use crate::scan::{FileView, Probe, ProbeCtx};
use crate::util::bytes::{cstr, find, u16_le, u32_le};
use crate::util::fmt::human_size;

use image::{DIR_CLR, DIR_DEBUG, DIR_SECURITY, PeImage, read, read_exact};
use version::VersionInfo;

/// Probes contributed by this module.
pub fn probes() -> Vec<Box<dyn Probe>> {
    vec![Box::new(PeProbe)]
}

/// Structure-aware removal for the containers this module owns. Every PE
/// marker is a RawBlank or a Truncate, so there is nothing to rewrite.
pub fn structural_remove(_data: &[u8], _region: Region) -> Option<Vec<u8>> {
    None
}

struct PeProbe;

impl Probe for PeProbe {
    fn id(&self) -> &'static str {
        "pe"
    }

    fn formats(&self) -> &'static [&'static str] {
        &["pe"]
    }

    fn run(&self, ctx: &ProbeCtx, out: &mut Vec<Finding>) {
        scan(ctx.view, out);
    }
}

const MIB: u64 = 1024 * 1024;
/// Largest file whose header checksum is recomputed.
const CHECKSUM_MAX: u64 = 32 * MIB;
/// Cap on debug directory entries.
const MAX_DEBUG_ENTRIES: usize = 32;
/// Cap on one CodeView record.
const MAX_CODEVIEW: usize = 4096;

fn scan(view: &dyn FileView, out: &mut Vec<Finding>) {
    let Some(img) = PeImage::parse(view) else {
        return;
    };
    let cert = Cert::read(view, &img);
    let caveat = caveat(&img, &cert);

    rich_header(view, &img, caveat, out);
    pdb_paths(view, &img, caveat, out);
    let version = version::find(&img, view);
    if let Some(v) = &version {
        version_info(v, caveat, out);
    }
    authenticode(&img, &cert, out);
    if let Some(v) = &version {
        impersonation(v, &cert, in_windows_dir(view.path()), out);
    }
    overlay(view, &img, &cert, out);
    checksum(view, &img, out);
    dotnet(view, &img, out);
    packers(&img, out);
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

/// What a scrub of this file disturbs beyond the marker bytes.
fn caveat(img: &PeImage, cert: &Cert) -> Option<&'static str> {
    match (matches!(cert, Cert::Present { .. }), img.checksum != 0) {
        (true, true) => {
            Some("scrubbing invalidates the Authenticode signature and the header checksum")
        }
        (true, false) => Some("scrubbing invalidates the Authenticode signature"),
        (false, true) => Some("scrubbing leaves the header checksum stale"),
        (false, false) => None,
    }
}

fn with_caveat(note: String, caveat: Option<&str>) -> String {
    match caveat {
        Some(c) => format!("{note}; {c}"),
        None => note,
    }
}

// ---------------------------------------------------------------------------
// Rich header

fn rich_header(view: &dyn FileView, img: &PeImage, caveat: Option<&str>, out: &mut Vec<Finding>) {
    const LISTED: usize = 16;
    let header = view.header();
    let Some(r) = rich::find(header, img.e_lfanew) else {
        return;
    };
    let mut note = if r.entries.is_empty() {
        "@comp.id table is empty".to_string()
    } else {
        let listed: Vec<String> = r.entries.iter().take(LISTED).map(rich::describe).collect();
        format!("@comp.id: {}", listed.join(", "))
    };
    if r.entries.len() > LISTED {
        note.push_str(&format!(", and {} more", r.entries.len() - LISTED));
    }
    let title = match rich::headline_release(&r.entries) {
        Some(rel) => format!("MSVC toolchain ({rel})"),
        None => "MSVC toolchain (Rich header)".to_string(),
    };
    let matched = header
        .get(r.dans_off..r.end_off.min(r.dans_off + 64))
        .unwrap_or(&[])
        .to_vec();
    let start = r.dans_off as u64;
    out.push(finding(
        Category::Brand(BrandKind::Toolchain),
        if r.clean {
            Confidence::Strong
        } else {
            Confidence::Moderate
        },
        Severity::Info,
        "pe.rich_header",
        title,
        Evidence::at(start)
            .with_note(with_caveat(note, caveat))
            .with_bytes(matched),
        Some(Marker::blank(
            Region::new(start, r.end_off as u64 - start),
            ContainerKind::Raw,
        )),
    ));
}

// ---------------------------------------------------------------------------
// PDB paths

fn pdb_paths(view: &dyn FileView, img: &PeImage, caveat: Option<&str>, out: &mut Vec<Finding>) {
    let Some(dir) = img.dir(DIR_DEBUG) else {
        return;
    };
    let Some(base) = img.rva_to_off(dir.rva) else {
        return;
    };
    let count = (dir.size as usize / 28).min(MAX_DEBUG_ENTRIES);
    let Some(table) = read(view, base, count * 28) else {
        return;
    };
    let mut seen: Vec<u64> = Vec::new();
    for entry in table.as_chunks::<28>().0 {
        if let Some(f) = codeview(view, img, entry, caveat) {
            // Several entries may point at the same record; report it once.
            if !seen.contains(&f.evidence.offset) {
                seen.push(f.evidence.offset);
                out.push(f);
            }
        }
    }
}

fn codeview(
    view: &dyn FileView,
    img: &PeImage,
    entry: &[u8],
    caveat: Option<&str>,
) -> Option<Finding> {
    const IMAGE_DEBUG_TYPE_CODEVIEW: u32 = 2;
    if u32_le(entry, 12)? != IMAGE_DEBUG_TYPE_CODEVIEW {
        return None;
    }
    let size = u32_le(entry, 16)? as usize;
    let rva = u32_le(entry, 20)?;
    let ptr = u32_le(entry, 24)?;
    let off = if ptr != 0 {
        u64::from(ptr)
    } else {
        img.rva_to_off(rva)?
    };
    let data = read(view, off, size.min(MAX_CODEVIEW))?;
    let (kind, path_at, detail) = match data.get(..4)? {
        b"RSDS" => {
            let guid = guid(data.get(4..20)?)?;
            let age = u32_le(&data, 20)?;
            ("RSDS", 24usize, format!("GUID {guid}, age {age}"))
        }
        b"NB10" => {
            let age = u32_le(&data, 12)?;
            ("NB10", 16usize, format!("age {age}"))
        }
        _ => return None,
    };
    let path = cstr(&data, path_at, data.len().saturating_sub(path_at))?;
    let text = String::from_utf8_lossy(path);
    if text.trim().is_empty() {
        return None;
    }
    let file = text.rsplit(['\\', '/']).next().unwrap_or(&text);
    let path_off = off + path_at as u64;
    Some(finding(
        Category::Junk(JunkKind::PdbPath),
        Confidence::Strong,
        Severity::Notice,
        "pe.pdb_path",
        format!("PDB path {}", clean(file, 60)),
        Evidence::at(path_off)
            .with_note(with_caveat(
                format!("{} ({kind}, {detail})", clean(&text, 260)),
                caveat,
            ))
            .with_bytes(path.get(..path.len().min(64)).unwrap_or(&[]).to_vec()),
        Some(Marker::blank(
            Region::new(path_off, path.len() as u64),
            ContainerKind::Raw,
        )),
    ))
}

fn guid(b: &[u8]) -> Option<String> {
    let d1 = u32_le(b, 0)?;
    let d2 = u16_le(b, 4)?;
    let d3 = u16_le(b, 6)?;
    let tail = b.get(8..16)?;
    let hex: String = tail.iter().map(|x| format!("{x:02X}")).collect();
    let (a, rest) = hex.split_at(4);
    Some(format!("{{{d1:08X}-{d2:04X}-{d3:04X}-{a}-{rest}}}"))
}

// ---------------------------------------------------------------------------
// Version resource

const VERSION_KEYS: [&str; 6] = [
    "CompanyName",
    "ProductName",
    "FileDescription",
    "OriginalFilename",
    "FileVersion",
    "LegalCopyright",
];

/// Free-form version strings that carry build or personal notes.
const JUNK_KEYS: [&str; 3] = ["Comments", "PrivateBuild", "SpecialBuild"];

/// Free-form version values deattribute blanks beside [`VERSION_KEYS`]: where
/// build notes and patch credits usually go. `InternalName` and
/// `ProductVersion` stay, since some installers and updaters read them.
const DEATTRIBUTE_EXTRA_KEYS: [&str; 4] = [
    "Comments",
    "LegalTrademarks",
    "PrivateBuild",
    "SpecialBuild",
];

/// Individual decorative version values behind the aggregate audit finding.
pub(crate) fn deattribute_version(view: &dyn FileView) -> Vec<Marker> {
    let Some(img) = PeImage::parse(view) else {
        return Vec::new();
    };
    let Some(info) = version::find(&img, view) else {
        return Vec::new();
    };
    info.strings
        .iter()
        .filter(|s| {
            (VERSION_KEYS.contains(&s.key.as_str())
                || DEATTRIBUTE_EXTRA_KEYS.contains(&s.key.as_str()))
                && !s.value.trim().is_empty()
                && s.value_len > 0
        })
        .map(|s| {
            Marker::blank(
                Region::new(s.value_off, s.value_len),
                ContainerKind::PeResource,
            )
        })
        .collect()
}

fn version_info(v: &VersionInfo, caveat: Option<&str>, out: &mut Vec<Finding>) {
    let pairs: Vec<String> = VERSION_KEYS
        .iter()
        .filter_map(|k| v.get(k).map(|s| format!("{k} = {}", clean(&s.value, 120))))
        .collect();
    if !pairs.is_empty() {
        let value = |k: &str| v.get(k).map(|s| clean(&s.value, 60));
        let title = match (value("CompanyName"), value("ProductName")) {
            (Some(c), Some(p)) => format!("{c} {p}"),
            (Some(c), None) => c,
            (None, Some(p)) => p,
            (None, None) => value("FileDescription")
                .or_else(|| value("OriginalFilename"))
                .unwrap_or_else(|| "Version information".to_string()),
        };
        out.push(finding(
            Category::Brand(BrandKind::Vendor),
            Confidence::Moderate,
            Severity::Info,
            "pe.version_info",
            title,
            Evidence::at(v.leaf_off).with_note(pairs.join("; ")),
            None,
        ));
    }

    for s in &v.strings {
        if s.value.trim().is_empty() || s.value_len == 0 {
            continue;
        }
        let junk_key = JUNK_KEYS.contains(&s.key.as_str());
        if !junk_key && !super::elf::names_user_path(&s.value) {
            continue;
        }
        let key = clean(&s.key, 32);
        out.push(finding(
            Category::Junk(JunkKind::VersionInfo),
            Confidence::Strong,
            Severity::Notice,
            "pe.version_info.junk",
            format!("Version info {key}: {}", clean(&s.value, 60)),
            Evidence::at(s.value_off).with_note(with_caveat(
                format!("{key} = {}", clean(&s.value, 200)),
                caveat,
            )),
            Some(Marker::blank(
                Region::new(s.value_off, s.value_len),
                ContainerKind::PeResource,
            )),
        ));
    }
}

const IMPERSONATED: [&str; 9] = [
    "Microsoft",
    "Google",
    "Adobe",
    "Apple",
    "Mozilla",
    "Oracle",
    "NVIDIA",
    "Intel",
    "Valve",
];

/// The first well-known vendor named as a whole word in `company`.
fn claimed_brand(company: &str) -> Option<&'static str> {
    let lower = company.to_ascii_lowercase();
    IMPERSONATED.into_iter().find(|brand| {
        let needle = brand.to_ascii_lowercase();
        lower.match_indices(needle.as_str()).any(|(i, m)| {
            let before = lower.get(..i).and_then(|s| s.chars().next_back());
            let after = lower.get(i + m.len()..).and_then(|s| s.chars().next());
            !before.is_some_and(char::is_alphanumeric) && !after.is_some_and(char::is_alphanumeric)
        })
    })
}

/// Whether `path` sits under a `Windows` directory, where the operating
/// system's own unsigned-looking files are signed through its catalog.
fn in_windows_dir(path: &std::path::Path) -> bool {
    path.components()
        .any(|c| c.as_os_str().eq_ignore_ascii_case("windows"))
}

fn impersonation(v: &VersionInfo, cert: &Cert, system_dir: bool, out: &mut Vec<Finding>) {
    if matches!(cert, Cert::Present { .. }) {
        return;
    }
    let Some(company) = v.get("CompanyName") else {
        return;
    };
    let Some(brand) = claimed_brand(&company.value) else {
        return;
    };
    let company_text = clean(&company.value, 120);
    // Inside the Windows directory almost every such file is catalog-signed,
    // so the claim drops to a weak notice there.
    let (confidence, severity, note) = if system_dir {
        (
            Confidence::Weak,
            Severity::Notice,
            format!(
                "CompanyName = {company_text} with no embedded Authenticode signature; the file is inside a Windows directory, where system files are normally signed through the catalog instead"
            ),
        )
    } else {
        (
            Confidence::Moderate,
            Severity::Warn,
            format!(
                "CompanyName = {company_text} with no embedded Authenticode signature (operating system files may be catalog-signed instead)"
            ),
        )
    };
    out.push(finding(
        Category::Deception(DeceptionKind::BrandImpersonation),
        confidence,
        severity,
        "pe.brand_impersonation",
        format!("Claims to be from {brand} but carries no signature"),
        Evidence::at(company.value_off).with_note(note),
        None,
    ));
}

// ---------------------------------------------------------------------------
// Authenticode

enum Cert {
    Missing,
    Present {
        off: u64,
        len: u64,
        revision: u16,
        kind: u16,
    },
    Broken {
        off: u64,
        len: u64,
    },
}

impl Cert {
    fn read(view: &dyn FileView, img: &PeImage) -> Self {
        let Some(dir) = img.dir(DIR_SECURITY) else {
            return Cert::Missing;
        };
        // The security directory holds a file offset, not an RVA.
        let off = u64::from(dir.rva);
        let len = u64::from(dir.size);
        let broken = Cert::Broken { off, len };
        if len < 8 || off.saturating_add(len) > view.size() {
            return broken;
        }
        let Some(head) = read_exact(view, off, 8) else {
            return broken;
        };
        let (Some(dw_len), Some(revision), Some(kind)) =
            (u32_le(&head, 0), u16_le(&head, 4), u16_le(&head, 6))
        else {
            return broken;
        };
        if dw_len < 8 || u64::from(dw_len) > len {
            return broken;
        }
        Cert::Present {
            off,
            len,
            revision,
            kind,
        }
    }
}

fn authenticode(img: &PeImage, cert: &Cert, out: &mut Vec<Finding>) {
    let slot = img.dirs_off + (DIR_SECURITY as u64) * 8;
    let f = match *cert {
        Cert::Missing => finding(
            Category::Integrity(SignatureStatus::NoEmbedded),
            Confidence::Strong,
            Severity::Info,
            "pe.authenticode",
            "No embedded Authenticode signature".to_string(),
            Evidence::at(slot).with_note(
                "the security directory is empty; the file may still be covered by a Windows catalog",
            ),
            None,
        ),
        Cert::Present {
            off,
            len,
            revision,
            kind,
        } => {
            let kind_name = match kind {
                0x0001 => " (X.509)",
                0x0002 => " (PKCS#7 SignedData)",
                _ => "",
            };
            finding(
                Category::Integrity(SignatureStatus::Present),
                Confidence::Strong,
                Severity::Info,
                "pe.authenticode",
                "Authenticode signature present (not verified)".to_string(),
                Evidence::at(off).with_note(format!(
                    "WIN_CERTIFICATE revision 0x{revision:04x}, type 0x{kind:04x}{kind_name}, {len} bytes; trust is not checked"
                )),
                None,
            )
        }
        Cert::Broken { off, len } => finding(
            Category::Integrity(SignatureStatus::Absent),
            Confidence::Strong,
            Severity::Warn,
            "pe.authenticode",
            "Authenticode table is damaged or truncated".to_string(),
            Evidence::at(slot).with_note(format!(
                "the security directory points at offset {off} for {len} bytes, which is not a valid WIN_CERTIFICATE inside this {}-byte file",
                img.file_size
            )),
            None,
        ),
    };
    out.push(f);
}

// ---------------------------------------------------------------------------
// Overlay

/// Where an overlay region sits relative to an Authenticode table.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Placement {
    /// No certificate table in the way.
    Plain,
    /// Between the last section and the certificate table.
    BeforeCert,
    /// After the certificate table.
    AfterCert,
}

/// Overlay signatures that installers and self-extractors legitimately carry.
const KNOWN_PAYLOADS: [(&[u8], &str); 5] = [
    (b"\xEF\xBE\xAD\xDENullsoftInst", "NSIS installer data"),
    (b"Inno Setup", "Inno Setup data"),
    (b"7z\xBC\xAF\x27\x1C", "a 7z archive"),
    (b"PK\x03\x04", "a zip archive"),
    (b"Rar!", "a RAR archive"),
];

/// Where GNU ld's COFF symbol and string tables end, when they sit right
/// after the section data, so an unstripped MinGW build is not an overlay.
fn coff_symbols_end(view: &dyn FileView, img: &PeImage, start: u64) -> u64 {
    if img.sym_ptr == 0 || img.sym_count == 0 {
        return start;
    }
    let ptr = u64::from(img.sym_ptr);
    if ptr < start || ptr > start.saturating_add(0x1000) {
        return start;
    }
    let size = view.size();
    let syms_end = ptr + u64::from(img.sym_count) * 18;
    if syms_end > size {
        return start;
    }
    let strtab = read_exact(view, syms_end, 4)
        .and_then(|b| u32_le(&b, 0))
        .map(u64::from)
        .unwrap_or(0);
    if strtab >= 4 && syms_end + strtab <= size {
        syms_end + strtab
    } else {
        syms_end
    }
}

fn overlay(view: &dyn FileView, img: &PeImage, cert: &Cert, out: &mut Vec<Finding>) {
    // Inconsistent headers give no trustworthy image end to measure from.
    if !img.layout_ok() {
        return;
    }
    let size = view.size();
    let start = coff_symbols_end(view, img, img.image_end());
    if start >= size || start < img.table_end {
        return;
    }
    let floor = img.table_end;
    match *cert {
        Cert::Present { off, len, .. } if off >= start => {
            let cert_end = off.saturating_add(len);
            if off > start {
                overlay_region(view, start, off, start, floor, Placement::BeforeCert, out);
            }
            if cert_end < size {
                overlay_region(
                    view,
                    cert_end,
                    size,
                    start,
                    floor,
                    Placement::AfterCert,
                    out,
                );
            }
        }
        _ => overlay_region(view, start, size, start, floor, Placement::Plain, out),
    }
}

/// Short all-zero tails are alignment padding, not an overlay.
fn is_padding(view: &dyn FileView, start: u64, len: u64) -> bool {
    if len >= 512 {
        return false;
    }
    read(view, start, len as usize).is_some_and(|b| b.iter().all(|&x| x == 0))
}

fn overlay_region(
    view: &dyn FileView,
    start: u64,
    end: u64,
    image_len: u64,
    floor: u64,
    place: Placement,
    out: &mut Vec<Finding>,
) {
    const BLOAT_MIN: u64 = 50 * MIB;
    let len = end - start;
    if is_padding(view, start, len) {
        return;
    }
    let head = read(view, start, len.min(64) as usize).unwrap_or_default();
    let known = KNOWN_PAYLOADS
        .iter()
        .find(|(sig, _)| find(&head, sig).is_some())
        .map(|(_, name)| *name);
    let severity = match (known, len > MIB) {
        (Some(_), _) => Severity::Info,
        (None, true) => Severity::Warn,
        (None, false) => Severity::Notice,
    };
    let size = human_size(len);
    let mut note = if len >= 1000 {
        format!("{len} bytes ({size}) after the image")
    } else {
        format!("{len} bytes after the image")
    };
    match place {
        Placement::Plain => {}
        Placement::BeforeCert => note.push_str(
            ", stored before the Authenticode table, so removing it would break the signature",
        ),
        Placement::AfterCert => {
            note.push_str(", added after the Authenticode table, outside the signed bytes")
        }
    }
    if let Some(name) = known {
        note.push_str(&format!(
            "; it starts with {name}, and installers carry overlays legitimately"
        ));
    }
    let title = match known {
        Some(name) => format!("Overlay of {size} holding {name}"),
        None => format!("Overlay of {size} appended after the image"),
    };
    // A truncate never reaches into the headers or the section table.
    let marker = match place {
        Placement::BeforeCert => None,
        Placement::Plain | Placement::AfterCert if start > 0 && start >= floor => {
            Some(Marker::truncate_at(start, ContainerKind::PeOverlay))
        }
        Placement::Plain | Placement::AfterCert => None,
    };
    out.push(finding(
        Category::Tamper(TamperKind::AppendedData),
        Confidence::Moderate,
        severity,
        "pe.overlay",
        title,
        Evidence::at(start)
            .with_note(note)
            .with_bytes(head.get(..head.len().min(16)).unwrap_or(&[]).to_vec()),
        marker.clone(),
    ));

    if len > BLOAT_MIN && len / 4 > image_len && mostly_zero(view, start, len) {
        out.push(finding(
            Category::Deception(DeceptionKind::OverlayBloat),
            Confidence::Moderate,
            Severity::Warn,
            "pe.overlay_bloat",
            format!("Overlay of {size} is mostly zero padding"),
            Evidence::at(start).with_note(format!(
                "{size} of mostly zero bytes after a {} image; padding like this pushes a file past scanner size limits",
                human_size(image_len)
            )),
            marker,
        ));
    }
}

/// Whether 4 KiB samples at the start, middle and end of a region are at
/// least 90 percent zero bytes.
fn mostly_zero(view: &dyn FileView, start: u64, len: u64) -> bool {
    const SAMPLE: u64 = 4096;
    let points = [start, start + len / 2, start + len.saturating_sub(SAMPLE)];
    let mut total = 0usize;
    let mut zeros = 0usize;
    for p in points {
        let Some(b) = read(view, p, SAMPLE as usize) else {
            return false;
        };
        total += b.len();
        zeros += b.iter().filter(|&&x| x == 0).count();
    }
    total > 0 && zeros * 10 >= total * 9
}

// ---------------------------------------------------------------------------
// Header checksum

/// The standard PE checksum: a 16-bit one's-complement sum of the file's
/// little-endian words with the CheckSum field taken as zero, plus the length.
pub(crate) fn pe_checksum(view: &dyn FileView, checksum_off: u64) -> Option<u32> {
    const CHUNK: usize = 1 << 20;
    let size = view.size();
    let mut sum: u64 = 0;
    let mut off = 0u64;
    while off < size {
        let want = CHUNK.min((size - off) as usize);
        let mut buf = read_exact(view, off, want)?.into_owned();
        for field in checksum_off..checksum_off + 4 {
            if field >= off
                && let Some(b) = buf.get_mut((field - off) as usize)
            {
                *b = 0;
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
        off += want as u64;
    }
    let folded = ((sum & 0xffff) + (sum >> 16)) & 0xffff;
    Some((folded as u32).wrapping_add(size as u32))
}

fn checksum(view: &dyn FileView, img: &PeImage, out: &mut Vec<Finding>) {
    if img.checksum == 0 || view.size() > CHECKSUM_MAX {
        return;
    }
    let Some(computed) = pe_checksum(view, img.checksum_off) else {
        return;
    };
    let stored = img.checksum;
    let evidence = Evidence::at(img.checksum_off)
        .with_note(format!("stored 0x{stored:08x}, computed 0x{computed:08x}"))
        .with_bytes(stored.to_le_bytes().to_vec());
    out.push(if computed == stored {
        finding(
            Category::Integrity(SignatureStatus::ChecksumOk),
            Confidence::Strong,
            Severity::Info,
            "pe.checksum",
            "Header checksum matches".to_string(),
            evidence,
            None,
        )
    } else {
        finding(
            Category::Integrity(SignatureStatus::ChecksumBad),
            Confidence::Strong,
            Severity::Notice,
            "pe.checksum",
            "Header checksum does not match the file".to_string(),
            evidence,
            None,
        )
    });
}

// ---------------------------------------------------------------------------
// .NET

fn dotnet(view: &dyn FileView, img: &PeImage, out: &mut Vec<Finding>) {
    let Some(dir) = img.dir(DIR_CLR) else {
        return;
    };
    let Some(off) = img.rva_to_off(dir.rva) else {
        return;
    };
    let Some(h) = read_exact(view, off, 72) else {
        return;
    };
    let (Some(cb), Some(major), Some(minor), Some(md_rva), Some(flags)) = (
        u32_le(&h, 0),
        u16_le(&h, 4),
        u16_le(&h, 6),
        u32_le(&h, 8),
        u32_le(&h, 16),
    ) else {
        return;
    };
    if cb < 72 {
        return;
    }
    let runtime = img
        .rva_to_off(md_rva)
        .and_then(|md| metadata_version(view, md));
    let pe_kind = if img.is64 { "PE32+" } else { "PE32" };
    let mut note = format!("{pe_kind}, CLR header {major}.{minor}");
    if let Some(v) = &runtime {
        note.push_str(&format!(", metadata version {v}"));
    }
    if flags & 0x1 != 0 {
        note.push_str(", IL only");
    }
    if flags & 0x8 != 0 {
        note.push_str(", strong-name signed");
    }
    let title = match &runtime {
        Some(v) => format!(".NET assembly ({v})"),
        None => ".NET assembly".to_string(),
    };
    out.push(finding(
        Category::Brand(BrandKind::Toolchain),
        Confidence::Strong,
        Severity::Info,
        "pe.dotnet",
        title,
        Evidence::at(off).with_note(note),
        None,
    ));
}

/// The runtime version string in a "BSJB" metadata root.
fn metadata_version(view: &dyn FileView, off: u64) -> Option<String> {
    let root = read(view, off, 16 + 256)?;
    if root.get(..4)? != b"BSJB" {
        return None;
    }
    let len = (u32_le(&root, 12)? as usize).min(255);
    let v = cstr(&root, 16, len)?;
    let s = clean(&String::from_utf8_lossy(v), 64);
    (!s.is_empty()).then_some(s)
}

// ---------------------------------------------------------------------------
// Packer section names

const PACKER_SECTIONS: [(&[u8], &str); 14] = [
    (b"UPX0", "UPX"),
    (b"UPX1", "UPX"),
    (b"UPX2", "UPX"),
    (b".themida", "Themida"),
    (b".winlice", "WinLicense"),
    (b".vmp0", "VMProtect"),
    (b".vmp1", "VMProtect"),
    (b".aspack", "ASPack"),
    (b".adata", "ASPack"),
    (b".petite", "Petite"),
    (b".MPRESS1", "MPRESS"),
    (b".MPRESS2", "MPRESS"),
    (b".enigma1", "Enigma Protector"),
    (b".enigma2", "Enigma Protector"),
];

fn packer_of(name: &[u8]) -> Option<&'static str> {
    PACKER_SECTIONS
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, p)| *p)
}

fn packers(img: &PeImage, out: &mut Vec<Finding>) {
    let mut seen: Vec<&str> = Vec::new();
    for s in &img.sections {
        let Some(packer) = packer_of(s.name_bytes()) else {
            continue;
        };
        if seen.contains(&packer) {
            continue;
        }
        seen.push(packer);

        let hits: Vec<&image::Section> = img
            .sections
            .iter()
            .filter(|t| packer_of(t.name_bytes()) == Some(packer))
            .collect();
        let mut names: Vec<String> = hits.iter().map(|t| t.name_str()).collect();
        names.sort();
        names.dedup();
        let entry_in = hits.iter().find(|t| t.contains_rva(img.entry_rva));
        let strong = names.len() >= 2 || entry_in.is_some();
        let mut note = format!("sections {}", names.join(", "));
        if let Some(t) = entry_in {
            note.push_str(&format!("; entry point inside {}", t.name_str()));
        }
        out.push(finding(
            Category::Brand(BrandKind::Packer),
            if strong {
                Confidence::Strong
            } else {
                Confidence::Moderate
            },
            Severity::Notice,
            "pe.packer_section",
            format!("Packed with {packer}"),
            Evidence::at(s.header_off)
                .with_note(note)
                .with_bytes(s.name.to_vec()),
            None,
        ));
    }
}
