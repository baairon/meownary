//! Quiet, marker-only deattribution shared by headless clean and the
//! interactive view: [`plan`] picks the credit spans to blank, and
//! [`write_deattributed`] writes a copy beside the original with those spans
//! blanked. The original is only ever read, so this needs no state store,
//! lock, journal or trash, and has nothing to undo.
//!
//! An archive carries no attribution itself, so a plain zip, a tar and a
//! tar.gz are handled through the files inside them: [`archive_kind`] says
//! which files get that treatment and [`deattribute_archive`] writes the copy.
//! Documents and apps that happen to be zip containers (docx, jar, apk) keep
//! the per-file path.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

mod deep;
pub mod mem;
mod route;
pub mod tar;
pub mod zip;

pub use mem::{ArchiveOutcome, MemOutcome, deattribute_bytes};
pub use route::{ArchiveKind, archive_file_count, archive_kind};

use crate::catalog::{catalog, marker_for};
use crate::model::{
    Category, ContainerKind, FileReport, Marker, Region, RemovalStrategy, TamperKind,
};
use crate::parsers::{catalog_probe, elf, macho, pe};
use crate::scan::FileView;
use crate::util::hash::hash_hex;

use super::engine::{EditError, eof_is_changed};
use super::fsio;
use super::{Risk, assess};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Brand,
    Patch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Basic,
    Deep,
}

impl Kind {
    pub fn slug(self) -> &'static str {
        match self {
            Self::Brand => "brand",
            Self::Patch => "patch",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    LoadBearing,
    NoMarker,
    Unsafe,
    Changed,
    Io,
    /// An identity remains in executable instructions.
    IdentityInCode,
    /// An identity remains in an import, export or entry point.
    FunctionalName,
    /// An identity remains in a URL or registry key.
    FunctionalValue,
    /// A structured identity could not be parsed safely.
    MalformedMetadata,
    /// The deep scan reached its bounded read budget.
    DeepBudget,
    /// An archive entry that cannot be read: encrypted, an unknown method,
    /// sparse or corrupt.
    UnsupportedEntry,
    /// An archive entry over the size limit.
    EntryTooLarge,
    /// An archive inside an archive, which is never opened.
    NestedArchive,
    /// The rest of an archive past a header that could not be read.
    ArchiveTail,
    /// A signed package (APK, signed JAR, wheel, NuGet) whose signature the
    /// copy would break.
    SignedContainer,
}

impl Reason {
    pub fn slug(self) -> &'static str {
        match self {
            Self::LoadBearing => "load-bearing",
            Self::NoMarker => "no removable marker",
            Self::Unsafe => "unsafe edit",
            Self::Changed => "changed since scan",
            Self::Io => "io error",
            Self::IdentityInCode => "identity in code",
            Self::FunctionalName => "functional name kept",
            Self::FunctionalValue => "functional value kept",
            Self::MalformedMetadata => "malformed metadata",
            Self::DeepBudget => "deep scan budget reached",
            Self::UnsupportedEntry => "unsupported entry",
            Self::EntryTooLarge => "entry too large",
            Self::NestedArchive => "nested archive",
            Self::ArchiveTail => "rest of the archive is unreadable",
            Self::SignedContainer => "signed package",
        }
    }
}

/// The reason printed for an archive with nothing to blank inside it.
pub const NOTHING_INSIDE: &str = "nothing to blank inside the archive";

#[derive(Debug, Clone)]
pub struct Target {
    pub kind: Kind,
    pub marker: Marker,
    pub expected_hash: String,
    /// Same-length bytes to write instead of the marker's fill byte.
    pub replacement: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Skipped {
    pub kind: Kind,
    pub reason: Reason,
}

/// Something the copy will lose that is not a skipped credit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Caveat {
    /// The file carries a code signature (Authenticode or `LC_CODE_SIGNATURE`)
    /// that any edit invalidates.
    SignatureInvalidated,
}

impl Caveat {
    pub fn slug(self) -> &'static str {
        match self {
            Self::SignatureInvalidated => "signature invalidated, re-sign to run",
        }
    }
}

#[derive(Debug, Default)]
pub struct FilePlan {
    pub targets: Vec<Target>,
    pub skipped: Vec<Skipped>,
    pub caveats: Vec<Caveat>,
}

impl Target {
    /// The bytes this target leaves in its region.
    pub fn new_bytes(&self) -> Vec<u8> {
        match (&self.replacement, &self.marker.removal) {
            (Some(bytes), _) => bytes.clone(),
            (None, RemovalStrategy::RawBlank { fill }) => {
                vec![*fill; usize::try_from(self.marker.region.len).unwrap_or(0)]
            }
            (None, _) => Vec::new(),
        }
    }
}

fn select(category: &Category, signature: &str) -> Option<Kind> {
    match category {
        Category::Brand(_) => Some(Kind::Brand),
        Category::Tamper(TamperKind::Patched | TamperKind::Cracked)
            if signature
                .strip_prefix("catalog.")
                .is_some_and(|id| PATCH_CREDIT_IDS.contains(&id)) =>
        {
            Some(Kind::Patch)
        }
        _ => None,
    }
}

fn load_bearing(id: &str) -> bool {
    id.starts_with("catalog.packer.")
        || id.starts_with("catalog.toolchain.dotnet")
        || matches!(
            id,
            "pe.dotnet"
                | "pe.packer_section"
                | "mp4.brand"
                | "ooxml.package"
                | "7z.info"
                | "rar.info"
                | "xz.info"
                | "macho.build_version"
                | "macho.encrypted"
                | "catalog.toolchain.go"
                | "catalog.toolchain.go.buildid"
                | "catalog.toolchain.pyinstaller"
                | "catalog.toolchain.pyinstaller.cookie"
                | "catalog.toolchain.electron"
                | "catalog.toolchain.nuitka"
                | "catalog.toolchain.qt"
                | "catalog.toolchain.delphi.borland"
                | "catalog.toolchain.delphi.embarcadero"
                | "catalog.installer.nsis"
                | "catalog.installer.nsis.manifest"
                | "catalog.installer.wixburn"
                | "catalog.installer.7z_sfx"
                | "catalog.installer.winrar_sfx"
                | "catalog.installer.squirrel"
                | "catalog.encoder.lame"
        )
}

fn standalone_credit(id: &str) -> bool {
    matches!(
        id,
        "toolchain.rust"
            | "toolchain.mingw"
            | "installer.inno"
            | "installer.installshield"
            | "encoder.lavf"
            | "encoder.lavc"
            | "encoder.x264"
            | "encoder.x265"
            | "encoder.handbrake"
    )
}

/// Catalog credits that name who patched or cracked the file.
const PATCH_CREDIT_IDS: &[&str] = &["tamper.patched_by", "tamper.cracked_by"];

/// Formats whose metadata sits under a CRC a raw blank would break: a catalog
/// needle there is cleaned only through the parser's own marker.
const CRC_FORMATS: &[&str] = &["ogg", "matroska", "webm"];

/// Catalog needles too short to trust without the version that follows them.
const VERSIONED_NEEDLES: &[&str] = &["encoder.lavf", "encoder.lavc"];

/// Bound a plain credit to the C string that holds it. The needle must start a
/// word (`dispatched by` is not `patched by`), the span runs back to the
/// string's NUL when one is near and forward to the next NUL or non-text byte,
/// and the result must be valid UTF-8. When the file's strings are not
/// NUL-terminated (Go, Rust), only the needle itself is blanked.
fn c_string_marker(
    view: &dyn FileView,
    offset: u64,
    needle_len: u64,
    available: usize,
    unterminated: bool,
    versioned: bool,
) -> Option<Marker> {
    if offset > 0 {
        let prev = view.read_at(offset - 1, 1).ok()?;
        if prev.first().is_some_and(u8::is_ascii_alphanumeric) {
            return None;
        }
    }
    let limit = available.min(80);
    let bytes = view.read_at(offset, limit).ok()?;
    let needle_len = usize::try_from(needle_len).ok()?;
    if bytes.len() < needle_len
        || !bytes[..needle_len]
            .iter()
            .all(|b| (0x20..=0x7e).contains(b))
    {
        return None;
    }
    if versioned && !bytes.get(needle_len).is_some_and(u8::is_ascii_digit) {
        return None;
    }
    if unterminated {
        return Some(Marker::blank(
            Region::new(offset, needle_len as u64),
            ContainerKind::Raw,
        ));
    }
    let text = |b: u8| (0x20..=0x7e).contains(&b) || b >= 0x80;
    let mut end = needle_len
        + bytes[needle_len..]
            .iter()
            .position(|&b| b == 0 || !text(b))?;
    if std::str::from_utf8(&bytes[..end]).is_err() {
        end = needle_len
            + bytes[needle_len..]
                .iter()
                .position(|&b| !(0x20..=0x7e).contains(&b))?;
    }
    let back = offset.min(64);
    let before = view.read_at(offset - back, back as usize).ok()?;
    let start = match before.iter().rposition(|&b| !(0x20..=0x7e).contains(&b)) {
        Some(i) if before[i] == 0 => offset - back + i as u64 + 1,
        _ => offset,
    };
    Some(Marker::blank(
        Region::new(start, offset - start + end as u64),
        ContainerKind::Raw,
    ))
}

fn push_skip(plan: &mut FilePlan, kind: Kind, reason: Reason) {
    let skip = Skipped { kind, reason };
    if !plan.skipped.contains(&skip) {
        plan.skipped.push(skip);
    }
}

/// Plan every selected span. This never reads finding titles, notes, or evidence
/// into output data. The caller provides a view of the same file it scanned.
pub fn plan(report: &FileReport, view: &dyn FileView) -> FilePlan {
    plan_mode(report, view, Mode::Basic)
}

pub fn plan_mode(report: &FileReport, view: &dyn FileView, mode: Mode) -> FilePlan {
    let mut out = FilePlan::default();
    let mut raw: Vec<(Kind, Marker)> = Vec::new();
    let pe_values = if report.format.as_deref() == Some("pe") {
        pe::deattribute_version(view)
    } else {
        Vec::new()
    };
    let elf_values = if report.format.as_deref() == Some("elf") {
        elf::deattribute_comment(view)
    } else {
        Vec::new()
    };
    raw.extend(pe_values.iter().cloned().map(|m| (Kind::Brand, m)));
    raw.extend(elf_values.iter().cloned().map(|m| (Kind::Brand, m)));

    for finding in &report.findings {
        let Some(kind) = select(&finding.category, &finding.signature_id) else {
            continue;
        };
        let id = finding.signature_id.as_str();
        if id.starts_with("catalog.") {
            continue;
        }
        if (id == "pe.version_info" && !pe_values.is_empty())
            || (id == "elf.comment" && !elf_values.is_empty())
        {
            continue;
        }
        match &finding.marker {
            Some(marker) => raw.push((kind, marker.clone())),
            None => push_skip(
                &mut out,
                kind,
                if load_bearing(id) {
                    Reason::LoadBearing
                } else {
                    Reason::NoMarker
                },
            ),
        }
    }

    let cat = catalog();
    let format = report.format.as_deref();
    let unterminated = report.findings.iter().any(|f| {
        f.signature_id.starts_with("catalog.toolchain.go")
            || f.signature_id == "catalog.toolchain.rust"
    });
    for hit in catalog_probe::deattribute_hits(view, format) {
        let sig = &cat.signatures[hit.index];
        let kind = if PATCH_CREDIT_IDS.contains(&sig.id.as_str()) {
            Kind::Patch
        } else {
            Kind::Brand
        };
        let id = format!("catalog.{}", sig.id);
        if load_bearing(&id) {
            push_skip(&mut out, kind, Reason::LoadBearing);
            continue;
        }
        let covered = || {
            raw.iter().any(|(_, m)| {
                m.region.offset <= hit.offset && m.region.end() >= hit.offset + hit.len
            })
        };
        if format.is_some_and(|f| CRC_FORMATS.contains(&f)) {
            if !covered() {
                push_skip(&mut out, kind, Reason::NoMarker);
            }
            continue;
        }
        // PDF and other structured producer values must come from a parser,
        // never an unbounded catalog needle in a content stream.
        if sig.id.starts_with("producer.") {
            if !covered() {
                match marker_for(sig, Region::new(hit.offset, hit.len)) {
                    Some(marker) => raw.push((kind, marker)),
                    None => push_skip(&mut out, kind, Reason::NoMarker),
                }
            }
            continue;
        }
        if kind == Kind::Patch || standalone_credit(&sig.id) {
            let versioned = VERSIONED_NEEDLES.contains(&sig.id.as_str());
            match c_string_marker(
                view,
                hit.offset,
                hit.len,
                hit.available,
                unterminated,
                versioned,
            ) {
                Some(marker) => raw.push((kind, marker)),
                None => push_skip(&mut out, kind, Reason::NoMarker),
            }
        } else {
            push_skip(&mut out, kind, Reason::NoMarker);
        }
    }

    let deep = (mode == Mode::Deep).then(|| deep::sweep(report, view));
    if let Some(d) = &deep {
        raw.extend(d.blanks.iter().cloned());
        for reason in &d.skipped {
            push_skip(&mut out, Kind::Brand, *reason);
        }
    }

    // At one offset the longer span sorts first, and the sort is stable, so a
    // parser's marker stays ahead of a shorter catalog or deep one it covers.
    raw.sort_by_key(|(_, m)| (m.region.offset, std::cmp::Reverse(m.region.len)));
    let mut merged: Vec<(Kind, Marker)> = Vec::new();
    for (kind, marker) in raw {
        if let Some((old_kind, old)) = merged.last_mut()
            && marker.region.offset < old.region.end()
        {
            if marker.region.end() <= old.region.end() {
                // Fully covered: the covering span already blanks it.
                if kind == Kind::Patch {
                    *old_kind = kind;
                }
            } else if old.removal == marker.removal {
                old.region.len = old.region.end().max(marker.region.end()) - old.region.offset;
                if kind == Kind::Patch {
                    *old_kind = kind;
                }
            } else {
                push_skip(&mut out, kind, Reason::Unsafe);
            }
            continue;
        }
        merged.push((kind, marker));
    }
    for (kind, marker) in merged {
        if !matches!(marker.removal, RemovalStrategy::RawBlank { .. })
            || !matches!(
                assess(report.format.as_deref(), report.size, &marker),
                Risk::Safe
            )
        {
            push_skip(&mut out, kind, Reason::Unsafe);
            continue;
        }
        let Ok(len) = usize::try_from(marker.region.len) else {
            push_skip(&mut out, kind, Reason::Unsafe);
            continue;
        };
        let Ok(bytes) = view.read_at(marker.region.offset, len) else {
            push_skip(&mut out, kind, Reason::Io);
            continue;
        };
        if bytes.len() != len {
            push_skip(&mut out, kind, Reason::Changed);
            continue;
        }
        out.targets.push(Target {
            kind,
            marker,
            expected_hash: hash_hex(&bytes),
            replacement: None,
        });
    }
    if let Some(d) = deep {
        for (kind, off, bytes) in d.rewrites {
            let end = off + bytes.len() as u64;
            if out
                .targets
                .iter()
                .any(|t| t.marker.region.offset <= off && t.marker.region.end() >= end)
            {
                continue;
            }
            if out
                .targets
                .iter()
                .any(|t| t.marker.region.offset < end && t.marker.region.end() > off)
            {
                push_skip(&mut out, kind, Reason::Unsafe);
                continue;
            }
            let marker = Marker::blank(Region::new(off, bytes.len() as u64), ContainerKind::Raw);
            if !matches!(
                assess(report.format.as_deref(), report.size, &marker),
                Risk::Safe
            ) {
                push_skip(&mut out, kind, Reason::Unsafe);
                continue;
            }
            let Some(original) = view
                .read_at(off, bytes.len())
                .ok()
                .filter(|o| o.len() == bytes.len())
            else {
                push_skip(&mut out, kind, Reason::Io);
                continue;
            };
            if original == bytes {
                continue;
            }
            out.targets.push(Target {
                kind,
                marker,
                expected_hash: hash_hex(&original),
                replacement: Some(bytes),
            });
        }
        for caveat in d.caveats {
            if !out.caveats.contains(&caveat) {
                out.caveats.push(caveat);
            }
        }
    }
    out.targets.sort_by_key(|t| t.marker.region.offset);
    if out.targets.is_empty() {
        return out;
    }
    let signed = match report.format.as_deref() {
        Some("pe") => {
            if let Some(sum) = deep::checksum_target(view, &out.targets) {
                out.targets.push(sum);
                out.targets.sort_by_key(|t| t.marker.region.offset);
            }
            deep::pe_signed(view)
        }
        Some("macho") => macho::deep_regions(view).signed,
        _ => false,
    };
    if signed && !out.caveats.contains(&Caveat::SignatureInvalidated) {
        out.caveats.push(Caveat::SignatureInvalidated);
    }
    out
}

/// The tag inserted before a deattributed copy's last extension.
pub const COPY_TAG: &str = "deattributed";

/// Where the deattributed copy of `path` goes: the same folder, with
/// `.deattributed` inserted before the last extension, so `setup-tool.exe`
/// becomes `setup-tool.deattributed.exe` and `README` becomes
/// `README.deattributed`. A dotfile with no other dot (`.bashrc`) has no
/// extension and gets the tag at the end. A tar keeps its compound extension
/// whole: `a.tar.gz` becomes `a.deattributed.tar.gz`. The name is assembled
/// from `OsStr` pieces, so a name that is not valid Unicode is kept exactly.
pub fn deattributed_name(path: &Path) -> PathBuf {
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        let lower = name.to_ascii_lowercase();
        let stem = lower
            .strip_suffix(".tar.gz")
            .or_else(|| lower.strip_suffix(".tar"))
            .map(str::len)
            .filter(|&n| n > 0);
        if let Some(n) = stem {
            return path.with_file_name(format!("{}.{COPY_TAG}{}", &name[..n], &name[n..]));
        }
    }
    let Some(stem) = path.file_stem() else {
        let mut whole = path.as_os_str().to_owned();
        whole.push(".");
        whole.push(COPY_TAG);
        return PathBuf::from(whole);
    };
    let mut name = stem.to_owned();
    name.push(".");
    name.push(COPY_TAG);
    if let Some(ext) = path.extension() {
        name.push(".");
        name.push(ext);
    }
    path.with_file_name(name)
}

/// Whether `path` is named like a deattributed copy: a file name that ends in
/// `.deattributed` or contains `.deattributed.` after a non-empty start, in any
/// letter case. Every name [`deattributed_name`] produces passes, so a rerun
/// never deattributes a copy again.
pub fn is_deattributed(path: &Path) -> bool {
    let Some(name) = path.file_name() else {
        return false;
    };
    let name = name.to_string_lossy().to_ascii_lowercase();
    let tag = format!(".{COPY_TAG}");
    name.len() > tag.len()
        && (name.ends_with(&tag) || name.find(&format!("{tag}.")).is_some_and(|at| at > 0))
}

/// Refuse a copy path that is a symlink or not a file; a missing path is fine.
pub(super) fn check_output(output: &Path) -> Result<(), EditError> {
    match fs::symlink_metadata(output) {
        Ok(m) if m.file_type().is_symlink() => Err(EditError::Symlink(output.to_path_buf())),
        Ok(m) if !m.is_file() => Err(EditError::Refused(
            "the copy's path is taken by something that is not a file".into(),
        )),
        _ => Ok(()),
    }
}

/// Deattribute the files inside an archive, writing the copy beside the
/// original unless `dry_run`. The outcome carries the entry skips either way;
/// `entries_cleaned == 0` means nothing inside had anything to blank and no
/// copy was written.
pub fn deattribute_archive(
    original: &Path,
    kind: ArchiveKind,
    dry_run: bool,
) -> Result<ArchiveOutcome, EditError> {
    deattribute_archive_mode(original, kind, dry_run, Mode::Basic)
}

pub fn deattribute_archive_mode(
    original: &Path,
    kind: ArchiveKind,
    dry_run: bool,
    mode: Mode,
) -> Result<ArchiveOutcome, EditError> {
    let output = deattributed_name(original);
    let found = match kind {
        ArchiveKind::Zip => return zip::deattribute_zip_mode(original, &output, dry_run, mode),
        ArchiveKind::Tar | ArchiveKind::TarGz => {
            let gz = kind == ArchiveKind::TarGz;
            if dry_run {
                tar::plan_tar_mode(original, gz, mode)?
            } else {
                tar::deattribute_tar_mode(original, gz, &output, mode)?
            }
        }
    };
    Ok(match found {
        Some(mut outcome) => {
            outcome.output = output;
            outcome
        }
        None => ArchiveOutcome {
            output,
            entries_cleaned: 0,
            brand: 0,
            patch: 0,
            skipped: Vec::new(),
        },
    })
}

/// Write the deattributed copy of `original` at [`deattributed_name`] and
/// return that path. `format` and `size` are the scan's, and `targets` come
/// from [`plan`] over the same scan.
///
/// The original is only read; its bytes and mtime never change. The steps:
///
/// 1. refuse an empty target list, an original that is itself a copy, a
///    symlink or non-file on either end, and any target that is not a safe raw
///    blank;
/// 2. check the original's size and every region hash against the scan, so a
///    file that changed since is [`EditError::Changed`] before anything is
///    written;
/// 3. stream the original into a unique temp file in the same folder, check
///    the size and region hashes again on that copy (catching a change made
///    mid-copy), blank the regions and fsync;
/// 4. rename the temp file over the copy path, which replaces an older copy
///    atomically instead of stacking a second one.
///
/// Any failure removes the temp file, leaving an older copy as it was.
pub fn write_deattributed(
    original: &Path,
    format: Option<&str>,
    size: u64,
    targets: &[Target],
) -> Result<PathBuf, EditError> {
    if targets.is_empty() {
        return Err(EditError::Refused("no credits to blank".into()));
    }
    if is_deattributed(original) {
        return Err(EditError::Refused(
            "the file is already a deattributed copy".into(),
        ));
    }
    for target in targets {
        if !matches!(target.marker.removal, RemovalStrategy::RawBlank { .. })
            || target
                .replacement
                .as_ref()
                .is_some_and(|b| b.len() as u64 != target.marker.region.len)
        {
            return Err(EditError::Refused(
                "a deattributed copy only blanks bytes in place".into(),
            ));
        }
        match assess(format, size, &target.marker) {
            Risk::Safe => {}
            Risk::Warn(r) | Risk::Refuse(r) => return Err(EditError::Refused(r)),
        }
    }
    let meta = fs::symlink_metadata(original)?;
    if meta.file_type().is_symlink() {
        return Err(EditError::Symlink(original.to_path_buf()));
    }
    if !meta.is_file() {
        return Err(EditError::Refused("not a regular file".into()));
    }
    let src = File::open(original)?;
    let opened = src.metadata()?;
    if opened.len() != size || !same_file(&meta, &opened) {
        return Err(EditError::Changed);
    }
    check_regions(&src, targets)?;

    let output = deattributed_name(original);
    match fs::symlink_metadata(&output) {
        Ok(m) if m.file_type().is_symlink() => return Err(EditError::Symlink(output)),
        Ok(m) if !m.is_file() => {
            return Err(EditError::Refused(
                "the copy's path is taken by something that is not a file".into(),
            ));
        }
        _ => {}
    }
    let (tmp, file) = fsio::create_temp_beside(&output)?;
    match build_copy(original, &src, file, &tmp, &output, size, targets, &meta) {
        Ok(()) => {
            if let Some(dir) = output.parent() {
                fsio::sync_dir(dir);
            }
            Ok(output)
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// What checking a written copy found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verified {
    /// The copy holds exactly the original with the planned spans replaced,
    /// keeps the original's format, plans nothing more, and passes the PE
    /// original-identity audit in deep mode.
    pub clean: bool,
    /// The rescan of the copy was partial, so `clean` could not be confirmed.
    pub partial: bool,
    /// The first section category still holding a readable original identity.
    pub residual: Option<&'static str>,
}

impl Verified {
    pub fn ok(self) -> bool {
        self.clean && !self.partial
    }

    const FAILED: Self = Self {
        clean: false,
        partial: false,
        residual: None,
    };
}

/// Report an original PE identity that deep mode has no planned edit for.
pub fn unedited_pe_identity(path: &Path) -> Option<&'static str> {
    let view = crate::scan::WindowedFile::open(path).ok()?;
    deep::residual_category(&view, &view)
}

/// Check a copy written by [`write_deattributed`]: byte for byte it is the
/// original with every target's new bytes in place, its format is unchanged,
/// and planning it again in the same mode finds nothing. Headless and the
/// interactive view both call this, so both report the same verdict.
pub fn verify_copy(
    original: &Path,
    output: &Path,
    format: Option<&str>,
    targets: &[Target],
    mode: Mode,
) -> Verified {
    if !same_with_targets(original, output, targets).unwrap_or(false) {
        return Verified::FAILED;
    }
    let again = crate::scan::scan_file_detailed(output, &crate::parsers::registry());
    if again.report.format.as_deref() != format {
        return Verified::FAILED;
    }
    let Ok(view) = crate::scan::WindowedFile::open(output) else {
        return Verified::FAILED;
    };
    let replanned = crate::scan::guard::guarded(|| plan_mode(&again.report, &view, mode));
    let residual = if mode == Mode::Deep && format == Some("pe") {
        crate::scan::WindowedFile::open(original)
            .ok()
            .and_then(|source| deep::residual_category(&source, &view))
    } else {
        None
    };
    Verified {
        clean: replanned.is_ok_and(|p| p.targets.is_empty()) && residual.is_none(),
        partial: again.report.partial,
        residual,
    }
}

/// Check an archive copy from [`deattribute_archive_mode`]: it reads as the
/// same kind of archive and cleaning it again in the same mode changes no entry.
pub fn verify_archive_copy(
    original: &Path,
    output: &Path,
    kind: ArchiveKind,
    mode: Mode,
) -> Verified {
    let (clean, residual) = match kind {
        ArchiveKind::Zip => zip::verify_copy(original, output, mode),
        ArchiveKind::Tar => (tar::verify_copy(original, output, false, mode), None),
        ArchiveKind::TarGz => (tar::verify_copy(original, output, true, mode), None),
    };
    Verified {
        clean,
        partial: false,
        residual,
    }
}

/// Stream both files and compare, with each target's new bytes laid over the
/// original.
fn same_with_targets(original: &Path, output: &Path, targets: &[Target]) -> io::Result<bool> {
    let a = File::open(original)?;
    let b = File::open(output)?;
    let size = a.metadata()?.len();
    if b.metadata()?.len() != size {
        return Ok(false);
    }
    let overlays: Vec<(u64, Vec<u8>)> = targets
        .iter()
        .map(|t| (t.marker.region.offset, t.new_bytes()))
        .collect();
    let mut want = vec![0u8; fsio::CHUNK];
    let mut got = vec![0u8; fsio::CHUNK];
    let mut pos = 0u64;
    while pos < size {
        let n = usize::try_from((size - pos).min(fsio::CHUNK as u64)).unwrap_or(fsio::CHUNK);
        fill_exact(&a, pos, &mut want[..n])?;
        fill_exact(&b, pos, &mut got[..n])?;
        let end = pos + n as u64;
        for (off, bytes) in &overlays {
            let o_end = off + bytes.len() as u64;
            if o_end <= pos || *off >= end {
                continue;
            }
            let from = (*off).max(pos);
            let to = o_end.min(end);
            let dst = (from - pos) as usize..(to - pos) as usize;
            let src = (from - off) as usize..(to - off) as usize;
            want[dst].copy_from_slice(&bytes[src]);
        }
        if want[..n] != got[..n] {
            return Ok(false);
        }
        pos = end;
    }
    Ok(true)
}

/// Read exactly `buf.len()` bytes at `off`, looping over short reads.
fn fill_exact(file: &File, off: u64, buf: &mut [u8]) -> io::Result<()> {
    let mut done = 0;
    while done < buf.len() {
        match fsio::read_at(file, off + done as u64, &mut buf[done..]) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => done += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Every target's region in `file` still hashes to the scan's value.
fn check_regions(file: &File, targets: &[Target]) -> Result<(), EditError> {
    for target in targets {
        let region = target.marker.region;
        let got = fsio::hash_range(file, region.offset, region.len).map_err(eof_is_changed)?;
        if !got.eq_ignore_ascii_case(target.expected_hash.trim()) {
            return Err(EditError::Changed);
        }
    }
    Ok(())
}

/// Fill the temp file `out` (at `tmp`) with a blanked copy of `src`, then move
/// it onto `output`. The caller removes `tmp` on failure.
#[allow(clippy::too_many_arguments)]
fn build_copy(
    src_path: &Path,
    src: &File,
    mut out: File,
    tmp: &Path,
    output: &Path,
    size: u64,
    targets: &[Target],
    meta: &fs::Metadata,
) -> Result<(), EditError> {
    let mut buf = vec![0u8; fsio::CHUNK];
    let mut copied = 0u64;
    loop {
        let n = match fsio::read_at(src, copied, &mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(EditError::Io(e)),
        };
        out.write_all(&buf[..n])?;
        copied += n as u64;
        if copied > size {
            return Err(EditError::Changed);
        }
    }
    if copied != size {
        return Err(EditError::Changed);
    }
    check_regions(&out, targets)?;
    for target in targets {
        if let RemovalStrategy::RawBlank { fill } = target.marker.removal {
            let region = target.marker.region;
            if let Some(bytes) = &target.replacement {
                fsio::write_at(&out, region.offset, bytes)?;
            } else {
                fsio::write_fill(&out, region.offset, region.len, fill)?;
            }
        }
    }
    out.sync_all()?;
    drop(out);
    // Keep the original's mode (an executable stays executable) without the
    // setuid and setgid bits. Windows only has a read-only bit, which would
    // block the next run's replace, so it is left clear there.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o1777;
        fs::set_permissions(tmp, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = meta;
    carry_origin_mark(src_path, tmp);
    fs::rename(tmp, output).map_err(|e| match e.kind() {
        io::ErrorKind::PermissionDenied => {
            EditError::Refused("the previous copy is read-only or in use".into())
        }
        _ => EditError::Io(e),
    })?;
    Ok(())
}

/// The file opened is the one whose metadata was checked, not something
/// swapped in between.
fn same_file(checked: &fs::Metadata, opened: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        checked.dev() == opened.dev() && checked.ino() == opened.ino()
    }
    #[cfg(not(unix))]
    {
        checked.len() == opened.len() && checked.modified().ok() == opened.modified().ok()
    }
}

/// Copy the download mark (Windows `Zone.Identifier`) onto the copy, so a
/// copy of a downloaded program is treated like the download itself. Best
/// effort: a file without the mark, or a volume without streams, is fine.
fn carry_origin_mark(original: &Path, tmp: &Path) {
    #[cfg(windows)]
    {
        let stream = |p: &Path| {
            let mut s = p.as_os_str().to_owned();
            s.push(":Zone.Identifier");
            PathBuf::from(s)
        };
        if let Ok(mark) = fs::read(stream(original)) {
            let _ = fs::write(stream(tmp), mark);
        }
    }
    #[cfg(not(windows))]
    let _ = (original, tmp);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn named(p: &str) -> PathBuf {
        deattributed_name(Path::new(p))
    }

    #[test]
    fn copy_names_insert_the_tag_before_the_last_extension() {
        assert_eq!(
            named("setup-tool.exe"),
            Path::new("setup-tool.deattributed.exe")
        );
        assert_eq!(named("report.pdf"), Path::new("report.deattributed.pdf"));
        assert_eq!(named("README"), Path::new("README.deattributed"));
        assert_eq!(
            named("dir/a.tar.gz"),
            Path::new("dir/a.deattributed.tar.gz")
        );
        assert_eq!(named("v1.2.3.bin"), Path::new("v1.2.3.deattributed.bin"));
        assert_eq!(named(".bashrc"), Path::new(".bashrc.deattributed"));
        assert_eq!(
            named(".config.json"),
            Path::new(".config.deattributed.json")
        );
        assert_eq!(named("trailing."), Path::new("trailing.deattributed."));
    }

    #[test]
    fn every_copy_name_is_recognised_and_originals_are_not() {
        for p in [
            "setup-tool.exe",
            "report.pdf",
            "README",
            "a.tar.gz",
            ".bashrc",
            ".config.json",
            "trailing.",
            "x.deattributed.exe",
        ] {
            assert!(!is_deattributed(Path::new(p)) || p.contains("deattributed"));
            assert!(is_deattributed(&named(p)), "{p}");
        }
        assert!(is_deattributed(Path::new("a/B.DEATTRIBUTED.EXE")));
        assert!(is_deattributed(Path::new("notes.deattributed")));
        assert!(!is_deattributed(Path::new("deattributed.exe")));
        assert!(!is_deattributed(Path::new(".deattributed")));
        assert!(is_deattributed(Path::new("a.deattributed.tar.gz")));
        assert!(is_deattributed(Path::new("dir/A.Deattributed.TAR")));
        assert!(!is_deattributed(Path::new("a.deattributed.d/plain.tar")));
        assert!(!is_deattributed(Path::new("deattributedx.exe")));
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_names_survive_exactly() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let p = Path::new(OsStr::from_bytes(b"caf\xe9\xff.exe"));
        let out = deattributed_name(p);
        assert_eq!(out.as_os_str().as_bytes(), b"caf\xe9\xff.deattributed.exe");
        assert!(is_deattributed(&out));
    }

    #[cfg(windows)]
    #[test]
    fn non_utf8_names_survive_exactly() {
        use std::ffi::OsString;
        use std::os::windows::ffi::{OsStrExt, OsStringExt};
        // A lone surrogate is a valid Windows name but not valid Unicode.
        let mut wide: Vec<u16> = vec![0x63, 0xD800, 0x61];
        wide.extend(".exe".encode_utf16());
        let p = PathBuf::from(OsString::from_wide(&wide));
        let out = deattributed_name(&p);
        let mut want: Vec<u16> = vec![0x63, 0xD800, 0x61];
        want.extend(".deattributed.exe".encode_utf16());
        assert_eq!(out.as_os_str().encode_wide().collect::<Vec<_>>(), want);
        assert!(is_deattributed(&out));
    }
}
