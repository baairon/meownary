//! Deattribution of one file held in memory: the same identity, probes and
//! planner as a file on disk, applied to a byte buffer. Archive support builds
//! on this, so an archive entry is cleaned exactly like the file it was packed
//! from. Nothing here reads titles, notes or evidence into its result.

use std::io;
use std::path::{Path, PathBuf};

use crate::model::{FileReport, RemovalStrategy};
use crate::parsers;
use crate::scan::reader::{HEADER_WINDOW, MAX_READ, TAIL_WINDOW};
use crate::scan::{FileView, Registry, guard};
use crate::util::hash::hash_hex;

use super::{Kind, Reason, plan};

/// What deattributing one file's bytes did.
#[derive(Debug, Default)]
pub struct MemOutcome {
    /// The blanked bytes, only when at least one blank was applied. The length
    /// always matches the input.
    pub bytes: Option<Vec<u8>>,
    /// Brand labels blanked.
    pub brand: usize,
    /// Patch credits blanked.
    pub patch: usize,
    /// Why credits that were found could not be blanked, one entry per reason.
    pub skipped: Vec<Reason>,
}

/// What deattributing an archive through its contents did.
#[derive(Debug, Clone)]
pub struct ArchiveOutcome {
    /// The deattributed copy's path (written, or what a dry run would write).
    pub output: PathBuf,
    /// Files inside that had something blanked. Zero means no copy was written.
    pub entries_cleaned: usize,
    /// Brand labels blanked across all entries.
    pub brand: usize,
    /// Patch credits blanked across all entries.
    pub patch: usize,
    /// Entries that were skipped or had credits left in place: the entry path
    /// inside the archive and the generic reason.
    pub skipped: Vec<(String, Reason)>,
}

/// Formats that hold other files. A nested one is never opened: it is an entry
/// with nothing to blank.
const CONTAINERS: &[&str] = &[
    "zip", "jar", "apk", "ooxml", "tar", "gzip", "bzip2", "xz", "zstd", "rar", "7z",
];

/// Whether `format` names a container that archive support does not recurse into.
pub(super) fn is_container(format: Option<&str>) -> bool {
    format.is_some_and(|f| CONTAINERS.contains(&f))
}

/// A borrowed `FileView` with the same windows as the on-disk and owned views,
/// so a byte buffer scans exactly like the file it came from.
pub(super) struct SliceView<'a> {
    path: PathBuf,
    data: &'a [u8],
    tail_start: usize,
}

impl<'a> SliceView<'a> {
    pub(super) fn new(name: &str, data: &'a [u8]) -> Self {
        Self {
            path: PathBuf::from(name),
            data,
            tail_start: data.len().saturating_sub(TAIL_WINDOW),
        }
    }
}

impl FileView for SliceView<'_> {
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
        &self.data[self.tail_start..]
    }
    fn tail_start(&self) -> u64 {
        self.tail_start as u64
    }
    fn read_at(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let Ok(start) = usize::try_from(offset) else {
            return Ok(Vec::new());
        };
        if start >= self.data.len() || len == 0 {
            return Ok(Vec::new());
        }
        let want = len.min(self.data.len() - start).min(MAX_READ);
        Ok(self.data[start..start + want].to_vec())
    }
}

/// Deattribute one file's bytes in memory. `name` is the entry's file name,
/// used only for identity hints. `bytes` is `Some` only when at least one blank
/// was applied; the length never changes.
pub fn deattribute_bytes(name: &str, data: &[u8]) -> MemOutcome {
    deattribute_with(name, data, &parsers::registry())
}

/// [`deattribute_bytes`] with the probe registry supplied, so an archive builds
/// it once for all of its entries.
pub(super) fn deattribute_with(name: &str, data: &[u8], registry: &Registry) -> MemOutcome {
    let view = SliceView::new(name, data);
    let mut report = FileReport::new(view.path.clone(), data.len() as u64);
    let mut panicked = false;
    let (format, mut findings) = match guard::guarded(|| parsers::identify(&view)) {
        Ok(found) => found,
        Err(()) => {
            panicked = true;
            (None, Vec::new())
        }
    };
    report.format = format.map(str::to_string);
    if is_container(format) {
        return MemOutcome::default();
    }
    for probe in registry {
        let wanted = probe.formats();
        if !wanted.is_empty() && !format.is_some_and(|f| wanted.contains(&f)) {
            continue;
        }
        let ctx = crate::scan::ProbeCtx::new(&view, format);
        match guard::guarded(|| {
            let mut local = Vec::new();
            probe.run(&ctx, &mut local);
            local
        }) {
            Ok(mut local) => findings.append(&mut local),
            Err(()) => panicked = true,
        }
    }
    report.findings = findings;
    report.partial = panicked;

    let file_plan = match guard::guarded(|| plan(&report, &view)) {
        Ok(p) => p,
        Err(()) => {
            return MemOutcome {
                skipped: vec![Reason::Unsafe],
                ..MemOutcome::default()
            };
        }
    };
    let mut out = MemOutcome::default();
    for skip in &file_plan.skipped {
        if !out.skipped.contains(&skip.reason) {
            out.skipped.push(skip.reason);
        }
    }
    let mut buf: Option<Vec<u8>> = None;
    for target in &file_plan.targets {
        let RemovalStrategy::RawBlank { fill } = target.marker.removal else {
            note(&mut out.skipped, Reason::Unsafe);
            continue;
        };
        let region = target.marker.region;
        let span = usize::try_from(region.offset)
            .ok()
            .zip(usize::try_from(region.len).ok())
            .and_then(|(start, len)| Some(start..start.checked_add(len)?))
            .filter(|r| r.end <= data.len());
        let Some(span) = span else {
            note(&mut out.skipped, Reason::Changed);
            continue;
        };
        if !hash_hex(&data[span.clone()]).eq_ignore_ascii_case(target.expected_hash.trim()) {
            note(&mut out.skipped, Reason::Changed);
            continue;
        }
        buf.get_or_insert_with(|| data.to_vec())[span].fill(fill);
        match target.kind {
            Kind::Brand => out.brand += 1,
            Kind::Patch => out.patch += 1,
        }
    }
    out.bytes = buf;
    out
}

fn note(reasons: &mut Vec<Reason>, reason: Reason) {
    if !reasons.contains(&reason) {
        reasons.push(reason);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A fake PE: a DOS header padded to 256 bytes, then an invented credit.
    pub(crate) fn fake_pe(credit: &[u8]) -> Vec<u8> {
        let mut bytes = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00".to_vec();
        bytes.resize(256, 0);
        bytes.extend_from_slice(credit);
        bytes.push(0);
        bytes
    }

    #[test]
    fn a_patch_credit_is_blanked_without_changing_the_length() {
        let data = fake_pe(b"patched by Invented");
        let out = deattribute_bytes("tool.exe", &data);
        let bytes = out.bytes.expect("blanked");
        assert_eq!(bytes.len(), data.len());
        assert!(!bytes.windows(10).any(|w| w == b"patched by"));
        assert_eq!((out.brand, out.patch), (0, 1));
        assert!(out.skipped.is_empty());
    }

    #[test]
    fn plain_text_has_nothing_to_blank() {
        let out = deattribute_bytes("notes.txt", b"hello there");
        assert!(out.bytes.is_none());
        assert_eq!((out.brand, out.patch), (0, 0));
    }

    #[test]
    fn nested_containers_are_left_alone() {
        let mut inner = b"PK\x05\x06".to_vec();
        inner.extend_from_slice(&[0; 18]);
        let out = deattribute_bytes("inner.zip", &inner);
        assert!(out.bytes.is_none());
        assert!(out.skipped.is_empty());
    }
}
