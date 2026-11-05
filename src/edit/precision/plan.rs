//! Original-coordinate edits, pinned inputs, streaming verification, and atomic output.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::edit::{EditEngine, deattribute, fsio};
use crate::scan::{FileView, WindowedFile};

use super::pattern::{Span, invalid, parse_hex};

struct LogicalView<'a> {
    view: &'a dyn FileView,
    path: &'a Path,
}
impl FileView for LogicalView<'_> {
    fn path(&self) -> &Path {
        self.path
    }
    fn size(&self) -> u64 {
        self.view.size()
    }
    fn header(&self) -> &[u8] {
        self.view.header()
    }
    fn tail(&self) -> &[u8] {
        self.view.tail()
    }
    fn tail_start(&self) -> u64 {
        self.view.tail_start()
    }
    fn read_at(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        self.view.read_at(offset, len)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hashes {
    pub size: u64,
    pub blake3: String,
    pub sha256: String,
}

struct HashWriter {
    size: u64,
    blake3: blake3::Hasher,
    sha256: Sha256,
}

impl HashWriter {
    fn new() -> Self {
        Self {
            size: 0,
            blake3: blake3::Hasher::new(),
            sha256: Sha256::new(),
        }
    }
    fn finish(self) -> Hashes {
        Hashes {
            size: self.size,
            blake3: self.blake3.finalize().to_hex().to_string(),
            sha256: format!("{:x}", self.sha256.finalize()),
        }
    }
}

impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.blake3.update(bytes);
        self.sha256.update(bytes);
        self.size += bytes.len() as u64;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub fn hash(path: &Path) -> io::Result<Hashes> {
    let mut file = File::open(path)?;
    let mut writer = HashWriter::new();
    io::copy(&mut file, &mut writer)?;
    Ok(writer.finish())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Payload {
    Hex { value: String },
    Fill { byte: u8, len: u64 },
    File { path: PathBuf, hashes: Hashes },
    Empty,
}

impl Payload {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            Self::Empty
        } else {
            Self::Hex {
                value: fsio::to_hex(bytes),
            }
        }
    }
    pub fn from_file(path: &Path) -> io::Result<Self> {
        regular(path)?;
        Ok(Self::File {
            path: fsio::canonical(path)?,
            hashes: hash(path)?,
        })
    }
    pub fn len(&self) -> io::Result<u64> {
        Ok(match self {
            Self::Empty => 0,
            Self::Hex { value } => {
                if value.len() > 32 * 1024 * 1024 {
                    return Err(invalid(
                        "inline bytes exceed 16 MiB; use a replacement file",
                    ));
                }
                parse_hex(value, false)?.0.len() as u64
            }
            Self::Fill { len, .. } => *len,
            Self::File { hashes, .. } => hashes.size,
        })
    }
    pub fn is_empty(&self) -> io::Result<bool> {
        self.len().map(|len| len == 0)
    }
    fn check(&self) -> io::Result<()> {
        if let Self::File { path, hashes } = self {
            regular(path)?;
            if &hash(path)? != hashes {
                return Err(invalid("replacement file changed since planning"));
            }
        }
        Ok(())
    }
    fn write(&self, output: &mut dyn Write) -> io::Result<()> {
        match self {
            Self::Empty => Ok(()),
            Self::Hex { value } => output.write_all(&parse_hex(value, false)?.0),
            Self::File { path, hashes } => {
                let file = File::open(path)?;
                copy_span(&file, 0, hashes.size, output)
            }
            Self::Fill { byte, len } => {
                let buffer = vec![*byte; fsio::CHUNK];
                let mut left = *len;
                while left > 0 {
                    let count = left.min(buffer.len() as u64) as usize;
                    output.write_all(&buffer[..count])?;
                    left -= count as u64;
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    Replace,
    Fill,
    Insert,
    Delete,
    Truncate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub kind: OperationKind,
    pub offset: u64,
    pub remove: u64,
    pub data: Payload,
    #[serde(default)]
    pub resize: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub edit: Request,
    pub expected_blake3: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EditSpec {
    pub version: u32,
    pub operations: Vec<Request>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeattributeCheck {
    pub deep: bool,
    pub options: deattribute::policy::Options,
    pub policy: deattribute::policy::VerificationPolicy,
    pub audit: Option<deattribute::audit::Audit>,
    pub coverage_complete: bool,
    /// The input path as it was given when planning, through
    /// [`logical_path`]: what the rules' `files` globs were matched against,
    /// so applying the plan matches them the same way wherever it runs.
    /// Plans saved before this field fall back to the canonical path.
    #[serde(default)]
    pub logical: Option<String>,
}

pub use crate::edit::deattribute::policy::logical_path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EditPlan {
    pub version: u32,
    pub input: PathBuf,
    pub before: Hashes,
    pub after: Hashes,
    pub operations: Vec<Operation>,
    pub raw: bool,
    pub deattribute: Option<DeattributeCheck>,
}

fn check_requests(requests: &[Request], size: u64) -> io::Result<u64> {
    if requests.len() > 100_000 {
        return Err(invalid("at most 100000 operations are supported"));
    }
    let mut end = 0;
    let mut last_offset = None;
    let mut output_size = size;
    for edit in requests {
        let stop = edit
            .offset
            .checked_add(edit.remove)
            .ok_or_else(|| invalid("edit range overflow"))?;
        if stop > size {
            return Err(invalid("edit is past EOF"));
        }
        if edit.offset < end || last_offset == Some(edit.offset) {
            return Err(invalid(
                "edits overlap or share an ambiguous insertion offset",
            ));
        }
        let insert = edit.data.len()?;
        match edit.kind {
            OperationKind::Replace if edit.remove != insert && !edit.resize => {
                return Err(invalid("replacement changes length; specify resize"));
            }
            OperationKind::Fill
                if edit.remove != insert || !matches!(edit.data, Payload::Fill { .. }) =>
            {
                return Err(invalid("fill requires a same-length fill payload"));
            }
            OperationKind::Insert if edit.remove != 0 || insert == 0 => {
                return Err(invalid("insert requires nonempty bytes and remove=0"));
            }
            OperationKind::Delete if insert != 0 || edit.remove == 0 => {
                return Err(invalid("delete requires remove>0 and empty data"));
            }
            OperationKind::Truncate if insert != 0 || stop != size => {
                return Err(invalid("truncate must remove the complete tail"));
            }
            _ => {}
        }
        output_size = output_size
            .checked_sub(edit.remove)
            .and_then(|n| n.checked_add(insert))
            .ok_or_else(|| invalid("output length overflow"))?;
        end = stop;
        last_offset = Some(edit.offset);
    }
    Ok(output_size)
}

/// An existing regular file that is not itself a symbolic link. Links in
/// parent folders resolve like any other path, so system aliases such as
/// macOS `/var` and Windows junctions keep working.
pub fn regular(path: &Path) -> io::Result<()> {
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(invalid("symbolic links are not followed"));
    }
    if !fs::metadata(path)?.is_file() {
        return Err(invalid("expected a regular file"));
    }
    Ok(())
}

fn validate_ranges(path: &Path, requests: &[Request], raw: bool) -> io::Result<()> {
    if raw {
        return Ok(());
    }
    let view = WindowedFile::open(path)?;
    let layout = deattribute::layout::inspect(&view);
    for edit in requests {
        if layout.format.is_some() && edit.remove != edit.data.len()? {
            return Err(invalid("resizing a recognized format requires --raw"));
        }
        let span = Span {
            offset: edit.offset,
            len: edit.remove.max(1),
        };
        if layout.retention(&span).is_some() {
            return Err(invalid(
                "editing a protected or unverified region requires --raw",
            ));
        }
    }
    Ok(())
}

impl EditPlan {
    pub fn create(path: &Path, mut requests: Vec<Request>, raw: bool) -> io::Result<Self> {
        regular(path)?;
        requests.sort_by_key(|e| e.offset);
        let before = hash(path)?;
        check_requests(&requests, before.size)?;
        validate_ranges(path, &requests, raw)?;
        Self::prepare(path, requests, before, raw, None)
    }

    fn prepare(
        path: &Path,
        requests: Vec<Request>,
        before: Hashes,
        raw: bool,
        deattribute: Option<DeattributeCheck>,
    ) -> io::Result<Self> {
        let file = File::open(path)?;
        let mut operations = Vec::new();
        for edit in requests {
            edit.data.check()?;
            let expected_blake3 = fsio::hash_range(&file, edit.offset, edit.remove)?;
            operations.push(Operation {
                edit,
                expected_blake3,
            });
        }
        let mut plan = Self {
            version: 1,
            input: fsio::canonical(path)?,
            after: before.clone(),
            before,
            operations,
            raw,
            deattribute,
        };
        let mut output = HashWriter::new();
        plan.write(&file, &mut output)?;
        plan.after = output.finish();
        plan.check_fresh()?;
        Ok(plan)
    }

    pub fn from_deattribute(
        path: &Path,
        planned: &deattribute::FilePlan,
        deep: bool,
        policy: deattribute::policy::VerificationPolicy,
    ) -> io::Result<Self> {
        regular(path)?;
        if !planned.errors.is_empty() {
            return Err(invalid(planned.errors.join("; ")));
        }
        let requests: Vec<_> = planned
            .targets
            .iter()
            .map(|t| Request {
                kind: OperationKind::Replace,
                offset: t.marker.region.offset,
                remove: t.marker.region.len,
                data: Payload::from_bytes(&t.new_bytes()),
                resize: false,
            })
            .collect();
        let before = hash(path)?;
        check_requests(&requests, before.size)?;
        let coverage_complete = !planned.skipped.iter().any(|s| {
            matches!(
                s.reason,
                deattribute::Reason::Io
                    | deattribute::Reason::Changed
                    | deattribute::Reason::MalformedMetadata
                    | deattribute::Reason::DeepBudget
            )
        });
        Self::prepare(
            path,
            requests,
            before,
            false,
            Some(DeattributeCheck {
                deep,
                policy,
                options: planned.configuration.clone().unwrap_or_default(),
                audit: planned.audit.clone(),
                coverage_complete,
                logical: Some(logical_path(path)),
            }),
        )
    }

    pub fn check_input(&self) -> io::Result<()> {
        self.check_input_at(&self.input)
    }

    /// The path the rules' `files` globs are matched against: the one saved
    /// at planning, else the canonical input.
    fn logical_input(&self) -> PathBuf {
        self.deattribute
            .as_ref()
            .and_then(|c| c.logical.as_deref())
            .map(PathBuf::from)
            .unwrap_or_else(|| self.input.clone())
    }

    fn check_fresh(&self) -> io::Result<()> {
        regular(&self.input)?;
        if hash(&self.input)? != self.before {
            return Err(invalid("input changed since planning"));
        }
        for op in &self.operations {
            op.edit.data.check()?;
        }
        Ok(())
    }

    fn check_input_at(&self, source: &Path) -> io::Result<()> {
        if self.version != 1 {
            return Err(invalid("unsupported edit plan version"));
        }
        regular(source)?;
        if hash(source)? != self.before {
            return Err(invalid("input changed since planning"));
        }
        let requests: Vec<_> = self.operations.iter().map(|op| op.edit.clone()).collect();
        if check_requests(&requests, self.before.size)? != self.after.size {
            return Err(invalid("plan output size is inconsistent"));
        }
        let file = File::open(source)?;
        for op in &self.operations {
            if fsio::hash_range(&file, op.edit.offset, op.edit.remove)? != op.expected_blake3 {
                return Err(invalid("affected range changed since planning"));
            }
            op.edit.data.check()?;
        }
        let mut expected = HashWriter::new();
        self.write(&file, &mut expected)?;
        if expected.finish() != self.after {
            return Err(invalid(
                "plan output fingerprint does not match its operations",
            ));
        }
        if let Some(check) = &self.deattribute {
            if self.raw {
                return Err(invalid("a deattribution plan cannot also be raw"));
            }
            let source_view = WindowedFile::open(source)?;
            let logical = self.logical_input();
            let view = LogicalView {
                view: &source_view,
                path: &logical,
            };
            let scan = crate::scan::scan_file_detailed(source, &crate::parsers::registry());
            let mode = if check.deep {
                deattribute::Mode::Deep
            } else {
                deattribute::Mode::Basic
            };
            let rebuilt =
                deattribute::plan_with_options(&scan.report, &view, mode, &check.options)?;
            if !rebuilt.errors.is_empty() || rebuilt.targets.len() != self.operations.len()
                || rebuilt.targets.iter().zip(&self.operations).any(|(target, op)| {
                    target.marker.region.offset != op.edit.offset || target.marker.region.len != op.edit.remove
                        || !matches!(&op.edit.data, Payload::Hex { value } if *value == fsio::to_hex(&target.new_bytes()))
                })
                || serde_json::to_value(&rebuilt.audit)? != serde_json::to_value(&check.audit)? {
                return Err(invalid("deattribution plan differs from the current rules and original file"));
            }
            let complete = !rebuilt.skipped.iter().any(|s| {
                matches!(
                    s.reason,
                    deattribute::Reason::Io
                        | deattribute::Reason::Changed
                        | deattribute::Reason::MalformedMetadata
                        | deattribute::Reason::DeepBudget
                )
            });
            if complete != check.coverage_complete {
                return Err(invalid("deattribution coverage was altered"));
            }
        } else {
            validate_ranges(source, &requests, self.raw)?;
        }
        Ok(())
    }

    fn write(&self, input: &File, output: &mut dyn Write) -> io::Result<()> {
        let mut offset = 0;
        for op in &self.operations {
            copy_span(input, offset, op.edit.offset - offset, output)?;
            op.edit.data.write(output)?;
            offset = op.edit.offset + op.edit.remove;
        }
        copy_span(input, offset, self.before.size - offset, output)
    }

    pub fn verify(&self, output: &Path) -> io::Result<VerifyReport> {
        let source = if hash(&self.input)? == self.before {
            self.input.clone()
        } else {
            if fsio::canonical(output)? != self.input || hash(output)? != self.after {
                return Err(invalid("input changed since planning"));
            }
            let engine = EditEngine::new()?;
            let mut snapshot = None;
            for record in engine.journal().records()?.into_iter().rev() {
                if record.path != self.input {
                    continue;
                }
                if let crate::edit::journal::UndoAction::RestoreSnapshot { trash_path } =
                    record.action
                {
                    regular(&trash_path)?;
                    let canonical = fsio::canonical(&trash_path)?;
                    if canonical.starts_with(fsio::canonical(engine.trash_root())?)
                        && hash(&canonical)? == self.before
                    {
                        snapshot = Some(canonical);
                        break;
                    }
                }
            }
            snapshot.ok_or_else(|| invalid("matching original undo snapshot is unavailable"))?
        };
        self.check_input_at(&source)?;
        self.verify_staged(output, &source)
    }

    fn verify_staged(&self, output: &Path, original: &Path) -> io::Result<VerifyReport> {
        regular(output)?;
        let got = hash(output)?;
        let byte_integrity = got == self.after;
        let view = WindowedFile::open(output)?;
        let mut report = VerifyReport {
            byte_integrity,
            coverage_complete: true,
            policy_satisfied: byte_integrity,
            structure_valid: None,
            audit: None,
            hashes: got,
            raw: self.raw,
        };
        if let Some(check) = &self.deattribute {
            report.coverage_complete = check.coverage_complete;
            let layout = deattribute::layout::inspect(&view);
            let source = WindowedFile::open(original)?;
            let original_format = crate::parsers::identity::identify(&source).0;
            report.structure_valid = Some(
                crate::parsers::identity::identify(&view).0 == original_format
                    && (original_format != Some("pe")
                        || (layout.valid && deattribute::imports_unchanged(&source, &view))),
            );
            if let Some(audit) = &check.audit {
                let result = audit.verify(&view)?;
                report.coverage_complete &= result.complete;
                report.policy_satisfied &= match check.policy {
                    deattribute::policy::VerificationPolicy::Strict => result.clean,
                    deattribute::policy::VerificationPolicy::Protected => result.policy_satisfied,
                };
                report.audit = Some(result);
            }
            // Re-probe structural/catalog metadata as well as the saved
            // identities, with the output standing in for the input: the
            // rules' file selectors see the planned path, not a temp name.
            let scan = crate::scan::scan_file_detailed(output, &crate::parsers::registry());
            let mode = if check.deep {
                deattribute::Mode::Deep
            } else {
                deattribute::Mode::Basic
            };
            let logical = self.logical_input();
            let as_input = LogicalView {
                view: &view,
                path: &logical,
            };
            let next = deattribute::plan_with_options(
                &scan.report,
                &as_input,
                mode,
                &check.options.for_output(),
            )?;
            report.coverage_complete &= !scan.report.partial
                && next.errors.is_empty()
                && !next.skipped.iter().any(|s| {
                    matches!(
                        s.reason,
                        deattribute::Reason::Io
                            | deattribute::Reason::Changed
                            | deattribute::Reason::MalformedMetadata
                            | deattribute::Reason::DeepBudget
                    )
                });
            // Explicit rules may intentionally replace or retain a catalog value.
            if check.options.rules.is_none() {
                report.policy_satisfied &= next.targets.is_empty();
            }
            report.policy_satisfied &=
                report.coverage_complete && report.structure_valid == Some(true);
        }
        Ok(report)
    }

    pub fn apply(
        &self,
        output: &Path,
        overwrite: bool,
        in_place: bool,
        raw: bool,
    ) -> io::Result<ApplyReport> {
        self.check_input()?;
        if self.raw && !raw {
            return Err(invalid("this plan needs an explicit --raw override"));
        }
        let destination = output_path(output)?;
        if self
            .operations
            .iter()
            .any(|op| matches!(&op.edit.data, Payload::File { path, .. } if *path == destination))
        {
            return Err(invalid("output cannot replace a payload file"));
        }
        if in_place && destination != self.input {
            return Err(invalid("--in-place requires the original input path"));
        }
        if !in_place && destination == self.input {
            return Err(invalid("use --in-place to replace the input"));
        }
        if !in_place && destination.exists() && !overwrite {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "output exists; use --overwrite",
            ));
        }
        let (temp, mut file) = fsio::create_temp_beside(&destination)?;
        let result = (|| {
            self.write(&File::open(&self.input)?, &mut file)?;
            file.sync_all()?;
            drop(file);
            let verified = self.verify_staged(&temp, &self.input)?;
            if !verified.ok() {
                return Err(io::Error::other(format!(
                    "staged output failed verification: {}",
                    serde_json::to_string(&verified)?
                )));
            }
            self.check_fresh()?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = fs::metadata(&self.input)?.permissions().mode() & 0o1777;
                fs::set_permissions(&temp, fs::Permissions::from_mode(mode))?;
            }
            let undo_id = if in_place {
                let mut engine = EditEngine::new()?;
                Some(
                    engine
                        .replace_staged(&self.input, &temp, &self.before.blake3, &self.after.blake3)
                        .map_err(io::Error::other)?
                        .undo_id,
                )
            } else {
                publish(&temp, &destination, overwrite)?;
                None
            };
            Ok(ApplyReport {
                output: destination.clone(),
                operations: self.operations.len(),
                undo_id,
                verified,
            })
        })();
        let _ = fs::remove_file(&temp);
        result
    }
}

/// One spelling per location: the deepest existing ancestor of `path` is
/// canonicalized and the rest of the path is appended. Two spellings of the
/// same place, such as macOS `/var` and `/private/var` or a Windows 8.3 short
/// name and its long name, resolve equal, so compare paths only in this form.
pub fn resolved(path: &Path) -> io::Result<PathBuf> {
    let absolute = std::path::absolute(path)?;
    let mut base = absolute.as_path();
    let mut rest = Vec::new();
    loop {
        if fs::symlink_metadata(base).is_ok() {
            let mut out = fsio::canonical(base)?;
            out.extend(rest.iter().rev());
            return Ok(out);
        }
        match (base.parent(), base.file_name()) {
            (Some(parent), Some(name)) => {
                rest.push(name.to_os_string());
                base = parent;
            }
            _ => return Ok(absolute),
        }
    }
}

/// Where a written file lands, in [`resolved`] form. An existing output must
/// be a regular file and never a symbolic link.
pub fn output_path(path: &Path) -> io::Result<PathBuf> {
    if fs::symlink_metadata(path).is_ok() {
        regular(path)?;
    }
    let destination = resolved(path)?;
    if destination.file_name().is_none() {
        return Err(invalid("output needs a filename"));
    }
    Ok(destination)
}

/// A hard link publishes a complete sibling without replacing a racing writer.
pub fn publish(temp: &Path, output: &Path, overwrite: bool) -> io::Result<()> {
    if overwrite {
        fs::rename(temp, output)?;
    } else {
        fs::hard_link(temp, output)?;
        fs::remove_file(temp)?;
    }
    if let Some(parent) = output.parent() {
        fsio::sync_dir(parent);
    }
    Ok(())
}

pub fn write_json(path: &Path, value: &impl Serialize, overwrite: bool) -> io::Result<()> {
    let output = output_path(path)?;
    let (temp, mut file) = fsio::create_temp_beside(&output)?;
    let result = (|| {
        serde_json::to_writer_pretty(&mut file, value)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        drop(file);
        publish(&temp, &output, overwrite)
    })();
    let _ = fs::remove_file(temp);
    result
}

fn copy_span(input: &File, offset: u64, len: u64, output: &mut dyn Write) -> io::Result<()> {
    let mut buffer = vec![0; fsio::CHUNK];
    let mut done = 0;
    while done < len {
        let count = (len - done).min(buffer.len() as u64) as usize;
        fsio::read_exact_at(input, offset + done, &mut buffer[..count])?;
        output.write_all(&buffer[..count])?;
        done += count as u64;
    }
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct VerifyReport {
    pub byte_integrity: bool,
    pub structure_valid: Option<bool>,
    pub coverage_complete: bool,
    pub policy_satisfied: bool,
    pub raw: bool,
    pub hashes: Hashes,
    pub audit: Option<deattribute::audit::AuditReport>,
}

impl VerifyReport {
    pub fn ok(&self) -> bool {
        self.byte_integrity
            && self.coverage_complete
            && self.policy_satisfied
            && self.structure_valid != Some(false)
    }
}

#[derive(Debug, Serialize)]
pub struct ApplyReport {
    pub output: PathBuf,
    pub operations: usize,
    pub undo_id: Option<u64>,
    pub verified: VerifyReport,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_check_saved_without_a_logical_path_still_loads() {
        let check: DeattributeCheck = serde_json::from_str(
            r#"{"deep":false,"options":{"limits":{"max_scan_bytes":1,"max_matches":1},"rules":null,"verification":"strict"},"policy":"strict","audit":null,"coverage_complete":true}"#,
        )
        .unwrap();
        assert_eq!(check.logical, None);
        assert_eq!(
            logical_path(Path::new("./bin/sample.dll")),
            "bin/sample.dll"
        );
        assert_eq!(logical_path(Path::new("bin\\sample.dll")), "bin/sample.dll");
    }

    #[test]
    fn resolved_spells_new_and_existing_paths_once() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a.bin");
        fs::write(&file, b"x").unwrap();
        let canonical = fsio::canonical(dir.path()).unwrap();
        assert_eq!(resolved(&file).unwrap(), canonical.join("a.bin"));
        assert_eq!(
            resolved(&dir.path().join("new").join("deeper").join("b.bin")).unwrap(),
            canonical.join("new").join("deeper").join("b.bin")
        );
        assert_eq!(output_path(&file).unwrap(), canonical.join("a.bin"));
    }

    #[cfg(unix)]
    #[test]
    fn linked_parent_folders_resolve_but_linked_files_are_refused() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        fs::create_dir(&real).unwrap();
        let alias = dir.path().join("alias");
        symlink(&real, &alias).unwrap();
        let file = real.join("a.bin");
        fs::write(&file, b"x").unwrap();
        // A file reached through a linked folder, like macOS /var, is an input.
        regular(&alias.join("a.bin")).unwrap();
        // Both spellings of one place compare equal, existing or not.
        assert_eq!(
            resolved(&alias.join("a.bin")).unwrap(),
            resolved(&file).unwrap()
        );
        assert_eq!(
            output_path(&alias.join("b.bin")).unwrap(),
            output_path(&real.join("b.bin")).unwrap()
        );
        // A link as the file itself is never followed, as input or output.
        let link = real.join("link.bin");
        symlink(&file, &link).unwrap();
        assert_eq!(
            regular(&link).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            output_path(&link).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
