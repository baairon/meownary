//! Per-file and whole-scan result aggregates.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::finding::{Finding, Severity};

/// Everything we concluded about one file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileReport {
    pub path: PathBuf,
    /// Size in bytes at scan time (used for overlay-bloat math and edit guards).
    pub size: u64,
    /// The identified true format slug (e.g. `pe`, `elf`, `zip`, `jpeg`),
    /// or `None` when nothing matched (reported as "unknown").
    pub format: Option<String>,
    /// `true` when the per-file guard caught a panic/timeout; findings may be
    /// partial. The scan never aborts because of one bad file.
    pub partial: bool,
    pub findings: Vec<Finding>,
}

impl FileReport {
    pub fn new(path: PathBuf, size: u64) -> Self {
        Self {
            path,
            size,
            format: None,
            partial: false,
            findings: Vec::new(),
        }
    }

    /// The loudest severity across findings, or `None` when clean.
    pub fn max_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }
}
