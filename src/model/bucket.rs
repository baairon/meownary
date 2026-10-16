//! Buckets group findings across every scanned file so the user can clean a
//! whole class at once ("mass", not one-at-a-time). A bucket is a view over
//! findings, keyed by a stable, hashable key.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::category::Category;
use super::finding::Severity;
use super::marker::ContainerKind;
use super::report::FileReport;

/// The dimension a bucket groups on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BucketBy {
    /// Coarse category slug ("junk", "tamper", ...).
    Category,
    /// A specific signature id ("pe.rich.msvc").
    Signature,
    /// The container kind of the removable marker.
    Container,
}

/// An aggregate over findings that share a key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bucket {
    pub by: BucketBy,
    /// The stable key value (the slug / signature id / container name).
    pub key: String,
    /// A short human label for the TUI.
    pub label: String,
    /// How many findings fall in this bucket.
    pub members: usize,
    /// How many of those carry a removable marker.
    pub removable: usize,
    /// Distinct files touched.
    pub files: usize,
    pub max_severity: Severity,
}

/// Group every finding across `reports` by `by`, returning buckets sorted by
/// descending severity then descending member count (loudest, biggest first).
pub fn bucketize(reports: &[FileReport], by: BucketBy) -> Vec<Bucket> {
    // key -> (label, members, removable, set-of-file-indices, max severity)
    let mut acc: BTreeMap<String, Acc> = BTreeMap::new();
    for (fi, report) in reports.iter().enumerate() {
        for finding in &report.findings {
            let (key, label) = match by {
                BucketBy::Category => {
                    let s = finding.category.slug();
                    (s.to_string(), category_label(&finding.category).to_string())
                }
                BucketBy::Signature => (finding.signature_id.clone(), finding.title.clone()),
                BucketBy::Container => match &finding.marker {
                    Some(m) => {
                        let s = container_slug(m.container);
                        (s.to_string(), s.to_string())
                    }
                    None => continue,
                },
            };
            let e = acc.entry(key).or_insert_with(|| Acc {
                label,
                members: 0,
                removable: 0,
                files: Vec::new(),
                max_severity: Severity::Info,
            });
            e.members += 1;
            if finding.is_removable() {
                e.removable += 1;
            }
            if !e.files.contains(&fi) {
                e.files.push(fi);
            }
            if finding.severity > e.max_severity {
                e.max_severity = finding.severity;
            }
        }
    }

    let mut out: Vec<Bucket> = acc
        .into_iter()
        .map(|(key, a)| Bucket {
            by,
            key,
            label: a.label,
            members: a.members,
            removable: a.removable,
            files: a.files.len(),
            max_severity: a.max_severity,
        })
        .collect();
    out.sort_by(|a, b| {
        b.max_severity
            .cmp(&a.max_severity)
            .then(b.members.cmp(&a.members))
            .then(a.key.cmp(&b.key))
    });
    out
}

struct Acc {
    label: String,
    members: usize,
    removable: usize,
    files: Vec<usize>,
    max_severity: Severity,
}

fn category_label(c: &Category) -> &'static str {
    match c {
        Category::Identity { .. } => "Identity",
        Category::Brand(_) => "Brand",
        Category::Integrity(_) => "Integrity",
        Category::Tamper(_) => "Tamper",
        Category::Deception(_) => "Deception",
        Category::Bundleware => "Bundleware",
        Category::Junk(_) => "Junk / metadata",
    }
}

fn container_slug(c: ContainerKind) -> &'static str {
    match c {
        ContainerKind::Raw => "raw",
        ContainerKind::PeOverlay => "pe-overlay",
        ContainerKind::PeResource => "pe-resource",
        ContainerKind::JpegApp1 => "jpeg-app1",
        ContainerKind::ZipComment => "zip-comment",
        ContainerKind::Id3v1 => "id3v1",
        ContainerKind::Id3v2 => "id3v2",
        ContainerKind::ElfSection => "elf-section",
        ContainerKind::MachoLoadCmd => "macho-loadcmd",
        ContainerKind::PngChunk => "png-chunk",
        ContainerKind::RiffChunk => "riff-chunk",
        ContainerKind::IsoBox => "iso-box",
        ContainerKind::EbmlElement => "ebml-element",
        ContainerKind::PdfObject => "pdf-object",
        ContainerKind::GzipHeader => "gzip-header",
        ContainerKind::JpegSegment => "jpeg-segment",
        ContainerKind::CfbStream => "cfb-stream",
        ContainerKind::TarHeader => "tar-header",
        ContainerKind::RarBlock => "rar-block",
        ContainerKind::Generic => "generic",
    }
}
