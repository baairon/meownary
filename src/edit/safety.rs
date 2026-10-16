//! Risk assessment for an edit. Every removal is classified before it runs so
//! the UI can confirm, and headless can gate `Warn` behind `--force` and always
//! skip `Refuse`. This is the guardrail that keeps a mislabeled finding from
//! quietly destroying a file.

use crate::model::{Marker, RemovalStrategy};
use crate::util::fmt::human_size;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Risk {
    /// Routine and reversible; apply after a normal confirm.
    Safe,
    /// Allowed, but the user should know why (reason). Needs `--force` headless.
    Warn(String),
    /// Never applied automatically; the edit would almost certainly corrupt.
    Refuse(String),
}

/// A truncate/delete moving more than this into trash earns a `Warn`.
pub const BIG_SNAPSHOT: u64 = 256 * 1024 * 1024;

/// Assess removing `marker` from a `size`-byte file of the given `format`.
pub fn assess(format: Option<&str>, size: u64, marker: &Marker) -> Risk {
    match &marker.removal {
        RemovalStrategy::RawBlank { .. } => {
            if marker.region.offset == 0 && is_structural_format(format) {
                return Risk::Refuse("would erase the file's magic bytes".into());
            }
            Risk::Safe
        }
        RemovalStrategy::Truncate { from } => {
            if is_signed_exe(format) {
                return Risk::Warn("truncating may remove an appended code signature".into());
            }
            let dropped = size.saturating_sub(*from);
            if dropped > BIG_SNAPSHOT {
                return Risk::Warn(format!(
                    "{} would be snapshotted to trash",
                    human_size(dropped)
                ));
            }
            Risk::Safe
        }
        RemovalStrategy::StructuralRemove => {
            Risk::Warn("rewrites the surrounding container to stay valid".into())
        }
        RemovalStrategy::DeleteFile => Risk::Warn("removes the whole file".into()),
    }
}

fn is_structural_format(f: Option<&str>) -> bool {
    matches!(
        f,
        Some(
            "pe" | "elf"
                | "macho"
                | "zip"
                | "rar"
                | "7z"
                | "png"
                | "jpeg"
                | "gif"
                | "pdf"
                | "gzip"
                | "xz"
                | "zstd"
        )
    )
}

fn is_signed_exe(f: Option<&str>) -> bool {
    matches!(f, Some("pe" | "macho"))
}
