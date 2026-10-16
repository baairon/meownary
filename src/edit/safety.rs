//! Risk assessment for an edit. Every removal is classified before it runs so
//! the UI can confirm, and headless can gate `Warn` behind `--force` and always
//! skip `Refuse`. This is the guardrail that keeps a mislabeled finding from
//! quietly destroying a file.
//!
//! The rules, in order:
//!
//! * A raw blank must lie inside the file, must not be empty, never touches
//!   offset 0, and never overlaps the first [`MAGIC_SPAN`] bytes of a
//!   structural format.
//! * A truncate must drop something, never empties the file, and never cuts
//!   into a structural format's first [`MAGIC_SPAN`] bytes. Truncating a
//!   signable executable, or dropping more than [`BIG_SNAPSHOT`], is a warning.
//! * A structural rewrite is safe for the containers listed in
//!   [`SAFE_STRUCTURAL`] (ZIP comments and entries, PNG chunks, JPEG segments,
//!   RIFF chunks, ISO boxes, tar headers, raw text), whose removers are
//!   round-trip tested by their owners, and a warning for every other
//!   container. The engine still reports it unsupported when the container's
//!   remover declines.
//! * Deleting a whole file is a warning.
//! * A marker that says it is not reversible is never better than a warning.

use crate::model::{ContainerKind, Marker, RemovalStrategy};
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

/// How many leading bytes of a structural format count as its magic.
pub const MAGIC_SPAN: u64 = 16;

/// The refusal reason for an edit that would hit a format's magic bytes. The
/// interactive view keys its friendlier copy off this exact text.
pub const MAGIC_REASON: &str = "would erase the file's magic bytes";

/// Containers whose structural remover is round-trip tested by its owning
/// parser, so dropping a marker through it is routine.
pub const SAFE_STRUCTURAL: &[ContainerKind] = &[
    ContainerKind::ZipComment,
    ContainerKind::PngChunk,
    ContainerKind::JpegApp1,
    ContainerKind::JpegSegment,
    ContainerKind::RiffChunk,
    ContainerKind::TarHeader,
    ContainerKind::IsoBox,
    ContainerKind::Raw,
];

/// Every format label whose leading bytes carry structure a reader depends on.
pub const STRUCTURAL_FORMATS: &[&str] = &[
    "pe",
    "elf",
    "macho",
    "rsrc",
    "appledouble",
    "wasm",
    "class",
    "zip",
    "jar",
    "apk",
    "ooxml",
    "rar",
    "7z",
    "gzip",
    "xz",
    "zstd",
    "bzip2",
    "tar",
    "pdf",
    "cfb",
    "msi",
    "png",
    "jpeg",
    "gif",
    "bmp",
    "webp",
    "mp4",
    "matroska",
    "webm",
    "ogg",
    "flac",
    "mp3",
    "wav",
    "avi",
    "lnk",
];

/// Assess removing `marker` from a `size`-byte file of the given `format`.
pub fn assess(format: Option<&str>, size: u64, marker: &Marker) -> Risk {
    let risk = assess_strategy(format, size, marker);
    if marker.reversible {
        return risk;
    }
    match risk {
        Risk::Safe => Risk::Warn("this change cannot be undone".into()),
        Risk::Warn(r) => Risk::Warn(format!("{r}; this change cannot be undone")),
        refuse @ Risk::Refuse(_) => refuse,
    }
}

fn assess_strategy(format: Option<&str>, size: u64, marker: &Marker) -> Risk {
    let structural = is_structural_format(format);
    match &marker.removal {
        RemovalStrategy::RawBlank { .. } => {
            let r = marker.region;
            if r.len == 0 {
                return Risk::Refuse("the marker region is empty".into());
            }
            if r.offset.checked_add(r.len).is_none_or(|end| end > size) {
                return Risk::Refuse("the marker region runs past the end of the file".into());
            }
            if r.offset == 0 || (structural && r.offset < MAGIC_SPAN) {
                return Risk::Refuse(MAGIC_REASON.into());
            }
            Risk::Safe
        }
        RemovalStrategy::Truncate { from } => {
            if *from == 0 {
                return Risk::Refuse("truncating to 0 bytes would empty the file".into());
            }
            if *from >= size {
                return Risk::Refuse("nothing lies past the truncation point".into());
            }
            if structural && *from < MAGIC_SPAN {
                return Risk::Refuse(MAGIC_REASON.into());
            }
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
            if SAFE_STRUCTURAL.contains(&marker.container) {
                Risk::Safe
            } else {
                Risk::Warn("rewrites the surrounding container to stay valid".into())
            }
        }
        RemovalStrategy::DeleteFile => Risk::Warn("removes the whole file".into()),
    }
}

/// Whether `f` names a format with structural leading bytes.
pub fn is_structural_format(f: Option<&str>) -> bool {
    f.is_some_and(|f| STRUCTURAL_FORMATS.contains(&f))
}

fn is_signed_exe(f: Option<&str>) -> bool {
    matches!(f, Some("pe" | "macho"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Region;

    fn blank(off: u64, len: u64) -> Marker {
        Marker::blank(Region::new(off, len), ContainerKind::Raw)
    }

    fn structural(c: ContainerKind) -> Marker {
        Marker {
            region: Region::new(100, 10),
            removal: RemovalStrategy::StructuralRemove,
            container: c,
            reversible: true,
        }
    }

    #[test]
    fn blanks_never_touch_magic() {
        assert_eq!(
            assess(Some("png"), 1000, &blank(8, 20)),
            Risk::Refuse(MAGIC_REASON.into())
        );
        assert_eq!(
            assess(Some("webm"), 1000, &blank(15, 1)),
            Risk::Refuse(MAGIC_REASON.into())
        );
        assert_eq!(assess(Some("png"), 1000, &blank(16, 20)), Risk::Safe);
        assert_eq!(assess(Some("script"), 1000, &blank(4, 4)), Risk::Safe);
        assert!(matches!(assess(None, 1000, &blank(0, 4)), Risk::Refuse(_)));
        assert!(matches!(
            assess(Some("png"), 100, &blank(90, 20)),
            Risk::Refuse(_)
        ));
        assert!(matches!(
            assess(Some("png"), 100, &blank(50, 0)),
            Risk::Refuse(_)
        ));
        assert!(matches!(
            assess(Some("png"), 100, &blank(u64::MAX, 2)),
            Risk::Refuse(_)
        ));
    }

    #[test]
    fn every_label_is_structural() {
        for f in [
            "pe",
            "elf",
            "macho",
            "rsrc",
            "appledouble",
            "wasm",
            "class",
            "zip",
            "jar",
            "apk",
            "ooxml",
            "rar",
            "7z",
            "gzip",
            "xz",
            "zstd",
            "bzip2",
            "tar",
            "pdf",
            "cfb",
            "msi",
            "png",
            "jpeg",
            "gif",
            "bmp",
            "webp",
            "mp4",
            "matroska",
            "webm",
            "ogg",
            "flac",
            "mp3",
            "wav",
            "avi",
            "lnk",
        ] {
            assert!(is_structural_format(Some(f)), "{f}");
        }
        assert!(!is_structural_format(Some("script")));
        assert!(!is_structural_format(None));
    }

    #[test]
    fn truncate_rules() {
        let t = |from| Marker::truncate_at(from, ContainerKind::PeOverlay);
        assert!(matches!(assess(Some("zip"), 100, &t(0)), Risk::Refuse(_)));
        assert!(matches!(assess(Some("zip"), 100, &t(100)), Risk::Refuse(_)));
        assert!(matches!(assess(Some("zip"), 100, &t(150)), Risk::Refuse(_)));
        assert!(matches!(assess(Some("zip"), 100, &t(8)), Risk::Refuse(_)));
        assert_eq!(assess(Some("zip"), 100, &t(50)), Risk::Safe);
        assert_eq!(assess(None, 100, &t(4)), Risk::Safe);
        assert!(matches!(assess(Some("pe"), 100, &t(50)), Risk::Warn(_)));
        assert!(matches!(
            assess(Some("zip"), BIG_SNAPSHOT * 2, &t(50)),
            Risk::Warn(_)
        ));
    }

    #[test]
    fn structural_safe_for_tested_removers_only() {
        let safe = [
            (ContainerKind::ZipComment, "zip"),
            (ContainerKind::PngChunk, "png"),
            (ContainerKind::JpegApp1, "jpeg"),
            (ContainerKind::JpegSegment, "jpeg"),
            (ContainerKind::RiffChunk, "webp"),
            (ContainerKind::TarHeader, "tar"),
            (ContainerKind::IsoBox, "mp4"),
            (ContainerKind::Raw, "script"),
        ];
        for (c, f) in safe {
            assert_eq!(assess(Some(f), 1000, &structural(c)), Risk::Safe, "{c:?}");
        }
        use ContainerKind::*;
        for c in [
            PeOverlay,
            PeResource,
            Id3v1,
            Id3v2,
            ElfSection,
            MachoLoadCmd,
            EbmlElement,
            PdfObject,
            GzipHeader,
            CfbStream,
            RarBlock,
            Generic,
        ] {
            assert!(
                matches!(assess(Some("zip"), 1000, &structural(c)), Risk::Warn(_)),
                "{c:?}"
            );
        }
        let mut oneway = structural(ContainerKind::JpegApp1);
        oneway.reversible = false;
        assert!(matches!(assess(Some("jpeg"), 1000, &oneway), Risk::Warn(_)));
    }

    #[test]
    fn structural_delete_and_irreversible() {
        let del = Marker {
            region: Region::new(0, 0),
            removal: RemovalStrategy::DeleteFile,
            container: ContainerKind::Generic,
            reversible: true,
        };
        assert!(matches!(assess(Some("pe"), 10, &del), Risk::Warn(_)));

        let mut oneway = blank(32, 4);
        oneway.reversible = false;
        assert!(matches!(assess(Some("png"), 100, &oneway), Risk::Warn(_)));
        let mut oneway_bad = blank(2, 4);
        oneway_bad.reversible = false;
        assert!(matches!(
            assess(Some("png"), 100, &oneway_bad),
            Risk::Refuse(_)
        ));
    }
}
