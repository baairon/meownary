//! A marker is a concrete, addressable region of a file that a finding points
//! at, plus the recipe for removing it. The edit engine consumes markers; the
//! probes produce them.

use serde::{Deserialize, Serialize};

/// A byte range within a file. `len == 0` is legal (a point annotation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Region {
    pub offset: u64,
    pub len: u64,
}

impl Region {
    pub fn new(offset: u64, len: u64) -> Self {
        Self { offset, len }
    }

    pub fn end(&self) -> u64 {
        self.offset.saturating_add(self.len)
    }
}

/// How the containing structure must be treated when the marker is removed.
/// The edit engine switches on this to pick a structure-aware vs raw edit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerKind {
    /// Loose bytes with no surrounding structure to keep valid.
    Raw,
    /// Appended data after a PE image (truncate at the overlay offset).
    PeOverlay,
    /// A resource inside a PE `.rsrc` tree.
    PeResource,
    /// A JPEG `APP1` segment (EXIF/XMP).
    JpegApp1,
    /// The trailing comment of a ZIP end-of-central-directory record.
    ZipComment,
    /// A 128-byte ID3v1 trailer.
    Id3v1,
    /// An ID3v2 header at the front of an audio file.
    Id3v2,
    /// A named ELF section.
    ElfSection,
    /// A Mach-O load command / linkedit region.
    MachoLoadCmd,
    /// A PNG chunk (length, type, data, CRC).
    PngChunk,
    /// A RIFF chunk (WebP, WAV, AVI).
    RiffChunk,
    /// An ISO base media box (MP4, MOV).
    IsoBox,
    /// An EBML element (Matroska, WebM).
    EbmlElement,
    /// A PDF object or Info dictionary entry.
    PdfObject,
    /// A gzip member header field (FNAME, FCOMMENT).
    GzipHeader,
    /// Any JPEG marker segment other than APP1.
    JpegSegment,
    /// A stream inside an OLE compound file.
    CfbStream,
    /// A tar entry header.
    TarHeader,
    /// A RAR block or service header.
    RarBlock,
    /// Known structure, but removal is still a plain blank/truncate.
    Generic,
}

/// What to do to the bytes to remove the marker. Each variant is reversible
/// through the undo journal (see `edit::journal`); the engine records the
/// original bytes before applying.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum RemovalStrategy {
    /// Overwrite the region in place with `fill` (length preserved). The
    /// cheapest and most broadly safe edit; undo restores the saved bytes.
    RawBlank { fill: u8 },
    /// Cut the file down to `from` bytes. Used for trailers and overlays.
    Truncate { from: u64 },
    /// Rewrite the surrounding container so it stays valid after the region is
    /// dropped. The engine owns the per-container implementation.
    StructuralRemove,
    /// Remove the whole file (snapshot to trash first).
    DeleteFile,
}

/// A removable region plus its removal recipe and container context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Marker {
    pub region: Region,
    pub removal: RemovalStrategy,
    pub container: ContainerKind,
    /// Whether the edit engine can restore this exactly (almost always true;
    /// false warns the user the change is one-way).
    pub reversible: bool,
}

impl Marker {
    /// A length-preserving in-place blank of `region`, the common case.
    pub fn blank(region: Region, container: ContainerKind) -> Self {
        Self {
            region,
            removal: RemovalStrategy::RawBlank { fill: 0 },
            container,
            reversible: true,
        }
    }

    /// Truncate the file at `region.offset` (drop everything from there on).
    pub fn truncate_at(offset: u64, container: ContainerKind) -> Self {
        Self {
            region: Region::new(offset, 0),
            removal: RemovalStrategy::Truncate { from: offset },
            container,
            reversible: true,
        }
    }
}
