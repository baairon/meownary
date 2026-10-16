//! The category taxonomy a finding falls into.
//!
//! `Category` is the coarse axis (what *kind* of thing we noticed); the inner
//! enums name the specific flavour. The human-readable value (a brand name, a
//! toolchain version, a signer CN) never lives here, it lives in
//! [`crate::model::Finding::title`] and the evidence note, so this taxonomy
//! stays small and stable while the catalog grows.

use serde::{Deserialize, Serialize};

/// The coarse category of a finding. Serialized adjacently as
/// `{"category": "...", "detail": ...}` so JSON consumers can switch on one key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "category", content = "detail", rename_all = "snake_case")]
pub enum Category {
    /// What the file actually is, and whether that contradicts its extension.
    Identity {
        declared_ext: Option<String>,
        true_format: String,
        mismatch: bool,
    },
    /// Who or what produced it: vendor, signer, toolchain, packer, installer.
    Brand(BrandKind),
    /// The state of any signature or checksum the format carries.
    Integrity(SignatureStatus),
    /// Evidence the artifact was altered after its original build/signing.
    Tamper(TamperKind),
    /// Patterns whose point is to mislead a human or a scanner.
    Deception(DeceptionKind),
    /// A wrapper/adware installer around some inner payload.
    Bundleware,
    /// Removable metadata: the main fuel for bulk cleaning.
    Junk(JunkKind),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrandKind {
    Vendor,
    Signer,
    Toolchain,
    Packer,
    Installer,
    MediaEncoder,
    DocProducer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureStatus {
    /// An embedded signature is present (trust not asserted, we have no store).
    Present,
    /// The format carries a signature slot and it is empty.
    Absent,
    SelfSigned,
    /// Signed with an ad-hoc identity (e.g. macOS `CS_ADHOC`).
    AdHoc,
    /// A cheap internal checksum matched.
    ChecksumOk,
    /// A cheap internal checksum did not match the bytes.
    ChecksumBad,
    /// No embedded signature; note it may still be covered by an external catalog.
    NoEmbedded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TamperKind {
    Cracked,
    Patched,
    ReSigned,
    /// A DRM/platform-emulation shim standing in for a vendor component.
    DrmShim,
    /// A proxy/hijack DLL placed to be loaded in a vendor's stead.
    ProxyDll,
    /// Bytes appended after the format's declared end (an overlay or trailer).
    AppendedData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeceptionKind {
    DoubleExt,
    /// A right-to-left override (U+202E) hiding the real extension.
    Rtlo,
    /// Padding/overlay far larger than the real content, e.g. to dodge scanners.
    OverlayBloat,
    /// Version info claims a known vendor the file is not signed by.
    BrandImpersonation,
    /// The password is leaked in the file name of an encrypted archive.
    PwInFilename,
    /// The content does not match the extension (softer than a full Identity mismatch).
    ExtMismatch,
    /// Whitespace padding that pushes the real extension out of view.
    HiddenExt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JunkKind {
    Exif,
    Xmp,
    Id3,
    ArchiveComment,
    VersionInfo,
    BuildPath,
    PdbPath,
    /// A free-form comment block (gzip, GIF, RIFF INFO, tar owner fields).
    Comment,
    /// A PNG text chunk (tEXt, zTXt, iTXt).
    TextChunk,
    /// IPTC / Photoshop metadata (JPEG APP13).
    Iptc,
    /// Document properties such as author and dates (PDF Info, OLE summary).
    DocInfo,
}

impl Category {
    /// A short, stable, lowercase slug for the coarse axis. Used for grouping,
    /// filtering, and the `--category` CLI flag.
    pub fn slug(&self) -> &'static str {
        match self {
            Category::Identity { .. } => "identity",
            Category::Brand(_) => "brand",
            Category::Integrity(_) => "integrity",
            Category::Tamper(_) => "tamper",
            Category::Deception(_) => "deception",
            Category::Bundleware => "bundleware",
            Category::Junk(_) => "junk",
        }
    }
}
