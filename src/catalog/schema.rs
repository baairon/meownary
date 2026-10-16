//! The detection catalog schema: the single, auditable source of truth for the
//! string/byte signatures the scan looks for. Entries live in `catalog.ron` as
//! data, not code, so they can be reviewed and extended without touching the
//! engine. Every entry must carry a real `source` URL and, for `Strong`
//! confidence, a non-empty `corroboration` list. The validator (and a test)
//! enforce that, which is how categorization stays honest.

use serde::{Deserialize, Serialize};

use crate::model::{
    BrandKind, Category, Confidence, ContainerKind, DeceptionKind, JunkKind, RemovalStrategy,
    Severity, TamperKind,
};

/// The whole catalog, as embedded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Catalog {
    pub signatures: Vec<Signature>,
}

/// Where in the file a detector looks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Window {
    Header,
    Tail,
    Whole,
}

/// How a signature is matched. Both forms are swept cheaply with aho-corasick.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Detect {
    /// A literal byte string, given as lowercase hex (e.g. `"ff20476f"`).
    Bytes { hex: String, window: Window },
    /// A UTF-8 substring.
    Text { needle: String, window: Window },
}

/// How a matched region may be cleaned, mapped to the engine's strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemovalSpec {
    RawBlank,
    Truncate,
    Structural,
    DeleteFile,
    /// The marker is informational only; nothing to remove.
    None,
}

/// The specific category + kind a signature maps to in the model. Keeping this
/// as a flat enum in the catalog keeps entries declarative.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CatKind {
    BrandVendor,
    BrandSigner,
    BrandToolchain,
    BrandPacker,
    BrandInstaller,
    BrandMediaEncoder,
    BrandDocProducer,
    TamperCracked,
    TamperPatched,
    TamperReSigned,
    TamperDrmShim,
    TamperProxyDll,
    DeceptionBrandImpersonation,
    Bundleware,
    JunkVersionInfo,
    JunkBuildPath,
    JunkPdbPath,
    JunkArchiveComment,
}

impl CatKind {
    /// Build the model [`Category`] this kind corresponds to.
    pub fn to_category(self) -> Category {
        use CatKind::*;
        match self {
            BrandVendor => Category::Brand(BrandKind::Vendor),
            BrandSigner => Category::Brand(BrandKind::Signer),
            BrandToolchain => Category::Brand(BrandKind::Toolchain),
            BrandPacker => Category::Brand(BrandKind::Packer),
            BrandInstaller => Category::Brand(BrandKind::Installer),
            BrandMediaEncoder => Category::Brand(BrandKind::MediaEncoder),
            BrandDocProducer => Category::Brand(BrandKind::DocProducer),
            TamperCracked => Category::Tamper(TamperKind::Cracked),
            TamperPatched => Category::Tamper(TamperKind::Patched),
            TamperReSigned => Category::Tamper(TamperKind::ReSigned),
            TamperDrmShim => Category::Tamper(TamperKind::DrmShim),
            TamperProxyDll => Category::Tamper(TamperKind::ProxyDll),
            DeceptionBrandImpersonation => Category::Deception(DeceptionKind::BrandImpersonation),
            Bundleware => Category::Bundleware,
            JunkVersionInfo => Category::Junk(JunkKind::VersionInfo),
            JunkBuildPath => Category::Junk(JunkKind::BuildPath),
            JunkPdbPath => Category::Junk(JunkKind::PdbPath),
            JunkArchiveComment => Category::Junk(JunkKind::ArchiveComment),
        }
    }
}

/// Map a [`RemovalSpec`] to a concrete [`RemovalStrategy`] for a matched region.
pub fn removal_for(spec: RemovalSpec) -> Option<(RemovalStrategy, ContainerKind)> {
    match spec {
        RemovalSpec::RawBlank => Some((RemovalStrategy::RawBlank { fill: 0 }, ContainerKind::Raw)),
        RemovalSpec::Truncate => Some((
            RemovalStrategy::Truncate { from: 0 },
            ContainerKind::Generic,
        )),
        RemovalSpec::Structural => {
            Some((RemovalStrategy::StructuralRemove, ContainerKind::Generic))
        }
        RemovalSpec::DeleteFile => Some((RemovalStrategy::DeleteFile, ContainerKind::Generic)),
        RemovalSpec::None => None,
    }
}

/// One catalog entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    /// Stable, unique, dotted id (e.g. `pe.packer.upx`).
    pub id: String,
    pub kind: CatKind,
    pub confidence: Confidence,
    pub severity: Severity,
    /// Format slugs this applies to; empty = any.
    #[serde(default)]
    pub formats: Vec<String>,
    pub title: String,
    pub detect: Detect,
    /// Other conditions/ids that must also hold to justify `Strong`. Required
    /// (non-empty) whenever `confidence == Strong`.
    #[serde(default)]
    pub corroboration: Vec<String>,
    /// A citation URL for the signature. Required, non-empty.
    pub source: String,
    /// A note on what benign thing might trip this, if any.
    #[serde(default)]
    pub false_positives: Option<String>,
    #[serde(default = "default_removal")]
    pub removal: RemovalSpec,
}

fn default_removal() -> RemovalSpec {
    RemovalSpec::None
}

/// Validate structural invariants. Returns the list of problems (empty = ok).
/// Enforced by a test so a bad catalog fails CI.
pub fn validate(cat: &Catalog) -> Vec<String> {
    let mut problems = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for sig in &cat.signatures {
        if !seen.insert(sig.id.clone()) {
            problems.push(format!("duplicate id: {}", sig.id));
        }
        if sig.id.trim().is_empty() {
            problems.push("empty id".to_string());
        }
        if !sig.source.starts_with("http://") && !sig.source.starts_with("https://") {
            problems.push(format!("{}: source must be a URL", sig.id));
        }
        if sig.confidence == Confidence::Strong && sig.corroboration.is_empty() {
            problems.push(format!(
                "{}: Strong confidence requires corroboration",
                sig.id
            ));
        }
        if let Detect::Bytes { hex, .. } = &sig.detect {
            if hex.is_empty() || hex.len() % 2 != 0 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                problems.push(format!("{}: malformed hex", sig.id));
            }
        }
        if let Detect::Text { needle, .. } = &sig.detect {
            if needle.is_empty() {
                problems.push(format!("{}: empty needle", sig.id));
            }
        }
    }
    problems
}
