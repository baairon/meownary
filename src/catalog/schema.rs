//! The detection catalog schema: the single, auditable source of truth for the
//! string and byte signatures the scan looks for. Entries live in
//! `catalog.ron` as data, not code, so they can be reviewed and extended
//! without touching the engine. Every entry must carry a real `source` URL,
//! and a `Strong` entry must name at least one other catalog entry (`sig:<id>`)
//! that has to match in the same file before Strong is kept. The validator
//! (and a test) enforce that, which is how categorization stays honest.

use serde::{Deserialize, Serialize};

use crate::model::{
    BrandKind, Category, Confidence, ContainerKind, DeceptionKind, JunkKind, Marker, Region,
    RemovalStrategy, Severity, SignatureStatus, TamperKind,
};

/// Every format label identity can produce. Catalog `formats` must use these.
pub const KNOWN_FORMATS: &[&str] = &[
    "pe", "elf", "wasm", "macho", "class", "zip", "rar", "7z", "gzip", "xz", "zstd", "bzip2",
    "tar", "pdf", "cfb", "png", "jpeg", "gif", "bmp", "webp", "wav", "avi", "riff", "mp4",
    "matroska", "ogg", "flac", "mp3", "lnk", "script", "jar", "apk", "ooxml", "msi", "webm",
];

/// Shortest pattern the catalog accepts, in bytes. Shorter needles match
/// noise in any sizeable binary.
pub const MIN_NEEDLE: usize = 4;

/// Prefix that marks a corroboration item as a reference to another entry.
pub const SIG_PREFIX: &str = "sig:";

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

impl Detect {
    /// The window this detector scans.
    pub fn window(&self) -> Window {
        match self {
            Detect::Bytes { window, .. } | Detect::Text { window, .. } => *window,
        }
    }

    /// The literal bytes to search for: hex decoded for `Bytes`, UTF-8 for
    /// `Text`. `None` when the hex is malformed or the pattern is empty.
    pub fn pattern(&self) -> Option<Vec<u8>> {
        let bytes = match self {
            Detect::Bytes { hex, .. } => decode_hex(hex)?,
            Detect::Text { needle, .. } => needle.as_bytes().to_vec(),
        };
        (!bytes.is_empty()).then_some(bytes)
    }
}

fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    let (pairs, _) = hex.as_bytes().as_chunks::<2>();
    pairs
        .iter()
        .map(|&[hi, lo]| {
            let hi = char::from(hi).to_digit(16)?;
            let lo = char::from(lo).to_digit(16)?;
            u8::try_from(hi * 16 + lo).ok()
        })
        .collect()
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
    JunkExif,
    JunkXmp,
    JunkId3,
    JunkComment,
    JunkTextChunk,
    JunkIptc,
    JunkDocInfo,
    TamperAppendedData,
    DeceptionDoubleExt,
    DeceptionRtlo,
    DeceptionOverlayBloat,
    DeceptionHiddenExt,
    IntegrityPresent,
    IntegrityAbsent,
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
            JunkExif => Category::Junk(JunkKind::Exif),
            JunkXmp => Category::Junk(JunkKind::Xmp),
            JunkId3 => Category::Junk(JunkKind::Id3),
            JunkComment => Category::Junk(JunkKind::Comment),
            JunkTextChunk => Category::Junk(JunkKind::TextChunk),
            JunkIptc => Category::Junk(JunkKind::Iptc),
            JunkDocInfo => Category::Junk(JunkKind::DocInfo),
            TamperAppendedData => Category::Tamper(TamperKind::AppendedData),
            DeceptionDoubleExt => Category::Deception(DeceptionKind::DoubleExt),
            DeceptionRtlo => Category::Deception(DeceptionKind::Rtlo),
            DeceptionOverlayBloat => Category::Deception(DeceptionKind::OverlayBloat),
            DeceptionHiddenExt => Category::Deception(DeceptionKind::HiddenExt),
            IntegrityPresent => Category::Integrity(SignatureStatus::Present),
            IntegrityAbsent => Category::Integrity(SignatureStatus::Absent),
        }
    }
}

/// Map a [`RemovalSpec`] to a concrete [`RemovalStrategy`] without a match.
///
/// This cannot know where the match sits, so `Truncate` comes back with
/// `from: u64::MAX`, which the engine treats as a no-op (never `from: 0`,
/// which would empty the file). Use [`marker_for`] to build a real marker for
/// a matched region.
pub fn removal_for(spec: RemovalSpec) -> Option<(RemovalStrategy, ContainerKind)> {
    match spec {
        RemovalSpec::RawBlank => Some((RemovalStrategy::RawBlank { fill: 0 }, ContainerKind::Raw)),
        RemovalSpec::Truncate => Some((
            RemovalStrategy::Truncate { from: u64::MAX },
            ContainerKind::Generic,
        )),
        RemovalSpec::Structural => {
            Some((RemovalStrategy::StructuralRemove, ContainerKind::Generic))
        }
        RemovalSpec::DeleteFile => Some((RemovalStrategy::DeleteFile, ContainerKind::Generic)),
        RemovalSpec::None => None,
    }
}

/// Build the marker for `sig` matched at `region`: RawBlank covers the match
/// with the entry's fill (0x00 unless `fill` says otherwise), Truncate cuts
/// the file at the match offset. Returns `None` for informational entries
/// and for any region starting at offset 0.
pub fn marker_for(sig: &Signature, region: Region) -> Option<Marker> {
    if region.offset == 0 {
        return None;
    }
    let (removal, container) = match removal_for(sig.removal)? {
        (RemovalStrategy::RawBlank { .. }, c) => (
            RemovalStrategy::RawBlank {
                fill: sig.fill.unwrap_or(0),
            },
            c,
        ),
        (RemovalStrategy::Truncate { .. }, c) => {
            return Some(Marker::truncate_at(region.offset, c));
        }
        other => other,
    };
    Some(Marker {
        region,
        removal,
        container,
        reversible: true,
    })
}

/// One catalog entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    /// Stable, unique, dotted id (e.g. `packer.upx`). Findings use
    /// `catalog.<id>` as their signature id.
    pub id: String,
    pub kind: CatKind,
    pub confidence: Confidence,
    pub severity: Severity,
    /// Format labels this applies to; empty = any.
    #[serde(default)]
    pub formats: Vec<String>,
    pub title: String,
    pub detect: Detect,
    /// Other entries (`sig:<id>`) that must also match for `Strong` to hold,
    /// plus free-text notes. Free text documents; only `sig:` items prove.
    #[serde(default)]
    pub corroboration: Vec<String>,
    /// A citation URL for the signature. Required, non-empty.
    pub source: String,
    /// A note on what benign thing might trip this, if any.
    #[serde(default)]
    pub false_positives: Option<String>,
    #[serde(default = "default_removal")]
    pub removal: RemovalSpec,
    /// Fill byte for `RawBlank` (default 0x00; use 0x20 inside text).
    #[serde(default)]
    pub fill: Option<u8>,
}

impl Signature {
    /// The entry ids named by `sig:` corroboration items.
    pub fn sig_refs(&self) -> impl Iterator<Item = &str> {
        self.corroboration
            .iter()
            .filter_map(|c| c.strip_prefix(SIG_PREFIX))
            .map(str::trim)
    }
}

fn default_removal() -> RemovalSpec {
    RemovalSpec::None
}

/// Validate structural invariants. Returns the list of problems (empty = ok).
/// Enforced by a test so a bad catalog fails CI.
pub fn validate(cat: &Catalog) -> Vec<String> {
    let mut problems = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let ids: std::collections::HashSet<&str> =
        cat.signatures.iter().map(|s| s.id.as_str()).collect();
    for sig in &cat.signatures {
        let id = &sig.id;
        if !seen.insert(id.clone()) {
            problems.push(format!("duplicate id: {id}"));
        }
        if id.trim().is_empty() {
            problems.push("empty id".to_string());
        }
        if !sig.source.starts_with("http://") && !sig.source.starts_with("https://") {
            problems.push(format!("{id}: source must be a URL"));
        }
        for fmt in &sig.formats {
            if !KNOWN_FORMATS.contains(&fmt.as_str()) {
                problems.push(format!("{id}: unknown format label {fmt:?}"));
            }
        }
        for r in sig.sig_refs() {
            if r == id {
                problems.push(format!("{id}: corroboration references itself"));
            } else if !ids.contains(r) {
                problems.push(format!("{id}: corroboration references unknown id {r:?}"));
            }
        }
        if sig.confidence == Confidence::Strong && sig.sig_refs().next().is_none() {
            problems.push(format!(
                "{id}: Strong confidence requires at least one sig: corroboration"
            ));
        }
        match &sig.detect {
            Detect::Bytes { hex, .. } => {
                if hex.is_empty()
                    || !hex.len().is_multiple_of(2)
                    || !hex.bytes().all(|b| b.is_ascii_hexdigit())
                {
                    problems.push(format!("{id}: malformed hex"));
                } else if hex.len() / 2 < MIN_NEEDLE {
                    problems.push(format!("{id}: pattern shorter than {MIN_NEEDLE} bytes"));
                }
            }
            Detect::Text { needle, .. } => {
                if needle.is_empty() {
                    problems.push(format!("{id}: empty needle"));
                } else if needle.len() < MIN_NEEDLE {
                    problems.push(format!("{id}: needle shorter than {MIN_NEEDLE} bytes"));
                }
            }
        }
        let edits_bytes = matches!(sig.removal, RemovalSpec::RawBlank | RemovalSpec::Truncate);
        if edits_bytes && sig.formats.is_empty() {
            problems.push(format!(
                "{id}: RawBlank/Truncate removal needs a format list (a match in an unknown file is not safely removable)"
            ));
        }
        if sig.removal == RemovalSpec::Structural {
            problems.push(format!(
                "{id}: Structural removal has no container to rewrite for a catalog match"
            ));
        }
        if sig.fill.is_some() && sig.removal != RemovalSpec::RawBlank {
            problems.push(format!("{id}: fill only applies to RawBlank removal"));
        }
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str) -> Signature {
        Signature {
            id: id.to_string(),
            kind: CatKind::BrandPacker,
            confidence: Confidence::Moderate,
            severity: Severity::Info,
            formats: vec!["pe".to_string()],
            title: "test".to_string(),
            detect: Detect::Text {
                needle: "NEEDLE".to_string(),
                window: Window::Whole,
            },
            corroboration: Vec::new(),
            source: "https://example.org/".to_string(),
            false_positives: None,
            removal: RemovalSpec::None,
            fill: None,
        }
    }

    fn problems(sigs: Vec<Signature>) -> Vec<String> {
        validate(&Catalog { signatures: sigs })
    }

    fn has(problems: &[String], needle: &str) -> bool {
        problems.iter().any(|p| p.contains(needle))
    }

    #[test]
    fn clean_entry_passes() {
        assert!(problems(vec![entry("a.b")]).is_empty());
    }

    #[test]
    fn duplicate_and_empty_ids() {
        let p = problems(vec![entry("a"), entry("a"), entry(" ")]);
        assert!(has(&p, "duplicate id: a"));
        assert!(has(&p, "empty id"));
    }

    #[test]
    fn source_must_be_url() {
        let mut e = entry("a");
        e.source = "upx.github.io".into();
        assert!(has(&problems(vec![e]), "source must be a URL"));
    }

    #[test]
    fn format_labels_must_be_known() {
        let mut e = entry("a");
        e.formats = vec!["pe".into(), "exe".into()];
        let p = problems(vec![e]);
        assert_eq!(p.len(), 1);
        assert!(has(&p, "unknown format label \"exe\""));
        for f in KNOWN_FORMATS {
            let mut ok = entry("b");
            ok.formats = vec![f.to_string()];
            assert!(problems(vec![ok]).is_empty(), "{f}");
        }
    }

    #[test]
    fn sig_refs_must_exist() {
        let mut e = entry("a");
        e.corroboration = vec!["sig:b".into(), "sig:missing".into(), "sig:a".into()];
        let p = problems(vec![e, entry("b")]);
        assert!(has(&p, "unknown id \"missing\""));
        assert!(has(&p, "references itself"));
        assert!(!has(&p, "\"b\""));
    }

    #[test]
    fn strong_needs_sig_corroboration() {
        let mut e = entry("a");
        e.confidence = Confidence::Strong;
        e.corroboration = vec!["free text is documentation, not proof".into()];
        assert!(has(
            &problems(vec![e.clone(), entry("b")]),
            "Strong confidence"
        ));
        e.corroboration.push("sig:b".into());
        assert!(problems(vec![e, entry("b")]).is_empty());
    }

    #[test]
    fn needles_have_a_minimum_length() {
        let mut short_text = entry("a");
        short_text.detect = Detect::Text {
            needle: "UPX".into(),
            window: Window::Header,
        };
        let mut short_hex = entry("b");
        short_hex.detect = Detect::Bytes {
            hex: "ffd8ff".into(),
            window: Window::Header,
        };
        let mut bad_hex = entry("c");
        bad_hex.detect = Detect::Bytes {
            hex: "zz00aa11".into(),
            window: Window::Header,
        };
        let mut empty = entry("d");
        empty.detect = Detect::Text {
            needle: String::new(),
            window: Window::Header,
        };
        let p = problems(vec![short_text, short_hex, bad_hex, empty]);
        assert!(has(&p, "a: needle shorter than 4"));
        assert!(has(&p, "b: pattern shorter than 4"));
        assert!(has(&p, "c: malformed hex"));
        assert!(has(&p, "d: empty needle"));
    }

    #[test]
    fn byte_edits_need_formats() {
        for removal in [RemovalSpec::RawBlank, RemovalSpec::Truncate] {
            let mut e = entry("a");
            e.formats.clear();
            e.removal = removal;
            assert!(has(&problems(vec![e.clone()]), "needs a format list"));
            e.formats = vec!["pdf".into()];
            assert!(problems(vec![e]).is_empty());
        }
        let mut info_only = entry("a");
        info_only.formats.clear();
        assert!(problems(vec![info_only]).is_empty());
    }

    #[test]
    fn structural_and_stray_fill_are_rejected() {
        let mut s = entry("a");
        s.removal = RemovalSpec::Structural;
        assert!(has(&problems(vec![s]), "Structural removal"));
        let mut f = entry("b");
        f.fill = Some(0x20);
        assert!(has(&problems(vec![f.clone()]), "fill only applies"));
        f.removal = RemovalSpec::RawBlank;
        assert!(problems(vec![f]).is_empty());
    }

    #[test]
    fn patterns_decode() {
        let b = Detect::Bytes {
            hex: "4D5a9000".into(),
            window: Window::Tail,
        };
        assert_eq!(b.pattern(), Some(vec![0x4d, 0x5a, 0x90, 0x00]));
        assert_eq!(b.window(), Window::Tail);
        let t = Detect::Text {
            needle: "Lavf".into(),
            window: Window::Whole,
        };
        assert_eq!(t.pattern(), Some(b"Lavf".to_vec()));
        let bad = Detect::Bytes {
            hex: "abc".into(),
            window: Window::Header,
        };
        assert_eq!(bad.pattern(), None);
    }

    #[test]
    fn markers_follow_the_match() {
        let mut e = entry("a");
        assert_eq!(marker_for(&e, Region::new(10, 4)), None);
        e.removal = RemovalSpec::RawBlank;
        let m = marker_for(&e, Region::new(10, 4)).unwrap();
        assert_eq!(m.removal, RemovalStrategy::RawBlank { fill: 0 });
        assert_eq!(m.region, Region::new(10, 4));
        assert_eq!(m.container, ContainerKind::Raw);
        e.fill = Some(0x20);
        let m = marker_for(&e, Region::new(10, 4)).unwrap();
        assert_eq!(m.removal, RemovalStrategy::RawBlank { fill: 0x20 });
        assert_eq!(marker_for(&e, Region::new(0, 4)), None);
        e.removal = RemovalSpec::Truncate;
        e.fill = None;
        let m = marker_for(&e, Region::new(77, 4)).unwrap();
        assert_eq!(m.removal, RemovalStrategy::Truncate { from: 77 });
        assert_eq!(m.region.offset, 77);
    }

    #[test]
    fn removal_for_never_truncates_from_zero() {
        let (s, _) = removal_for(RemovalSpec::Truncate).unwrap();
        assert_ne!(s, RemovalStrategy::Truncate { from: 0 });
        assert!(removal_for(RemovalSpec::None).is_none());
    }

    #[test]
    fn every_kind_maps() {
        use CatKind::*;
        let kinds = [
            JunkExif,
            JunkXmp,
            JunkId3,
            JunkComment,
            JunkTextChunk,
            JunkIptc,
            JunkDocInfo,
            TamperAppendedData,
            DeceptionDoubleExt,
            DeceptionRtlo,
            DeceptionOverlayBloat,
            DeceptionHiddenExt,
            IntegrityPresent,
            IntegrityAbsent,
        ];
        let slugs: Vec<&str> = kinds.iter().map(|k| k.to_category().slug()).collect();
        assert_eq!(
            slugs,
            [
                "junk",
                "junk",
                "junk",
                "junk",
                "junk",
                "junk",
                "junk",
                "tamper",
                "deception",
                "deception",
                "deception",
                "deception",
                "integrity",
                "integrity"
            ]
        );
        assert_eq!(
            IntegrityAbsent.to_category(),
            Category::Integrity(SignatureStatus::Absent)
        );
    }

    #[test]
    fn ron_accepts_old_and_new_shapes() {
        let src = r#"(signatures: [
            (id: "old", kind: BrandPacker, confidence: moderate, severity: info,
             formats: ["pe"], title: "t", detect: Text(needle: "ABCD", window: Whole),
             source: "https://example.org/", removal: None),
            (id: "new", kind: JunkDocInfo, confidence: moderate, severity: notice,
             formats: ["pdf"], title: "t", detect: Bytes(hex: "41424344", window: Tail),
             source: "https://example.org/", removal: RawBlank, fill: Some(32)),
        ])"#;
        let cat: Catalog = ron::from_str(src).unwrap();
        assert_eq!(cat.signatures[0].fill, None);
        assert_eq!(cat.signatures[1].fill, Some(0x20));
        assert!(validate(&cat).is_empty());
    }
}
