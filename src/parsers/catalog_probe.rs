//! The catalog probe: sweeps the header and tail windows of every file for the
//! byte and text patterns in `catalog.ron` with one aho-corasick automaton,
//! and turns each entry's first match into a finding.
//!
//! Rules:
//! - `Header` entries match only inside the header window, `Tail` entries only
//!   inside the tail window, `Whole` entries in either. When the two windows
//!   touch or overlap (a small file), they are scanned once as one buffer, so
//!   nothing is counted twice. A pattern never matches across the gap between
//!   the windows of a large file.
//! - An entry with a `formats` list only applies to files of those formats.
//! - At most one finding per entry per file, at the first absolute offset.
//! - A `Strong` entry keeps Strong only when every `sig:` entry it names also
//!   matched in the same file; otherwise it drops to Moderate and says why.
//! - A marker whose region would start at offset 0 is dropped.

use std::sync::OnceLock;

use aho_corasick::{AhoCorasick, MatchKind};

use crate::catalog::{Catalog, Signature, Window, catalog, marker_for};
use crate::model::{Category, Confidence, Evidence, Finding, Region, TamperKind};
use crate::scan::{FileView, Probe, ProbeCtx};

/// Probes contributed by this module.
pub fn probes() -> Vec<Box<dyn Probe>> {
    vec![Box::new(CatalogProbe)]
}

struct CatalogProbe;

impl Probe for CatalogProbe {
    fn id(&self) -> &'static str {
        "catalog"
    }

    fn formats(&self) -> &'static [&'static str] {
        &[]
    }

    fn run(&self, ctx: &ProbeCtx, out: &mut Vec<Finding>) {
        let Some(matcher) = embedded_matcher() else {
            return;
        };
        out.extend(scan(catalog(), matcher, ctx.view, ctx.format));
    }
}

/// Most matched bytes kept as evidence.
const EVIDENCE_BYTES: usize = 32;

/// One automaton over every entry's pattern, plus the map from pattern index
/// back to the entry it came from.
struct Matcher {
    ac: AhoCorasick,
    entry_of: Vec<usize>,
}

impl Matcher {
    fn build(cat: &Catalog) -> Option<Self> {
        let mut patterns = Vec::new();
        let mut entry_of = Vec::new();
        for (i, sig) in cat.signatures.iter().enumerate() {
            if let Some(p) = sig.detect.pattern() {
                patterns.push(p);
                entry_of.push(i);
            }
        }
        let ac = AhoCorasick::builder()
            .match_kind(MatchKind::Standard)
            .build(&patterns)
            .ok()?;
        Some(Self { ac, entry_of })
    }
}

fn embedded_matcher() -> Option<&'static Matcher> {
    static MATCHER: OnceLock<Option<Matcher>> = OnceLock::new();
    MATCHER.get_or_init(|| Matcher::build(catalog())).as_ref()
}

/// The first accepted match of one entry.
#[derive(Debug, Clone)]
struct Hit {
    offset: u64,
    bytes: Vec<u8>,
    len: u64,
}

/// A contiguous stretch of the file and which windows it belongs to.
struct Span<'a> {
    data: &'a [u8],
    start: u64,
    header_end: u64,
    tail_start: u64,
}

impl Span<'_> {
    /// Whether `[off, off + len)` lies wholly in the header / tail window.
    fn windows(&self, off: u64, len: u64) -> (bool, bool) {
        let end = off.saturating_add(len);
        (end <= self.header_end, off >= self.tail_start)
    }
}

/// Every selected catalog occurrence in the existing scan windows. Audit scans
/// still report only the first occurrence of each signature.
pub(crate) struct CreditHit {
    pub index: usize,
    pub offset: u64,
    pub len: u64,
    pub available: usize,
}

pub(crate) fn deattribute_hits(view: &dyn FileView, format: Option<&str>) -> Vec<CreditHit> {
    let Some(matcher) = embedded_matcher() else {
        return Vec::new();
    };
    let cat = catalog();
    let header = view.header();
    let tail = view.tail();
    let header_end = header.len() as u64;
    let tail_start = view.tail_start();
    let joined;
    let spans: Vec<Span> = if tail_start <= header_end {
        let skip = usize::try_from(header_end - tail_start).unwrap_or(usize::MAX);
        let rest = tail.get(skip..).unwrap_or_default();
        let data: &[u8] = if rest.is_empty() {
            header
        } else {
            joined = [header, rest].concat();
            &joined
        };
        vec![Span {
            data,
            start: 0,
            header_end,
            tail_start,
        }]
    } else {
        vec![
            Span {
                data: header,
                start: 0,
                header_end,
                tail_start,
            },
            Span {
                data: tail,
                start: tail_start,
                header_end,
                tail_start,
            },
        ]
    };
    let mut out = Vec::new();
    for span in &spans {
        for mat in matcher.ac.find_overlapping_iter(span.data) {
            let Some(&index) = matcher.entry_of.get(mat.pattern().as_usize()) else {
                continue;
            };
            let Some(sig) = cat.signatures.get(index) else {
                continue;
            };
            let category = sig.kind.to_category();
            if !matches!(category, Category::Brand(_))
                && !(category == Category::Tamper(TamperKind::Patched)
                    && sig.id == "tamper.patched_by")
            {
                continue;
            }
            if !format_ok(sig, format) {
                continue;
            }
            let offset = span.start + mat.start() as u64;
            let len = mat.len() as u64;
            let (in_header, in_tail) = span.windows(offset, len);
            if !match sig.detect.window() {
                Window::Header => in_header,
                Window::Tail => in_tail,
                Window::Whole => true,
            } {
                continue;
            }
            out.push(CreditHit {
                index,
                offset,
                len,
                available: span.data.len() - mat.start(),
            });
        }
    }
    out
}

fn scan(cat: &Catalog, m: &Matcher, view: &dyn FileView, format: Option<&str>) -> Vec<Finding> {
    let header = view.header();
    let tail = view.tail();
    let header_end = header.len() as u64;
    let tail_start = view.tail_start();
    let mut hits: Vec<Option<Hit>> = vec![None; cat.signatures.len()];

    let joined;
    let spans: Vec<Span> = if tail_start <= header_end {
        // Windows touch or overlap: one contiguous buffer, scanned once.
        let skip = usize::try_from(header_end - tail_start).unwrap_or(usize::MAX);
        let rest = tail.get(skip..).unwrap_or_default();
        let data: &[u8] = if rest.is_empty() {
            header
        } else {
            joined = [header, rest].concat();
            &joined
        };
        vec![Span {
            data,
            start: 0,
            header_end,
            tail_start,
        }]
    } else {
        vec![
            Span {
                data: header,
                start: 0,
                header_end,
                tail_start,
            },
            Span {
                data: tail,
                start: tail_start,
                header_end,
                tail_start,
            },
        ]
    };

    for span in &spans {
        for mat in m.ac.find_overlapping_iter(span.data) {
            let Some(&idx) = m.entry_of.get(mat.pattern().as_usize()) else {
                continue;
            };
            let Some(sig) = cat.signatures.get(idx) else {
                continue;
            };
            if !format_ok(sig, format) {
                continue;
            }
            let off = span.start + mat.start() as u64;
            let len = mat.len() as u64;
            let (in_header, in_tail) = span.windows(off, len);
            let allowed = match sig.detect.window() {
                Window::Header => in_header,
                Window::Tail => in_tail,
                Window::Whole => true,
            };
            if !allowed {
                continue;
            }
            let slot = &mut hits[idx];
            if slot.as_ref().is_none_or(|h| off < h.offset) {
                let end = mat.end().min(mat.start() + EVIDENCE_BYTES);
                *slot = Some(Hit {
                    offset: off,
                    bytes: span.data.get(mat.start()..end).unwrap_or_default().to_vec(),
                    len,
                });
            }
        }
    }

    let mut out: Vec<(u64, usize, Finding)> = Vec::new();
    for (idx, hit) in hits.iter().enumerate() {
        let (Some(hit), Some(sig)) = (hit, cat.signatures.get(idx)) else {
            continue;
        };
        out.push((hit.offset, idx, finding(cat, sig, hit, &hits)));
    }
    out.sort_by_key(|(off, idx, _)| (*off, *idx));
    out.into_iter().map(|(_, _, f)| f).collect()
}

fn format_ok(sig: &Signature, format: Option<&str>) -> bool {
    sig.formats.is_empty() || format.is_some_and(|f| sig.formats.iter().any(|x| x == f))
}

fn finding(cat: &Catalog, sig: &Signature, hit: &Hit, hits: &[Option<Hit>]) -> Finding {
    let mut confidence = sig.confidence;
    let mut why = None;
    if confidence == Confidence::Strong {
        let missing: Vec<&str> = sig
            .sig_refs()
            .filter(|r| {
                !cat.signatures
                    .iter()
                    .position(|s| s.id == *r)
                    .is_some_and(|i| hits.get(i).is_some_and(Option::is_some))
            })
            .collect();
        let has_refs = sig.sig_refs().next().is_some();
        if !has_refs {
            confidence = Confidence::Moderate;
            why = Some("downgraded to moderate: no corroborating entry is declared".to_string());
        } else if !missing.is_empty() {
            confidence = Confidence::Moderate;
            why = Some(format!(
                "downgraded to moderate: corroborating {} not found in this file",
                missing.join(", ")
            ));
        }
    }

    let mut note = vec![format!(
        "matched \"{}\"",
        String::from_utf8_lossy(&hit.bytes).escape_debug()
    )];
    if let Some(fp) = &sig.false_positives {
        note.push(format!("false positives: {fp}"));
    }
    if let Some(why) = why {
        note.push(why);
    }

    let mut evidence = Evidence::at(hit.offset)
        .with_bytes(hit.bytes.clone())
        .with_note(note.join("; "));
    evidence.catalog_ref = Some(sig.id.clone());

    Finding {
        category: sig.kind.to_category(),
        confidence,
        severity: sig.severity,
        signature_id: format!("catalog.{}", sig.id),
        title: sig.title.clone(),
        evidence,
        marker: marker_for(sig, Region::new(hit.offset, hit.len)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{CatKind, Detect, RemovalSpec};
    use crate::model::{RemovalStrategy, Severity};
    use crate::scan::MemView;
    use crate::scan::reader::{HEADER_WINDOW, TAIL_WINDOW};

    fn sig(id: &str, needle: &str, window: Window, formats: &[&str]) -> Signature {
        Signature {
            id: id.to_string(),
            kind: CatKind::BrandPacker,
            confidence: Confidence::Moderate,
            severity: Severity::Info,
            formats: formats.iter().map(|s| s.to_string()).collect(),
            title: format!("{id} title"),
            detect: Detect::Text {
                needle: needle.to_string(),
                window,
            },
            corroboration: Vec::new(),
            source: "https://example.org/".to_string(),
            false_positives: None,
            removal: RemovalSpec::None,
            fill: None,
        }
    }

    fn run_cat(cat: &Catalog, data: Vec<u8>, format: Option<&str>) -> Vec<Finding> {
        let m = Matcher::build(cat).unwrap();
        scan(cat, &m, &MemView::new("f.bin", data), format)
    }

    fn put(buf: &mut [u8], off: usize, s: &[u8]) {
        buf[off..off + s.len()].copy_from_slice(s);
    }

    /// A file large enough that the windows leave a gap between them.
    const BIG: usize = HEADER_WINDOW + TAIL_WINDOW + 4096;

    #[test]
    fn header_window_only_sees_the_header() {
        let cat = Catalog {
            signatures: vec![sig("h", "HEADNEEDLE", Window::Header, &[])],
        };
        let mut data = vec![0u8; BIG];
        put(&mut data, 100, b"HEADNEEDLE");
        let f = run_cat(&cat, data.clone(), None);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].evidence.offset, 100);
        assert_eq!(f[0].signature_id, "catalog.h");
        assert_eq!(f[0].evidence.catalog_ref.as_deref(), Some("h"));
        assert_eq!(f[0].evidence.matched, b"HEADNEEDLE");

        let mut data = vec![0u8; BIG];
        put(&mut data, BIG - 200, b"HEADNEEDLE");
        assert!(run_cat(&cat, data, None).is_empty());
    }

    #[test]
    fn tail_window_offsets_are_absolute() {
        let cat = Catalog {
            signatures: vec![sig("t", "TAILNEEDLE", Window::Tail, &[])],
        };
        let mut data = vec![0u8; BIG];
        put(&mut data, BIG - 200, b"TAILNEEDLE");
        put(&mut data, 50, b"TAILNEEDLE");
        let f = run_cat(&cat, data, None);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].evidence.offset, (BIG - 200) as u64);
    }

    #[test]
    fn whole_takes_the_first_offset_in_either_window() {
        let cat = Catalog {
            signatures: vec![sig("w", "BOTHNEEDLE", Window::Whole, &[])],
        };
        let mut data = vec![0u8; BIG];
        put(&mut data, BIG - 200, b"BOTHNEEDLE");
        put(&mut data, 5000, b"BOTHNEEDLE");
        put(&mut data, 9000, b"BOTHNEEDLE");
        let f = run_cat(&cat, data, None);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].evidence.offset, 5000);

        let mut data = vec![0u8; BIG];
        put(&mut data, BIG - 300, b"BOTHNEEDLE");
        let f = run_cat(&cat, data, None);
        assert_eq!(f[0].evidence.offset, (BIG - 300) as u64);
    }

    #[test]
    fn no_hit_across_the_gap() {
        let cat = Catalog {
            signatures: vec![sig("g", "GAPNEEDLE", Window::Whole, &[])],
        };
        let mut data = vec![0u8; BIG];
        // "GAP" ends the header window and "NEEDLE" starts the tail window;
        // the bytes between them are not read, so this must not match.
        put(&mut data, HEADER_WINDOW - 3, b"GAP");
        put(&mut data, BIG - TAIL_WINDOW, b"NEEDLE");
        assert!(run_cat(&cat, data.clone(), None).is_empty());
        // Nor does a match that lives entirely inside the gap.
        put(&mut data, HEADER_WINDOW + 100, b"GAPNEEDLE");
        assert!(run_cat(&cat, data, None).is_empty());
    }

    #[test]
    fn small_file_overlap_is_scanned_once() {
        let size = HEADER_WINDOW + 30_000;
        let tail_start = size - TAIL_WINDOW;
        let cat = Catalog {
            signatures: vec![
                sig("h", "HEADNEEDLE", Window::Header, &[]),
                sig("t", "TAILNEEDLE", Window::Tail, &[]),
                sig("w", "STRADDLER", Window::Whole, &[]),
                sig("hs", "STRADDLER2", Window::Header, &[]),
            ],
        };
        let mut data = vec![0u8; size];
        // In both windows: one finding each, same offset.
        put(&mut data, tail_start + 10, b"HEADNEEDLE");
        put(&mut data, tail_start + 10 + 20, b"TAILNEEDLE");
        // Past the header window, so the Header entry must not see it.
        put(&mut data, HEADER_WINDOW + 500, b"HEADNEEDLE");
        // Straddling the header end: real contiguous bytes in a small file.
        put(&mut data, HEADER_WINDOW - 4, b"STRADDLER2");
        let f = run_cat(&cat, data, None);
        let got: Vec<(String, u64)> = f
            .iter()
            .map(|f| (f.signature_id.clone(), f.evidence.offset))
            .collect();
        assert_eq!(
            got,
            vec![
                ("catalog.h".to_string(), (tail_start + 10) as u64),
                ("catalog.t".to_string(), (tail_start + 30) as u64),
                ("catalog.w".to_string(), (HEADER_WINDOW - 4) as u64),
            ]
        );
    }

    #[test]
    fn tiny_file_with_full_overlap() {
        let cat = Catalog {
            signatures: vec![
                sig("h", "NEEDLE", Window::Header, &[]),
                sig("t", "NEEDLE", Window::Tail, &[]),
            ],
        };
        let mut data = b"xxxxNEEDLExxxxNEEDLE".to_vec();
        data.extend_from_slice(b"..");
        let f = run_cat(&cat, data, None);
        assert_eq!(f.len(), 2);
        assert!(f.iter().all(|f| f.evidence.offset == 4));
    }

    #[test]
    fn formats_gate_entries() {
        let cat = Catalog {
            signatures: vec![
                sig("pe_only", "GATEDNEEDLE", Window::Whole, &["pe", "elf"]),
                sig("any", "OPENNEEDLE", Window::Whole, &[]),
            ],
        };
        let data = b"..GATEDNEEDLE..OPENNEEDLE..".to_vec();
        let ids = |fmt| -> Vec<String> {
            run_cat(&cat, data.clone(), fmt)
                .into_iter()
                .map(|f| f.signature_id)
                .collect()
        };
        assert_eq!(ids(Some("pe")), ["catalog.pe_only", "catalog.any"]);
        assert_eq!(ids(Some("elf")), ["catalog.pe_only", "catalog.any"]);
        assert_eq!(ids(Some("png")), ["catalog.any"]);
        assert_eq!(ids(None), ["catalog.any"]);
    }

    fn corroborated_catalog() -> Catalog {
        let mut strong = sig("main", "MAINNEEDLE", Window::Whole, &["pe"]);
        strong.confidence = Confidence::Strong;
        strong.corroboration = vec!["sig:first".into(), "sig:second".into(), "free text".into()];
        strong.false_positives = Some("rare".into());
        let mut second = sig("second", "SECONDNEEDLE", Window::Header, &["pe"]);
        second.confidence = Confidence::Weak;
        Catalog {
            signatures: vec![
                strong,
                sig("first", "FIRSTNEEDLE", Window::Whole, &[]),
                second,
            ],
        }
    }

    #[test]
    fn corroboration_keeps_strong() {
        let cat = corroborated_catalog();
        let data = b"MAINNEEDLE FIRSTNEEDLE SECONDNEEDLE".to_vec();
        let f = run_cat(&cat, data, Some("pe"));
        let main = f.iter().find(|f| f.signature_id == "catalog.main").unwrap();
        assert_eq!(main.confidence, Confidence::Strong);
        let note = main.evidence.note.as_deref().unwrap();
        assert!(note.contains("false positives: rare"));
        assert!(!note.contains("downgraded"));
    }

    #[test]
    fn missing_corroboration_downgrades() {
        let cat = corroborated_catalog();
        let f = run_cat(&cat, b"MAINNEEDLE FIRSTNEEDLE".to_vec(), Some("pe"));
        let main = f.iter().find(|f| f.signature_id == "catalog.main").unwrap();
        assert_eq!(main.confidence, Confidence::Moderate);
        let note = main.evidence.note.as_deref().unwrap();
        assert!(note.contains("downgraded to moderate"));
        assert!(note.contains("second"));
        assert!(note.contains("false positives: rare"));
    }

    #[test]
    fn corroboration_must_itself_pass_its_gates() {
        let mut cat = corroborated_catalog();
        cat.signatures[1].formats = vec!["elf".into()];
        let data = b"MAINNEEDLE FIRSTNEEDLE SECONDNEEDLE".to_vec();
        let f = run_cat(&cat, data, Some("pe"));
        let main = f.iter().find(|f| f.signature_id == "catalog.main").unwrap();
        assert_eq!(main.confidence, Confidence::Moderate);
    }

    #[test]
    fn markers_follow_the_spec_and_skip_offset_zero() {
        let mut blank = sig("blank", "PRODUCERNAME", Window::Whole, &["pdf"]);
        blank.removal = RemovalSpec::RawBlank;
        blank.fill = Some(0x20);
        let mut cut = sig("cut", "TRAILERMARK", Window::Tail, &["pdf"]);
        cut.removal = RemovalSpec::Truncate;
        let cat = Catalog {
            signatures: vec![blank, cut],
        };
        let mut data = b"%PDF-1.4\n(PRODUCERNAME)\n".to_vec();
        data.extend_from_slice(b"TRAILERMARK junk");
        let f = run_cat(&cat, data.clone(), Some("pdf"));
        assert_eq!(f.len(), 2);
        let m = f[0].marker.as_ref().unwrap();
        assert_eq!(m.region, Region::new(10, 12));
        assert_eq!(m.removal, RemovalStrategy::RawBlank { fill: 0x20 });
        let t = f[1].marker.as_ref().unwrap();
        assert_eq!(t.removal, RemovalStrategy::Truncate { from: 24 });

        // Apply the blank: the finding is gone and the file is still a PDF.
        let mut cleaned = data.clone();
        for b in &mut cleaned[10..22] {
            *b = 0x20;
        }
        let after = run_cat(&cat, cleaned.clone(), Some("pdf"));
        assert!(after.iter().all(|f| f.signature_id != "catalog.blank"));
        let (fmt, _) = crate::parsers::identity::identify(&MemView::new("a.pdf", cleaned));
        assert_eq!(fmt, Some("pdf"));

        // Apply the truncate: the trailer finding is gone too.
        let mut cut = data.clone();
        cut.truncate(24);
        let after = run_cat(&cat, cut.clone(), Some("pdf"));
        assert!(after.iter().all(|f| f.signature_id != "catalog.cut"));
        assert_eq!(
            crate::parsers::identity::identify(&MemView::new("a.pdf", cut)).0,
            Some("pdf")
        );

        // A match at offset 0 keeps the finding but drops the marker.
        let f = run_cat(&cat, b"PRODUCERNAME rest".to_vec(), Some("pdf"));
        assert_eq!(f.len(), 1);
        assert!(f[0].marker.is_none());
    }

    #[test]
    fn one_finding_per_entry_and_bounded_evidence() {
        let long = "L".repeat(80);
        let cat = Catalog {
            signatures: vec![sig("long", &long, Window::Whole, &[])],
        };
        let mut data = vec![b'.'; 1000];
        put(&mut data, 10, long.as_bytes());
        put(&mut data, 300, long.as_bytes());
        let f = run_cat(&cat, data, None);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].evidence.matched.len(), EVIDENCE_BYTES);
        let m = f[0].marker.as_ref();
        assert!(m.is_none());
    }

    #[test]
    fn hex_patterns_match_bytes() {
        let mut s = sig("bytes", "", Window::Header, &[]);
        s.detect = Detect::Bytes {
            hex: "deadbeef00".into(),
            window: Window::Header,
        };
        let cat = Catalog {
            signatures: vec![s],
        };
        let f = run_cat(&cat, vec![1, 2, 0xde, 0xad, 0xbe, 0xef, 0x00, 9], None);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].evidence.offset, 2);
    }

    #[test]
    fn garbage_and_empty_inputs() {
        let cat = corroborated_catalog();
        for data in [
            Vec::new(),
            vec![0u8; 3],
            vec![0xffu8; 100_000],
            b"MAINNEEDL".to_vec(),
        ] {
            assert!(run_cat(&cat, data, Some("pe")).is_empty());
        }
    }

    #[test]
    fn embedded_catalog_runs() {
        let probe = CatalogProbe;
        let mut header = vec![0u8; 0x400];
        put(&mut header, 0, b"MZ");
        put(&mut header, 0x178, b"UPX0\0\0\0\0");
        put(&mut header, 0x1a0, b"UPX1\0\0\0\0");
        put(&mut header, 0x3e0, b"3.96\0UPX!");
        let view = MemView::new("a.exe", header.clone());
        let mut out = Vec::new();
        probe.run(&ProbeCtx::new(&view, Some("pe")), &mut out);
        let upx = out
            .iter()
            .find(|f| f.signature_id == "catalog.packer.upx")
            .unwrap();
        assert_eq!(upx.confidence, Confidence::Strong);
        assert_eq!(upx.evidence.offset, 0x3e5);

        put(&mut header, 0x178, b"text\0\0\0\0");
        let view = MemView::new("a.exe", header);
        let mut out = Vec::new();
        probe.run(&ProbeCtx::new(&view, Some("pe")), &mut out);
        let upx = out
            .iter()
            .find(|f| f.signature_id == "catalog.packer.upx")
            .unwrap();
        assert_eq!(upx.confidence, Confidence::Moderate);

        let mut out = Vec::new();
        let view = MemView::new("a.png", b"\x89PNG\r\n\x1a\nUPX!UPX0UPX1".to_vec());
        probe.run(&ProbeCtx::new(&view, Some("png")), &mut out);
        assert!(
            out.iter()
                .all(|f| !f.signature_id.starts_with("catalog.packer."))
        );
    }
}
