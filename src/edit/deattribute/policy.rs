//! Explicit identity rules supplement inference without product-specific code.

use std::collections::BTreeSet;
use std::io;

use serde::{Deserialize, Serialize};

use crate::edit::precision::pattern::{
    Boundary, Encoding, Limits, Matcher, Pattern, Span, invalid,
};
use crate::scan::FileView;

use super::audit::{Allowance, Audit};
use super::deep::Rewrite;
use super::{Kind, layout::Layout};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Publisher,
    Product,
    Toolchain,
    ThirdParty,
    Credits,
    BuildPaths,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub id: String,
    pub scope: Scope,
    pub names: Vec<String>,
    #[serde(default = "encodings")]
    pub encodings: Vec<Encoding>,
    #[serde(default = "identifier")]
    pub boundary: Boundary,
    #[serde(default = "yes")]
    pub ignore_ascii_case: bool,
    /// No replacement means spaces in the original encoding.
    #[serde(default)]
    pub replacement: Option<String>,
    /// Replacement must fit. Shorter strings need explicit padding.
    #[serde(default)]
    pub pad: Option<char>,
    #[serde(default)]
    pub files: Vec<String>,
    #[serde(default)]
    pub regions: Vec<String>,
    #[serde(default)]
    pub expected_matches: Option<usize>,
}

fn encodings() -> Vec<Encoding> {
    vec![
        Encoding::Utf8,
        Encoding::Utf16le,
        Encoding::Utf16be,
        Encoding::Windows1252,
    ]
}
fn identifier() -> Boundary {
    Boundary::Identifier
}
fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rules {
    pub version: u32,
    #[serde(default)]
    pub identities: Vec<Identity>,
    /// Protected spans selected by exact encoded patterns, with all occurrences retained.
    #[serde(default)]
    pub exclusions: Vec<Pattern>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationPolicy {
    #[default]
    Strict,
    Protected,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Options {
    pub limits: Limits,
    pub rules: Option<Rules>,
    pub verification: VerificationPolicy,
}

/// Simple case-sensitive `*`/`?` globs over the normalized logical path.
/// No regex, shell expansion, or platform-dependent path interpretation.
pub fn glob(pattern: &str, value: &str) -> bool {
    let p: Vec<_> = pattern.chars().collect();
    let v: Vec<_> = value.chars().collect();
    let (mut i, mut j, mut star, mut retry) = (0, 0, None, 0);
    while j < v.len() {
        if i < p.len() && (p[i] == '?' || p[i] == v[j]) {
            i += 1;
            j += 1;
        } else if i < p.len() && p[i] == '*' {
            star = Some(i);
            i += 1;
            retry = j;
        } else if let Some(s) = star {
            retry += 1;
            j = retry;
            i = s + 1;
        } else {
            return false;
        }
    }
    while i < p.len() && p[i] == '*' {
        i += 1;
    }
    i == p.len()
}

pub struct PlannedRules {
    pub rewrites: Vec<Rewrite>,
    pub audit: Audit,
    pub matches: usize,
}

impl Rules {
    pub fn validate(&self) -> io::Result<()> {
        if self.version != 1 {
            return Err(invalid("unsupported rules version"));
        }
        if self.identities.len() > 1000 || self.exclusions.len() > 1000 {
            return Err(invalid("too many rules"));
        }
        let mut ids = BTreeSet::new();
        for rule in &self.identities {
            if rule.id.is_empty() || !ids.insert(&rule.id) {
                return Err(invalid("rule ids must be nonempty and unique"));
            }
            if rule.names.is_empty() || rule.encodings.is_empty() {
                return Err(invalid("each rule needs names and encodings"));
            }
            if rule
                .files
                .iter()
                .chain(&rule.regions)
                .any(|g| g.len() > 4096)
            {
                return Err(invalid("selector is too long"));
            }
            if rule.names.iter().any(|s| s.is_empty() || s.len() > 65536) {
                return Err(invalid("identity length must be 1..65536 bytes"));
            }
        }
        Ok(())
    }

    pub fn plan(
        &self,
        view: &dyn FileView,
        mut layout: Layout,
        limits: &Limits,
    ) -> io::Result<PlannedRules> {
        self.validate()?;
        let range = Span {
            offset: 0,
            len: view.size(),
        };
        let excluded = Matcher::new(&self.exclusions)?.search(view, range.clone(), limits)?;
        if !excluded.complete {
            return Err(invalid("exclusion scan incomplete; no edits planned"));
        }
        layout
            .excluded
            .extend(excluded.matches.iter().map(|m| Span {
                offset: m.offset,
                len: m.len,
            }));
        let path = view.path().to_string_lossy().replace('\\', "/");
        let mut audit = Audit {
            layout,
            limits: limits.clone(),
            complete: true,
            ..Audit::default()
        };
        let mut rewrites = Vec::new();
        let mut matches = 0;
        let mut owners = Vec::new();
        let mut patterns = Vec::new();
        for rule in &self.identities {
            if !rule.files.is_empty() && !rule.files.iter().any(|g| glob(g, &path)) {
                continue;
            }
            let before = patterns.len();
            let mut encoded = BTreeSet::new();
            for name in &rule.names {
                for &encoding in &rule.encodings {
                    let Ok(bytes) = encoding.encode(name) else {
                        continue;
                    };
                    if !encoded.insert(bytes) {
                        continue;
                    }
                    patterns.push(Pattern::Text {
                        value: name.clone(),
                        encoding,
                        boundary: rule.boundary,
                        ignore_ascii_case: rule.ignore_ascii_case,
                    });
                    owners.push(rule);
                }
            }
            if patterns.len() == before {
                return Err(invalid(format!("rule {} cannot encode any name", rule.id)));
            }
        }
        let found = Matcher::new(&patterns)?.search(view, range, limits)?;
        if !found.complete {
            return Err(invalid("identity rules exceeded the scan budget"));
        }
        for rule in &self.identities {
            if !rule.files.is_empty() && !rule.files.iter().any(|g| glob(g, &path)) {
                continue;
            }
            let hits: Vec<_> = found
                .matches
                .iter()
                .filter(|m| std::ptr::eq(owners[m.pattern], rule))
                .collect();
            let selected: Vec<_> = found
                .matches
                .iter()
                .filter(|m| std::ptr::eq(owners[m.pattern], rule))
                .filter(|m| {
                    rule.regions.is_empty()
                        || rule
                            .regions
                            .iter()
                            .any(|g| glob(g, audit.layout.category(m.offset)))
                })
                .collect();
            let unique: BTreeSet<_> = selected.iter().map(|m| (m.offset, m.len)).collect();
            if rule.expected_matches.is_some_and(|n| n != unique.len()) {
                return Err(invalid(format!(
                    "rule {} expected {} matches, found {}",
                    rule.id,
                    rule.expected_matches.unwrap_or(0),
                    unique.len()
                )));
            }
            matches += unique.len();
            for hit in selected {
                let span = Span {
                    offset: hit.offset,
                    len: hit.len,
                };
                if audit.layout.retention(&span).is_some() {
                    continue;
                }
                let encoding = hit.encoding.unwrap_or_default();
                let bytes = if let Some(text) = &rule.replacement {
                    let mut bytes = encoding.encode(text)?;
                    if bytes.len() > hit.len as usize {
                        return Err(invalid(format!("rule {} replacement is too long", rule.id)));
                    }
                    if bytes.len() < hit.len as usize {
                        let pad = rule.pad.ok_or_else(|| {
                            invalid(format!("rule {} needs explicit padding", rule.id))
                        })?;
                        let padding = encoding.encode(&pad.to_string())?;
                        if !(hit.len as usize - bytes.len()).is_multiple_of(padding.len()) {
                            return Err(invalid("padding does not fit the encoded field"));
                        }
                        while bytes.len() < hit.len as usize {
                            bytes.extend_from_slice(&padding);
                        }
                    }
                    bytes
                } else {
                    encoding.spaces(hit.len as usize)
                };
                rewrites.push((
                    if rule.scope == Scope::Credits {
                        Kind::Patch
                    } else {
                        Kind::Brand
                    },
                    hit.offset,
                    bytes,
                ));
            }
            // Region selectors also apply to verification, as documented retained spans.
            if !rule.regions.is_empty() {
                for hit in &hits {
                    if !rule
                        .regions
                        .iter()
                        .any(|g| glob(g, audit.layout.category(hit.offset)))
                    {
                        audit.allowed.push(Allowance {
                            pattern: hit.pattern,
                            span: Span {
                                offset: hit.offset,
                                len: hit.len,
                            },
                        });
                    }
                }
            }
        }
        audit.patterns = patterns;
        // Conflicting explicit replacements are refused rather than ordered silently.
        rewrites.sort_by_key(|(_, off, bytes)| (*off, bytes.len()));
        rewrites.dedup();
        let mut active: Option<&Rewrite> = None;
        for current in &rewrites {
            let Some(previous) = active else {
                active = Some(current);
                continue;
            };
            let pair = [previous, current];
            let (_, off, bytes) = &pair[0];
            let (_, next, value) = &pair[1];
            let overlap = (off + bytes.len() as u64).saturating_sub(*next) as usize;
            if overlap > 0 {
                let n = overlap.min(value.len());
                if bytes[(*next - off) as usize..(*next - off) as usize + n] != value[..n] {
                    return Err(invalid("conflicting identity replacements overlap"));
                }
            }
            if next + value.len() as u64 > off + bytes.len() as u64 {
                active = Some(current);
            }
        }
        Ok(PlannedRules {
            rewrites,
            audit,
            matches,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edit::deattribute::layout::Region;
    use crate::scan::MemView;

    fn raw_layout(size: u64) -> Layout {
        Layout {
            size,
            valid: true,
            fields: vec![Span {
                offset: 0,
                len: size,
            }],
            regions: vec![Region {
                span: Span {
                    offset: 0,
                    len: size,
                },
                category: "raw".into(),
            }],
            ..Layout::default()
        }
    }

    #[test]
    fn nested_conflicting_replacements_are_refused() {
        let view = MemView::new("sample.bin", b"ABCDEFGH".to_vec());
        let rules: Rules = serde_json::from_str(r#"{"version":1,"identities":[{"id":"whole","scope":"product","names":["ABCDEFGH"],"encodings":["ascii"],"boundary":"substring","replacement":"12345678"},{"id":"inner","scope":"product","names":["BC"],"encodings":["ascii"],"boundary":"substring","replacement":"23"},{"id":"conflict","scope":"product","names":["FG"],"encodings":["ascii"],"boundary":"substring","replacement":"00"}]}"#).unwrap();
        assert!(
            rules
                .plan(&view, raw_layout(view.size()), &Limits::default())
                .is_err()
        );
    }

    #[test]
    fn protected_residuals_and_region_exclusions_are_distinguished() {
        let view = MemView::new("sample.bin", b"North North".to_vec());
        let rules: Rules = serde_json::from_str(r#"{"version":1,"identities":[{"id":"publisher","scope":"publisher","names":["North"],"encodings":["ascii"],"regions":["data"],"expected_matches":1}]}"#).unwrap();
        let mut layout = raw_layout(view.size());
        layout.regions = vec![
            Region {
                span: Span { offset: 0, len: 5 },
                category: "data".into(),
            },
            Region {
                span: Span { offset: 6, len: 5 },
                category: "code".into(),
            },
        ];
        let plan = rules.plan(&view, layout, &Limits::default()).unwrap();
        assert_eq!(plan.matches, 1);
        let output = MemView::new("output", b"      North".to_vec());
        let verified = plan.audit.verify(&output).unwrap();
        assert!(verified.policy_satisfied && !verified.clean);
        assert_eq!(
            verified.residuals[0].retained.as_deref(),
            Some("outside selected regions")
        );
    }
}
