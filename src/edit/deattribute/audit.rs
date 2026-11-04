//! Reuse the original identities, range map, and matching policy for verification.

use std::io;

use serde::{Deserialize, Serialize};

use crate::edit::precision::pattern::{
    Boundary, Encoding, Limits, Match, Matcher, Pattern, SearchReport, Span,
};
use crate::scan::FileView;

use super::layout::Layout;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Audit {
    pub patterns: Vec<Pattern>,
    pub layout: Layout,
    pub limits: Limits,
    pub complete: bool,
    pub unexamined: Vec<Span>,
    #[serde(default)]
    pub allowed: Vec<Allowance>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allowance {
    pub pattern: usize,
    pub span: Span,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Residual {
    pub rule: usize,
    pub offset: u64,
    pub len: u64,
    pub encoding: Option<Encoding>,
    pub region: String,
    pub retained: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub complete: bool,
    pub clean: bool,
    pub policy_satisfied: bool,
    pub residuals: Vec<Residual>,
    pub unexamined: Vec<Span>,
}

pub fn identity_patterns<'a>(terms: impl IntoIterator<Item = &'a String>) -> Vec<Pattern> {
    let mut out = Vec::new();
    for term in terms {
        if term.chars().count() < 4 {
            continue;
        }
        // UTF-8 covers ASCII too. Do not count the same bytes twice as ANSI.
        for encoding in [
            Encoding::Utf8,
            Encoding::Utf16le,
            Encoding::Utf16be,
            Encoding::Windows1252,
        ] {
            if encoding == Encoding::Windows1252 && term.is_ascii() {
                continue;
            }
            if encoding.encode(term).is_err() {
                continue;
            }
            out.push(Pattern::Text {
                value: term.clone(),
                encoding,
                ignore_ascii_case: true,
                boundary: Boundary::Identifier,
            });
        }
    }
    out
}

impl Audit {
    pub fn classify(&self, hit: &Match) -> Residual {
        Residual {
            rule: hit.pattern,
            offset: hit.offset,
            len: hit.len,
            encoding: hit.encoding,
            region: self.layout.category(hit.offset).to_owned(),
            retained: self
                .layout
                .retention(&Span {
                    offset: hit.offset,
                    len: hit.len,
                })
                .or_else(|| {
                    self.allowed
                        .iter()
                        .any(|a| {
                            a.pattern == hit.pattern
                                && a.span.offset <= hit.offset
                                && a.span.offset.saturating_add(a.span.len) >= hit.offset + hit.len
                        })
                        .then_some("outside selected regions")
                })
                .map(str::to_owned),
        }
    }

    pub fn search(&self, view: &dyn FileView) -> io::Result<SearchReport> {
        Matcher::new(&self.patterns)?.search(
            view,
            Span {
                offset: 0,
                len: view.size(),
            },
            &self.limits,
        )
    }

    pub fn verify(&self, view: &dyn FileView) -> io::Result<AuditReport> {
        let found = self.search(view)?;
        let residuals: Vec<_> = found.matches.iter().map(|m| self.classify(m)).collect();
        let mut unexamined = self.unexamined.clone();
        unexamined.extend(found.unexamined);
        unexamined.sort_by_key(|r| (r.offset, r.len));
        unexamined.dedup();
        let complete = self.complete && found.complete && unexamined.is_empty();
        Ok(AuditReport {
            complete,
            clean: complete && residuals.is_empty(),
            policy_satisfied: complete && residuals.iter().all(|r| r.retained.is_some()),
            residuals,
            unexamined,
        })
    }
}
