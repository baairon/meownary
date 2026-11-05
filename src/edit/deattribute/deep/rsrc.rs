//! Structured deep edits in Macintosh resource forks.

use crate::edit::precision::pattern::{Limits, Span};
use crate::parsers::rsrc;
use crate::scan::FileView;

use super::super::Reason;
use super::super::audit::{self, identity_patterns};
use super::super::layout::{Layout, Region};
use super::pipl::Pipl;
use super::{
    Budget, Deep, Encoding, Hit, Protected, read_full, redact_hits, residuals, roots, single_byte,
};

/// Up to `count` consecutive Pascal strings. An empty one is a valid entry,
/// so it is passed over rather than ending the list.
fn pascal(view: &dyn FileView, off: u64, len: u64, count: usize) -> Vec<Hit> {
    if len == 0 || len > 1024 * 1024 {
        return Vec::new();
    }
    let Some(raw) = read_full(view, off, len as usize) else {
        return Vec::new();
    };
    let mut hits = Vec::new();
    let mut at = 0usize;
    for _ in 0..count {
        let Some(&size) = raw.get(at) else {
            break;
        };
        let size = size as usize;
        if at + 1 + size > raw.len() {
            break;
        }
        if size > 0 {
            hits.push(Hit {
                off: off + at as u64 + 1,
                len: size,
                text: single_byte(&raw[at + 1..at + 1 + size]),
                encoding: Encoding::SingleByte,
            });
        }
        at += size + 1;
    }
    hits
}

/// The string bodies a fork carries, as many as `budget` allows, with the
/// names, name spans and PiPL lists it holds and the reasons it could not
/// read.
struct Parsed {
    hits: Vec<Hit>,
    names: Vec<String>,
    name_spans: Vec<Span>,
    pipls: Vec<Pipl>,
    evidence: Vec<(String, super::Source)>,
    skipped: Vec<Reason>,
}

fn read_fork(view: &dyn FileView, fork: &rsrc::Fork, budget: &mut Budget) -> Parsed {
    let mut out = Parsed {
        hits: Vec::new(),
        names: Vec::new(),
        name_spans: Vec::new(),
        pipls: Vec::new(),
        evidence: Vec::new(),
        skipped: Vec::new(),
    };
    for res in &fork.resources {
        if let Some((off, len)) = res.name
            && let Some(raw) = read_full(view, off, len)
        {
            out.names.push(single_byte(&raw));
            out.name_spans.push(Span {
                offset: off,
                len: len as u64,
            });
        }
        match &res.kind {
            b"PiPL" | b"PIPL" => {
                match read_full(view, res.off, res.len as usize)
                    .and_then(|raw| Pipl::parse(&raw, res.off))
                {
                    Some(pipl) => {
                        out.evidence.extend(pipl.evidence());
                        out.pipls.push(pipl);
                    }
                    None => out.skipped.push(Reason::MalformedMetadata),
                }
            }
            b"STR " => out
                .hits
                .extend(budget.admit(pascal(view, res.off, res.len, 1))),
            b"STR#" => {
                if let Some(raw) = read_full(view, res.off, 2) {
                    let count = u16::from_be_bytes([raw[0], raw[1]]) as usize;
                    if count <= 4096 {
                        let found = pascal(view, res.off + 2, res.len.saturating_sub(2), count);
                        out.hits.extend(budget.admit(found));
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// The fork's layout: every byte is a structural record (the fork and map
/// headers, the type list, the reference entries with their IDs, the name
/// list and the AppleDouble envelope), except the string bodies and PiPL
/// text an edit may change; the resource names are linkage the host looks
/// up.
fn fork_layout(view: &dyn FileView, fork: &rsrc::Fork, parsed: &Parsed) -> Layout {
    let size = view.size();
    let mut fields: Vec<Span> = parsed
        .hits
        .iter()
        .map(|h| Span {
            offset: h.off,
            len: h.len as u64,
        })
        .collect();
    fields.extend(
        parsed
            .pipls
            .iter()
            .flat_map(Pipl::text_fields)
            .map(|h| Span {
                offset: h.off,
                len: h.len as u64,
            }),
    );
    let region = |offset: u64, len: u64, category: &str| Region {
        span: Span { offset, len },
        category: category.to_string(),
    };
    let mut regions = Vec::new();
    if fork.base > 0 {
        regions.push(region(0, fork.base, "AppleDouble header"));
    }
    regions.push(region(fork.base, 16, "resource header"));
    regions.push(region(fork.data.0, fork.data.1, "resource data"));
    regions.push(region(fork.map.0, fork.map.1, "resource map"));
    Layout {
        size,
        format: Some(
            if fork.apple_double {
                "appledouble"
            } else {
                "rsrc"
            }
            .to_string(),
        ),
        regions,
        protected: vec![Span {
            offset: 0,
            len: size,
        }],
        linkage: parsed.name_spans.clone(),
        excluded: Vec::new(),
        fields,
        valid: true,
    }
}

/// The layout [`super::super::layout::inspect`] gives a resource fork, the
/// same one the deep sweep audits with. `None` when the fork does not parse.
pub(super) fn layout(view: &dyn FileView) -> Option<Layout> {
    let fork = rsrc::parse(view)?;
    let parsed = read_fork(view, &fork, &mut Budget::new(super::MAX_DEEP_STRINGS));
    Some(fork_layout(view, &fork, &parsed))
}

/// Deep edits in a resource fork, with an audit of what it learned: the
/// identities the strings and PiPL lists name become the audit's patterns,
/// the resource names are linkage (the host looks them up, so they stay and
/// count as retained), and every structural byte is kept. At most `max`
/// string bodies are read; past that the sweep reports the deep budget.
pub(super) fn sweep(view: &dyn FileView, limits: &Limits, max: usize) -> Deep {
    let Some(fork) = rsrc::parse(view) else {
        return Deep {
            skipped: vec![Reason::MalformedMetadata],
            ..Deep::default()
        };
    };
    let mut budget = Budget::new(max);
    let parsed = read_fork(view, &fork, &mut budget);
    let layout = fork_layout(view, &fork, &parsed);
    let Parsed {
        hits,
        names,
        pipls,
        evidence,
        mut skipped,
        ..
    } = parsed;
    let roots = roots(&hits, None, &evidence);
    let mut rewrites = redact_hits(&hits, &roots, &Protected::default());
    for pipl in &pipls {
        let (planned, residual) = pipl.rewrites(&roots);
        rewrites.extend(planned);
        skipped.extend(residual);
    }
    // Resource names are looked up by the host, so they count as linkage.
    skipped.extend(residuals(&hits, &[], &names, &roots));
    budget.report(&mut skipped);
    let complete = !skipped.iter().any(|reason| {
        matches!(
            reason,
            Reason::DeepBudget | Reason::MalformedMetadata | Reason::Io
        )
    });
    Deep {
        rewrites,
        skipped,
        audit: Some(audit::Audit {
            patterns: identity_patterns(&roots),
            layout,
            limits: limits.clone(),
            complete,
            unexamined: Vec::new(),
            allowed: Vec::new(),
        }),
        ..Deep::default()
    }
}
