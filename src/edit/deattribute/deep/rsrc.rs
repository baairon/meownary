//! Structured deep edits in Macintosh resource forks.

use crate::edit::precision::pattern::{Limits, Span};
use crate::parsers::rsrc;
use crate::scan::FileView;

use super::super::Reason;
use super::super::audit::{self, identity_patterns};
use super::super::layout::{Layout, Region};
use super::pipl::Pipl;
use super::{
    Deep, Encoding, Hit, Protected, read_full, redact_hits, residuals, roots, single_byte,
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

/// Deep edits in a resource fork, with an audit of what it learned: the
/// identities the strings and PiPL lists name become the audit's patterns,
/// the resource names are linkage (the host looks them up, so they stay and
/// count as retained), and the string records are the fields an edit may
/// change.
pub(super) fn sweep(view: &dyn FileView, limits: &Limits) -> Deep {
    let Some(fork) = rsrc::parse(view) else {
        return Deep {
            skipped: vec![Reason::MalformedMetadata],
            ..Deep::default()
        };
    };
    let mut pipls = Vec::new();
    let mut hits = Vec::new();
    let mut evidence = Vec::new();
    let mut names = Vec::new();
    let mut name_spans = Vec::new();
    let mut skipped = Vec::new();
    for res in &fork.resources {
        if let Some((off, len)) = res.name
            && let Some(raw) = read_full(view, off, len)
        {
            names.push(single_byte(&raw));
            name_spans.push(Span {
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
                        evidence.extend(pipl.evidence());
                        pipls.push(pipl);
                    }
                    None => skipped.push(Reason::MalformedMetadata),
                }
            }
            b"STR " => hits.extend(pascal(view, res.off, res.len, 1)),
            b"STR#" => {
                if let Some(raw) = read_full(view, res.off, 2) {
                    let count = u16::from_be_bytes([raw[0], raw[1]]) as usize;
                    if count <= 4096 {
                        hits.extend(pascal(view, res.off + 2, res.len.saturating_sub(2), count));
                    }
                }
            }
            _ => {}
        }
    }
    let roots = roots(&hits, None, &evidence);
    let mut rewrites = redact_hits(&hits, &roots, &Protected::default());
    for pipl in &pipls {
        let (planned, residual) = pipl.rewrites(&roots);
        rewrites.extend(planned);
        skipped.extend(residual);
    }
    // Resource names are looked up by the host, so they count as linkage.
    skipped.extend(residuals(&hits, &[], &names, &roots));
    let complete = !skipped.iter().any(|reason| {
        matches!(
            reason,
            Reason::DeepBudget | Reason::MalformedMetadata | Reason::Io
        )
    });
    let mut fields: Vec<Span> = hits
        .iter()
        .map(|h| Span {
            offset: h.off,
            len: h.len as u64,
        })
        .collect();
    fields.extend(pipls.iter().flat_map(Pipl::text_fields).map(|h| Span {
        offset: h.off,
        len: h.len as u64,
    }));
    let layout = Layout {
        size: view.size(),
        format: Some("rsrc".to_string()),
        regions: vec![Region {
            span: Span {
                offset: 0,
                len: view.size(),
            },
            category: "resource fork".to_string(),
        }],
        protected: Vec::new(),
        linkage: name_spans,
        excluded: Vec::new(),
        fields,
        valid: true,
    };
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
