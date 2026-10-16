//! Structured deep edits in Macintosh resource forks.

use crate::parsers::rsrc;
use crate::scan::FileView;

use super::super::Reason;
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

pub(super) fn sweep(view: &dyn FileView) -> Deep {
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
    let mut skipped = Vec::new();
    for res in &fork.resources {
        if let Some((off, len)) = res.name
            && let Some(raw) = read_full(view, off, len)
        {
            names.push(single_byte(&raw));
        }
        match &res.kind {
            b"PiPL" => {
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
    Deep {
        rewrites,
        skipped,
        ..Deep::default()
    }
}
