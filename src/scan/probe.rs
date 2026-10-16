//! The probe interface. Every parser is a `Probe`: given a bounded view of one
//! file and its already-identified format, it appends findings. Probes must be
//! `Sync` because the scan runs them across a rayon pool.

use crate::model::Finding;

use super::reader::FileView;

/// What a probe is handed for one file.
pub struct ProbeCtx<'a> {
    pub view: &'a dyn FileView,
    /// The identified true-format slug, if identity matched anything.
    pub format: Option<&'a str>,
}

impl<'a> ProbeCtx<'a> {
    pub fn new(view: &'a dyn FileView, format: Option<&'a str>) -> Self {
        Self { view, format }
    }

    /// Whether this file's format is one of `wanted` (or `wanted` is empty).
    pub fn format_in(&self, wanted: &[&str]) -> bool {
        wanted.is_empty() || self.format.map(|f| wanted.contains(&f)).unwrap_or(false)
    }
}

/// A single detection unit. Keep `run` fail-soft: on anything unexpected,
/// return without pushing, never panic (the scan guards it either way).
pub trait Probe: Sync + Send {
    /// Stable id prefix for findings this probe emits (e.g. `pe`).
    fn id(&self) -> &'static str;

    /// Format slugs this probe applies to. Empty means "run on every file"
    /// (used by cross-cutting probes like filename/deception checks).
    fn formats(&self) -> &'static [&'static str] {
        &[]
    }

    /// Inspect `ctx` and append any findings to `out`.
    fn run(&self, ctx: &ProbeCtx, out: &mut Vec<Finding>);
}

/// The set of probes the scan runs, built once and shared across threads.
pub type Registry = Vec<Box<dyn Probe>>;
