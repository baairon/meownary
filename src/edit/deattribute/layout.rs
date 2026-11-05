//! One range classification used by matching, editing, and verification.

use serde::{Deserialize, Serialize};

use crate::edit::precision::pattern::Span;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Region {
    pub span: Span,
    pub category: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Layout {
    pub size: u64,
    pub format: Option<String>,
    pub regions: Vec<Region>,
    pub protected: Vec<Span>,
    pub linkage: Vec<Span>,
    #[serde(default)]
    pub excluded: Vec<Span>,
    /// Parsed text fields inside a larger protected metadata record.
    pub fields: Vec<Span>,
    pub valid: bool,
}

impl Layout {
    pub fn category(&self, offset: u64) -> &str {
        self.regions
            .iter()
            .find(|r| offset >= r.span.offset && offset < r.span.offset.saturating_add(r.span.len))
            .map_or("unclassified", |r| r.category.as_str())
    }

    pub fn retention(&self, span: &Span) -> Option<&'static str> {
        if self.excluded.iter().any(|r| r.overlaps(span)) {
            return Some("explicit exclusion");
        }
        if self.linkage.iter().any(|r| r.overlaps(span)) {
            return Some("protected linkage");
        }
        if !self.valid {
            return Some("unverified layout");
        }
        if self.fields.iter().any(|r| {
            r.offset <= span.offset
                && r.offset.saturating_add(r.len) >= span.offset.saturating_add(span.len)
        }) {
            return None;
        }
        self.protected
            .iter()
            .any(|r| r.overlaps(span))
            .then_some("structural record")
    }
}

pub fn inspect(view: &dyn crate::scan::FileView) -> Layout {
    let format = crate::parsers::identity::identify(view).0;
    if format == Some("pe") {
        return super::deep::pe_layout(view);
    }
    if matches!(format, Some("rsrc" | "appledouble"))
        && let Some(layout) = super::deep::rsrc_layout(view)
    {
        return layout;
    }
    let size = view.size();
    let fields: Vec<Span> = match format {
        Some("elf") => crate::parsers::elf::data_regions(view)
            .into_iter()
            .chain(crate::parsers::elf::debug_string_regions(view))
            .map(|(offset, len)| Span { offset, len })
            .collect(),
        Some("macho") => crate::parsers::macho::deep_regions(view)
            .regions
            .into_iter()
            .map(|(offset, len)| Span { offset, len })
            .collect(),
        None | Some("script") => vec![Span {
            offset: 0,
            len: size,
        }],
        _ => Vec::new(),
    };
    Layout {
        size,
        format: format.map(str::to_owned),
        regions: vec![Region {
            span: Span {
                offset: 0,
                len: size,
            },
            category: format.unwrap_or("raw").into(),
        }],
        protected: vec![Span {
            offset: 0,
            len: size,
        }],
        linkage: Vec::new(),
        excluded: Vec::new(),
        valid: !fields.is_empty() || size == 0,
        fields,
    }
}
