//! Load and cache the embedded catalog once.

use std::sync::OnceLock;

use super::schema::Catalog;

/// The embedded catalog source.
pub const CATALOG_RON: &str = include_str!("catalog.ron");

/// The embedded catalog, parsed on first use and reused thereafter. A parse
/// failure yields an empty catalog rather than a panic; the `catalog_is_valid`
/// test keeps that from ever shipping.
pub fn catalog() -> &'static Catalog {
    static CAT: OnceLock<Catalog> = OnceLock::new();
    CAT.get_or_init(|| {
        ron::from_str(CATALOG_RON).unwrap_or_else(|_| Catalog {
            signatures: Vec::new(),
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::validate;

    #[test]
    fn catalog_is_valid() {
        let parsed: Result<Catalog, _> = ron::from_str(CATALOG_RON);
        let cat = match parsed {
            Ok(c) => c,
            Err(e) => panic!("embedded catalog.ron must parse: {e}"),
        };
        let problems = validate(&cat);
        assert!(problems.is_empty(), "catalog problems: {problems:#?}");
        assert_eq!(catalog().signatures.len(), cat.signatures.len());
        assert!(!cat.signatures.is_empty());
    }
}
