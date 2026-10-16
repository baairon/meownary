//! Load and cache the embedded catalog once.

use std::sync::OnceLock;

use super::schema::{Catalog, validate};

/// The embedded catalog, parsed on first use and reused thereafter.
pub fn catalog() -> &'static Catalog {
    static CAT: OnceLock<Catalog> = OnceLock::new();
    CAT.get_or_init(|| {
        let cat: Catalog =
            ron::from_str(include_str!("catalog.ron")).expect("embedded catalog.ron must parse");
        debug_assert!(
            validate(&cat).is_empty(),
            "embedded catalog invalid: {:?}",
            validate(&cat)
        );
        cat
    })
}
