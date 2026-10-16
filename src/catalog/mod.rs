//! The detection catalog: a reviewable, sourced table of byte/string signatures
//! the scan matches, plus its schema and validator.

pub mod embed;
pub mod schema;

pub use embed::catalog;
pub use schema::{CatKind, Catalog, Detect, RemovalSpec, Signature, Window, removal_for, validate};
