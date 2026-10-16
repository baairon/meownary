//! The detection catalog: a reviewable, sourced table of byte/string signatures
//! the scan matches, plus its schema and validator.

pub mod embed;
pub mod schema;

pub use embed::catalog;
pub use schema::{
    CatKind, Catalog, Detect, KNOWN_FORMATS, RemovalSpec, Signature, Window, marker_for,
    removal_for, validate,
};
