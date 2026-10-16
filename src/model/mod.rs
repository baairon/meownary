//! The shared data model: the contracts every scan, parser, edit and UI module
//! agrees on. Kept dependency-light (serde only) so it compiles first and the
//! rest of the crate builds against stable types.

pub mod bucket;
pub mod category;
pub mod finding;
pub mod marker;
pub mod report;

pub use bucket::{Bucket, BucketBy, bucketize};
pub use category::{BrandKind, Category, DeceptionKind, JunkKind, SignatureStatus, TamperKind};
pub use finding::{Confidence, Evidence, Finding, Severity};
pub use marker::{ContainerKind, Marker, Region, RemovalStrategy};
pub use report::FileReport;
