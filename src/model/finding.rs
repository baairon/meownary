//! A single thing a probe noticed about a file.

use serde::{Deserialize, Serialize};

use super::category::Category;
use super::marker::Marker;

/// How sure we are the finding is real and correctly categorized. This is a
/// first-class probe output, not a post-hoc guess: `Strong` must be backed by
/// corroboration (see the catalog's corroboration rules), never a lone generic
/// string. `Weak` is surfaced dimly and never drives a default destructive edit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Weak,
    Moderate,
    Strong,
}

/// How loudly to surface the finding, which also drives its theme color.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Notice,
    Warn,
    Alert,
}

/// The concrete thing we saw: where, the bytes, and a human note.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// Absolute file offset the evidence starts at.
    pub offset: u64,
    /// The matched bytes, bounded to a small window. Serialized as a hex string.
    #[serde(with = "hexbytes")]
    pub matched: Vec<u8>,
    /// A short human explanation ("CompanyName = Microsoft Corporation").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// The catalog entry id this came from, for diagnosis and suppression.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catalog_ref: Option<String>,
}

impl Evidence {
    pub fn at(offset: u64) -> Self {
        Self {
            offset,
            matched: Vec::new(),
            note: None,
            catalog_ref: None,
        }
    }

    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }

    pub fn with_bytes(mut self, bytes: impl Into<Vec<u8>>) -> Self {
        self.matched = bytes.into();
        self
    }
}

/// One observation about a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub category: Category,
    pub confidence: Confidence,
    pub severity: Severity,
    /// Stable id of the probe/signature that produced this (e.g. `pe.rich.msvc`).
    pub signature_id: String,
    /// One-line human summary shown in the list and JSON.
    pub title: String,
    pub evidence: Evidence,
    /// Present when the finding points at a removable region.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub marker: Option<Marker>,
}

impl Finding {
    /// Whether this finding can be acted on (cleaned) by the edit engine.
    pub fn is_removable(&self) -> bool {
        self.marker.is_some()
    }
}

/// Serialize `Vec<u8>` as a lowercase hex string (and back), so JSON evidence
/// is readable instead of a numeric array.
mod hexbytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push(char::from_digit((b >> 4) as u32, 16).unwrap());
            out.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
        }
        s.serialize_str(&out)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        if s.len() % 2 != 0 {
            return Err(serde::de::Error::custom("odd-length hex"));
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(serde::de::Error::custom))
            .collect()
    }
}
