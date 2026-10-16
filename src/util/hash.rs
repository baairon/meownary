//! Small hashing helpers (blake3) for TOCTOU region checks and `--hash`.

/// Lowercase hex blake3 of `bytes`.
pub fn hash_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}
