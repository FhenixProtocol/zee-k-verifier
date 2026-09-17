//! Shared safe serialization/deserialization for tfhe types.
//!
//! Uses tfhe's `safe_serialize`/`safe_deserialize` which includes:
//! - Versionized format (forward-compatible across tfhe-rs upgrades)
//! - Type name tag (catches type mismatches)
//! - Size limit (prevents DoS via oversized payloads)
//!
//! All cofhe services should use these functions for tfhe type serialization.

use tfhe::safe_serialization::{safe_deserialize, safe_serialize};

/// Maximum serialized size limit (1 GB)
pub const SAFE_SERIALIZATION_SIZE_LIMIT: u64 = 1 << 30;

/// Serialize a tfhe type using safe_serialize.
/// Compatible with tfhe WASM `safe_deserialize`.
pub fn serialize<T>(value: &T) -> Result<Vec<u8>, String>
where
    T: serde::Serialize + tfhe::Versionize + tfhe::named::Named,
{
    let mut buf = Vec::new();
    safe_serialize(value, &mut buf, SAFE_SERIALIZATION_SIZE_LIMIT)
        .map_err(|e| format!("safe_serialize failed: {e}"))?;
    Ok(buf)
}

/// Deserialize a tfhe type using safe_deserialize.
/// Compatible with tfhe WASM `safe_serialize`.
pub fn deserialize<T>(bytes: &[u8]) -> Result<T, String>
where
    T: serde::de::DeserializeOwned + tfhe::Unversionize + tfhe::named::Named,
{
    safe_deserialize(bytes, SAFE_SERIALIZATION_SIZE_LIMIT)
        .map_err(|e| format!("safe_deserialize failed: {e}"))
}
