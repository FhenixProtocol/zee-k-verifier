//! Key generation utilities for CoFHE services.
//!
//! This module provides utilities for:
//! - Checking the GENERATE_KEYS environment variable before auto-generating keys
//! - Computing key hashes for logging and verification
//! - Logging key information without exposing sensitive data

use sha2::{Digest, Sha256};

/// Compute SHA256 hash of data and return first 8 hex characters.
/// Useful for logging key identifiers without exposing full key data.
///
/// # Arguments
/// * `data` - The key data to hash
///
/// # Returns
/// A string containing the first 8 hex characters of the SHA256 hash
///
/// # Examples
/// ```
/// use rust_common::keygen::compute_key_hash;
///
/// let key_data = b"my-secret-key";
/// let hash = compute_key_hash(key_data);
/// assert_eq!(hash.len(), 8);
/// ```
pub fn compute_key_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex::encode(&result[..4])
}

/// Log key file path and hash using the log crate, when you already have the data in memory.
///
/// # Arguments
/// * `key_name` - A human-readable name for the key (e.g., "Public Key", "Signer Key")
/// * `path` - The file path where the key is stored
/// * `data` - The key data bytes
///
/// # Examples
/// ```no_run
/// use rust_common::keygen::log_key_hash;
///
/// let key_data = b"my-secret-key";
/// log_key_hash("My Key", "/path/to/key", key_data);
/// // Logs: "Key loaded: My Key from '/path/to/key' (hash: 3a7bd3e2)"
/// ```
pub fn log_key_hash(key_name: &str, path: &str, data: &[u8]) {
    log::info!(
        "Key loaded: {} from '{}' (hash: {})",
        key_name,
        path,
        compute_key_hash(data)
    );
}

/// Log key file path and hash using the log crate.
/// Reads the file from disk. If the file cannot be read, logs an info message with the error.
///
/// # Arguments
/// * `key_name` - A human-readable name for the key (e.g., "Public Key", "Signer Key")
/// * `path` - The file path where the key is stored
///
/// # Examples
/// ```no_run
/// use rust_common::keygen::log_key_info;
///
/// log_key_info("My Key", "/path/to/key");
/// // Logs: "Key loaded: My Key from '/path/to/key' (hash: 3a7bd3e2)"
/// // Or: "Key not found: My Key at '/path/to/key' (error: No such file or directory)"
/// ```
pub fn log_key_info(key_name: &str, path: &str) {
    match std::fs::read(path) {
        Ok(data) => {
            log_key_hash(key_name, path, &data);
        }
        Err(e) => {
            log::info!("Key not found: {} at '{}' (error: {})", key_name, path, e);
        }
    }
}

/// Check if the GENERATE_KEYS environment variable is set to "true".
/// If not set, panic with a helpful error message.
///
/// This function enforces a security policy: cryptographic keys should never be
/// auto-generated in production unless explicitly enabled via environment variable.
///
/// # Arguments
/// * `key_type` - A description of the key type being generated (e.g., "Cryptographic keys", "Signer key")
/// * `location` - The path or location where the key was expected to be found
///
/// # Panics
/// Panics if GENERATE_KEYS is not set to "true"
///
/// # Examples
/// ```should_panic
/// use rust_common::keygen::require_generate_keys_env;
///
/// // This will panic if GENERATE_KEYS != "true"
/// require_generate_keys_env("Test Key", "/path/to/key");
/// ```
///
/// ```no_run
/// use rust_common::keygen::require_generate_keys_env;
///
/// std::env::set_var("GENERATE_KEYS", "true");
/// require_generate_keys_env("Test Key", "/path/to/key");
/// // Logs: "GENERATE_KEYS=true, proceeding with generation of Test Key at '/path/to/key'"
/// ```
pub fn require_generate_keys_env(key_type: &str, location: &str) {
    let generate_keys = std::env::var("GENERATE_KEYS")
        .unwrap_or_else(|_| "false".to_string())
        .to_lowercase()
        == "true";

    if !generate_keys {
        panic!(
            "{} not found in '{}' and GENERATE_KEYS environment variable is not set to 'true'. \
            For security reasons, keys will not be auto-generated. \
            Either: \n\
            1. Set GENERATE_KEYS=true to generate new keys (development/first-time setup only), or\n\
            2. Mount existing keys to the keys directory",
            key_type, location
        );
    }

    log::info!(
        "GENERATE_KEYS=true, proceeding with generation of {} at '{}'",
        key_type,
        location
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_key_hash() {
        let data = b"test-key-data";
        let hash = compute_key_hash(data);

        // Hash should be 8 hex characters (4 bytes)
        assert_eq!(hash.len(), 8);

        // Same input should produce same hash
        let hash2 = compute_key_hash(data);
        assert_eq!(hash, hash2);

        // Different input should produce different hash
        let different_data = b"different-key-data";
        let different_hash = compute_key_hash(different_data);
        assert_ne!(hash, different_hash);
    }

    #[test]
    fn test_compute_key_hash_deterministic() {
        // Known SHA256 hash for "test"
        // SHA256("test") = 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
        // First 4 bytes: 9f86d081
        let data = b"test";
        let hash = compute_key_hash(data);
        assert_eq!(hash, "9f86d081");
    }

    #[test]
    fn test_log_key_hash() {
        // This test just ensures the function doesn't panic
        // In a real environment with logging configured, you'd check the log output
        let data = b"test-key";
        log_key_hash("Test Key", "/tmp/test", data);
    }

    #[test]
    fn test_log_key_info_nonexistent_file() {
        // This should log an error message but not panic
        log_key_info("Test Key", "/nonexistent/path/to/key");
    }

    #[test]
    fn test_log_key_info_existing_file() {
        use std::io::Write;

        // Create a temporary file
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join("test_key_file");
        let mut file = std::fs::File::create(&temp_file).unwrap();
        file.write_all(b"test-key-content").unwrap();
        drop(file);

        // Log the key info
        log_key_info("Test Key", temp_file.to_str().unwrap());

        // Clean up
        std::fs::remove_file(temp_file).ok();
    }

    #[test]
    #[should_panic(expected = "not found")]
    fn test_require_generate_keys_env_without_env_var() {
        // Clear the env var to ensure it's not set
        std::env::remove_var("GENERATE_KEYS");

        require_generate_keys_env("Test Key", "/path/to/key");
    }

    #[test]
    #[should_panic(expected = "not found")]
    fn test_require_generate_keys_env_with_false() {
        std::env::set_var("GENERATE_KEYS", "false");

        require_generate_keys_env("Test Key", "/path/to/key");
    }

    #[test]
    fn test_require_generate_keys_env_with_true() {
        std::env::set_var("GENERATE_KEYS", "true");

        // This should not panic
        require_generate_keys_env("Test Key", "/path/to/key");

        // Clean up
        std::env::remove_var("GENERATE_KEYS");
    }

    #[test]
    fn test_require_generate_keys_env_case_insensitive() {
        // Test various case variations
        for value in &["TRUE", "True", "TrUe", "true"] {
            std::env::set_var("GENERATE_KEYS", value);
            require_generate_keys_env("Test Key", "/path/to/key");
        }

        std::env::remove_var("GENERATE_KEYS");
    }
}
