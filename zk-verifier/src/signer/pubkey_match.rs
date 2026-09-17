//! Boot-time gate: confirm the loaded signing key matches the published
//! signer public key.
//!
//! In production the private `signer_pk` is fetched from Secret Manager
//! (keys-side, attested path) while its public counterpart is published in the
//! GCS bucket next to the TFHE artifacts. The two come from independent sources
//! and can drift apart — e.g. rotating the secret without re-publishing the
//! public key, or vice-versa. This check re-derives the public key from the
//! loaded private key and compares it to the published one, so the signer
//! identity consumers trust in GCS is provably the one the enclave signs with.
//!
//! Mismatch is a hard error: the caller fails the boot before serving.

use k256::ecdsa::{SigningKey, VerifyingKey};
use rust_common::log::info;
use rust_common::signing::{EvmAddress, Signer};

/// Verify that `signing_key` corresponds to the public key published at
/// `expected_pubkey_path` (compressed-SEC1 bytes written next to the TFHE
/// artifacts).
///
/// Returns `Err` if the file is missing/unreadable, can't be parsed as a
/// secp256k1 public key, or doesn't match the key derived from `signing_key`.
pub fn verify_signer_matches_pubkey(
    signing_key: &SigningKey,
    expected_pubkey_path: &str,
) -> Result<(), String> {
    let expected_bytes = std::fs::read(expected_pubkey_path)
        .map_err(|e| format!("reading published signer pubkey '{expected_pubkey_path}': {e}"))?;

    // Parse into a canonical curve point so the comparison is point-equality,
    // not byte-equality — guards against compressed-vs-uncompressed encoding.
    let expected = VerifyingKey::from_sec1_bytes(&expected_bytes).map_err(|e| {
        format!("parsing published signer pubkey '{expected_pubkey_path}' as secp256k1: {e}")
    })?;

    let computed = signing_key.verifying_key();
    if computed != &expected {
        return Err(format!(
            "signer key / published pubkey mismatch: the loaded signing key does not correspond \
             to the public key published at '{expected_pubkey_path}'. The signing key (Secret \
             Manager) and the published pubkey (GCS) must be rotated together."
        ));
    }

    // Log the bound identity for audit, mirroring verifier/mod.rs.
    let address: EvmAddress = (&Signer::from_bytes(&signing_key.to_bytes())
        .map_err(|e| format!("constructing signer for address logging: {e}"))?)
        .into();
    info!("Signer key matches published pubkey; bound signer address: {address}");

    Ok(())
}

/// Verify that `signing_key` derives to `expected_address` (an `0x`-prefixed EVM
/// address).
///
/// Used by the TDX launcher's multi-partner Shamir path: the published identity
/// is the `zk_signer_address` inside the keygen's bucket-sourced `PublicMaterial`
/// (not a separately-uploaded pubkey file). The manifest is not attested, so this
/// on-boot check — that the reconstructed signer matches `zk_signer_address` — is
/// what anchors the signer identity. Comparison is
/// case-insensitive (EVM addresses may differ only in EIP-55 checksum casing).
pub fn verify_signer_matches_address(
    signing_key: &SigningKey,
    expected_address: &str,
) -> Result<(), String> {
    let address: EvmAddress = (&Signer::from_bytes(&signing_key.to_bytes())
        .map_err(|e| format!("constructing signer for address check: {e}"))?)
        .into();
    let computed = address.to_string();
    if !computed.eq_ignore_ascii_case(expected_address) {
        return Err(format!(
            "signer identity mismatch: the reconstructed signing key derives to {computed}, but \
             the keygen published zk_signer_address {expected_address}. The partners' shares and \
             the published identity must come from the same ceremony."
        ));
    }
    info!("Signer matches published zk_signer_address; bound signer address: {computed}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use k256::ecdsa::SigningKey;

    use super::*;

    /// Write `key`'s compressed-SEC1 public key to a temp file; return its path.
    fn write_pubkey(key: &SigningKey, name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(name);
        let bytes = key.verifying_key().to_encoded_point(true).as_bytes().to_vec();
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn matching_key_and_pubkey_pass() {
        let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let path = write_pubkey(&key, "pubkey_match_ok.bin");

        assert!(verify_signer_matches_pubkey(&key, path.to_str().unwrap()).is_ok());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn mismatched_key_and_pubkey_fail() {
        let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let other = SigningKey::from_slice(&[8u8; 32]).unwrap();
        let path = write_pubkey(&other, "pubkey_match_mismatch.bin");

        let err = verify_signer_matches_pubkey(&key, path.to_str().unwrap()).unwrap_err();
        assert!(err.contains("mismatch"), "unexpected error: {err}");

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn missing_file_fails() {
        let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let err = verify_signer_matches_pubkey(&key, "/nonexistent/signer_public_key").unwrap_err();
        assert!(err.contains("reading published signer pubkey"), "unexpected error: {err}");
    }

    #[test]
    fn garbage_file_fails() {
        let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let path = std::env::temp_dir().join("pubkey_match_garbage.bin");
        std::fs::write(&path, b"not a public key").unwrap();

        let err = verify_signer_matches_pubkey(&key, path.to_str().unwrap()).unwrap_err();
        assert!(err.contains("parsing"), "unexpected error: {err}");

        let _ = std::fs::remove_file(path);
    }
}
