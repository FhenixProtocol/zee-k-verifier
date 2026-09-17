#[cfg(not(feature = "mock-signer"))]
use k256::ecdsa::SigningKey;
use rust_common::keygen::{log_key_hash, require_generate_keys_env};
use rust_common::log::debug;
#[cfg(not(feature = "mock-keys"))]
use tfhe::{zk::CompactPkeCrs, CompactPublicKey, CompressedServerKey, ServerKey};
#[cfg(not(feature = "mock-keys"))]
use tfhe_versionable::Unversionize;

use crate::config::KeyConfig;

/// Load the three TFHE public artifacts from the on-disk paths in `key_config`.
///
/// Public so the TDX launcher (in the `tdx-signer` crate) can call it after
/// fetching `signer_pk` separately from Secret Manager. The local-dev binary
/// goes through [`get_keys`] instead, which also loads the signer.
#[cfg(not(feature = "mock-keys"))]
pub fn load_tfhe_artifacts(key_config: &KeyConfig) -> (CompactPkeCrs, CompactPublicKey, ServerKey) {
    let crs_bytes = std::fs::read(&key_config.crs_path).expect("Failed to read CRS file");
    let pk_bytes = std::fs::read(&key_config.pk_path).expect("Failed to read public key file");
    let sk_bytes = std::fs::read(&key_config.sk_path).expect("Failed to read server key file");

    // Log key locations and hashes for alignment verification
    log_key_hash("CRS", &key_config.crs_path, &crs_bytes);
    log_key_hash("Public Key", &key_config.pk_path, &pk_bytes);
    log_key_hash("Server Key", &key_config.sk_path, &sk_bytes);

    deserialize_tfhe_artifacts(&crs_bytes, &pk_bytes, &sk_bytes)
        .expect("Failed to deserialize TFHE artifacts")
}

/// Deserialize the three TFHE public artifacts from their `safe_serialize` bytes.
///
/// Shared by [`load_tfhe_artifacts`] (which reads them off disk) and the TDX
/// launcher in the `tdx-signer` crate (which pulls them out of the keygen's
/// bucket-sourced `PublicMaterial` — `server_key`/`compact_public_key`/`crs`,
/// integrity via bucket IAM — rather than staging separate files). The server key is written compressed by
/// the keygen, so try `CompressedServerKey` first and fall back to a plain
/// `ServerKey` for compatibility.
#[cfg(not(feature = "mock-keys"))]
pub fn deserialize_tfhe_artifacts(
    crs_bytes: &[u8],
    pk_bytes: &[u8],
    sk_bytes: &[u8],
) -> Result<(CompactPkeCrs, CompactPublicKey, ServerKey), String> {
    let crs: CompactPkeCrs =
        deserialize_versionized(crs_bytes).map_err(|e| format!("deserialize CRS: {e}"))?;
    let pk: CompactPublicKey =
        deserialize_versionized(pk_bytes).map_err(|e| format!("deserialize public key: {e}"))?;
    // Try CompressedServerKey first (what the keygen writes), fall back to ServerKey.
    let server_key = match deserialize_versionized::<CompressedServerKey>(sk_bytes) {
        Ok(compressed) => compressed.decompress(),
        Err(_) => deserialize_versionized::<ServerKey>(sk_bytes)
            .map_err(|e| format!("deserialize server key: {e}"))?,
    };
    Ok((crs, pk, server_key))
}

#[cfg(not(feature = "mock-keys"))]
pub fn get_keys(
    key_config: &KeyConfig,
) -> (CompactPkeCrs, CompactPublicKey, ServerKey, SigningKey) {
    let (crs, pk, server_key) = load_tfhe_artifacts(key_config);

    let signing_key = load_signer_pk(&key_config.signer_pk_path);

    // Log signer key hash
    let signer_bytes = signing_key.to_bytes();
    log_key_hash("Signer Key", &key_config.signer_pk_path, &signer_bytes);

    (crs, pk, server_key, signing_key)
}

#[cfg(not(feature = "mock-signer"))]
fn load_signer_pk(signer_pk_path: &str) -> SigningKey {
    if std::path::Path::new(signer_pk_path).exists() {
        debug!("Loading existing signer key from: {}", signer_pk_path);
        load_pk(signer_pk_path)
    } else {
        require_generate_keys_env("Signer key", signer_pk_path);

        let pk = SigningKey::random(&mut rand::thread_rng());
        let pk_bytes = pk.to_bytes();
        debug!("Saving new signer key to: {}", signer_pk_path);
        std::fs::write(signer_pk_path, pk_bytes).expect("Failed to write public key file");
        pk
    }
}

#[cfg(not(feature = "mock-signer"))]
fn load_pk(path: &str) -> SigningKey {
    debug!("Reading signer key from: {}", path);
    let pk_bytes = std::fs::read(path).expect("Failed to read public key file");
    SigningKey::from_slice(pk_bytes.as_slice()).expect("Failed to deserialize public key")
}

#[cfg(not(feature = "mock-keys"))]
fn deserialize_versionized<T: serde::de::DeserializeOwned + Unversionize + tfhe::named::Named>(
    bytes: &[u8],
) -> Result<T, String> {
    rust_common::safe_serde::deserialize(bytes)
}
