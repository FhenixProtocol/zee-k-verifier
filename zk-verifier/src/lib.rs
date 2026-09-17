//! `zk-verifier` — TFHE ZK-proof verification + ECDSA signing.
//!
//! Two entry points:
//!
//! - [`run_server_from_config`] — local-dev convenience: reads keys from
//!   the file paths in [`config::Config`], builds a [`KeyMaterial`], and
//!   runs the server.
//! - [`run_server_with_keys`] — for callers (e.g. the TDX launcher in the
//!   `tdx-signer` crate) that obtain key material out of band and want the
//!   server to start with keys already in memory.

pub mod config;
mod otel_push;
mod otel_split;

mod api;
mod health;
mod server;
mod signer;
mod storage;
mod telemetry;
mod verifier;

#[cfg(not(feature = "mock-keys"))]
mod keys;
#[cfg(feature = "mock-keys")]
mod mock_keys;

use k256::ecdsa::SigningKey;
/// Load the three TFHE public artifacts (`crs`, `pk`, `sk`) from the on-disk
/// paths in `key_config`. Available only in the real-keys build configuration
/// (i.e. the default / `production` features, not `mock-keys`).
///
/// The TDX launcher (in the `tdx-signer` crate) calls this after fetching the
/// signing key from Secret Manager, to assemble a [`KeyMaterial`] for
/// [`run_server`].
#[cfg(not(feature = "mock-keys"))]
pub use keys::{deserialize_tfhe_artifacts, load_tfhe_artifacts};
use tfhe::zk::CompactPkeCrs;
use tfhe::{CompactPublicKey, ServerKey};

#[cfg(not(feature = "mock-keys"))]
use crate::keys::get_keys;
#[cfg(feature = "mock-keys")]
use crate::mock_keys::get_keys;

/// All the key material a zk-verifier server needs to run.
///
/// `signer_pk` is the only true secret — in TDX it is reconstructed by
/// `tdx-signer` from the partners' Shamir shares on the attested boot path. The
/// TFHE artifacts (`crs`, `pk`, `sk`) are public; in TDX they come from the
/// keygen's bucket-sourced `PublicMaterial` (digest-checked against the manifest;
/// integrity via bucket IAM, not attestation), in local dev from disk.
pub struct KeyMaterial {
    pub crs: CompactPkeCrs,
    pub pk: CompactPublicKey,
    pub sk: ServerKey,
    pub signer_pk: SigningKey,
    /// Published signer identity to gate boot against. `Some(zk_signer_address)`
    /// on the TDX path (checked against the reconstructed signer's address);
    /// `None` on the local-dev path (which instead checks the signer against the
    /// on-disk `signer_public_key` file).
    pub expected_signer_address: Option<String>,
}

pub use server::run_server;
/// Exposed for the `stress-verify` load generator (`scripts/stress_verify.rs`)
/// so it can mint proofs whose metadata binding + key parameters match the
/// verifier exactly. Not part of the stable public API.
#[doc(hidden)]
pub use verifier::Verifier;

/// Convenience: assemble a [`KeyMaterial`] by reading every key — TFHE
/// artifacts *and* the signing key — from the on-disk paths in `config.keys`.
///
/// Used by the local-dev binary (`src/main.rs`). The TDX launcher in the
/// `tdx-signer` crate does not call this — it assembles `KeyMaterial`
/// directly because `signer_pk` arrives from Secret Manager, not from disk.
pub fn load_keys_from_config(config: &config::Config) -> KeyMaterial {
    let (crs, pk, sk, signer_pk) = get_keys(&config.keys);
    // Local dev verifies the signer against the on-disk signer_public_key file
    // (see run_server), so no expected address is carried here.
    KeyMaterial { crs, pk, sk, signer_pk, expected_signer_address: None }
}
