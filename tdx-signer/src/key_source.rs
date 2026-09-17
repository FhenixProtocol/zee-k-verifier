//! zk-signer key source: reconstruct the Shamir-split zk-signer secret from the
//! partners via the embedded `cofhe-keys` reader and assemble it into the
//! in-memory signing key.
//!
//! Replaces the legacy single-secret Secret-Manager fetch. The reconstructed
//! scalar is **never persisted** — it lives only inside the [`SigningKey`] for
//! the process lifetime (TDX-encrypted memory), and the transient share bytes are
//! zeroized by the reader and on assembly.
//!
//! The reader is **auth-agnostic**: the caller supplies the per-partner
//! Secret-Manager tokens (attested WIF federation, one per partner — see
//! `attestation.rs` / `cofhe_keys::gcp_auth`) and the compute-SA GCS token. This module
//! owns only the consumer-side glue: turning the verified, reconstructed
//! [`ZkSignerShare`] into a [`SigningKey`]. The gather, liar-filtering by per-share
//! digest, T-of-N reconstruction, and full-key-digest validation all live in
//! `cofhe-keys` (one shared, tested implementation) — not re-tested here. Share
//! authenticity comes from the partner write-gate; consumer-side provenance
//! verification was removed.

use anyhow::Result;
use cofhe_keys::serialization::ZkSignerShare;
use k256::ecdsa::SigningKey;
use zeroize::Zeroizing;

/// Expected length of the secp256k1 `zk_signer_priv` scalar.
const SIGNER_KEY_LEN: usize = 32;

/// Turn a verified + reconstructed [`ZkSignerShare`] into the in-memory signing
/// key. Consumes the share and wraps the secret bytes in [`Zeroizing`] up front
/// so every exit path — the length bail or success — drops them wiped.
pub fn assemble(share: ZkSignerShare) -> Result<SigningKey> {
    let priv_bytes = Zeroizing::new(share.zk_signer_priv);
    // The zk signer is contractually a 32-byte secp256k1 scalar (the producer
    // writes `SigningKey::to_bytes()`, fixed 32 B, and the reader validates the
    // reconstruction against the published full digest — so a healthy ceremony
    // always yields 32 B here). This guard is defense-in-depth: `k256::from_slice`
    // is lenient (it left-pads a short input into a *different* valid key — a wrong
    // signing address — rather than rejecting it), and the legacy single-secret
    // path had this explicit check (old main.rs), so keep it at the new seam.
    if priv_bytes.len() != SIGNER_KEY_LEN {
        anyhow::bail!(
            "zk_signer_priv must be {SIGNER_KEY_LEN} bytes, got {}",
            priv_bytes.len()
        );
    }
    SigningKey::from_slice(&priv_bytes)
        .map_err(|e| anyhow::anyhow!("constructing SigningKey from zk_signer_priv: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // The one seam this integration adds: a verified+reconstructed ZkSignerShare
    // decodes into the runtime signing key, and the scalar round-trips exactly (so
    // the derived signing identity is the reconstructed one, not a left-padded
    // stand-in).
    #[test]
    fn assemble_builds_signer() {
        let scalar = [0x11u8; SIGNER_KEY_LEN];
        let share = ZkSignerShare {
            zk_signer_priv: scalar.to_vec(),
        };
        let signer = assemble(share).expect("assemble");
        assert_eq!(signer.to_bytes()[..], scalar[..]);
    }

    // A malformed signer component (wrong length) is rejected, not silently
    // left-padded into a different valid key — the secp256k1 scalar must be
    // exactly 32 bytes.
    #[test]
    fn assemble_rejects_bad_len() {
        let share = ZkSignerShare {
            zk_signer_priv: vec![0x11u8; SIGNER_KEY_LEN - 1],
        };
        assert!(assemble(share).is_err());
    }
}
