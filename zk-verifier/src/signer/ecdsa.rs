//! Ciphertext signing extension for rust-common's Signer
//!
//! Re-exports the common Signer and adds zk-verifier specific ciphertext
//! signing functionality.

use k256::ecdsa::{RecoveryId, Signature};
use rust_common::log::trace;
// Re-export the common Signer
pub use rust_common::signing::Signer;
use rust_common::signing::{SigningError, SigningMessageBuilder};
use tfhe::FheTypes;

/// A per-ciphertext message hash: the 32-byte keccak256 commitment over
/// `(ct_hash, ct_type, sz, acc_addr, chain_id_padded, contract_addr)`.
///
/// Produced by [`SignCtExt::ct_message_hash`]. Signed on its own in the legacy
/// per-ciphertext flow, and folded into the single batch commitment in the batch
/// flow (see [`SignCtExt::sign_batch`]).
pub type CtMessageHash = [u8; 32];

/// Extension trait for signing ciphertexts
pub trait SignCtExt {
    /// Build the per-ciphertext message hash:
    /// `keccak256(ct_hash || ct_type || sz || acc_addr || chain_id_padded || contract_addr)`
    ///
    /// Where `chain_id_padded` is the chain_id as a 32-byte big-endian integer and
    /// `contract_addr` is the 20-byte address of the contract the input may be consumed by.
    /// The order must match `TaskManager.extractSigner`'s `abi.encodePacked`.
    ///
    /// This is the per-ciphertext commitment that both flows sign: on its own in
    /// the legacy flow, and folded into the single batch signature in the batch
    /// flow (see [`SignCtExt::sign_batch`]). Because the contract is bound here,
    /// the batch digest inherits the binding — there is no batch-level field.
    fn ct_message_hash(
        &self,
        ct_hash: &[u8],
        ct_type: FheTypes,
        sz: u8,
        acc_addr: &[u8],
        chain_id: u32,
        contract_addr: &[u8],
    ) -> CtMessageHash;

    /// Produce a single signature over a whole batch of ciphertexts.
    ///
    /// The batch message is the keccak256 of the concatenated per-ciphertext
    /// message hashes (in ciphertext order):
    /// `keccak256(hash_0 || hash_1 || ... || hash_n)`
    ///
    /// where each `hash_i` is produced by [`SignCtExt::ct_message_hash`].
    fn sign_batch(
        &self,
        ct_message_hashes: &[CtMessageHash],
    ) -> Result<(Signature, RecoveryId), SigningError>;
}

impl SignCtExt for Signer {
    fn ct_message_hash(
        &self,
        ct_hash: &[u8],
        ct_type: FheTypes,
        sz: u8,
        acc_addr: &[u8],
        chain_id: u32,
        contract_addr: &[u8],
    ) -> CtMessageHash {
        trace!(
            "Building ct message hash for account {:?} with type {:?} bound to contract {:?}",
            acc_addr,
            ct_type,
            contract_addr
        );

        // Build the chain_id as 32-byte padded big-endian
        let mut chain_id_bytes = [0u8; 32];
        chain_id_bytes[28..].copy_from_slice(&chain_id.to_be_bytes());

        // Build the message using SigningMessageBuilder. Field order must match
        // TaskManager.extractSigner's abi.encodePacked, with contract_addr appended last.
        let hash = SigningMessageBuilder::new()
            .add(ct_hash)
            .add(ct_type as u8)
            .add(sz)
            .add(acc_addr)
            .add(chain_id_bytes)
            .add(contract_addr)
            .build_hash();

        trace!("Generated ct message hash: 0x{}", hex::encode(hash));

        hash
    }

    fn sign_batch(
        &self,
        ct_message_hashes: &[CtMessageHash],
    ) -> Result<(Signature, RecoveryId), SigningError> {
        trace!("Signing batch of {} ciphertext hashes", ct_message_hashes.len());

        // Refuse the empty batch. Folding zero hashes would produce
        // keccak256("") — a constant, caller-independent digest — and signing it
        // would yield a signature a consumer could present as proof that an
        // empty batch was verified.
        if ct_message_hashes.is_empty() {
            return Err(SigningError::SigningFailed(
                "cannot sign an empty batch of ciphertexts".to_string(),
            ));
        }

        // Fold the per-ciphertext hashes into a single batch commitment:
        // keccak256(hash_0 || hash_1 || ... || hash_n)
        let mut builder = SigningMessageBuilder::new();
        for hash in ct_message_hashes {
            builder = builder.add(*hash);
        }
        let batch_hash = builder.build_hash();

        trace!("Generated batch message hash: 0x{}", hex::encode(batch_hash));

        self.sign_prehash(&batch_hash)
    }
}
#[cfg(test)]
mod tests {
    use tfhe::FheTypes;

    use super::*;

    #[test]
    fn test_ct_message_hash() {
        let signer = Signer::from_bytes(&[1u8; 32]).unwrap();

        let ct_hash = vec![1, 2, 3, 4];
        let ct_type = FheTypes::Bool;
        let sz = 0u8;
        let acc_addr = hex::decode("fff123").unwrap();
        let chain_id = 11155111u32;
        let contract_addr = hex::decode("00000000000000000000000000000000000000aa").unwrap();

        let hash =
            signer.ct_message_hash(&ct_hash, ct_type, sz, &acc_addr, chain_id, &contract_addr);

        // Deterministic for the same inputs
        assert_eq!(
            hash,
            signer.ct_message_hash(&ct_hash, ct_type, sz, &acc_addr, chain_id, &contract_addr)
        );

        // Different ct_hash produces a different message hash
        let other =
            signer.ct_message_hash(&[5, 6, 7, 8], ct_type, sz, &acc_addr, chain_id, &contract_addr);
        assert_ne!(hash, other);

        // A different consuming contract must produce a different message hash —
        // this is the binding that stops a verified input being replayed into
        // another contract.
        let other_contract = hex::decode("00000000000000000000000000000000000000bb").unwrap();
        let bound_elsewhere =
            signer.ct_message_hash(&ct_hash, ct_type, sz, &acc_addr, chain_id, &other_contract);
        assert_ne!(hash, bound_elsewhere);
    }

    #[test]
    fn test_sign_batch() {
        // Create a test signing key
        let signing_key_bytes = [1u8; 32];
        let signer = Signer::from_bytes(&signing_key_bytes).unwrap();

        let sz = 0u8;
        let acc_addr = hex::decode("fff123").unwrap();
        let chain_id = 11155111u32;
        let contract_addr = hex::decode("00000000000000000000000000000000000000aa").unwrap();

        let hash_a = signer.ct_message_hash(
            &[1, 2, 3, 4],
            FheTypes::Bool,
            sz,
            &acc_addr,
            chain_id,
            &contract_addr,
        );
        let hash_b = signer.ct_message_hash(
            &[5, 6, 7, 8],
            FheTypes::Uint64,
            sz,
            &acc_addr,
            chain_id,
            &contract_addr,
        );

        // Sign the batch
        let (signature, recovery_id) = signer.sign_batch(&[hash_a, hash_b]).unwrap();

        // Verify signature is non-zero and valid format
        assert!(!signature.to_bytes().iter().all(|&x| x == 0));
        assert!(recovery_id.to_byte() < 4);

        // A different batch (different membership / order) produces a different signature
        let (different_signature, _) = signer.sign_batch(&[hash_b, hash_a]).unwrap();
        assert_ne!(signature.to_bytes(), different_signature.to_bytes());

        // The contract binding carries through the fold: the same ciphertexts bound
        // to a different contract yield a different batch signature, without the
        // batch digest needing a contract field of its own.
        let other_contract = hex::decode("00000000000000000000000000000000000000bb").unwrap();
        let elsewhere_a = signer.ct_message_hash(
            &[1, 2, 3, 4],
            FheTypes::Bool,
            sz,
            &acc_addr,
            chain_id,
            &other_contract,
        );
        let elsewhere_b = signer.ct_message_hash(
            &[5, 6, 7, 8],
            FheTypes::Uint64,
            sz,
            &acc_addr,
            chain_id,
            &other_contract,
        );
        let (elsewhere_signature, _) = signer.sign_batch(&[elsewhere_a, elsewhere_b]).unwrap();
        assert_ne!(signature.to_bytes(), elsewhere_signature.to_bytes());
    }

    #[test]
    fn test_sign_batch_rejects_empty() {
        let signer = Signer::from_bytes(&[1u8; 32]).unwrap();

        // An empty batch has nothing to commit to: folding zero hashes yields
        // keccak256("") — a constant digest, identical for every caller, chain,
        // and account. Signing it would hand out a signature that a consumer
        // could present as "this empty batch was verified".
        let err = signer.sign_batch(&[]).expect_err("empty batch must not be signed");
        assert!(
            err.to_string().to_lowercase().contains("empty"),
            "error should say the batch was empty, got: {err}"
        );
    }

    #[test]
    fn test_signer_from_bytes() {
        let valid_bytes = [1u8; 32];
        let signer = Signer::from_bytes(&valid_bytes).unwrap();
        let key_bytes = signer.signing_key().to_bytes().to_vec();
        assert!(Signer::from_bytes(&key_bytes).is_ok());

        let valid_bytes = [2u8; 32];
        assert!(Signer::from_bytes(&valid_bytes).is_ok());
    }
}
