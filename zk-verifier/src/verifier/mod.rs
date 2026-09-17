pub mod error;
pub mod traits;

use k256::ecdsa::{RecoveryId, Signature};
use rust_common::log::{debug, error, info, trace};
use sha3::{Digest, Keccak256};
use tfhe::prelude::CiphertextList;
use tfhe::zk::CompactPkeCrs;
use tfhe::{CompactPublicKey, FheTypes, ProvenCompactCiphertextList};
use traits::SerializeIndex;

use crate::signer::ecdsa::{CtMessageHash, SignCtExt, Signer};
use crate::signer::evm_address::EvmAddress;
use crate::verifier::error::{Result, VerifierError};

/// A verified, expanded ciphertext together with the per-ciphertext commitment
/// computed for it: `keccak256(ct_hash || ct_type || sz || acc_addr ||
/// chain_id_padded || contract_addr)`. The batch signature folds these hashes in
/// order, so each one travels with the ciphertext it belongs to rather than in a
/// side vector.
pub struct VerifiedCt {
    pub ct_bytes: Vec<u8>,
    pub ct_type: FheTypes,
    pub ct_hash: Vec<u8>,
    pub message_hash: CtMessageHash,
}

/// Result of the batch signing flow.
///
/// The whole batch is covered by a single `signature` over
/// `keccak256(hash_0 || hash_1 || ... || hash_n)`, where each `hash_i` is the
/// per-ciphertext message hash (see `SignCtExt::ct_message_hash`).
pub struct VerifiedBatch {
    pub cts: Vec<VerifiedCt>,
    pub signature: Signature,
    pub recid: RecoveryId,
}

pub struct Verifier {
    pub pk: CompactPublicKey,
    pub crs: CompactPkeCrs,
    signer: Signer,
}

impl Verifier {
    pub fn new(crs: CompactPkeCrs, pk: CompactPublicKey, signer: Signer) -> Self {
        debug!("Creating new verifier instance");
        info!("Verifier initialized with signer address: {}", EvmAddress::from(&signer));

        Self { pk, crs, signer }
    }

    /// Verify the proof, expand the ciphertexts, and compute each ciphertext's
    /// per-ciphertext message hash.
    ///
    /// Returns the verified ciphertexts in submission order, each carrying its own
    /// `message_hash`.
    fn verify_and_expand(
        &self,
        proven_cts: ProvenCompactCiphertextList,
        account_addr: &str,
        security_zone: u8,
        chain_id: u32,
        contract_addr: &str,
    ) -> Result<Vec<VerifiedCt>> {
        let log_context = format!(
            "account: {}, security zone: {}, chain id: {}, contract: {}",
            account_addr, security_zone, chain_id, contract_addr
        );
        debug!("Starting verification for {}", log_context);
        let account_addr_bytes =
            hex::decode(account_addr.strip_prefix("0x").unwrap_or(account_addr))?;
        trace!("Decoded account address: {} bytes: {:?}", account_addr, account_addr_bytes);
        let contract_addr_bytes =
            hex::decode(contract_addr.strip_prefix("0x").unwrap_or(contract_addr))?;
        let metadata = Self::reconstruct_metadata(&account_addr_bytes, security_zone, chain_id);
        trace!("Reconstructed metadata: {:?}", metadata);

        let expander = {
            let _t = crate::telemetry::StepTimer::start("verify_and_expand");
            proven_cts.verify_and_expand(&self.crs, &self.pk, &metadata).map_err(|e| {
                error!("Failed to verify packed list: {}", e);
                VerifierError::ProofVerificationError(format!(
                    "could not verify packed list: {}",
                    e
                ))
            })?
        };

        debug!(
            "Successfully verified proof, processing {} ciphertexts for {}",
            expander.len(),
            log_context
        );
        // expand + hash are timed separately and accumulated across ciphertexts,
        // then recorded once per request after the loop (telemetry::record_step).
        let mut expand_elapsed = std::time::Duration::ZERO;
        let mut hash_elapsed = std::time::Duration::ZERO;
        let mut verified_cts = vec![];
        for i in 0..expander.len() {
            trace!("Processing ciphertext {}/{} for {}", i + 1, expander.len(), log_context);
            let expand_start = std::time::Instant::now();
            let (ct_type, ct_bytes) = expander
                .serialize_index(i)
                .map_err(|e| {
                    error!(
                        "Failed to expand ciphertext {}/{} for {}: {}",
                        i + 1,
                        expander.len(),
                        log_context,
                        e
                    );
                    VerifierError::InvalidInput(format!(
                        "unable to expand ct, index={} err={}",
                        i, e
                    ))
                })?
                .ok_or_else(|| {
                    error!(
                        "Missing ciphertext at index {}/{} for {}",
                        i + 1,
                        expander.len(),
                        log_context
                    );
                    VerifierError::InvalidInput(format!("could not get ct, index={}", i))
                })?;
            expand_elapsed += expand_start.elapsed();

            let hash_start = std::time::Instant::now();
            let ct_hash: [u8; 32] = Keccak256::digest(&ct_bytes).into();
            let ct_hash = ct_hash.to_vec();
            trace!(
                "Generated hash for ciphertext {}/{} for {}: 0x{}",
                i + 1,
                expander.len(),
                log_context,
                hex::encode(&ct_hash)
            );

            let message_hash = self.signer.ct_message_hash(
                &ct_hash,
                ct_type,
                security_zone,
                &account_addr_bytes,
                chain_id,
                &contract_addr_bytes,
            );
            hash_elapsed += hash_start.elapsed();

            verified_cts.push(VerifiedCt { ct_bytes, ct_type, ct_hash, message_hash });
        }
        crate::telemetry::record_step("expand", expand_elapsed);
        // "hash", not "sign": building the per-ct commitments is all that happens
        // here. The signing itself is timed in verify_and_sign_batch below, where
        // sign_batch is actually called.
        crate::telemetry::record_step("hash", hash_elapsed);

        Ok(verified_cts)
    }

    /// Batch flow: verify and produce a **single signature** over the whole batch.
    ///
    /// The signature covers `keccak256(hash_0 || hash_1 || ... || hash_n)`, where
    /// each `hash_i` is the per-ciphertext message hash. Since each `hash_i`
    /// already binds `contract_addr`, the batch digest inherits that binding.
    #[metrics_utils_macros::measured_function()]
    pub fn verify_and_sign_batch(
        &self,
        proven_cts: ProvenCompactCiphertextList,
        account_addr: &str,
        security_zone: u8,
        chain_id: u32,
        contract_addr: &str,
    ) -> Result<VerifiedBatch> {
        let cts = self.verify_and_expand(
            proven_cts,
            account_addr,
            security_zone,
            chain_id,
            contract_addr,
        )?;

        // Sign the whole batch with a single signature over
        // keccak256(hash_0 || hash_1 || ... || hash_n).
        let (signature, recid) = {
            let _t = crate::telemetry::StepTimer::start("sign");
            let ct_message_hashes: Vec<CtMessageHash> =
                cts.iter().map(|ct| ct.message_hash).collect();
            self.signer.sign_batch(&ct_message_hashes)?
        };
        debug!("Signed batch of {} ciphertexts", cts.len());

        Ok(VerifiedBatch { cts, signature, recid })
    }

    pub fn reconstruct_metadata(account_addr: &[u8], security_zone: u8, chain_id: u32) -> Vec<u8> {
        trace!(
            "Reconstructing metadata for account {:?} with security zone {} and chain id {}",
            account_addr,
            security_zone,
            chain_id
        );

        let mut chain_id_bytes = [0u8; 32];
        chain_id_bytes[28..].copy_from_slice(&chain_id.to_be_bytes());

        let mut metadata_bytes = Vec::new();
        metadata_bytes.push(security_zone);
        metadata_bytes.extend_from_slice(account_addr);
        metadata_bytes.extend_from_slice(&chain_id_bytes);
        metadata_bytes
    }

    pub fn get_signer_evm_address(&self) -> EvmAddress {
        (&self.signer).into()
    }
}

#[cfg(feature = "mock-keys")]
use tfhe::shortint::{
    parameters::{CompactPublicKeyEncryptionParameters, ShortintKeySwitchingParameters},
    ClassicPBSParameters,
};

#[cfg(feature = "mock-keys")]
impl Verifier {
    pub const PARAMS: ClassicPBSParameters =
        tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    pub const CPK_PARAMS: CompactPublicKeyEncryptionParameters = tfhe::shortint::parameters::v0_11::compact_public_key_only::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    pub const CASTING_PARAMS: ShortintKeySwitchingParameters = tfhe::shortint::parameters::v0_11::key_switching::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
}

#[cfg(test)]
mod tests {
    use k256::ecdsa::hazmat::DigestPrimitive;
    use k256::sha2::Digest;
    use k256::Secp256k1;
    use rand::RngCore;
    use sha3::Keccak256;
    use signature::hazmat::PrehashVerifier;
    use tfhe::zk::ZkComputeLoad;
    use tfhe::{set_server_key, CompactPublicKey, CompressedFheUint64, FheTypes, ServerKey};

    use super::*;

    #[test]
    fn test_reconstruct_metadata() {
        let account_addr = "0xfff123";
        let account_addr_bytes =
            hex::decode(account_addr.strip_prefix("0x").unwrap_or(account_addr)).unwrap();
        let security_zone = 0u8;
        let chain_id = 11155111u32;
        let mut chain_id_bytes = [0u8; 32]; // Initialize 256-bit array
        chain_id_bytes[28..].copy_from_slice(&chain_id.to_be_bytes()); // Place 11155111 in last 4 bytes
        let mut metadata = Vec::new();
        metadata.push(security_zone);
        metadata.extend_from_slice(&account_addr_bytes);
        metadata.extend_from_slice(&chain_id_bytes);
        assert_eq!(
            Verifier::reconstruct_metadata(&account_addr_bytes, security_zone, chain_id),
            metadata
        );
    }

    #[test]
    fn test_verify_and_sign_batch() {
        let (crs, server_key, public_key) = setup_tfhers();

        let account_addr = "0xfff123";
        let account_addr_bytes =
            hex::decode(account_addr.strip_prefix("0x").unwrap_or(account_addr)).unwrap();
        let contract_addr = "0x00000000000000000000000000000000000000aa";
        let contract_addr_bytes =
            hex::decode(contract_addr.strip_prefix("0x").unwrap_or(contract_addr)).unwrap();
        let security_zone = 0u8;
        let chain_id = 11155111u32;
        let metadata = Verifier::reconstruct_metadata(&account_addr_bytes, security_zone, chain_id);

        let proven_batch = create_proven_list(&public_key, &crs, &metadata);

        set_server_key(server_key);
        let signer = Signer::from_bytes(&[1u8; 32]).unwrap();
        let verifier = crate::verifier::Verifier::new(crs.clone(), public_key.clone(), signer);
        let verifying_key = verifier.signer.signing_key().verifying_key();

        let batch = verifier
            .verify_and_sign_batch(
                proven_batch,
                account_addr,
                security_zone,
                chain_id,
                contract_addr,
            )
            .unwrap();
        assert_eq!(batch.cts.len(), 2);

        // The ciphertexts really did expand, and each carries the message hash the
        // batch digest was folded from.
        let ct_0 = &batch.cts[0].ct_bytes;
        let _fhe_u64: CompressedFheUint64 = rust_common::safe_serde::deserialize(ct_0.as_slice())
            .expect("failed to safe_deserialize CT");
        assert_eq!(batch.cts[0].ct_type, FheTypes::Uint64);

        for ct in &batch.cts {
            let ct_hash: [u8; 32] = Keccak256::digest(&ct.ct_bytes).into();
            let expected = create_message_to_sign(
                &ct_hash,
                ct.ct_type as u8,
                security_zone,
                &account_addr_bytes,
                chain_id,
                &contract_addr_bytes,
            );
            assert_eq!(
                ct.message_hash, expected,
                "message_hash on the ct must be the independently reconstructed hash"
            );
        }

        // Reconstruct the batch digest: keccak256(hash_0 || hash_1 || ...),
        // where each hash_i is the per-ciphertext message hash — contract included.
        let batch_hash = create_batch_hash(
            &batch.cts,
            security_zone,
            &account_addr_bytes,
            chain_id,
            &contract_addr_bytes,
        );

        // The single signature verifies against the batch digest.
        assert!(verifying_key.verify_prehash(&batch_hash, &batch.signature).is_ok());

        // The contract binding reaches the batch digest: rebuilding it for a
        // different consuming contract yields a digest the batch signature does
        // not cover, so a verified batch cannot be replayed into another contract.
        let other_contract = hex::decode("00000000000000000000000000000000000000bb").unwrap();
        let bound_elsewhere = create_batch_hash(
            &batch.cts,
            security_zone,
            &account_addr_bytes,
            chain_id,
            &other_contract,
        );
        assert_ne!(bound_elsewhere, batch_hash);
        assert!(verifying_key.verify_prehash(&bound_elsewhere, &batch.signature).is_err());

        // Also verify "EVM style"
        let recovered_key = k256::ecdsa::VerifyingKey::recover_from_prehash(
            &batch_hash,
            &batch.signature,
            batch.recid,
        )
        .unwrap();
        assert_eq!(recovered_key, *verifying_key);

        // Tampering with the batch digest breaks verification.
        let mut tampered = batch_hash;
        tampered[0] ^= 1; // flip a bit
        assert!(verifying_key.verify_prehash(&tampered, &batch.signature).is_err());
        // Also verify "EVM style"
        let recovered_key = k256::ecdsa::VerifyingKey::recover_from_digest(
            <Secp256k1 as DigestPrimitive>::Digest::new_with_prefix(&tampered),
            &batch.signature,
            batch.recid,
        )
        .unwrap();
        assert_ne!(recovered_key, *verifying_key);
    }

    fn setup_tfhers() -> (CompactPkeCrs, ServerKey, CompactPublicKey) {
        let params = tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
        let cpk_params = tfhe::shortint::parameters::v0_11::compact_public_key_only::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
        let casting_params = tfhe::shortint::parameters::v0_11::key_switching::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

        let config = tfhe::ConfigBuilder::with_custom_parameters(params)
            .use_dedicated_compact_public_key_parameters((cpk_params, casting_params))
            .build();

        let crs = CompactPkeCrs::from_config(config, 64).unwrap();
        let client_key = tfhe::ClientKey::generate(config);
        let server_key = tfhe::ServerKey::new(&client_key);
        let public_key = tfhe::CompactPublicKey::try_new(&client_key).unwrap();

        (crs, server_key, public_key)
    }

    fn create_proven_list(
        public_key: &CompactPublicKey,
        crs: &CompactPkeCrs,
        metadata: &[u8],
    ) -> ProvenCompactCiphertextList {
        let mut rng = rand::thread_rng();
        let clear_a = rng.next_u64();
        let clear_b = rng.next_u64();

        tfhe::ProvenCompactCiphertextList::builder(public_key)
            .push(clear_a)
            .push(clear_b)
            .build_with_proof_packed(crs, &metadata, ZkComputeLoad::Verify)
            .unwrap()
    }

    fn create_message_to_sign(
        ct_hash: &[u8],
        ct_type: u8,
        security_zone: u8,
        account_addr: &[u8],
        chain_id: u32,
        contract_addr: &[u8],
    ) -> [u8; 32] {
        let mut chain_id_bytes = [0u8; 32]; // Initialize 256-bit array
        chain_id_bytes[28..].copy_from_slice(&chain_id.to_be_bytes()); // Place 11155111 in last 4 bytes

        let mut hasher = Keccak256::new();
        hasher.update(ct_hash);
        hasher.update([ct_type]);
        hasher.update([security_zone]);
        hasher.update(account_addr);
        hasher.update(chain_id_bytes);
        hasher.update(contract_addr);
        hasher.finalize().into()
    }

    /// Reconstruct the batch digest the way a consumer would:
    /// keccak256(hash_0 || hash_1 || ... || hash_n), where each hash_i is the
    /// per-ciphertext message hash over
    /// (ct_hash, ct_type, sz, acc_addr, chain_id, contract_addr).
    fn create_batch_hash(
        cts: &[VerifiedCt],
        security_zone: u8,
        account_addr: &[u8],
        chain_id: u32,
        contract_addr: &[u8],
    ) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        for ct in cts {
            let ct_hash: [u8; 32] = Keccak256::digest(&ct.ct_bytes).into();
            let message_hash = create_message_to_sign(
                &ct_hash,
                ct.ct_type as u8,
                security_zone,
                account_addr,
                chain_id,
                contract_addr,
            );
            hasher.update(message_hash);
        }
        hasher.finalize().into()
    }
}
