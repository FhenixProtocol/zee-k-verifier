//! Standalone verification script for fetching and verifying ciphertexts from GCS
//!
//! This script is completely standalone and does not depend on any zk-verifier service code.
//! It uses only TFHE.rs and standard libraries for verification.
//!
//! This script:
//! 1. Takes a ct_hash as input
//! 2. Fetches the StoredCiphertext from GCS
//! 3. Fetches the associated StoredProof from GCS
//! 4. Verifies the proof using TFHE.rs directly
//! 5. Compares the ct_hash with stored values
//! 6. Outputs the result in human-readable or JSON format

use std::process;

use clap::Parser;
use google_cloud_storage::client::Storage;
use rust_common::log::{debug, error, info};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use tfhe::prelude::*;
use tfhe::zk::CompactPkeCrs;
use tfhe::{CompactPublicKey, CompressedServerKey, ServerKey};
use tfhe_versionable::Unversionize;

// ============================================================================
// Constants
// ============================================================================

const SHARD_PREFIX_LENGTH: usize = 4;

// Constants for hash adjustment (matching fhe-engine)
const TRIVIAL_ENCRYPT_AND_TYPE_BYTE: usize = 30;
const SECURITY_ZONE_BYTE: usize = 31;
const TYPE_MASK: u8 = 0x7F; // 0b01111111 - lowest 7 bits
const TRIVIAL_ENCRYPT_FLAG: u8 = 0x80; // 0b10000000 - highest bit

// ============================================================================
// Configuration Types (Inlined from zk_verifier)
// ============================================================================

#[derive(Debug, Deserialize, Clone)]
struct Config {
    keys: KeyConfig,
    storage: Option<StorageConfig>,
}

#[derive(Debug, Deserialize, Clone)]
struct KeyConfig {
    crs_path: String,
    pk_path: String,
    sk_path: String,
}

#[derive(Debug, Deserialize, Clone)]
struct StorageConfig {
    bucket: String,
}

// ============================================================================
// Storage Types (Inlined from zk_verifier::storage::types)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CtMetadata {
    ct_hash: String,
    proof_id: String,
    account_addr: String,
    security_zone: u8,
    chain_id: u32,
    ct_index: usize,
    ct_type: u8,
    timestamp: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredCiphertext {
    metadata: CtMetadata,
    ct_data: Vec<u8>,
}

impl StoredCiphertext {
    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        bincode::deserialize(bytes)
            .map_err(|e| format!("Failed to deserialize StoredCiphertext: {}", e))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProofMetadata {
    proof_id: String,
    account_addr: String,
    security_zone: u8,
    chain_id: u32,
    ct_hashes: Vec<String>,
    ct_count: usize,
    timestamp: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredProof {
    metadata: ProofMetadata,
    proof_data: Vec<u8>,
}

impl StoredProof {
    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        bincode::deserialize(bytes).map_err(|e| format!("Failed to deserialize StoredProof: {}", e))
    }
}

// ============================================================================
// Path Generation (Inlined from zk_verifier::storage::gcs)
// ============================================================================

/// Generate the object key path for a given key with hardcoded sharding
fn generate_object_key(
    key: &str,
    base_path: &Option<String>,
    dynamic_path: Option<&str>,
) -> String {
    // Clean any 0x prefix
    let clean_key = key.strip_prefix("0x").unwrap_or(key);

    // Apply hardcoded prefix sharding using first SHARD_PREFIX_LENGTH characters
    let sharded_path = if clean_key.len() >= SHARD_PREFIX_LENGTH {
        let prefix = &clean_key[0..SHARD_PREFIX_LENGTH];
        format!("{}/{}", prefix, clean_key)
    } else {
        // Key is shorter than prefix length, use key itself as prefix
        format!("{}/{}", clean_key, clean_key)
    };

    // Build final path: base_path / dynamic_path / sharded_path
    let mut path_parts = Vec::new();

    if let Some(base) = base_path {
        path_parts.push(base.as_str());
    }

    if let Some(dynamic) = dynamic_path {
        path_parts.push(dynamic);
    }

    path_parts.push(&sharded_path);

    path_parts.join("/")
}

// ============================================================================
// Verification Logic (Using TFHE.rs directly)
// ============================================================================

struct VerifiedCt {
    ct_hash: [u8; 32],
}

// Trait for serializing ciphertexts from expander
trait SerializeFromExpander {
    fn serialize(
        expander: &tfhe::CompactCiphertextListExpander,
        index: usize,
    ) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>>;
}

macro_rules! impl_serialize_from_expander {
    ($($t:ty),*) => {
        $(
            impl SerializeFromExpander for $t {
                fn serialize(
                    expander: &tfhe::CompactCiphertextListExpander,
                    index: usize,
                ) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
                    let mut buf = vec![];
                    let ct = match expander.get::<$t>(index)? {
                        Some(ct) => ct,
                        None => return Ok(None),
                    };
                    let ct = ct.compress();

                    bincode::serialize_into(&mut buf, &ct)?;
                    Ok(Some(buf))
                }
            }
        )*
    };
}

impl_serialize_from_expander!(
    tfhe::FheBool,
    tfhe::FheUint4,
    tfhe::FheUint8,
    tfhe::FheUint16,
    tfhe::FheUint32,
    tfhe::FheUint64,
    tfhe::FheUint128,
    tfhe::FheUint160,
    tfhe::FheUint256,
    tfhe::FheUint512,
    tfhe::FheUint1024,
    tfhe::FheUint2048,
    tfhe::FheUint2,
    tfhe::FheUint6,
    tfhe::FheUint10,
    tfhe::FheUint12,
    tfhe::FheUint14,
    tfhe::FheInt2,
    tfhe::FheInt4,
    tfhe::FheInt6,
    tfhe::FheInt8,
    tfhe::FheInt10,
    tfhe::FheInt12,
    tfhe::FheInt14,
    tfhe::FheInt16,
    tfhe::FheInt32,
    tfhe::FheInt64,
    tfhe::FheInt128,
    tfhe::FheInt160,
    tfhe::FheInt256
);

trait SerializeIndex {
    #[allow(clippy::type_complexity)]
    fn serialize_index(
        &self,
        index: usize,
    ) -> Result<Option<(tfhe::FheTypes, Vec<u8>)>, Box<dyn std::error::Error>>;
}

impl SerializeIndex for tfhe::CompactCiphertextListExpander {
    fn serialize_index(
        &self,
        index: usize,
    ) -> Result<Option<(tfhe::FheTypes, Vec<u8>)>, Box<dyn std::error::Error>> {
        let ct_type = match self.get_kind_of(index) {
            Some(ct_type) => ct_type,
            None => return Ok(None),
        };

        match ct_type {
            tfhe::FheTypes::Bool => {
                <tfhe::FheBool as SerializeFromExpander>::serialize(self, index)
            }
            tfhe::FheTypes::Uint4 => {
                <tfhe::FheUint4 as SerializeFromExpander>::serialize(self, index)
            }
            tfhe::FheTypes::Uint8 => {
                <tfhe::FheUint8 as SerializeFromExpander>::serialize(self, index)
            }
            tfhe::FheTypes::Uint16 => {
                <tfhe::FheUint16 as SerializeFromExpander>::serialize(self, index)
            }
            tfhe::FheTypes::Uint32 => {
                <tfhe::FheUint32 as SerializeFromExpander>::serialize(self, index)
            }
            tfhe::FheTypes::Uint64 => {
                <tfhe::FheUint64 as SerializeFromExpander>::serialize(self, index)
            }
            tfhe::FheTypes::Uint128 => {
                <tfhe::FheUint128 as SerializeFromExpander>::serialize(self, index)
            }
            tfhe::FheTypes::Uint160 => {
                <tfhe::FheUint160 as SerializeFromExpander>::serialize(self, index)
            }
            tfhe::FheTypes::Uint256 => {
                <tfhe::FheUint256 as SerializeFromExpander>::serialize(self, index)
            }
            tfhe::FheTypes::Uint512 => {
                <tfhe::FheUint512 as SerializeFromExpander>::serialize(self, index)
            }
            tfhe::FheTypes::Uint1024 => {
                <tfhe::FheUint1024 as SerializeFromExpander>::serialize(self, index)
            }
            tfhe::FheTypes::Uint2048 => {
                <tfhe::FheUint2048 as SerializeFromExpander>::serialize(self, index)
            }
            tfhe::FheTypes::Uint2 => {
                <tfhe::FheUint2 as SerializeFromExpander>::serialize(self, index)
            }
            tfhe::FheTypes::Uint6 => {
                <tfhe::FheUint6 as SerializeFromExpander>::serialize(self, index)
            }
            tfhe::FheTypes::Uint10 => {
                <tfhe::FheUint10 as SerializeFromExpander>::serialize(self, index)
            }
            tfhe::FheTypes::Uint12 => {
                <tfhe::FheUint12 as SerializeFromExpander>::serialize(self, index)
            }
            tfhe::FheTypes::Uint14 => {
                <tfhe::FheUint14 as SerializeFromExpander>::serialize(self, index)
            }
            tfhe::FheTypes::Int2 => {
                <tfhe::FheInt2 as SerializeFromExpander>::serialize(self, index)
            }
            tfhe::FheTypes::Int4 => {
                <tfhe::FheInt4 as SerializeFromExpander>::serialize(self, index)
            }
            tfhe::FheTypes::Int6 => {
                <tfhe::FheInt6 as SerializeFromExpander>::serialize(self, index)
            }
            tfhe::FheTypes::Int8 => {
                <tfhe::FheInt8 as SerializeFromExpander>::serialize(self, index)
            }
            tfhe::FheTypes::Int10 => {
                <tfhe::FheInt10 as SerializeFromExpander>::serialize(self, index)
            }
            tfhe::FheTypes::Int12 => {
                <tfhe::FheInt12 as SerializeFromExpander>::serialize(self, index)
            }
            tfhe::FheTypes::Int14 => {
                <tfhe::FheInt14 as SerializeFromExpander>::serialize(self, index)
            }
            tfhe::FheTypes::Int16 => {
                <tfhe::FheInt16 as SerializeFromExpander>::serialize(self, index)
            }
            tfhe::FheTypes::Int32 => {
                <tfhe::FheInt32 as SerializeFromExpander>::serialize(self, index)
            }
            tfhe::FheTypes::Int64 => {
                <tfhe::FheInt64 as SerializeFromExpander>::serialize(self, index)
            }
            tfhe::FheTypes::Int128 => {
                <tfhe::FheInt128 as SerializeFromExpander>::serialize(self, index)
            }
            tfhe::FheTypes::Int160 => {
                <tfhe::FheInt160 as SerializeFromExpander>::serialize(self, index)
            }
            tfhe::FheTypes::Int256 => {
                <tfhe::FheInt256 as SerializeFromExpander>::serialize(self, index)
            }
            other => Err(format!("Unsupported FHE type: {:?}", other).into()),
        }
        .map(|ct| ct.map(|ct| (ct_type, ct)))
    }
}

/// Reconstruct metadata for proof verification (matching TFHE.rs expectations)
fn reconstruct_metadata(account_addr: &[u8], security_zone: u8, chain_id: u32) -> Vec<u8> {
    let mut chain_id_bytes = [0u8; 32];
    chain_id_bytes[28..].copy_from_slice(&chain_id.to_be_bytes());

    let mut metadata_bytes = Vec::new();
    metadata_bytes.push(security_zone);
    metadata_bytes.extend_from_slice(account_addr);
    metadata_bytes.extend_from_slice(&chain_id_bytes);

    metadata_bytes
}

/// Verify a ProvenCompactCiphertextList and extract CT hashes
fn verify_and_extract_hashes(
    proven_list: tfhe::ProvenCompactCiphertextList,
    public_key: &CompactPublicKey,
    crs: &CompactPkeCrs,
    account_addr: &str,
    security_zone: u8,
    chain_id: u32,
) -> Result<Vec<VerifiedCt>, String> {
    // Convert account address to bytes (remove 0x prefix if present)
    let account_bytes = hex::decode(account_addr.strip_prefix("0x").unwrap_or(account_addr))
        .map_err(|e| format!("Invalid account address: {}", e))?;

    if account_bytes.len() != 20 {
        return Err(format!("Account address must be 20 bytes, got {}", account_bytes.len()));
    }

    // Reconstruct metadata for verification
    let metadata = reconstruct_metadata(&account_bytes, security_zone, chain_id);

    // Verify the ZK proof and expand in one step
    let expander = proven_list
        .verify_and_expand(crs, public_key, &metadata)
        .map_err(|e| format!("ZK proof verification failed: {:?}", e))?;

    info!("ZK proof verified successfully, processing {} ciphertexts", expander.len());

    let mut verified_cts = Vec::new();

    // Process each ciphertext
    for index in 0..expander.len() {
        // Get serialized ciphertext with type
        let (_ct_type, ct_bytes) = expander
            .serialize_index(index)
            .map_err(|e| format!("Failed to expand ciphertext at index {}: {}", index, e))?
            .ok_or_else(|| format!("Missing ciphertext at index {}", index))?;

        // Hash: Keccak256(ct_bytes)
        let ct_hash: [u8; 32] = Keccak256::digest(&ct_bytes).into();

        verified_cts.push(VerifiedCt { ct_hash });
    }

    Ok(verified_cts)
}

/// Adjust hash to embed metadata (encryption type, security zone, trivially encrypted flag)
/// Equivalent to Go's adjustHashForMetadata function in fheos/operations/operations.go
fn adjust_hash_for_metadata(
    mut hash: [u8; 32],
    uint_type: u8,
    security_zone: u8,
    is_trivially_encrypted: bool,
) -> [u8; 32] {
    // Set byte[30]: lowest 7 bits for uintType, highest bit for isTriviallyEncrypted flag
    hash[TRIVIAL_ENCRYPT_AND_TYPE_BYTE] = uint_type & TYPE_MASK;
    if is_trivially_encrypted {
        hash[TRIVIAL_ENCRYPT_AND_TYPE_BYTE] |= TRIVIAL_ENCRYPT_FLAG;
    }

    // Set byte[31]: security zone
    hash[SECURITY_ZONE_BYTE] = security_zone;

    hash
}

// ============================================================================
// Key Loading (Inlined from zk_verifier::keys)
// ============================================================================

fn load_keys(key_config: &KeyConfig) -> (CompactPkeCrs, CompactPublicKey, ServerKey) {
    let crs_bytes = std::fs::read(&key_config.crs_path).expect("Failed to read CRS file");
    info!("1/4 CRS file read successfully");
    let crs: CompactPkeCrs =
        deserialize_versionized(&crs_bytes).expect("Failed to deserialize CRS");
    info!("1/4 CRS deserialized successfully");

    let pk_bytes = std::fs::read(&key_config.pk_path).expect("Failed to read public key file");
    info!("2/4 Public key file read successfully");
    let pk: CompactPublicKey =
        deserialize_versionized(&pk_bytes).expect("Failed to deserialize public key");
    info!("2/4 Public key deserialized successfully");

    let sk_bytes = std::fs::read(&key_config.sk_path).expect("Failed to read server key file");
    info!("3/4 Server key file read successfully");
    let compressed_server_key: CompressedServerKey =
        deserialize_versionized(&sk_bytes).expect("Failed to deserialize server key");
    info!("3/4 Server key deserialized successfully");
    let server_key = compressed_server_key.decompress();
    info!("3/3 Server key decompressed successfully");

    (crs, pk, server_key)
}

fn deserialize_versionized<T>(bytes: &[u8]) -> Result<T, String>
where
    T: Unversionize + for<'de> serde::Deserialize<'de> + tfhe::named::Named,
{
    rust_common::safe_serde::deserialize(bytes).map_err(|e| format!("safe_deserialize failed: {e}"))
}

// ============================================================================
// Configuration Loading
// ============================================================================

fn load_config(config_path: &str) -> Result<Config, String> {
    use config::{Config as ConfigBuilder, File};

    let builder = ConfigBuilder::builder()
        .set_default("keys.crs_path", "./keys/crs")
        .unwrap()
        .set_default("keys.pk_path", "./keys/pk")
        .unwrap()
        .set_default("keys.sk_path", "./keys/sk")
        .unwrap()
        .set_default("storage.bucket", "")
        .unwrap()
        .add_source(File::with_name(config_path));

    builder
        .build()
        .map_err(|e| format!("Failed to load config: {}", e))?
        .try_deserialize()
        .map_err(|e| format!("Failed to deserialize config: {}", e))
}

// ============================================================================
// CLI and Main Logic
// ============================================================================

/// Verification script for ciphertexts stored in GCS
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// CT hash to verify (e.g., 0xabc123...)
    #[arg(value_name = "CT_HASH")]
    ct_hash: String,

    /// Chain ID where the CT is stored
    #[arg(value_name = "CHAIN_ID")]
    chain_id: u32,

    /// Output format as JSON
    #[arg(short, long)]
    json: bool,

    /// Path to configuration file
    #[arg(short, long, default_value = "../config/local/config.toml")]
    config: String,
}

/// Result structure for JSON output
#[derive(Serialize)]
struct VerificationResult {
    status: String,
    ct_hash: String,
    proof_id: String,
    metadata: MetadataOutput,
    verification: VerificationDetails,
}

#[derive(Serialize)]
struct MetadataOutput {
    account_addr: String,
    security_zone: u8,
    chain_id: u32,
    ct_index: usize,
    ct_type: u8,
    timestamp: String,
}

#[derive(Serialize)]
struct VerificationDetails {
    proof_valid: bool,
    ct_hash_matches: bool,
}

#[tokio::main]
async fn main() {
    // Initialize logger with default config
    rust_common::logger::init_default_logger("verify-ct").expect("Failed to initialize logger");

    let args = Args::parse();

    // Load configuration
    if !args.json {
        println!("Loading configuration from {}...", args.config);
    }

    let config = match load_config(&args.config) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            eprintln!("Error: Failed to load configuration: {}", e);
            process::exit(1);
        }
    };

    // Verify storage configuration exists
    let storage_config = match config.storage {
        Some(ref cfg) => cfg,
        None => {
            error!("No storage configuration found in config file");
            eprintln!("Error: No storage configuration found in config file");
            process::exit(1);
        }
    };

    if !args.json {
        println!(
            "Fetching CT {} from GCS bucket {} (chain_id: {})...",
            args.ct_hash, storage_config.bucket, args.chain_id
        );
    }

    // Run the verification
    match run_verification(&args.ct_hash, args.chain_id, &config).await {
        Ok(result) => {
            if args.json {
                println!("{}", serde_json::to_string_pretty(&result).unwrap());
            } else {
                print_human_readable(&result);
            }
            process::exit(0);
        }
        Err(e) => {
            error!("Verification failed: {}", e);
            if args.json {
                let error_result = serde_json::json!({
                    "status": "error",
                    "error": e,
                });
                println!("{}", serde_json::to_string_pretty(&error_result).unwrap());
            } else {
                eprintln!("\n✗ Verification FAILED: {}", e);
            }
            process::exit(1);
        }
    }
}

async fn run_verification(
    ct_hash: &str,
    chain_id: u32,
    config: &Config,
) -> Result<VerificationResult, String> {
    let storage_config = config.storage.as_ref().ok_or("No storage configuration")?;

    // Parse the provided hash and extract metadata from it
    let provided_hash = ct_hash.strip_prefix("0x").unwrap_or(ct_hash);
    let provided_hash_bytes =
        hex::decode(provided_hash).map_err(|e| format!("Invalid CT hash format: {}", e))?;

    if provided_hash_bytes.len() != 32 {
        return Err(format!("CT hash must be 32 bytes, got {}", provided_hash_bytes.len()));
    }

    // Extract metadata from the provided hash (bytes 30-31)
    let security_zone = provided_hash_bytes[SECURITY_ZONE_BYTE];
    let type_and_flag_byte = provided_hash_bytes[TRIVIAL_ENCRYPT_AND_TYPE_BYTE];
    let is_trivially_encrypted = (type_and_flag_byte & TRIVIAL_ENCRYPT_FLAG) != 0;
    let ct_type = type_and_flag_byte & TYPE_MASK;

    info!(
        "Extracted from hash: security_zone={}, ct_type={}, trivially_encrypted={}",
        security_zone, ct_type, is_trivially_encrypted
    );

    // Initialize GCS client (always ADC; in dev, `GCE_METADATA_HOST` points
    // the auth library at a mock metadata server).
    debug!("Initializing GCS client...");
    let storage = Storage::builder()
        .build()
        .await
        .map_err(|e| format!("Failed to create GCS client: {}", e))?;
    let parent = format!("projects/_/buckets/{}", storage_config.bucket);

    // Load FHE keys
    info!("Loading FHE keys from {:?}", config.keys);
    let (crs, pk, server_key) = load_keys(&config.keys);

    // Set the server key for TFHE operations (required for proof verification)
    tfhe::set_server_key(server_key);

    // Fetch CT using the provided hash (adjusted hash is the storage key) and extracted security zone
    let stored_ct = fetch_ciphertext(
        &storage,
        &parent,
        ct_hash, // Use the provided hash directly as the storage key
        chain_id,
        security_zone,
    )
    .await
    .map_err(|e| format!("Failed to fetch ciphertext: {}", e))?;

    info!("Found CT in security zone {}", security_zone);

    info!("Found CT with proof_id: {}", stored_ct.metadata.proof_id);

    // First, let's verify that the stored CT data hashes to what's in the metadata
    let stored_ct_hash_raw: [u8; 32] = Keccak256::digest(&stored_ct.ct_data).into();

    let adjusted_stored_hash = adjust_hash_for_metadata(
        stored_ct_hash_raw,
        stored_ct.metadata.ct_type,
        stored_ct.metadata.security_zone,
        is_trivially_encrypted,
    );

    let computed_hash_from_storage = format!("0x{}", hex::encode(adjusted_stored_hash));
    info!(
        "Hash of stored CT data: raw=0x{}, adjusted={}",
        hex::encode(stored_ct_hash_raw),
        computed_hash_from_storage
    );
    info!("Hash in CT metadata: {}", stored_ct.metadata.ct_hash);

    if computed_hash_from_storage != stored_ct.metadata.ct_hash {
        error!("CRITICAL: Stored CT data hash doesn't match metadata!");
        error!("  Computed from CT data: {}", computed_hash_from_storage);
        error!("  Stored in metadata:    {}", stored_ct.metadata.ct_hash);
        return Err("Stored CT data corruption detected".to_string());
    }

    info!("✓ Stored CT data hash matches metadata");

    // Fetch the proof from GCS
    let stored_proof = fetch_proof(
        &storage,
        &parent,
        &stored_ct.metadata.proof_id,
        stored_ct.metadata.chain_id,
        stored_ct.metadata.security_zone,
    )
    .await
    .map_err(|e| format!("Failed to fetch proof: {}", e))?;

    info!(
        "Verifying proof with metadata (account: {}, security_zone: {}, chain_id: {})",
        stored_ct.metadata.account_addr,
        stored_ct.metadata.security_zone,
        stored_ct.metadata.chain_id
    );

    // Deserialize the proof
    let proven_list: tfhe::ProvenCompactCiphertextList =
        bincode::deserialize(&stored_proof.proof_data)
            .map_err(|e| format!("Failed to deserialize proof: {}", e))?;

    // Verify using TFHE.rs directly
    let verified_cts = verify_and_extract_hashes(
        proven_list,
        &pk,
        &crs,
        &stored_ct.metadata.account_addr,
        stored_ct.metadata.security_zone,
        stored_ct.metadata.chain_id,
    )
    .map_err(|e| format!("Proof verification failed: {}", e))?;

    // Find the CT in the verified list by matching hash
    // Note: We need to find which CT in the proof matches our stored CT
    info!("Searching for matching CT among {} verified CTs", verified_cts.len());

    let ct_index = stored_ct.metadata.ct_index;
    info!("Stored metadata claims CT is at index {}", ct_index);

    // First, try the index from metadata
    let verified_ct = verified_cts.get(ct_index).ok_or_else(|| {
        format!("CT index {} not found in verified list of {} CTs", ct_index, verified_cts.len())
    })?;

    // Log all CT hashes for debugging
    for (i, vct) in verified_cts.iter().enumerate() {
        let adj_hash = adjust_hash_for_metadata(
            vct.ct_hash,
            stored_ct.metadata.ct_type,
            stored_ct.metadata.security_zone,
            is_trivially_encrypted,
        );
        info!(
            "CT[{}]: original=0x{}, adjusted=0x{}",
            i,
            hex::encode(vct.ct_hash),
            hex::encode(adj_hash)
        );
    }

    // Adjust the hash for metadata (matching fhe-engine behavior)
    // The verifier generates a plain Keccak256 hash, but fhe-engine adjusts it with metadata
    let hash_array = verified_ct.ct_hash;

    // Log the original hash before adjustment
    let original_hash = format!("0x{}", hex::encode(verified_ct.ct_hash));
    debug!("Original hash from verifier: {}", original_hash);
    debug!(
        "CT type: {}, Security zone: {}, trivially_encrypted: {}",
        stored_ct.metadata.ct_type, stored_ct.metadata.security_zone, is_trivially_encrypted
    );

    let adjusted_hash = adjust_hash_for_metadata(
        hash_array,
        stored_ct.metadata.ct_type,
        stored_ct.metadata.security_zone,
        is_trivially_encrypted,
    );

    // Compare ct_hash
    let generated_ct_hash = format!("0x{}", hex::encode(adjusted_hash));
    debug!("Adjusted hash after metadata: {}", generated_ct_hash);
    debug!("Expected hash from storage: {}", stored_ct.metadata.ct_hash);

    let ct_hash_matches = generated_ct_hash == stored_ct.metadata.ct_hash;

    if !ct_hash_matches {
        error!("Hash mismatch!");
        error!("  Original hash:  {}", original_hash);
        error!("  Adjusted hash:  {}", generated_ct_hash);
        error!("  Expected hash:  {}", stored_ct.metadata.ct_hash);
        error!("  CT type:        {}", stored_ct.metadata.ct_type);
        error!("  Security zone:  {}", stored_ct.metadata.security_zone);
        error!("  Byte[30] (type+flag): 0x{:02x}", adjusted_hash[TRIVIAL_ENCRYPT_AND_TYPE_BYTE]);
        error!("  Byte[31] (sec zone):  0x{:02x}", adjusted_hash[SECURITY_ZONE_BYTE]);
    }

    if ct_hash_matches {
        info!("✓ Verification complete: proof_valid=true, ct_hash_matches=true");
    } else {
        error!("✗ Verification failed: ct_hash mismatch");
    }

    Ok(VerificationResult {
        status: if ct_hash_matches { "success".to_string() } else { "mismatch".to_string() },
        ct_hash: stored_ct.metadata.ct_hash.clone(),
        proof_id: stored_ct.metadata.proof_id.clone(),
        metadata: MetadataOutput {
            account_addr: stored_ct.metadata.account_addr.clone(),
            security_zone: stored_ct.metadata.security_zone,
            chain_id: stored_ct.metadata.chain_id,
            ct_index: stored_ct.metadata.ct_index,
            ct_type: stored_ct.metadata.ct_type,
            timestamp: stored_ct.metadata.timestamp.clone(),
        },
        verification: VerificationDetails { proof_valid: true, ct_hash_matches },
    })
}

async fn fetch_ciphertext(
    storage: &Storage,
    parent: &str,
    ct_hash: &str,
    chain_id: u32,
    security_zone: u8,
) -> Result<StoredCiphertext, String> {
    // Build base path: cofhe/v1/chain/{chain_id}/security-zone/{zone}/verified-inputs
    let base_path =
        format!("cofhe/v1/chain/{}/security-zone/{}/verified-inputs", chain_id, security_zone);
    let object_path = generate_object_key(ct_hash, &Some(base_path), None);

    info!("Fetching CT from path: {}", object_path);

    let data = read_object_bytes(storage, parent, &object_path).await?;

    StoredCiphertext::from_bytes(&data)
        .map_err(|e| format!("Failed to deserialize StoredCiphertext: {}", e))
}

async fn fetch_proof(
    storage: &Storage,
    parent: &str,
    proof_id: &str,
    chain_id: u32,
    security_zone: u8,
) -> Result<StoredProof, String> {
    // Build base path: cofhe/v1/chain/{chain_id}/security-zone/{zone}/verification-proofs
    let base_path =
        format!("cofhe/v1/chain/{}/security-zone/{}/verification-proofs", chain_id, security_zone);
    let object_path = generate_object_key(proof_id, &Some(base_path), None);

    debug!("Fetching proof from path: {}", object_path);

    let data = read_object_bytes(storage, parent, &object_path).await?;

    StoredProof::from_bytes(&data).map_err(|e| format!("Failed to deserialize StoredProof: {}", e))
}

/// Stream a full object into memory. The 0.23 client returned `Vec<u8>` from
/// `download_object(&request, &Range::default())`; in 1.x reads are always streaming.
async fn read_object_bytes(
    storage: &Storage,
    parent: &str,
    object_path: &str,
) -> Result<Vec<u8>, String> {
    let mut reader = storage
        .read_object(parent.to_string(), object_path.to_string())
        .send()
        .await
        .map_err(|e| format!("GCS download failed for {}: {}", object_path, e))?;

    let mut data = Vec::new();
    while let Some(chunk) = reader
        .next()
        .await
        .transpose()
        .map_err(|e| format!("GCS download chunk error for {}: {}", object_path, e))?
    {
        data.extend_from_slice(&chunk);
    }
    Ok(data)
}

fn print_human_readable(result: &VerificationResult) {
    println!("\n{}", "=".repeat(60));
    println!("Verification Result");
    println!("{}", "=".repeat(60));
    println!();

    println!("CT Hash:      {}", result.ct_hash);
    println!("Proof ID:     {}", result.proof_id);
    println!();

    println!("Metadata:");
    println!("  Account:       {}", result.metadata.account_addr);
    println!("  Security Zone: {}", result.metadata.security_zone);
    println!("  Chain ID:      {}", result.metadata.chain_id);
    println!("  CT Index:      {}", result.metadata.ct_index);
    println!("  CT Type:       {}", result.metadata.ct_type);
    println!("  Timestamp:     {}", result.metadata.timestamp);
    println!();

    println!("Verification:");
    let check = if result.verification.proof_valid { "✓" } else { "✗" };
    println!("  {} Proof verified", check);

    let check = if result.verification.ct_hash_matches { "✓" } else { "✗" };
    println!("  {} CT hash matches", check);
    println!();

    if result.status == "success" {
        println!("✓ Verification PASSED");
    } else {
        println!("✗ Verification FAILED");
    }
    println!("{}", "=".repeat(60));
}
