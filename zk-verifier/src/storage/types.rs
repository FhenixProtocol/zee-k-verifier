use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::errors::{StorageError, StorageResult};

/// Helper function to convert any serializable metadata to a HashMap
fn metadata_to_map<T: Serialize>(metadata: &T) -> HashMap<String, String> {
    match serde_json::to_value(metadata) {
        Ok(Value::Object(map)) => map
            .into_iter()
            .map(|(k, v)| (k, if let Value::String(s) = v { s } else { v.to_string() }))
            .collect(),
        _ => HashMap::new(),
    }
}

/// Metadata for a ciphertext (embedded in StoredCiphertext)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtMetadata {
    pub ct_hash: String,
    pub proof_id: String,
    pub account_addr: String,
    pub security_zone: u8,
    pub chain_id: u32,
    pub ct_index: usize,
    pub ct_type: u8,
    pub timestamp: String,
}

impl From<&CtMetadata> for HashMap<String, String> {
    fn from(metadata: &CtMetadata) -> Self {
        metadata_to_map(metadata)
    }
}

/// Complete ciphertext storage format: metadata + data
/// Serialized using bincode and stored as a single file in storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCiphertext {
    /// Metadata about this ciphertext
    pub metadata: CtMetadata,
    /// Raw ciphertext bytes
    pub ct_data: Vec<u8>,
}

impl StoredCiphertext {
    pub fn new(metadata: CtMetadata, ct_data: Vec<u8>) -> Self {
        Self { metadata, ct_data }
    }

    /// Serialize to bytes using bincode
    pub fn to_bytes(&self) -> StorageResult<Vec<u8>> {
        bincode::serialize(self).map_err(|e| {
            StorageError::Serialization(format!("Failed to serialize StoredCiphertext: {}", e))
        })
    }

    /// Deserialize from bytes using bincode
    #[allow(dead_code)]
    pub fn from_bytes(bytes: &[u8]) -> StorageResult<Self> {
        bincode::deserialize(bytes).map_err(|e| {
            StorageError::Serialization(format!("Failed to deserialize StoredCiphertext: {}", e))
        })
    }
}

/// Metadata for a proof (embedded in StoredProof)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofMetadata {
    pub proof_id: String,
    pub account_addr: String,
    pub security_zone: u8,
    pub chain_id: u32,
    pub ct_hashes: Vec<String>,
    pub ct_count: usize,
    pub timestamp: String,
}

impl From<&ProofMetadata> for HashMap<String, String> {
    fn from(metadata: &ProofMetadata) -> Self {
        metadata_to_map(metadata)
    }
}

/// Complete proof storage format: metadata + data
/// Serialized using bincode and stored as a single file in storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredProof {
    /// Metadata about this proof
    pub metadata: ProofMetadata,
    /// Raw proof bytes (the proven_list_bytes)
    pub proof_data: Vec<u8>,
}

impl StoredProof {
    pub fn new(metadata: ProofMetadata, proof_data: Vec<u8>) -> Self {
        Self { metadata, proof_data }
    }

    /// Serialize to bytes using bincode
    pub fn to_bytes(&self) -> StorageResult<Vec<u8>> {
        bincode::serialize(self).map_err(|e| {
            StorageError::Serialization(format!("Failed to serialize StoredProof: {}", e))
        })
    }

    /// Deserialize from bytes using bincode
    #[allow(dead_code)]
    pub fn from_bytes(bytes: &[u8]) -> StorageResult<Self> {
        bincode::deserialize(bytes).map_err(|e| {
            StorageError::Serialization(format!("Failed to deserialize StoredProof: {}", e))
        })
    }
}
