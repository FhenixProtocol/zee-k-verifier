pub mod errors;
pub mod gcs;
pub mod storage_manager;
pub mod types;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use errors::{StorageError, StorageResult};

/// Generic trait for object storage providers (GCS, S3, etc.)
#[async_trait]
pub trait StorageProvider: Send + Sync {
    /// Upload an object to storage with optional metadata
    ///
    /// # Arguments
    /// * `key` - The object key/path
    /// * `data` - The raw bytes to store
    /// * `metadata` - Optional key-value metadata to attach
    /// * `base_path` - Optional base path prefix (e.g., "cts", "proofs")
    /// * `dynamic_path` - Optional dynamic path segment (e.g., chain_id) inserted between base_path and sharded key
    ///
    /// # Returns
    /// * `Ok(())` on successful upload
    /// * `Err` on upload failures (network, permissions, etc.)
    async fn upload(
        &self,
        key: &str,
        data: &[u8],
        metadata: Option<&HashMap<String, String>>,
        base_path: Option<&str>,
        dynamic_path: Option<&str>,
    ) -> Result<(), StorageError>;

    /// Get the backend type identifier (for logging/metrics)
    fn backend_name(&self) -> &'static str;

    /// Cheapest call that proves the backend answers — enough to tell "bucket
    /// and credentials resolve" from "unreachable", writing nothing.
    ///
    /// Used by the dependency health loop (`crate::health`) on a timer, never
    /// on the request path, so it must stay cheap and side-effect free.
    async fn probe(&self) -> Result<(), StorageError>;
}

/// Builder for creating different storage backends from configuration
pub struct StorageFactory;

impl StorageFactory {
    /// Create a storage backend from configuration
    ///
    /// Returns Arc<dyn ObjectStorage> to allow future backend implementations
    /// to be swapped in without changing calling code.
    pub async fn from_config(
        config: &crate::config::StorageConfig,
    ) -> StorageResult<Arc<dyn StorageProvider>> {
        // Route to the appropriate backend based on configuration
        match config.backend.as_str() {
            "gcs" => {
                let storage = gcs::GcsStorage::new(config).await?;
                Ok(Arc::new(storage) as Arc<dyn StorageProvider>)
            }
            _ => Err(StorageError::Configuration(format!(
                "Unsupported storage backend: {}",
                config.backend
            ))),
        }
    }
}
