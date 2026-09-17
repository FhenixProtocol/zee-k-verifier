use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use futures::future::try_join_all;
use metrics::{counter, histogram};
use rust_common::log::{debug, error, info, warn};

use super::errors::StorageResult;
use super::StorageProvider;
use crate::config::RetryConfig;
use crate::storage::types::{CtMetadata, ProofMetadata, StoredCiphertext, StoredProof};

// Base paths for organizing CTs and proofs in storage
const COFHE_VERSION: &str = "cofhe/v1";

// Bounded label values. Kept separate from the human-readable operation name,
// which embeds the ct hash — using that as a label would be one series per
// stored object.
const KIND_CT: &str = "ct";
const KIND_PROOF: &str = "proof";
const CTS_TYPE: &str = "verified-inputs";
const PROOFS_TYPE: &str = "verification-proofs";

/// Publish the retry counter at zero for both bounded `kind` values, so the
/// series exist from boot. See `api::init_error_counters` for why.
pub(crate) fn init_error_counters() {
    for kind in [KIND_CT, KIND_PROOF] {
        counter!("storage_persist_retries_total", "kind" => kind).increment(0);
    }
}

/// Main proof storage handler
/// Uses a single storage backend for both CTs and proofs.
pub struct StorageManager {
    storage: Arc<dyn StorageProvider>,
    retry_config: RetryConfig,
}

impl StorageManager {
    pub fn new(storage: Arc<dyn StorageProvider>, retry_config: Option<RetryConfig>) -> Self {
        Self { storage, retry_config: retry_config.unwrap_or_default() }
    }

    /// Build base path for storage objects
    /// Format: cofhe/v0/chain/{chain_id}/security-zone/{security_zone}/{type}
    fn build_base_path(chain_id: u32, security_zone: u8, object_type: &str) -> String {
        format!(
            "{}/chain/{}/security-zone/{}/{}",
            COFHE_VERSION, chain_id, security_zone, object_type
        )
    }

    /// Calculate proof ID from proof bytes using blake3
    pub fn calculate_proof_id(proof_bytes: &[u8]) -> String {
        format!("0x{}", blake3::hash(proof_bytes).to_hex())
    }

    /// Store proof and all associated CTs to storage with retry logic
    /// This is the main entry point that ensures consistency: if any part fails after all retries,
    /// the entire operation fails and returns an error to the client.
    ///
    /// Uploads CTs and Proof in parallel to improve performance and reduce failure windows.
    pub async fn store_proof_and_cts(
        &self,
        proven_list_bytes: &[u8],
        ct_data: Vec<(String, Vec<u8>, u8)>, // (ct_hash, ct_bytes, ct_type)
        account_addr: &str,
        security_zone: u8,
        chain_id: u32,
    ) -> StorageResult<String> {
        let proof_id = Self::calculate_proof_id(proven_list_bytes);
        let timestamp = Utc::now().to_rfc3339();
        let ct_count = ct_data.len();
        let ct_hashes: Vec<String> = ct_data.iter().map(|(hash, _, _)| hash.clone()).collect();
        let chain_id_str = chain_id.to_string();
        let log_context = format!(
            "ct count: {}, ct hashes: {}, proof id: {}, account: {}, security zone: {}, chain id: \
             {} to {}",
            ct_count,
            ct_hashes.join(", "),
            proof_id,
            account_addr,
            security_zone,
            chain_id,
            self.storage.backend_name()
        );

        debug!("Preparing to store {}", log_context);

        let mut futures: Vec<
            std::pin::Pin<Box<dyn std::future::Future<Output = StorageResult<()>> + Send>>,
        > = Vec::with_capacity(ct_count + 1);

        // 1. Create futures for CT uploads
        for (index, (ct_hash, ct_bytes, ct_type)) in ct_data.into_iter().enumerate() {
            let ct_metadata = CtMetadata {
                ct_hash: ct_hash.clone(),
                proof_id: proof_id.clone(),
                account_addr: account_addr.to_string(),
                security_zone,
                chain_id,
                ct_index: index,
                ct_type,
                timestamp: timestamp.clone(),
            };

            let ct_hash_clone = ct_hash.clone();

            futures.push(Box::pin(async move {
                self.store_ct_with_retry(&ct_hash, &ct_bytes, &ct_metadata, chain_id).await.map_err(
                    |e| {
                        error!("Failed to store CT {} after all retries: {}", ct_hash_clone, e);
                        e
                    },
                )
            }));
        }

        // 2. Create future for Proof upload
        let proof_metadata = ProofMetadata {
            proof_id: proof_id.clone(),
            account_addr: account_addr.to_string(),
            security_zone,
            chain_id,
            ct_hashes,
            ct_count,
            timestamp,
        };

        let proof_bytes_vec = proven_list_bytes.to_vec();
        let proof_id_clone = proof_id.clone();

        futures.push(Box::pin(async move {
            self.store_proof_with_retry(
                &proof_id_clone,
                &proof_bytes_vec,
                &proof_metadata,
                &chain_id_str,
            )
            .await
            .map_err(|e| {
                error!("Failed to store proof {} after all retries: {}", proof_id_clone, e);
                e
            })
        }));

        // Execute all uploads concurrently
        try_join_all(futures).await?;

        debug!("Successfully stored {}", log_context);
        Ok(proof_id)
    }

    /// Store a single CT with retry logic
    /// Uses upsert semantics (direct upload with overwrite) to avoid race conditions
    /// Stores metadata both embedded in file (bincode) and as storage metadata
    pub async fn store_ct_with_retry(
        &self,
        ct_hash: &str,
        ct_bytes: &[u8],
        metadata: &CtMetadata,
        chain_id: u32,
    ) -> StorageResult<()> {
        let base_path = Self::build_base_path(chain_id, metadata.security_zone, CTS_TYPE);

        // Create StoredCiphertext with embedded metadata
        let stored_ct = StoredCiphertext::new(metadata.clone(), ct_bytes.to_vec());
        let serialized_bytes = stored_ct.to_bytes()?;

        // Also prepare storage metadata for indexing/filtering
        let metadata_map: HashMap<String, String> = metadata.into();

        self.retry_operation(
            || async {
                debug!(
                    "Uploading CT {} to storage with embedded + storage metadata (upsert)",
                    ct_hash
                );
                self.storage
                    .upload(
                        ct_hash,
                        &serialized_bytes,
                        Some(&metadata_map),
                        Some(&base_path),
                        None, // No additional dynamic path needed
                    )
                    .await
            },
            KIND_CT,
            &format!("CT {}", ct_hash),
        )
        .await
    }

    /// Store proof with embedded metadata as single file (with retry)
    /// Uses upsert semantics (direct upload with overwrite) to avoid race conditions
    /// Stores metadata embedded in file (bincode) and minimal storage metadata
    async fn store_proof_with_retry(
        &self,
        proof_id: &str,
        proof_bytes: &[u8],
        metadata: &ProofMetadata,
        chain_id: &str,
    ) -> StorageResult<()> {
        let chain_id_num: u32 = chain_id.parse().unwrap_or(0);
        let base_path = Self::build_base_path(chain_id_num, metadata.security_zone, PROOFS_TYPE);

        // Create StoredProof with embedded metadata
        let stored_proof = StoredProof::new(metadata.clone(), proof_bytes.to_vec());
        let serialized_bytes = stored_proof.to_bytes()?;

        // Minimal storage metadata for indexing (just the key fields)
        // Use generic conversion to avoid duplication
        let storage_metadata: HashMap<String, String> = metadata.into();

        self.retry_operation(
            || async {
                debug!("Uploading proof {} to storage with embedded metadata (upsert)", proof_id);
                self.storage
                    .upload(
                        proof_id,
                        &serialized_bytes,
                        Some(&storage_metadata),
                        Some(&base_path),
                        None, // No additional dynamic path needed
                    )
                    .await
            },
            KIND_PROOF,
            &format!("Proof {}", proof_id),
        )
        .await
    }

    /// Generic retry operation with exponential backoff
    /// `kind` is a bounded label value; `operation_name` embeds the object id and
    /// must never reach a metric label.
    async fn retry_operation<F, Fut>(
        &self,
        mut operation: F,
        kind: &'static str,
        operation_name: &str,
    ) -> StorageResult<()>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = StorageResult<()>>,
    {
        let mut delay_ms = self.retry_config.initial_delay_ms;
        let mut attempts = 0;
        // Whole retried operation, backoff included.
        // `storage_operation_duration_milliseconds` already covers one attempt.
        let started = std::time::Instant::now();

        loop {
            match operation().await {
                Ok(()) => {
                    if attempts > 0 {
                        info!(
                            "Successfully completed {} after {} retries",
                            operation_name, attempts
                        );
                    }
                    Self::record_persist_outcome(kind, "success", started);
                    return Ok(());
                }
                Err(e) => {
                    attempts += 1;

                    // Don't retry if error is not retryable
                    if !e.is_retryable() {
                        error!("Non-retryable error for {}: {}", operation_name, e);
                        Self::record_persist_outcome(kind, "error", started);
                        return Err(e);
                    }

                    if attempts > self.retry_config.max_retries {
                        error!(
                            "Failed to complete {} after {} attempts: {}",
                            operation_name, attempts, e
                        );
                        Self::record_persist_outcome(kind, "error", started);
                        return Err(e);
                    }

                    warn!(
                        "Attempt {}/{} failed for {}: {}. Retrying in {}ms...",
                        attempts, self.retry_config.max_retries, operation_name, e, delay_ms
                    );

                    // Separate from the outcome: an operation that always
                    // succeeds on retry looks healthy without this.
                    counter!("storage_persist_retries_total", "kind" => kind).increment(1);

                    tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;

                    // Exponential backoff with max cap
                    delay_ms = (delay_ms * 2).min(self.retry_config.max_delay_ms);
                }
            }
        }
    }

    /// One increment per logical persist, not per attempt.
    /// `storage_operations_total` counts attempts and cannot answer "was it
    /// stored" — a success there may be followed by a failing retry.
    fn record_persist_outcome(
        kind: &'static str,
        status: &'static str,
        started: std::time::Instant,
    ) {
        counter!("storage_persist_total", "kind" => kind, "status" => status).increment(1);
        histogram!("storage_persist_duration_milliseconds", "kind" => kind)
            .record(started.elapsed().as_secs_f64() * 1000.0);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    use async_trait::async_trait;
    use tokio::sync::Mutex as AsyncMutex;

    use super::*;
    use crate::storage::errors::StorageError;

    /// Mock storage backend for testing
    pub struct MockStorage {
        pub uploaded: Arc<
            AsyncMutex<Vec<(String, Vec<u8>, Option<HashMap<String, String>>, Option<String>)>>,
        >,
        pub upload_fail_on_nth: Arc<AtomicUsize>,
        pub upload_count: Arc<AtomicUsize>,
        pub should_fail: Arc<AtomicBool>,
    }

    impl MockStorage {
        pub fn new() -> Self {
            Self {
                uploaded: Arc::new(AsyncMutex::new(Vec::new())),
                upload_fail_on_nth: Arc::new(AtomicUsize::new(0)),
                upload_count: Arc::new(AtomicUsize::new(0)),
                should_fail: Arc::new(AtomicBool::new(false)),
            }
        }

        pub fn fail_on_nth_upload(&self, n: usize) {
            self.upload_fail_on_nth.store(n, Ordering::SeqCst);
        }

        pub fn set_should_fail(&self, should_fail: bool) {
            self.should_fail.store(should_fail, Ordering::SeqCst);
        }

        pub async fn get_uploaded(
            &self,
        ) -> Vec<(String, Vec<u8>, Option<HashMap<String, String>>, Option<String>)> {
            self.uploaded.lock().await.clone()
        }

        pub async fn get_upload_count(&self) -> usize {
            self.upload_count.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl StorageProvider for MockStorage {
        async fn upload(
            &self,
            key: &str,
            data: &[u8],
            metadata: Option<&HashMap<String, String>>,
            _base_path: Option<&str>,
            dynamic_path: Option<&str>,
        ) -> Result<(), StorageError> {
            let count = self.upload_count.fetch_add(1, Ordering::SeqCst) + 1;

            if self.should_fail.load(Ordering::SeqCst) {
                return Err(StorageError::Generic("Mock storage failure".to_string()));
            }

            let fail_on_nth = self.upload_fail_on_nth.load(Ordering::SeqCst);
            if fail_on_nth > 0 && count == fail_on_nth {
                return Err(StorageError::Generic(format!("Mock failure on upload #{}", count)));
            }

            self.uploaded.lock().await.push((
                key.to_string(),
                data.to_vec(),
                metadata.map(|m| m.clone()),
                dynamic_path.map(|s| s.to_string()),
            ));
            Ok(())
        }

        fn backend_name(&self) -> &'static str {
            "mock"
        }

        async fn probe(&self) -> Result<(), StorageError> {
            if self.should_fail.load(Ordering::SeqCst) {
                return Err(StorageError::Generic("Mock storage probe failure".to_string()));
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_calculate_proof_id() {
        let proof_bytes = b"test proof data";
        let proof_id = StorageManager::calculate_proof_id(proof_bytes);

        // Should be hex-encoded blake3 hash with 0x prefix
        assert!(proof_id.starts_with("0x"));
        assert_eq!(proof_id.len(), 2 + 64); // 0x + 64 hex chars

        // Should be deterministic
        let proof_id2 = StorageManager::calculate_proof_id(proof_bytes);
        assert_eq!(proof_id, proof_id2);

        // Different data should produce different hash
        let proof_id3 = StorageManager::calculate_proof_id(b"different data");
        assert_ne!(proof_id, proof_id3);
    }

    #[tokio::test]
    async fn test_store_proof_and_cts_success() {
        let storage = Arc::new(MockStorage::new());

        let proof_storage = StorageManager::new(storage.clone(), None);

        let proof_bytes = b"test proof binary data";
        let ct_data = vec![
            ("0xhash1".to_string(), b"ct_data_1".to_vec(), 5u8),
            ("0xhash2".to_string(), b"ct_data_2".to_vec(), 5u8),
        ];

        let result = proof_storage
            .store_proof_and_cts(proof_bytes, ct_data.clone(), "0x1234567890abcdef", 1, 11155111)
            .await;

        assert!(result.is_ok());
        let proof_id = result.unwrap();
        assert!(proof_id.starts_with("0x"));

        // Check uploads (2 CTs + 1 proof = 3 total)
        let uploads = storage.get_uploaded().await;
        assert_eq!(uploads.len(), 3);

        // First two uploads should be CTs
        let ct_uploads = &uploads[0..2];

        // Verify first CT has embedded metadata + data
        assert_eq!(ct_uploads[0].0, "0xhash1");
        // No dynamic path anymore, it's all in base_path
        assert_eq!(ct_uploads[0].3, None);

        // Deserialize StoredCiphertext to verify embedded metadata and data
        let stored_ct = StoredCiphertext::from_bytes(&ct_uploads[0].1).unwrap();
        assert_eq!(stored_ct.ct_data, b"ct_data_1");
        assert_eq!(stored_ct.metadata.ct_hash, "0xhash1");
        assert_eq!(stored_ct.metadata.proof_id, proof_id);
        assert_eq!(stored_ct.metadata.account_addr, "0x1234567890abcdef");
        assert_eq!(stored_ct.metadata.security_zone, 1);
        assert_eq!(stored_ct.metadata.chain_id, 11155111);
        assert_eq!(stored_ct.metadata.ct_index, 0);
        assert_eq!(stored_ct.metadata.ct_type, 5);

        // Verify storage metadata (also attached for indexing)
        let storage_metadata = ct_uploads[0].2.as_ref().unwrap();
        assert_eq!(storage_metadata.get("proof_id").unwrap(), &proof_id);
        assert_eq!(storage_metadata.get("account_addr").unwrap(), "0x1234567890abcdef");

        // Third upload should be the proof (single file with embedded metadata)
        let proof_upload = &uploads[2];

        // Verify the stored proof
        let stored_proof = StoredProof::from_bytes(&proof_upload.1).unwrap();
        assert_eq!(stored_proof.proof_data, proof_bytes);
        assert_eq!(stored_proof.metadata.proof_id, proof_id);
        assert_eq!(stored_proof.metadata.ct_count, 2);
        // No dynamic path anymore, it's all in base_path
        assert_eq!(proof_upload.3, None);
    }

    #[tokio::test]
    async fn test_store_proof_and_cts_upsert_semantics() {
        let storage = Arc::new(MockStorage::new());

        let proof_storage = StorageManager::new(storage.clone(), None);

        let proof_bytes = b"test proof";
        let ct_data = vec![
            ("0xhash1".to_string(), b"ct1".to_vec(), 5u8),
            ("0xhash2".to_string(), b"ct2".to_vec(), 5u8),
        ];

        let result = proof_storage.store_proof_and_cts(proof_bytes, ct_data, "0xaddr", 1, 1).await;

        assert!(result.is_ok());

        // With upsert semantics, both CTs should always be uploaded
        // 2 CTs + 1 proof = 3 uploads total
        let uploads = storage.get_uploaded().await;
        assert_eq!(uploads.len(), 3);
        assert_eq!(uploads[0].0, "0xhash1");
        assert_eq!(uploads[1].0, "0xhash2");
    }

    #[tokio::test]
    async fn test_retry_mechanism_eventual_success() {
        let storage = Arc::new(MockStorage::new());

        // Fail on the 1st upload, should retry and succeed
        storage.fail_on_nth_upload(1);

        let retry_config = RetryConfig { max_retries: 3, initial_delay_ms: 10, max_delay_ms: 100 };

        let proof_storage = StorageManager::new(storage.clone(), Some(retry_config));

        let proof_bytes = b"test";
        let ct_data = vec![("0xhash1".to_string(), b"ct1".to_vec(), 5u8)];

        let result = proof_storage.store_proof_and_cts(proof_bytes, ct_data, "0xaddr", 1, 1).await;

        // Should succeed after retries
        assert!(result.is_ok());

        // Verify it tried multiple times (initial attempt + retry)
        let upload_count = storage.get_upload_count().await;
        assert!(upload_count > 1, "Expected retries but got upload_count={}", upload_count);
    }

    /// The retry counter exists at zero before anything fails. Cloud Monitoring
    /// will not create a PromQL alert policy over a metric with no descriptor,
    /// so without this the `storage-retry-storm` alert cannot be deployed until
    /// after the first retry storm it is meant to catch.
    #[test]
    fn retry_counter_is_published_at_zero_before_any_failure() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();

        metrics::with_local_recorder(&recorder, || init_error_counters());

        let rendered = handle.render();
        for kind in [KIND_CT, KIND_PROOF] {
            assert!(
                rendered.contains(&format!("storage_persist_retries_total{{kind=\"{kind}\"}} 0")),
                "kind={kind} missing from a clean boot\n{rendered}"
            );
        }
    }

    /// Retries and outcome are recorded, and the object id never reaches a label
    /// — the second half is what stops someone collapsing `kind` and
    /// `operation_name` back into one argument.
    ///
    /// Not a `#[tokio::test]`: `with_local_recorder` is thread-local, so the
    /// runtime has to be driven inside the closure.
    #[test]
    fn persist_records_outcome_and_retries_without_leaking_object_ids() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();

        metrics::with_local_recorder(&recorder, || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .expect("current-thread runtime");
            rt.block_on(async {
                let storage = Arc::new(MockStorage::new());
                storage.fail_on_nth_upload(1);
                let retry_config =
                    RetryConfig { max_retries: 3, initial_delay_ms: 1, max_delay_ms: 4 };
                let manager = StorageManager::new(storage, Some(retry_config));
                let ct_data = vec![("0xdeadbeefcafe".to_string(), b"ct".to_vec(), 5u8)];
                manager
                    .store_proof_and_cts(b"proof", ct_data, "0xaddr", 1, 1)
                    .await
                    .expect("succeeds after a retry");
            });
        });

        let rendered = handle.render();

        assert!(
            rendered.contains("storage_persist_retries_total"),
            "a retried persist recorded no retry counter\n{rendered}"
        );
        assert!(
            rendered.contains("storage_persist_total"),
            "a completed persist recorded no outcome counter\n{rendered}"
        );
        assert!(
            rendered.contains(&format!("kind=\"{KIND_CT}\"")),
            "the bounded kind label is missing\n{rendered}"
        );
        assert!(
            !rendered.contains("0xdeadbeefcafe"),
            "the ct hash leaked into a metric label — that is unbounded cardinality, one time \
             series per stored object\n{rendered}"
        );
    }

    #[tokio::test]
    async fn test_retry_mechanism_exhaustion() {
        let storage = Arc::new(MockStorage::new());

        // Always fail
        storage.set_should_fail(true);

        let retry_config = RetryConfig { max_retries: 2, initial_delay_ms: 5, max_delay_ms: 20 };

        let proof_storage = StorageManager::new(storage.clone(), Some(retry_config));

        let proof_bytes = b"test";
        let ct_data = vec![("0xhash1".to_string(), b"ct1".to_vec(), 5u8)];

        let result = proof_storage.store_proof_and_cts(proof_bytes, ct_data, "0xaddr", 1, 1).await;

        // Should fail after exhausting retries
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Mock storage failure"));
    }

    #[tokio::test]
    async fn test_proof_storage_failure_after_cts_stored() {
        let storage = Arc::new(MockStorage::new());

        // Fail on the 2nd upload
        // Note: With parallel execution, the order is non-deterministic
        // This could fail the CT or the proof depending on which future completes first
        storage.fail_on_nth_upload(2);

        // Disable retries so the 2nd upload actually fails
        let retry_config = RetryConfig { max_retries: 0, initial_delay_ms: 0, max_delay_ms: 0 };
        let proof_storage = StorageManager::new(storage.clone(), Some(retry_config));

        let proof_bytes = b"test proof";
        let ct_data = vec![("0xhash1".to_string(), b"ct1".to_vec(), 5u8)];

        let result = proof_storage.store_proof_and_cts(proof_bytes, ct_data, "0xaddr", 1, 1).await;

        // Should fail because one upload failed
        assert!(result.is_err());

        // With parallel execution, either 0 or 1 uploads might have succeeded before the failure
        // This demonstrates the potential inconsistency issue with parallel uploads
        let uploads = storage.get_uploaded().await;
        assert!(uploads.len() <= 1, "Expected at most 1 upload to succeed, got {}", uploads.len());
    }

    #[tokio::test]
    async fn test_multiple_cts_with_metadata() {
        let storage = Arc::new(MockStorage::new());

        let proof_storage = StorageManager::new(storage.clone(), None);

        let proof_bytes = b"proof_data";
        let ct_data = vec![
            ("0xhash1".to_string(), b"ct1".to_vec(), 3u8),
            ("0xhash2".to_string(), b"ct2".to_vec(), 4u8),
            ("0xhash3".to_string(), b"ct3".to_vec(), 5u8),
        ];

        let result =
            proof_storage.store_proof_and_cts(proof_bytes, ct_data, "0xaccount", 2, 42161).await;

        assert!(result.is_ok());
        let proof_id = result.unwrap();

        // Get all uploads (3 CTs + 1 proof = 4 total)
        let uploads = storage.get_uploaded().await;
        assert_eq!(uploads.len(), 4);

        // First 3 uploads are CTs
        let ct_uploads = &uploads[0..3];

        // Verify each CT has correct metadata
        for (idx, upload) in ct_uploads.iter().enumerate() {
            let metadata = upload.2.as_ref().unwrap();
            assert_eq!(metadata.get("proof_id").unwrap(), &proof_id);
            assert_eq!(metadata.get("ct_index").unwrap(), &idx.to_string());
            assert_eq!(metadata.get("security_zone").unwrap(), "2");
            assert_eq!(metadata.get("chain_id").unwrap(), "42161");
            assert_eq!(metadata.get("account_addr").unwrap(), "0xaccount");
        }

        // 4th upload is the proof with embedded metadata
        let proof_upload = &uploads[3];

        // Deserialize the StoredProof
        let stored_proof = StoredProof::from_bytes(&proof_upload.1).unwrap();
        assert_eq!(stored_proof.metadata.ct_hashes.len(), 3);
        assert_eq!(stored_proof.metadata.ct_count, 3);
        assert_eq!(stored_proof.metadata.security_zone, 2);
        assert_eq!(stored_proof.metadata.proof_id, proof_id);
    }

    #[tokio::test]
    async fn test_ct_metadata_to_hashmap_conversion() {
        let metadata = CtMetadata {
            ct_hash: "0xhash789".to_string(),
            proof_id: "0xproof123".to_string(),
            account_addr: "0xaccount456".to_string(),
            security_zone: 3,
            chain_id: 1,
            ct_index: 5,
            ct_type: 7,
            timestamp: "2024-01-01T00:00:00Z".to_string(),
        };

        let map: HashMap<String, String> = (&metadata).into();

        assert_eq!(map.get("ct_hash").unwrap(), "0xhash789");
        assert_eq!(map.get("proof_id").unwrap(), "0xproof123");
        assert_eq!(map.get("account_addr").unwrap(), "0xaccount456");
        assert_eq!(map.get("security_zone").unwrap(), "3");
        assert_eq!(map.get("chain_id").unwrap(), "1");
        assert_eq!(map.get("ct_index").unwrap(), "5");
        assert_eq!(map.get("ct_type").unwrap(), "7");
        assert_eq!(map.get("timestamp").unwrap(), "2024-01-01T00:00:00Z");
        assert_eq!(map.len(), 8);
    }

    #[tokio::test]
    async fn test_stored_ciphertext_serialization() {
        let metadata = CtMetadata {
            ct_hash: "0xhash1".to_string(),
            proof_id: "0xproof123".to_string(),
            account_addr: "0xaccount".to_string(),
            security_zone: 2,
            chain_id: 1,
            ct_index: 0,
            ct_type: 5,
            timestamp: "2024-01-01T00:00:00Z".to_string(),
        };

        let ct_data = b"test ciphertext data".to_vec();
        let stored_ct = StoredCiphertext::new(metadata.clone(), ct_data.clone());

        // Test serialization
        let bytes = stored_ct.to_bytes().unwrap();
        assert!(!bytes.is_empty());

        // Test deserialization
        let deserialized = StoredCiphertext::from_bytes(&bytes).unwrap();
        assert_eq!(deserialized.metadata.ct_hash, "0xhash1");
        assert_eq!(deserialized.metadata.proof_id, "0xproof123");
        assert_eq!(deserialized.metadata.ct_index, 0);
        assert_eq!(deserialized.ct_data, ct_data);
    }

    #[tokio::test]
    async fn test_stored_proof_serialization() {
        let metadata = ProofMetadata {
            proof_id: "0xproof123".to_string(),
            account_addr: "0xaccount".to_string(),
            security_zone: 1,
            chain_id: 11155111,
            ct_hashes: vec!["0xhash1".to_string(), "0xhash2".to_string()],
            ct_count: 2,
            timestamp: "2024-01-15T10:30:00Z".to_string(),
        };

        let proof_data = b"test proof binary data".to_vec();
        let stored_proof = StoredProof::new(metadata.clone(), proof_data.clone());

        // Test serialization
        let bytes = stored_proof.to_bytes().unwrap();
        assert!(!bytes.is_empty());

        // Test deserialization
        let deserialized = StoredProof::from_bytes(&bytes).unwrap();
        assert_eq!(deserialized.metadata.proof_id, "0xproof123");
        assert_eq!(deserialized.metadata.ct_count, 2);
        assert_eq!(deserialized.metadata.ct_hashes.len(), 2);
        assert_eq!(deserialized.proof_data, proof_data);
    }

    #[tokio::test]
    async fn test_proof_metadata_serialization() {
        let metadata = ProofMetadata {
            proof_id: "0xtest".to_string(),
            account_addr: "0xaddr".to_string(),
            security_zone: 1,
            chain_id: 11155111,
            ct_hashes: vec!["0xhash1".to_string(), "0xhash2".to_string()],
            ct_count: 2,
            timestamp: "2024-01-15T10:30:00Z".to_string(),
        };

        let json = serde_json::to_string(&metadata).unwrap();
        let deserialized: ProofMetadata = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.proof_id, metadata.proof_id);
        assert_eq!(deserialized.ct_count, metadata.ct_count);
        assert_eq!(deserialized.ct_hashes, metadata.ct_hashes);
    }
}
