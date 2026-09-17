use std::collections::HashMap;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use google_cloud_gax::error::Error as GaxError;
use google_cloud_storage::client::Storage;
use metrics::{counter, histogram};
use rust_common::log::*;
use tokio::time::timeout;

use super::errors::{StorageError, StorageResult};
use super::StorageProvider;
use crate::config::StorageConfig;

/// CRITICAL: Sharding prefix length is HARDCODED and must NEVER be changed.
/// Changing this value will break all existing storage paths and make data inaccessible.
/// This uses the first 4 characters of the hash as the shard prefix.
/// This is enough to spread the data across the storage bucket.
/// Example: "abcd1234..." -> "base/abcd/abcd1234..."
const SHARD_PREFIX_LENGTH: usize = 4;

/// Synthetic key used by both the startup probe and the health probe. Reading a
/// key that does not exist answers 404 once the bucket and credentials resolve,
/// which is exactly the "does the backend answer" signal, with nothing written.
const PROBE_KEY: &str = ".zk-verifier-startup-probe";

/// Google Cloud Storage backend implementation
/// Base paths are passed at upload/exists time, not baked into the client
pub struct GcsStorage {
    storage: Storage,
    // Parent resource path "projects/_/buckets/{bucket}" required by the 1.x API.
    // Cached here so we don't rebuild it on every upload.
    parent: String,
    bucket: String,
    upload_timeout: Duration,
}

impl GcsStorage {
    /// Create a new GcsStorage instance from configuration
    pub async fn new(config: &StorageConfig) -> StorageResult<Self> {
        debug!("Initializing GCS storage: bucket={}", config.bucket);

        let upload_timeout = Duration::from_secs(config.upload_timeout_secs);
        let parent = format!("projects/_/buckets/{}", config.bucket);

        // Always ADC. In production the GCE metadata server provides the token;
        // in local dev a mock metadata server (see docker-compose.yml +
        // `GCE_METADATA_HOST`) serves any-string-as-token. fake-gcs-server
        // ignores the token, so dev and prod share one Rust code path.
        let storage = Storage::builder()
            .with_endpoint(&config.storage_endpoint)
            .build()
            .await
            .map_err(|e| {
                StorageError::Configuration(format!("Failed to build GCS Storage client: {}", e))
            })?;

        // Startup probe via the data plane. A read on a synthetic key returns
        // 404 when the bucket + auth are fine, lets transport / DNS / auth
        // failures surface at boot instead of at the first real upload.
        match storage.read_object(parent.clone(), PROBE_KEY).send().await {
            Ok(mut reader) => {
                // Object happens to exist (unlikely); drain to release the
                // connection, stopping at end-of-stream or on a chunk error.
                while matches!(reader.next().await, Some(Ok(_))) {}
            }
            Err(e) if e.http_status_code() == Some(404) => {}
            Err(e) => {
                let classified = Self::classify_error(&e);
                return Err(StorageError::Configuration(format!(
                    "GCS startup probe failed for bucket '{}': {}",
                    config.bucket, classified
                )));
            }
        }

        info!(
            "Initialized GCS storage: bucket={}, shard_prefix_length={}, upload_timeout={:?}, \
             retry_config={:?}, endpoint={:?}",
            config.bucket,
            SHARD_PREFIX_LENGTH,
            upload_timeout,
            config.retry_config,
            config.storage_endpoint
        );

        Ok(GcsStorage { storage, parent, bucket: config.bucket.clone(), upload_timeout })
    }

    /// Generate the object key path for a given key
    ///
    /// Applies base path, dynamic path, and hardcoded sharding prefix.
    fn object_key(&self, key: &str, base_path: Option<&str>, dynamic_path: Option<&str>) -> String {
        generate_object_key(key, &base_path.map(|s| s.to_string()), dynamic_path)
    }

    /// Classify a gax error into the appropriate StorageError variant.
    /// Mapping is bucketed by HTTP status to preserve the downstream retry contract
    /// (Network/Timeout/Generic are retryable; PermissionDenied/NotFound are not).
    fn classify_error(e: &GaxError) -> StorageError {
        let msg = e.to_string();
        match e.http_status_code() {
            Some(401) => StorageError::PermissionDenied(format!("Authentication failed: {}", msg)),
            Some(403) => StorageError::PermissionDenied(format!("Permission denied: {}", msg)),
            Some(404) => StorageError::NotFound(msg),
            Some(408) => {
                StorageError::Timeout { operation: "GCS request".to_string(), timeout_secs: 0 }
            }
            Some(code) if code == 429 || (500..=599).contains(&code) => {
                StorageError::Network(format!("GCS server error {}: {}", code, msg))
            }
            Some(code) => StorageError::Generic(format!("GCS error {}: {}", code, msg)),
            // No HTTP status: transport / DNS / connect failure. Treat as retryable Network
            // so the existing retry layer keeps the same behavior as the 0.23 HttpClient path.
            None => StorageError::Network(format!("GCS transport error: {}", msg)),
        }
    }
}

/// Generate the object key path for a given key
///
/// Applies base path, dynamic path, and HARDCODED sharding prefix.
/// Path structure: {base_path}/{dynamic_path}/{shard_prefix}/{key}
///
/// CRITICAL: The sharding prefix length is hardcoded to prevent accidental changes
/// that would break existing storage paths.
pub fn generate_object_key(
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

#[async_trait]
impl StorageProvider for GcsStorage {
    async fn upload(
        &self,
        key: &str,
        data: &[u8],
        metadata: Option<&HashMap<String, String>>,
        base_path: Option<&str>,
        dynamic_path: Option<&str>,
    ) -> StorageResult<()> {
        let object_path = self.object_key(key, base_path, dynamic_path);
        let start = Instant::now();
        let size = data.len();

        debug!("Uploading to GCS: key={}, size={} bytes", object_path, size);

        let payload = bytes::Bytes::from(data.to_vec());
        let mut req = self.storage.write_object(self.parent.clone(), object_path.clone(), payload);
        if let Some(meta) = metadata {
            req = req.set_metadata(meta.clone());
        }

        // send_unbuffered: small in-memory payload, no resumable buffer needed.
        // send_buffered would add a resumable-upload buffer that's overkill here
        // and changes multipart behavior against fake-gcs-server.
        let result = timeout(self.upload_timeout, req.send_unbuffered()).await;

        // Record metrics
        let duration_ms = start.elapsed().as_millis() as f64;
        histogram!(
            "storage_operation_duration_milliseconds",
            "backend" => "gcs",
            "operation" => "upload",
            "bucket" => self.bucket.clone()
        )
        .record(duration_ms);
        histogram!(
            "storage_upload_bytes",
            "backend" => "gcs",
            "bucket" => self.bucket.clone()
        )
        .record(size as f64);

        match result {
            Ok(Ok(_)) => {
                debug!(
                    "Successfully uploaded to GCS: key={}, size={} bytes, duration={}ms",
                    object_path, size, duration_ms
                );
                counter!(
                    "storage_operations_total",
                    "backend" => "gcs",
                    "operation" => "upload",
                    "bucket" => self.bucket.clone(),
                    "status" => "success"
                )
                .increment(1);
                Ok(())
            }
            Ok(Err(e)) => {
                warn!(
                    "Failed to upload to GCS bucket {} at path {}: {}",
                    self.bucket, object_path, e
                );
                let storage_error = Self::classify_error(&e);
                let error_type: &'static str = (&storage_error).into();
                counter!(
                    "storage_operations_total",
                    "backend" => "gcs",
                    "operation" => "upload",
                    "bucket" => self.bucket.clone(),
                    "status" => "error",
                    "error_type" => error_type
                )
                .increment(1);
                Err(storage_error)
            }
            Err(_) => {
                warn!(
                    "Timeout uploading to GCS bucket {} at path {} after {:?}",
                    self.bucket, object_path, self.upload_timeout
                );
                counter!(
                    "storage_operations_total",
                    "backend" => "gcs",
                    "operation" => "upload",
                    "bucket" => self.bucket.clone(),
                    "status" => "error",
                    "error_type" => "timeout"
                )
                .increment(1);
                Err(StorageError::Timeout {
                    operation: format!("upload to {}", object_path),
                    timeout_secs: self.upload_timeout.as_secs(),
                })
            }
        }
    }

    fn backend_name(&self) -> &'static str {
        "gcs"
    }

    /// Same call the startup probe makes, on the timer instead of at boot.
    async fn probe(&self) -> Result<(), StorageError> {
        match self.storage.read_object(self.parent.clone(), PROBE_KEY).send().await {
            Ok(mut reader) => {
                // The key exists (it should not); drain to release the
                // connection, stopping at end-of-stream or on a chunk error.
                while matches!(reader.next().await, Some(Ok(_))) {}
                Ok(())
            }
            // 404 IS the healthy answer: the bucket and credentials resolved,
            // the synthetic key simply is not there.
            Err(e) if e.http_status_code() == Some(404) => Ok(()),
            Err(e) => Err(Self::classify_error(&e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_object_key_with_hardcoded_sharding() {
        // Test normal hash (64 chars) - uses hardcoded 4-char prefix
        assert_eq!(
            generate_object_key(
                "a1b2c3d4e5f6789012345678901234567890123456789012345678901234",
                &None,
                None,
            ),
            "a1b2/a1b2c3d4e5f6789012345678901234567890123456789012345678901234"
        );

        // Test hash with 0x prefix (should be stripped)
        assert_eq!(
            generate_object_key(
                "0xa1b2c3d4e5f6789012345678901234567890123456789012345678901234",
                &None,
                None,
            ),
            "a1b2/a1b2c3d4e5f6789012345678901234567890123456789012345678901234"
        );

        // Test short hash (less than 4 chars)
        assert_eq!(generate_object_key("abc", &None, None), "abc/abc");
    }

    #[test]
    fn test_object_key_with_base_path() {
        assert_eq!(
            generate_object_key(
                "a1b2c3d4e5f6789012345678901234567890123456789012345678901234",
                &Some("ciphertexts".to_string()),
                None,
            ),
            "ciphertexts/a1b2/a1b2c3d4e5f6789012345678901234567890123456789012345678901234"
        );
    }

    #[test]
    fn test_prefix_distribution() {
        // Verify different hashes get different 4-char prefixes (hardcoded)
        let hash1 = "a1b2c3d4e5f6789012345678901234567890123456789012345678901234";
        let hash2 = "f9e8d7c6b5a4321098765432109876543210987654321098765432109876";
        let hash3 = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab";

        let key1 = generate_object_key(hash1, &None, None);
        let key2 = generate_object_key(hash2, &None, None);
        let key3 = generate_object_key(hash3, &None, None);

        assert!(key1.contains("a1b2/"));
        assert!(key2.contains("f9e8/"));
        assert!(key3.contains("1234/"));

        // All keys should be different
        assert_ne!(key1, key2);
        assert_ne!(key2, key3);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_object_key_with_dynamic_path() {
        // Test with chain_id as dynamic path (legacy support)
        assert_eq!(
            generate_object_key(
                "a1b2c3d4e5f6789012345678901234567890123456789012345678901234",
                &Some("ciphertexts".to_string()),
                Some("8453"),
            ),
            "ciphertexts/8453/a1b2/a1b2c3d4e5f6789012345678901234567890123456789012345678901234"
        );

        // Test with dynamic path but no base path
        assert_eq!(
            generate_object_key(
                "a1b2c3d4e5f6789012345678901234567890123456789012345678901234",
                &None,
                Some("8453"),
            ),
            "8453/a1b2/a1b2c3d4e5f6789012345678901234567890123456789012345678901234"
        );

        // Test with multiple dynamic path segments (chain_id)
        assert_eq!(
            generate_object_key(
                "f9e8d7c6b5a4321098765432109876543210987654321098765432109876",
                &Some("ciphertexts".to_string()),
                Some("42161"),
            ),
            "ciphertexts/42161/f9e8/f9e8d7c6b5a4321098765432109876543210987654321098765432109876"
        );
    }

    // ---------------------------------------------------------------------
    // End-to-end smoke test against `fake-gcs-server` + `mock-gce-metadata`.
    //
    // Gated by `#[ignore]` — `cargo test` doesn't run it. To exercise:
    //
    //   docker compose up fake-gcs-server mock-gce-metadata -d
    //   FAKE_GCS_URL=http://localhost:4443 MOCK_MDS_URL=localhost:8080 \
    //     cargo test storage::gcs::tests::e2e_ -- --ignored --nocapture
    //
    // Requires the `cofhe_verified_inputs_dev` bucket to exist in the
    // emulator — created by the `fake-gcs-server-data-init` service in
    // docker-compose.yml. `MOCK_MDS_URL` points the auth library's MDS path
    // at the mock metadata server so the prod ADC code path is exercised.
    // ---------------------------------------------------------------------

    use crate::config::RetryConfig;

    const E2E_BUCKET: &str = "cofhe_verified_inputs_dev";

    fn e2e_endpoint() -> Option<String> {
        std::env::var("FAKE_GCS_URL").ok()
    }

    /// Set GCE_METADATA_HOST so the auth library's MDS path resolves to the
    /// mock metadata server. Required before any `GcsStorage::new` call.
    fn ensure_mock_mds() {
        let mds =
            std::env::var("MOCK_MDS_URL").expect("MOCK_MDS_URL must be set (e.g. localhost:8080)");
        std::env::set_var("GCE_METADATA_HOST", mds);
    }

    fn e2e_config(endpoint: &str) -> StorageConfig {
        StorageConfig {
            backend: "gcs".to_string(),
            bucket: E2E_BUCKET.to_string(),
            upload_timeout_secs: 30,
            retry_config: RetryConfig::default(),
            storage_endpoint: endpoint.to_string(),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "requires running fake-gcs-server + mock-gce-metadata; see comment above"]
    async fn e2e_upload_round_trips_against_fake_gcs() {
        ensure_mock_mds();
        let endpoint = e2e_endpoint().expect("FAKE_GCS_URL must be set");
        let storage = GcsStorage::new(&e2e_config(&endpoint))
            .await
            .expect("GcsStorage::new should succeed against fake-gcs-server");

        let key = "deadbeef00112233445566778899aabbccddeeff00112233445566778899aabb";
        let base = "cofhe/v1/chain/8453/security-zone/0/verified-inputs";
        let payload = b"hello-zk-verifier-migration";

        let mut meta = HashMap::new();
        meta.insert("ct_hash".to_string(), format!("0x{}", key));
        meta.insert("test_marker".to_string(), "gcs-1x-migration".to_string());

        storage
            .upload(key, payload, Some(&meta), Some(base), None)
            .await
            .expect("upload should succeed");

        // Read back via fake-gcs's REST API directly, so the assertion doesn't
        // depend on the same client implementation we're trying to test.
        let object_path = generate_object_key(key, &Some(base.to_string()), None);
        let mut encoded = String::new();
        for b in object_path.as_bytes() {
            match *b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    encoded.push(*b as char)
                }
                other => encoded.push_str(&format!("%{:02X}", other)),
            }
        }
        let url = format!(
            "{}/storage/v1/b/{}/o/{}?alt=media",
            endpoint.trim_end_matches('/'),
            E2E_BUCKET,
            encoded
        );

        let body = reqwest::get(&url)
            .await
            .expect("fake-gcs GET should not transport-fail")
            .error_for_status()
            .expect("fake-gcs GET should return 2xx")
            .bytes()
            .await
            .expect("body");
        assert_eq!(body.as_ref(), payload, "uploaded bytes should round-trip");
    }

    /// Exercises `Storage::read_object` against fake-gcs (same client API the
    /// `verify-stored-ct` binary uses), confirming the streaming read shape
    /// works against the emulator. Uses the same ADC code path as production.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "requires running fake-gcs-server + mock-gce-metadata; see comment above"]
    async fn e2e_read_object_streams_back_uploaded_bytes() {
        ensure_mock_mds();
        let endpoint = e2e_endpoint().expect("FAKE_GCS_URL must be set");
        let cfg = e2e_config(&endpoint);
        let storage = GcsStorage::new(&cfg).await.expect("GcsStorage::new");

        let key = "cafef00d11112222333344445555666677778888999900001111222233334444";
        let base = "cofhe/v1/chain/8453/security-zone/0/verification-proofs";
        let payload = b"read-path-smoke";
        storage.upload(key, payload, None, Some(base), None).await.expect("upload");

        let object_path = generate_object_key(key, &Some(base.to_string()), None);
        let parent = format!("projects/_/buckets/{}", E2E_BUCKET);
        let reader_client =
            Storage::builder().with_endpoint(&endpoint).build().await.expect("Storage::builder");
        let mut reader =
            reader_client.read_object(parent, object_path).send().await.expect("read_object");

        let mut data = Vec::new();
        while let Some(chunk) = reader.next().await.transpose().expect("chunk") {
            data.extend_from_slice(&chunk);
        }
        assert_eq!(data, payload);
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "requires running fake-gcs-server + mock-gce-metadata; see comment above"]
    async fn e2e_unreachable_endpoint_fails_at_startup() {
        // The startup probe is back, so unreachable endpoints fail in
        // `GcsStorage::new` (wrapped as Configuration) rather than at first
        // upload.
        ensure_mock_mds();
        let cfg = e2e_config("http://127.0.0.1:1"); // closed port
        match GcsStorage::new(&cfg).await {
            Ok(_) => panic!("GcsStorage::new should fail against an unreachable endpoint"),
            Err(StorageError::Configuration(msg)) => {
                assert!(!msg.is_empty(), "Configuration error must carry a message");
            }
            Err(other) => panic!("expected Configuration error, got {:?}", other),
        }
    }

    #[test]
    fn test_object_key_with_new_path_format() {
        // Test with new path format: cofhe/v1/chain/{chain_id}/security-zone/{zone}/verified-inputs
        // Sharding is HARDCODED to 4 characters
        let base_path = "cofhe/v1/chain/11155111/security-zone/0/verified-inputs";
        assert_eq!(
            generate_object_key(
                "a1b2c3d4e5f6789012345678901234567890123456789012345678901234",
                &Some(base_path.to_string()),
                None,
            ),
            "cofhe/v1/chain/11155111/security-zone/0/verified-inputs/a1b2/\
             a1b2c3d4e5f6789012345678901234567890123456789012345678901234"
        );

        // Test with verification-proofs
        let proof_base_path = "cofhe/v1/chain/8453/security-zone/1/verification-proofs";
        assert_eq!(
            generate_object_key(
                "0xff44239487234jh234iuh234",
                &Some(proof_base_path.to_string()),
                None,
            ),
            "cofhe/v1/chain/8453/security-zone/1/verification-proofs/ff44/ff44239487234jh234iuh234"
        );
    }
}
