use std::sync::Arc;
use std::time::Duration;

use axum::middleware;
use rust_common::log::{debug, error, info};
use tower_http::cors::{Any, CorsLayer};

use crate::api::{self, track_http_metrics, AppState};
use crate::config::{Config, MetricsMode};
use crate::signer::ecdsa::Signer;
#[cfg(feature = "external-storage")]
use crate::storage::{storage_manager::StorageManager, StorageFactory};
use crate::verifier::Verifier;
use crate::KeyMaterial;

/// Run the verifier with key material supplied by the caller.
///
/// Local-dev callers assemble [`KeyMaterial`] via
/// [`crate::load_keys_from_config`] (reads everything from disk). The TDX
/// launcher in the `tdx-signer` crate assembles it differently — `signer_pk`
/// from Secret Manager via the attested boot path, the rest from a launcher-
/// mounted volume via [`crate::load_tfhe_artifacts`].
pub async fn run_server(
    config: Config,
    keys: KeyMaterial,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Initializing ZK-Verifier server...");

    let KeyMaterial { crs, pk, sk, signer_pk, expected_signer_address } = keys;

    // Fail the boot if the loaded signing key doesn't match the published signer
    // identity (real-signer builds only — the mock-signer build uses a random
    // in-memory key with nothing to match). Two sources of the published identity:
    //   - TDX Shamir path: the `zk_signer_address` from the keygen's PublicMaterial
    //     (carried in `expected_signer_address`; bucket-sourced, integrity via bucket
    //     IAM — the reconstructed signer must match it or boot fails).
    //   - Local dev: the on-disk `signer_public_key` file next to the TFHE artifacts.
    #[cfg(not(feature = "mock-signer"))]
    match &expected_signer_address {
        Some(addr) => crate::signer::pubkey_match::verify_signer_matches_address(&signer_pk, addr)?,
        None => crate::signer::pubkey_match::verify_signer_matches_pubkey(
            &signer_pk,
            &config.keys.signer_pubkey_path,
        )?,
    }
    // In mock-signer builds nothing checks the identity; keep the field from
    // tripping unused-variable lints.
    #[cfg(feature = "mock-signer")]
    let _ = &expected_signer_address;

    info!("Creating signer and verifier...");
    let verifier = Verifier::new(crs, pk, Signer::new(signer_pk));
    debug!("Signer and verifier initialized");

    // Initialize proof storage if configured
    #[cfg(feature = "external-storage")]
    let (external_storage, health_storage) = {
        let storage_config = config.storage.as_ref().ok_or(
            "Storage configuration is required when 'external-storage' feature is enabled. Please \
             add a [storage] section to your config file.",
        )?;

        info!("Initializing external storage with configuration: {:?}", storage_config);

        // Validate storage configuration
        if let Err(e) = storage_config.validate() {
            return Err(format!("Invalid external storage configuration: {}", e).into());
        }

        // Initialize storage backend via factory. The Arc is cloned rather
        // than moved so the health loop can probe the same backend (and reuse
        // its warm client) instead of building a second one.
        let storage_backend = StorageFactory::from_config(storage_config).await?;
        let proof_storage = StorageManager::new(
            Arc::clone(&storage_backend),
            Some(storage_config.retry_config.clone()),
        );
        (Some(proof_storage), Some(storage_backend))
    };

    #[cfg(feature = "external-storage")]
    let state =
        Arc::new(AppState::new(verifier, sk, config.store_cts.endpoint.clone(), external_storage));

    #[cfg(not(feature = "external-storage"))]
    let state = Arc::new(AppState::new(verifier, sk, config.store_cts.endpoint.clone()));

    // No backend compiled in: the health loop publishes no storage series at
    // all rather than a 0, which would claim something is broken.
    #[cfg(not(feature = "external-storage"))]
    let health_storage: Option<Arc<dyn crate::storage::StorageProvider>> = None;

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([http::Method::POST])
        .allow_headers([http::header::CONTENT_TYPE])
        .max_age(Duration::from_secs(3600));
    let app = api::create_router()
        .with_state(state)
        .layer(cors)
        .layer(middleware::from_fn(track_http_metrics));

    let api_addr = format!("{}:{}", config.server.bind_address, config.server.bind_port);
    info!("Starting HTTP API server on {}...", api_addr);
    let api_listener = tokio::net::TcpListener::bind(&api_addr).await?;
    info!("API server running on {}", api_addr);
    info!("StoreCts endpoint configured as: {}", config.store_cts.endpoint);

    // One recorder always feeds the text exposition. In otlp mode a second
    // feeds the push pipeline and the two ride a fanout, because
    // `set_global_recorder` accepts exactly one recorder and the exposition
    // must survive as the debug surface while OTLP does the collecting.
    let (prom_recorder, prom_handle) = api::prometheus_recorder();
    let _otel_provider = match config.metrics.mode {
        MetricsMode::Otlp => match crate::otel_push::build_pipeline(&config.metrics) {
            Ok((provider, otel_recorder)) => {
                let fanout = metrics_util::layers::FanoutBuilder::default()
                    .add_recorder(prom_recorder)
                    .add_recorder(otel_recorder)
                    .build();
                metrics::set_global_recorder(fanout)
                    .map_err(|e| format!("install fanout metrics recorder: {e}"))?;
                Some(provider)
            }
            // Fail-open: a metadata blip or a missing IAM grant must not turn a
            // monitoring gap into an outage; metrics-target-down catches the
            // silence (teecryptor#73 review). The exposition still works, which
            // is how an operator tells this apart from a dead process.
            Err(e) => {
                error!("metrics: OTLP push failed to build — running WITHOUT metrics export: {e}");
                metrics::set_global_recorder(prom_recorder)
                    .map_err(|e| format!("install prometheus metrics recorder: {e}"))?;
                None
            }
        },
        MetricsMode::Prometheus => {
            metrics::set_global_recorder(prom_recorder)
                .map_err(|e| format!("install prometheus metrics recorder: {e}"))?;
            None
        }
    };

    // Liveness heartbeat: always 1, re-reported on every scrape or push.
    // `platform/metrics-target-down` alerts on its absence.
    metrics::gauge!("zk_verifier_up").set(1.0);

    // Error-only counters, published at zero so an alert policy can be created
    // before the first failure rather than after it.
    api::init_error_counters();
    #[cfg(feature = "external-storage")]
    crate::storage::storage_manager::init_error_counters();

    // Dependency health. Spawned after the recorder is installed (the gauges
    // need it) and before the servers, so the series exist — at 0 — from the
    // moment the process is serving. The task is detached and runs for the
    // process lifetime.
    crate::health::spawn(
        crate::health::Dependencies {
            client: reqwest::Client::new(),
            store_cts_endpoint: config.store_cts.endpoint.clone(),
            storage: health_storage,
        },
        Duration::from_secs(config.health.probe_interval_secs),
    );

    // Two servers, one process. In otlp mode the exposition port is NOT a
    // collection path — the push is — it is the IAP-only debug surface (see
    // tdx-signer/compute/main.tf); in prometheus mode it is the only path.
    let metrics_addr = format!("{}:{}", config.server.bind_address, config.server.metrics_port);
    info!("Metrics exposition on {} ({:?} mode)", metrics_addr, config.metrics.mode);
    let metrics_listener = tokio::net::TcpListener::bind(&metrics_addr).await?;
    tokio::try_join!(
        axum::serve(api_listener, app),
        axum::serve(metrics_listener, api::create_metrics_router(prom_handle))
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::response::Response;
    use axum::routing::post;
    use axum::Router;
    use hex;
    use rand::RngCore;
    use serde_json::Value;
    use tfhe::zk::CompactPkeCrs;
    use tfhe::{CompactPublicKey, ProvenCompactCiphertextList, ServerKey};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tower::ServiceExt;

    use super::*;

    /// Build an `AppState` for tests with explicit concurrency limits (via the
    /// `with_concurrency` builder), bypassing the `VERIFY_CONCURRENCY` /
    /// `MAX_INFLIGHT` env vars so the gate behaviour is deterministic regardless
    /// of the host's core count.
    fn test_state(
        zk_verifier: Verifier,
        server_key: ServerKey,
        external_endpoint: String,
        verify: usize,
        admit: usize,
    ) -> Arc<AppState> {
        let state = AppState::new(
            zk_verifier,
            server_key,
            external_endpoint,
            #[cfg(feature = "external-storage")]
            None,
        )
        .with_concurrency(verify, admit);
        Arc::new(state)
    }

    #[test_log::test(tokio::test)]
    async fn test_verify_batch_endpoint() -> Result<(), Box<dyn std::error::Error>> {
        // Set up mock server for store-cts feature testing
        #[cfg(feature = "store-cts")]
        let (mock_endpoint, shutdown_tx) = setup_mock_cts_server().await;

        #[cfg(not(feature = "store-cts"))]
        let mock_endpoint = "".to_string();

        // Generate keys once — used for both bad-request and valid-request sub-tests
        let (crs, server_key, public_key) = setup_tfhers();
        let signer = Signer::from_bytes(&[1u8; 32]).unwrap();
        let verifier = Verifier::new(crs.clone(), public_key.clone(), signer);
        // Generous limits — this test exercises the happy path through
        // spawn_blocking + set_server_key on the blocking thread.
        let state = test_state(verifier, server_key, mock_endpoint.clone(), 4, 256);

        // Test with empty payload — fails at hex decode before any crypto
        let app = api::create_router().with_state(state.clone());
        let request = Request::builder()
            .method("POST")
            .uri("/verifyBatch")
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"packed_list": "", "account_addr": "", "security_zone": 0, "chain_id": 11155111, "contract_address": ""}"#))?;
        let response: Response = ServiceExt::oneshot(app, request).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Now test with a valid payload
        let account_addr = "0x12345678abcdef";
        let account_addr_bytes =
            hex::decode(account_addr.strip_prefix("0x").unwrap_or(account_addr)).unwrap();
        let security_zone = 1u8;
        let chain_id = 11155111u32;
        let contract_address = "0x00000000000000000000000000000000000000aa";
        let metadata = Verifier::reconstruct_metadata(&account_addr_bytes, security_zone, chain_id);

        let proven_list = create_proven_list(&public_key, &crs, &metadata);
        let packed_list_bytes = rust_common::safe_serde::serialize(&proven_list).unwrap();
        let packed_list_hex = hex::encode(&packed_list_bytes);

        let request_payload = format!(
            r#"{{"packed_list": "{}", "account_addr": "{}", "security_zone": {}, "chain_id": {}, "contract_address": "{}"}}"#,
            packed_list_hex, account_addr, security_zone, chain_id, contract_address
        );

        // ---- The removed per-ciphertext endpoint: no longer routed ----
        // A payload that used to succeed here must now miss the router entirely.
        let app = api::create_router().with_state(state.clone());
        let request = Request::builder()
            .method("POST")
            .uri("/verify")
            .header("Content-Type", "application/json")
            .body(Body::from(request_payload.clone()))?;
        let response: Response = ServiceExt::oneshot(app, request).await?;
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "POST /verify was removed; only /verifyBatch remains"
        );

        // ---- Batch endpoint: a single signature covering all ciphertexts ----
        let app = api::create_router().with_state(state.clone());
        let request = Request::builder()
            .method("POST")
            .uri("/verifyBatch")
            .header("Content-Type", "application/json")
            .body(Body::from(request_payload))?;
        let response: Response = ServiceExt::oneshot(app, request).await?;
        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let body: Value = serde_json::from_slice(&body_bytes)?;
        assert_eq!(body["status"], "success");

        let data = &body["data"];
        // One signature for the whole batch (not one per ciphertext).
        assert!(data["signature"].as_str().unwrap().starts_with("0x"));
        assert!(data["recid"].is_number());

        // Two ciphertexts in, two entries out, each with its hash and type.
        let ciphertexts = data["ciphertexts"].as_array().expect("no ciphertexts in batch response");
        assert_eq!(ciphertexts.len(), 2);
        for ct in ciphertexts {
            assert!(ct["ct_hash"].as_str().unwrap().starts_with("0x"));
            assert!(ct["ct_type"].is_number());
            // Batch entries must NOT carry their own signature.
            assert!(ct.get("signature").is_none());
        }

        // Shut down the mock server if it was started
        #[cfg(feature = "store-cts")]
        {
            shutdown_tx.send(()).unwrap_or_else(|_| println!("Failed to shut down mock server"));
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        Ok(())
    }

    /// A proven list carrying zero ciphertexts must be rejected, not signed: the
    /// batch digest of an empty list is the constant keccak256(""), so a
    /// signature over it says nothing about this account, chain, or request.

    #[test_log::test(tokio::test)]
    async fn test_verify_batch_rejects_empty_list() -> Result<(), Box<dyn std::error::Error>> {
        let (crs, server_key, public_key) = setup_tfhers();
        let signer = Signer::from_bytes(&[1u8; 32]).unwrap();
        let verifier = Verifier::new(crs.clone(), public_key.clone(), signer);
        let state = test_state(verifier, server_key, "".to_string(), 1, 8);

        let account_addr = "0x12345678abcdef";
        let account_addr_bytes = hex::decode(account_addr.trim_start_matches("0x")).unwrap();
        let contract_addr = "0x00000000000000000000000000000000000000aa";
        let security_zone = 1u8;
        let chain_id = 11155111u32;
        let metadata = Verifier::reconstruct_metadata(&account_addr_bytes, security_zone, chain_id);

        // Same as create_proven_list, but with nothing pushed into the builder.
        let empty_list = tfhe::ProvenCompactCiphertextList::builder(&public_key)
            .build_with_proof_packed(&crs, &metadata, tfhe::zk::ZkComputeLoad::Verify)?;
        let packed_list_hex = hex::encode(rust_common::safe_serde::serialize(&empty_list).unwrap());

        let request_payload = format!(
            r#"{{"packed_list": "{}", "account_addr": "{}", "security_zone": {}, "chain_id": {}, "contract_address": "{}"}}"#,
            packed_list_hex, account_addr, security_zone, chain_id, contract_addr
        );

        let app = api::create_router().with_state(state.clone());
        let request = Request::builder()
            .method("POST")
            .uri("/verifyBatch")
            .header("Content-Type", "application/json")
            .body(Body::from(request_payload))?;
        let response: Response = ServiceExt::oneshot(app, request).await?;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        let body: Value = serde_json::from_slice(&body_bytes)?;
        assert_eq!(body["status"], "error");
        let message = body["data"]["message"].as_str().unwrap().to_lowercase();
        assert!(message.contains("empty"), "error should mention the empty batch, got: {message}");

        Ok(())
    }

    /// Build a verifier + server key and a valid, fully-proven `/verify` JSON
    /// body that passes `verify_and_sign_batch_impl`. Returns the state pieces and the
    /// request body so concurrency tests can drive real verifies.
    fn valid_verify_setup() -> (Verifier, ServerKey, String) {
        let (crs, server_key, public_key) = setup_tfhers();
        let signer = Signer::from_bytes(&[1u8; 32]).unwrap();
        let verifier = Verifier::new(crs.clone(), public_key.clone(), signer);

        let account_addr = "0x12345678abcdef";
        let account_addr_bytes =
            hex::decode(account_addr.strip_prefix("0x").unwrap_or(account_addr)).unwrap();
        let security_zone = 1u8;
        let chain_id = 11155111u32;
        let contract_address = "0x00000000000000000000000000000000000000aa";
        let metadata = Verifier::reconstruct_metadata(&account_addr_bytes, security_zone, chain_id);
        let proven_list = create_proven_list(&public_key, &crs, &metadata);
        let packed_list_hex =
            hex::encode(rust_common::safe_serde::serialize(&proven_list).unwrap());
        let body = format!(
            r#"{{"packed_list": "{}", "account_addr": "{}", "security_zone": {}, "chain_id": {}, "contract_address": "{}"}}"#,
            packed_list_hex, account_addr, security_zone, chain_id, contract_address
        );
        (verifier, server_key, body)
    }

    /// Admission cap: when every `MAX_INFLIGHT` permit is held, a new
    /// `/verifyBatch` must shed with 503 (NOT queue). We hold the sole permit
    /// (admit = 1) from the test, so the request is rejected at the admission gate
    /// before it ever reaches the CPU stage — fully deterministic, no timing.
    #[test_log::test(tokio::test)]
    async fn verify_admission_cap_sheds_with_503() {
        let (verifier, server_key, body) = valid_verify_setup();
        let state = test_state(verifier, server_key, "".to_string(), 4, 1);

        // Exhaust the single admission permit and keep it held for the request.
        let _held = state.admit_sem.clone().acquire_owned().await.unwrap();

        let app = api::create_router().with_state(state.clone());
        let request = Request::builder()
            .method("POST")
            .uri("/verifyBatch")
            .header("Content-Type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let response: Response = ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "overflow must shed with 503"
        );
        assert_eq!(
            response.headers().get("Retry-After").and_then(|v| v.to_str().ok()),
            Some("1"),
            "shed response must carry Retry-After"
        );
    }

    /// Concurrency gate: with VERIFY_CONCURRENCY = 1, only one verify may run at
    /// a time. We hold the sole CPU permit from the test, fire a `/verifyBatch`, and
    /// assert it is still blocked (has not responded) while the permit is held;
    /// once we release it the request completes with 200. This proves verifies
    /// serialize on the gate, deterministically (no reliance on verify timing).
    #[test_log::test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
    async fn verify_concurrency_gate_serializes() {
        // A working StoreCts endpoint is needed for the post-verify persist to
        // succeed (and return 200) when the `store-cts` feature is enabled.
        #[cfg(feature = "store-cts")]
        let (endpoint, shutdown_tx) = setup_mock_cts_server().await;
        #[cfg(not(feature = "store-cts"))]
        let endpoint = "".to_string();

        let (verifier, server_key, body) = valid_verify_setup();
        // verify = 1: a single CPU permit. admit large so admission never sheds.
        let state = test_state(verifier, server_key, endpoint, 1, 256);

        // Hold the only CPU permit, so any incoming verify must wait on the gate.
        let held = state.verify_sem.clone().acquire_owned().await.unwrap();

        // Real server so the request runs as an independent concurrent task.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = api::create_router().with_state(state.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let url = format!("http://{}/verifyBatch", addr);
        let done = Arc::new(AtomicUsize::new(0));
        let done2 = done.clone();
        let req = tokio::spawn(async move {
            let status = reqwest::Client::new()
                .post(&url)
                .header("Content-Type", "application/json")
                .body(body)
                .send()
                .await
                .unwrap()
                .status();
            done2.store(1, Ordering::SeqCst);
            status
        });

        // While we hold the permit, the request must be parked on the gate.
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(done.load(Ordering::SeqCst), 0, "verify must block while the CPU gate is held");

        // Release the gate; the request now acquires the permit and completes.
        drop(held);
        let status = req.await.unwrap();
        assert_eq!(status.as_u16(), 200, "verify should succeed once the gate frees");
        assert_eq!(done.load(Ordering::SeqCst), 1);

        #[cfg(feature = "store-cts")]
        let _ = shutdown_tx.send(());
    }

    #[test_log::test(tokio::test)]
    async fn test_healthz_endpoint() -> Result<(), Box<dyn std::error::Error>> {
        // healthz never touches state, but create_router() requires AppState to build.
        let (crs, server_key, public_key) = setup_tfhers();
        let signer = Signer::from_bytes(&[1u8; 32]).unwrap();
        let verifier = Verifier::new(crs, public_key, signer);
        let state = Arc::new(AppState::new(
            verifier,
            server_key,
            String::new(),
            #[cfg(feature = "external-storage")]
            None,
        ));

        let app = api::create_router().with_state(state);
        let request = Request::builder().method("GET").uri("/healthz").body(Body::empty())?;
        let response: Response = ServiceExt::oneshot(app, request).await?;
        assert_eq!(response.status(), StatusCode::OK);

        Ok(())
    }

    fn setup_tfhers() -> (CompactPkeCrs, ServerKey, CompactPublicKey) {
        use tfhe::shortint::parameters;

        let params = parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
        let cpk_params = parameters::v0_11::compact_public_key_only::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
        let casting_params = parameters::v0_11::key_switching::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

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
            .build_with_proof_packed(crs, metadata, tfhe::zk::ZkComputeLoad::Verify)
            .unwrap()
    }

    async fn setup_mock_cts_server() -> (String, oneshot::Sender<()>) {
        let app = Router::new().route("/StoreCts", post(handle_store_cts));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    shutdown_rx.await.ok();
                })
                .await
                .unwrap();
        });

        (format!("http://{}", addr), shutdown_tx)
    }

    async fn handle_store_cts(
        axum::extract::Json(payload): axum::extract::Json<Value>,
    ) -> StatusCode {
        if payload.get("cts").is_some() && payload.get("chainId").is_some() {
            StatusCode::OK
        } else {
            StatusCode::BAD_REQUEST
        }
    }
}
