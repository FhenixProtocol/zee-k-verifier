mod base64;
mod hex;
#[cfg(not(feature = "external-storage"))]
use std::future::ready;
use std::sync::Arc;
use std::time::Instant;

use ::hex as hex_crate;
use axum::extract::{MatchedPath, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use metrics::{counter, gauge, histogram};
use metrics_exporter_prometheus::{
    Matcher, PrometheusBuilder, PrometheusHandle, PrometheusRecorder,
};
use rust_common::log::{debug, error, trace, warn};
use serde::{Deserialize, Serialize};
use tfhe::{set_server_key, ProvenCompactCiphertextList, ServerKey};
use tokio::sync::Semaphore;

#[cfg(feature = "external-storage")]
use crate::storage::storage_manager::StorageManager;
use crate::verifier::{VerifiedBatch, VerifiedCt, Verifier};

/// Bucket boundaries for every `_milliseconds` histogram.
///
/// Without an explicit list `PrometheusBuilder` renders a `histogram!` as a
/// **summary** — no `_bucket` series, so no `histogram_quantile()` and no
/// aggregation across instances. The ceiling is the LB backend's
/// `timeout_sec = 300`; dense where a healthy verify sits.
const DURATION_MS_BUCKETS: &[f64] = &[
    1.0, 2.5, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2000.0, 3000.0, 5000.0, 7500.0,
    10_000.0, 15_000.0, 30_000.0, 60_000.0, 120_000.0, 300_000.0,
];

/// Every histogram measured in milliseconds. Listed explicitly: one missing from
/// here silently reverts to a summary.
const DURATION_MS_METRICS: &[&str] = &[
    "storage_operation_duration_milliseconds",
    "storage_persist_duration_milliseconds",
    "store_cts_duration_milliseconds",
    "http_request_duration_milliseconds",
    "function_duration_milliseconds",
    "async_function_duration_milliseconds",
    "zk_verify_step_duration_milliseconds",
];

/// 1KiB to 64MiB. A serialized ciphertext is kilobytes to low megabytes; the top
/// bucket exists to make an unexpectedly large payload visible.
/// How many ciphertexts each `/verifyBatch` call actually covered.
///
/// `/verifyBatch` is the only verification endpoint, so this is the full
/// distribution of real batch sizes — a single-input encrypt shows up as a
/// batch of one, not as a separate metric.
const BATCH_SIZE_METRIC: &str = "zk_verify_batch_size_ciphertexts";

/// Bucket edges for [`BATCH_SIZE_METRIC`], placed around the on-chain
/// break-even point for `TaskManager`'s `InputVerified` event shape: up to 3
/// inputs, one event per input is cheaper; from 4 up, a single array-valued
/// event wins. So `le="3"` against the total count reads directly as "how often
/// the per-input shape is the cheaper one", which is the question that decides
/// whether reshaping the event is worth a multi-service migration.
///
/// Without explicit buckets `metrics-exporter-prometheus` renders a histogram
/// as a summary, which reports quantiles and cannot answer "what share exceeds
/// 4" at all.
const BATCH_SIZE_BUCKETS: &[f64] = &[1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 8.0, 12.0, 16.0, 32.0, 64.0];

// Constants for hash adjustment (matching fhe-engine)
const TRIVIAL_ENCRYPT_AND_TYPE_BYTE: usize = 30;
const SECURITY_ZONE_BYTE: usize = 31;
const TYPE_MASK: u8 = 0x7F; // 0b01111111 - lowest 7 bits
const TRIVIAL_ENCRYPT_FLAG: u8 = 0x80; // 0b10000000 - highest bit

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

/// Represents the outcome of a storage operation
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
enum StorageOutcome {
    /// Successfully stored with the given proof ID
    Stored(String),
    /// Storage feature is disabled via feature flag
    Disabled,
    /// Storage is not configured in the application
    NotConfigured,
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    #[serde(rename = "packed_list")]
    #[serde(with = "hex")]
    pub packed_list: Vec<u8>,
    #[serde(rename = "account_addr")]
    pub account_addr: String,
    #[serde(rename = "security_zone")]
    pub security_zone: u8,
    #[serde(rename = "chain_id")]
    pub chain_id: u32,
    /// Address of the contract the input may be consumed by. Bound into the
    /// signed message so a verified input cannot be replayed into another contract.
    #[serde(rename = "contract_address")]
    pub contract_address: String,
}

// Internal request structure for updating CT
#[derive(Serialize, Clone)]
struct StoreCtsEntry {
    utype: u8,
    value: String,
    #[serde(rename = "securityZone")]
    security_zone: u8,
}

#[derive(Serialize)]
struct StoreCtsRequest {
    cts: Vec<StoreCtsEntry>,
    #[serde(rename = "chainId")]
    chain_id: u32,
    signature: String,
}

/// A single verified ciphertext in the batch response. The batch as a whole is
/// covered by one signature (see [`BatchVerifyResponse::Success`]); `ct_hash`
/// and `ct_type` are the per-ciphertext fields a consumer needs to reconstruct
/// the signed digest.
#[derive(Serialize, Debug)]
pub struct CiphertextResponse {
    pub ct_hash: String,
    pub ct_type: u8,
}

#[cfg(feature = "mock-keys")]
#[derive(Serialize)]
pub struct PublicKeyResponse {
    #[serde(with = "hex")]
    pub public_key: Vec<u8>,
}

#[cfg(feature = "mock-keys")]
#[derive(Serialize)]
pub struct CrsResponse {
    #[serde(with = "hex")]
    pub crs: Vec<u8>,
}

/// Response for the `POST /verifyBatch` endpoint: a single signature covering
/// the whole batch.
#[derive(Serialize)]
#[serde(tag = "status", content = "data")]
pub enum BatchVerifyResponse {
    #[serde(rename = "success")]
    Success {
        /// The verified ciphertexts, in submission order.
        ciphertexts: Vec<CiphertextResponse>,
        /// Single signature covering the whole batch:
        /// keccak256(hash_0 || hash_1 || ... || hash_n).
        signature: String,
        /// Recovery id for the batch signature.
        recid: u8,
    },
    #[serde(rename = "error")]
    Error { message: String },
}

#[derive(Serialize)]
pub struct SignerAddressResponse {
    pub address: String,
}

/// Default admission cap (max total in-flight `/verify` requests) when
/// `MAX_INFLIGHT` is unset. Overflow above this sheds with 503 + `Retry-After`.
const DEFAULT_MAX_INFLIGHT: usize = 256;

/// Threads in a single tfhe-zk-pok proof-verification pool
/// (`tfhe_zk_pok::proofs::VERIF_MAX_THREADS_COUNT`). tfhe runs each verify in a
/// dedicated rayon pool of this size and creates `ceil(cores / this)` such
/// pools, so one verify already saturates a pool's worth of cores. The count of
/// independent pools — `ceil(cores / 32)` — is therefore the concurrency at
/// which verifies stop contending, and the right default for the CPU gate: the
/// raw core count would admit many verifies onto a single 32-thread pool on a
/// <=32-vCPU host and multiply their latency instead of isolating it.
const TFHE_VERIF_POOL_THREADS: usize = 32;

/// Upper clamp on the CPU gate — a sanity ceiling for a fat-fingered
/// `VERIFY_CONCURRENCY` (more concurrent verifies than this never helps).
const MAX_VERIFY_CONCURRENCY: usize = 4096;

/// Upper clamp on the admission cap — guards against a huge `MAX_INFLIGHT`
/// panicking `Semaphore::new` (tokio caps permits at `Semaphore::MAX_PERMITS`).
const MAX_INFLIGHT_CEIL: usize = 1 << 20;

/// Resolve the CPU gate size: `VERIFY_CONCURRENCY` env var, else the number of
/// independent tfhe verification pools `ceil(available_parallelism / 32)` (see
/// [`TFHE_VERIF_POOL_THREADS`]). Clamped to `1..=MAX_VERIFY_CONCURRENCY`.
fn verify_concurrency_from_env() -> usize {
    std::env::var("VERIFY_CONCURRENCY")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or_else(default_verify_concurrency)
        .clamp(1, MAX_VERIFY_CONCURRENCY)
}

/// `ceil(available_parallelism / 32)`, minimum 1 — the count of independent
/// tfhe verification pools on this host (see [`TFHE_VERIF_POOL_THREADS`]).
fn default_verify_concurrency() -> usize {
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    cores.div_ceil(TFHE_VERIF_POOL_THREADS).max(1)
}

/// Resolve the admission cap: `MAX_INFLIGHT` env var, else
/// [`DEFAULT_MAX_INFLIGHT`]. Clamped to `1..=MAX_INFLIGHT_CEIL`.
fn max_inflight_from_env() -> usize {
    std::env::var("MAX_INFLIGHT")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_MAX_INFLIGHT)
        .clamp(1, MAX_INFLIGHT_CEIL)
}

#[allow(dead_code)]
pub struct AppState {
    pub zk_verifier: Verifier,
    pub server_key: ServerKey,
    pub external_endpoint: String,
    #[cfg(feature = "external-storage")]
    pub external_storage: Option<StorageManager>,
    /// Wait-only CPU gate — bounds concurrent TFHE proof verifies to
    /// `VERIFY_CONCURRENCY` (default = `ceil(cores / 32)`, the number of
    /// independent tfhe verification pools). Excess callers wait; none are
    /// rejected here. Sized small so verifies don't oversubscribe cores or
    /// monopolize the blocking pool.
    pub verify_sem: Arc<Semaphore>,
    /// Admission cap — bounds total in-flight `/verify` requests to
    /// `MAX_INFLIGHT` (default 256). Acquired with `try_acquire_owned` and held
    /// for the whole request (incl. the post-verify storage I/O), so it caps
    /// total in-flight, not just the CPU stage. Overflow sheds with 503.
    pub admit_sem: Arc<Semaphore>,
}

impl AppState {
    /// Build state with concurrency limits taken from the environment
    /// (`VERIFY_CONCURRENCY`, `MAX_INFLIGHT`) — see [`verify_concurrency_from_env`]
    /// and [`max_inflight_from_env`] for the defaults.
    pub fn new(
        zk_verifier: Verifier,
        server_key: ServerKey,
        external_endpoint: String,
        #[cfg(feature = "external-storage")] external_storage: Option<StorageManager>,
    ) -> Self {
        let verify = verify_concurrency_from_env();
        let admit = max_inflight_from_env();
        debug!("verify concurrency gate = {}, admission cap = {}", verify, admit);
        Self {
            zk_verifier,
            server_key,
            external_endpoint,
            #[cfg(feature = "external-storage")]
            external_storage,
            verify_sem: Arc::new(Semaphore::new(verify)),
            admit_sem: Arc::new(Semaphore::new(admit)),
        }
    }

    /// Override the CPU-gate (`verify`) and admission-cap (`admit`) sizes
    /// explicitly, bypassing the env vars. Both are clamped to >= 1. Boot-time
    /// builder (mirrors teecryptor); also used by tests to make the gate
    /// behaviour deterministic regardless of the host's core count.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn with_concurrency(mut self, verify: usize, admit: usize) -> Self {
        self.verify_sem = Arc::new(Semaphore::new(verify.max(1)));
        self.admit_sem = Arc::new(Semaphore::new(admit.max(1)));
        self
    }
}

// Internal function to update CT via HTTP call
#[metrics_utils_macros::measured_async_function()]
async fn store_cts_internally(
    client: &reqwest::Client,
    endpoint: &str,
    chain_id: u32,
    updates: Vec<StoreCtsEntry>,
) -> Result<(), String> {
    let endpoint = endpoint.to_string() + "/StoreCts"; // todo shouldn't be hardcoded
    let request = StoreCtsRequest { cts: updates, chain_id, signature: "toml".to_string() }; // todo replace mock signature
    match client.post(endpoint.clone()).json(&request).send().await {
        Ok(response) if response.status().is_success() => Ok(()),
        Ok(response) => {
            Err(format!("Service returned error at endpoint {}: {}", endpoint, response.status()))
        }
        Err(e) => Err(format!("Failed to contact service at endpoint {}: {}", endpoint, e)),
    }
}

// Retryable version of store_cts_internally with exponential backoff
async fn store_cts_internally_retryable(
    endpoint: &str,
    verified_cts: &[VerifiedCt],
    chain_id: u32,
    security_zone: u8,
    max_retries: u32,
    initial_delay_ms: u64,
) -> Result<(), String> {
    let client = reqwest::Client::new();
    let ct_hashes = verified_cts
        .iter()
        .map(|verified| format!("0x{}", hex_crate::encode(&verified.ct_hash)))
        .collect::<Vec<String>>()
        .join(", ");
    let log_context = format!(
        "internally: ct count: {}, ct hashes: {}, endpoint: {}, chain_id: {}, security_zone: {}",
        verified_cts.len(),
        ct_hashes,
        endpoint,
        chain_id,
        security_zone
    );
    debug!("Preparing to store {}", log_context);

    let updates: Vec<StoreCtsEntry> = verified_cts
        .iter()
        .map(|verified| StoreCtsEntry {
            utype: verified.ct_type as u8,
            value: format!("0x{}", hex_crate::encode(verified.ct_bytes.as_slice())),
            security_zone,
        })
        .collect();

    // Across the whole retried operation, backoff sleeps included: that is what
    // the caller waits for.
    let started = Instant::now();
    let mut delay_ms = initial_delay_ms;
    let mut retries_left = max_retries;
    loop {
        match store_cts_internally(&client, endpoint, chain_id, updates.clone()).await {
            Ok(()) => {
                debug!("Successfully stored {}", log_context);
                record_store_cts_outcome("success", started);
                return Ok(());
            }
            Err(e) => {
                if retries_left == 0 {
                    record_store_cts_outcome("error", started);
                    return Err(format!(
                        "Failed to store ciphertexts internally after {} attempts for {}: {}",
                        max_retries, log_context, e
                    ));
                }
                warn!(
                    "Failed to store ciphertexts internally (retries left: {}) for {}: {}",
                    retries_left, log_context, e
                );
            }
        }

        // Separate from the outcome: a run that always succeeds on its second
        // attempt is indistinguishable from a healthy one without this.
        counter!("store_cts_retries_total").increment(1);

        retries_left -= 1;
        debug!("Retrying in {}ms...", delay_ms);
        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        delay_ms *= 2; // Exponential backoff
    }
}

/// One increment per logical store-cts operation, not per HTTP attempt.
fn record_store_cts_outcome(status: &'static str, started: Instant) {
    counter!("store_cts_total", "status" => status).increment(1);
    histogram!("store_cts_duration_milliseconds").record(started.elapsed().as_secs_f64() * 1000.0);
}

/// RAII guard that keeps the `zk_verify_in_flight` gauge balanced on every exit
/// path. Constructed with [`InFlightGuard::enter`] (increments) and decrements
/// on drop, so the count is correct whether the verify returns normally,
/// panics, or the *handler* future is dropped mid-flight (client disconnect).
/// Lives inside the `spawn_blocking` closure — which always runs to completion,
/// so drop is guaranteed — mirroring how the CPU permit rides into the task.
struct InFlightGuard;

impl InFlightGuard {
    fn enter() -> Self {
        gauge!("zk_verify_in_flight").increment(1.0);
        Self
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        gauge!("zk_verify_in_flight").decrement(1.0);
    }
}

// The k8s zk-verifier in cofhe runs the identical verify code without these
// guards; mirror this concurrency hardening there.

/// Acquire the admission permit, which bounds *total* in-flight requests rather
/// than just the CPU stage. `try_acquire_owned` never waits: at the cap we shed
/// immediately with 503 + Retry-After instead of queueing unboundedly. The
/// returned permit must be held for the whole request, including the post-verify
/// storage I/O.
/// Publish the error-only counters at zero so their series exist from boot.
///
/// A counter that has never fired has no series, and Cloud Monitoring refuses
/// to create a PromQL alert policy over a metric with no descriptor — so the
/// alert cannot exist until after the first event it is meant to catch, which
/// then goes unnoticed. Zero-initialising costs one flat series each and keeps
/// `increase(...) > 0` quiet until something real happens.
pub(crate) fn init_error_counters() {
    counter!("zk_verify_admission_rejected_total").increment(0);
    counter!("store_cts_retries_total").increment(0);
}

fn admit(state: &Arc<AppState>, endpoint: &str) -> Option<tokio::sync::OwnedSemaphorePermit> {
    match state.admit_sem.clone().try_acquire_owned() {
        Ok(permit) => Some(permit),
        Err(_) => {
            counter!("zk_verify_admission_rejected_total").increment(1);
            warn!("in-flight cap reached; shedding {endpoint} with 503 (retryable)");
            None
        }
    }
}

/// Run a CPU-bound verify behind the CPU gate, on the blocking pool. Shared by
/// `/verify` and `/verifyBatch` so both endpoints are gated identically —
/// duplicating this per handler is how one endpoint ends up silently ungated.
///
/// The CPU permit rides into the blocking task so it is released only when the
/// CPU work truly finishes. `set_server_key` is a tfhe THREAD-LOCAL, so it must
/// be set on the blocking thread that runs the verify, not on the async thread.
async fn gated_verify<T, F>(
    state: &Arc<AppState>,
    run: F,
) -> std::result::Result<T, (StatusCode, String)>
where
    F: FnOnce(&Arc<AppState>) -> std::result::Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    debug!("Awaiting verify CPU permit ({} available)...", state.verify_sem.available_permits());
    let cpu_permit = {
        let _t = crate::telemetry::StepTimer::start("cpu_gate_wait");
        state
            .verify_sem
            .clone()
            .acquire_owned()
            .await
            .expect("verify gate semaphore is never closed")
    };

    let st = state.clone();
    let join = tokio::task::spawn_blocking(move || {
        let _cpu = cpu_permit; // released only when the verify truly finishes

        // RAII gauge, inside the (never-cancellable) blocking task so it stays
        // balanced even if the handler future is dropped on client disconnect
        // while awaiting the join, or the verify panics.
        let _in_flight = InFlightGuard::enter();
        {
            let _t = crate::telemetry::StepTimer::start("set_server_key");
            set_server_key(st.server_key.clone());
        }
        run(&st)
    })
    .await;

    match join {
        Ok(Ok(out)) => Ok(out),
        Ok(Err(e)) => Err((StatusCode::BAD_REQUEST, e)),
        Err(e) => {
            error!("verify task panicked: {e}");
            Err((StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()))
        }
    }
}

/// Log the verified ciphertexts (shared by the legacy and batch endpoints).
fn log_verified(cts: &[VerifiedCt], account_addr: &str, security_zone: u8, chain_id: u32) {
    let ct_hashes = cts
        .iter()
        .map(|verified| format!("0x{}", hex_crate::encode(&verified.ct_hash)))
        .collect::<Vec<String>>()
        .join(", ");

    debug!(
        "Successfully verified and signed ct count: {}, non-adjusted ct hashes: {}, account: {}, \
         security zone: {}, chain id: {}",
        cts.len(),
        ct_hashes,
        account_addr,
        security_zone,
        chain_id
    );
}

/// Persist the verified ciphertexts to external storage and the StoreCts
/// endpoint (each gated by its feature flag), running both in parallel. Both
/// must succeed. Shared by the legacy and batch endpoints.
///
/// On failure returns an `(status, client_message)` tuple; detailed errors are
/// logged here and the client message is intentionally generic.
async fn persist_cts(
    state: &Arc<AppState>,
    packed_list_bytes: &[u8],
    cts: &[VerifiedCt],
    account_addr: &str,
    security_zone: u8,
    chain_id: u32,
) -> std::result::Result<(), (StatusCode, String)> {
    // Unified storage logic: external storage and StoreCTS endpoint in parallel
    // Both must succeed if enabled.

    #[cfg(not(feature = "external-storage"))]
    let external_storage_future = ready(Ok(StorageOutcome::Disabled));

    #[cfg(feature = "external-storage")]
    let external_storage_future = async {
        if let Some(ref storage) = state.external_storage {
            let ct_data: Vec<(String, Vec<u8>, u8)> = cts
                .iter()
                .map(|verified| {
                    // Adjust hash to embed metadata (matching fhe-engine behavior)
                    let mut hash_array = [0u8; 32];
                    hash_array.copy_from_slice(&verified.ct_hash);
                    let adjusted_hash = adjust_hash_for_metadata(
                        hash_array,
                        verified.ct_type as u8,
                        security_zone,
                        false, // Assuming not trivially encrypted for now
                    );
                    let ct_hash = format!("0x{}", hex_crate::encode(adjusted_hash));

                    debug!(
                        "Adjusted CT hash: original=0x{}, adjusted={}, type={}, security_zone={}",
                        hex_crate::encode(&verified.ct_hash),
                        ct_hash,
                        verified.ct_type as u8,
                        security_zone
                    );

                    (ct_hash, verified.ct_bytes.clone(), verified.ct_type as u8)
                })
                .collect();

            storage
                .store_proof_and_cts(
                    packed_list_bytes,
                    ct_data,
                    account_addr,
                    security_zone,
                    chain_id,
                )
                .await
                .map_err(|e| {
                    use crate::storage::errors::StorageError;

                    let status = match e {
                        StorageError::Timeout { .. } => StatusCode::GATEWAY_TIMEOUT,
                        StorageError::Network(_) => StatusCode::BAD_GATEWAY,
                        StorageError::PermissionDenied(_) => StatusCode::FORBIDDEN,
                        StorageError::NotFound { .. } => StatusCode::NOT_FOUND,
                        StorageError::Serialization { .. } => StatusCode::BAD_REQUEST,
                        _ => StatusCode::INTERNAL_SERVER_ERROR,
                    };
                    (status, format!("Saving to external storage failed: {}", e))
                })
        } else {
            debug!("No external storage configured");
            Ok(String::new())
        }
    };

    #[cfg(feature = "store-cts")]
    let store_cts_future = async {
        store_cts_internally_retryable(
            &state.external_endpoint,
            cts,
            chain_id,
            security_zone,
            5,    // todo make configurable
            1000, // todo make configurable
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("store_cts failed: {}", e)))
    };

    #[cfg(not(feature = "store-cts"))]
    let store_cts_future = ready(Ok(()));

    // Run both operations in parallel and wait for both to complete
    let (external_storage_result, store_cts_result) = {
        let _t = crate::telemetry::StepTimer::start("storage");
        tokio::join!(external_storage_future, store_cts_future)
    };

    // Check results - BOTH must succeed for transaction to succeed
    // Log all failures before returning
    let external_err: Option<&(StatusCode, String)> = external_storage_result.as_ref().err();
    let store_cts_err: Option<&(StatusCode, String)> = store_cts_result.as_ref().err();

    if let Some((_, msg)) = external_err {
        error!("External storage failed: {}", msg);
    }
    if let Some((_, msg)) = store_cts_err {
        error!("Store-cts endpoint failed: {}", msg);
    }

    // Return the first error encountered (with generic message to client)
    if let Some((status, _)) = external_err.or(store_cts_err) {
        return Err((*status, "Could not persist data".to_string()));
    }

    Ok(())
}

/// Batch endpoint: returns a single signature covering the whole batch.
///
/// Gated exactly like `/verify` above — same admission cap, same CPU gate, same
/// blocking pool. A batch verify is at least as CPU-hungry as a single one, so
/// leaving it ungated would let it bypass the admission cap the legacy path is
/// protected by.
#[metrics_utils_macros::measured_async_function()]
async fn verify_and_sign_batch(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<VerifyRequest>,
) -> Response {
    let _admit = match admit(&state, "/verifyBatch") {
        Some(permit) => permit,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                [("Retry-After", "1")],
                Json(BatchVerifyResponse::Error {
                    message: "Server busy, retry shortly".to_string(),
                }),
            )
                .into_response()
        }
    };

    let VerifyRequest {
        packed_list: packed_list_bytes,
        account_addr,
        security_zone,
        chain_id,
        contract_address,
    } = payload;
    debug!(
        "Processing batch verification request for account: {}, security_zone: {}, chain_id: {}, \
         contract: {}",
        account_addr, security_zone, chain_id, contract_address
    );

    let (pl, addr, contract) =
        (packed_list_bytes.clone(), account_addr.clone(), contract_address.clone());
    let result = match gated_verify(&state, move |st| {
        verify_and_sign_batch_impl(st, pl, addr, security_zone, chain_id, contract)
    })
    .await
    {
        Ok(result) => result,
        Err((status, message)) => {
            error!("Batch verification failed: {}", message);
            return (status, Json(BatchVerifyResponse::Error { message })).into_response();
        }
    };

    // Recorded before persistence: this is the batch the caller asked us to
    // cover and we verified, whether or not the downstream store then succeeds.
    histogram!(BATCH_SIZE_METRIC).record(result.cts.len() as f64);

    log_verified(&result.cts, &account_addr, security_zone, chain_id);

    if let Err((status, message)) =
        persist_cts(&state, &packed_list_bytes, &result.cts, &account_addr, security_zone, chain_id)
            .await
    {
        return (status, Json(BatchVerifyResponse::Error { message })).into_response();
    }

    // Convert the verified results into response format.
    // NOTE: entries use the original hash (not adjusted) because that's what was
    // folded into the signed batch digest.
    let VerifiedBatch { cts, signature, recid } = result;
    let ciphertexts: Vec<CiphertextResponse> = cts
        .into_iter()
        .map(|verified| CiphertextResponse {
            ct_hash: format!("0x{}", hex_crate::encode(&verified.ct_hash)),
            ct_type: verified.ct_type as u8,
        })
        .collect();
    let signature = format!("0x{}", hex_crate::encode(signature.to_bytes()));
    let recid = recid.to_byte();

    debug!(
        "Returning successful response with {} ciphertexts and a batch signature",
        ciphertexts.len()
    );
    trace!("Ciphertexts: {:?}, signature: {}, recid: {}", ciphertexts, signature, recid);
    (StatusCode::OK, Json(BatchVerifyResponse::Success { ciphertexts, signature, recid }))
        .into_response()
}

#[metrics_utils_macros::measured_function()]
fn verify_and_sign_batch_impl(
    state: &Arc<AppState>,
    packed_list_bytes: Vec<u8>,
    account_addr: String,
    security_zone: u8,
    chain_id: u32,
    contract_address: String,
) -> Result<VerifiedBatch, String> {
    let packed_list: ProvenCompactCiphertextList = {
        let _t = crate::telemetry::StepTimer::start("deserialize");
        rust_common::safe_serde::deserialize(packed_list_bytes.as_slice())
            .map_err(|e| format!("failed to deserialize packed list: {e}"))?
    };

    let result = state
        .zk_verifier
        // Display, not Debug: `{:?}` would leak Rust type names into the client
        // message (e.g. `Signing(SigningFailed("..."))`). The legacy endpoint
        // above deliberately keeps `{:?}` so its strings stay byte-identical to
        // what clients saw before the batch work.
        .verify_and_sign_batch(
            packed_list,
            &account_addr,
            security_zone,
            chain_id,
            &contract_address,
        )
        .map_err(|e| format!("failed to verify and sign batch: {e}"))?;

    Ok(result)
}

#[cfg(feature = "mock-keys")]
async fn get_public_key(
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<PublicKeyResponse>) {
    println!("get public key");
    match rust_common::safe_serde::serialize(&state.zk_verifier.pk) {
        Ok(serialized) => (StatusCode::OK, Json(PublicKeyResponse { public_key: serialized })),
        Err(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(PublicKeyResponse { public_key: Vec::new() }))
        }
    }
}

#[cfg(feature = "mock-keys")]
async fn get_crs(State(state): State<Arc<AppState>>) -> (StatusCode, Json<CrsResponse>) {
    println!("get crs");
    match rust_common::safe_serde::serialize(&state.zk_verifier.crs) {
        Ok(serialized) => (StatusCode::OK, Json(CrsResponse { crs: serialized })),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(CrsResponse { crs: Vec::new() })),
    }
}

#[metrics_utils_macros::measured_async_function()]
async fn get_signer_address(
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<SignerAddressResponse>) {
    (
        StatusCode::OK,
        Json(SignerAddressResponse { address: state.zk_verifier.get_signer_evm_address() }),
    )
}

pub fn create_router() -> Router<Arc<AppState>> {
    let router = Router::new()
        .route("/verifyBatch", post(verify_and_sign_batch))
        .route("/signerAddress", get(get_signer_address))
        .route("/healthz", get(|| async { StatusCode::OK }));

    #[cfg(feature = "mock-keys")]
    let router =
        router.route("/GetNetworkPublicKey", get(get_public_key)).route("/crs", get(get_crs));

    router
}

/// Every bucketed histogram paired with its boundaries. Drives both the exporter
/// and the tests that assert no histogram escapes it.
pub(crate) fn bucketed_metrics() -> Vec<(&'static str, &'static [f64])> {
    let mut metrics: Vec<(&'static str, &'static [f64])> =
        DURATION_MS_METRICS.iter().map(|name| (*name, DURATION_MS_BUCKETS)).collect();
    metrics.push((BATCH_SIZE_METRIC, BATCH_SIZE_BUCKETS));
    metrics
}

/// Shared by the served recorder and the tests. Buckets must be declared before
/// the recorder is built — a metric's distribution type is fixed on first record.
fn metrics_builder() -> PrometheusBuilder {
    let mut builder = PrometheusBuilder::new().add_global_label("service", "zk-verifier");
    for (name, buckets) in bucketed_metrics() {
        builder = builder
            .set_buckets_for_metric(Matcher::Full(name.to_string()), buckets)
            .expect("every bucket list in bucketed_metrics is non-empty");
    }
    builder
}

/// The prometheus recorder and the handle that renders it — built, NOT
/// installed. Split from the router because `metrics::set_global_recorder`
/// accepts exactly one recorder: in push mode the caller fans this one out
/// alongside the OTLP recorder, so the text exposition keeps working while
/// OTLP is the real collection path.
pub fn prometheus_recorder() -> (PrometheusRecorder, PrometheusHandle) {
    let recorder = metrics_builder().build_recorder();
    let handle = recorder.handle();
    (recorder, handle)
}

pub fn create_metrics_router(handle: PrometheusHandle) -> Router {
    Router::new().route(
        "/metrics",
        get(move || async move {
            debug!("Serving metrics data through GET /metrics");
            handle.render()
        }),
    )
}

/// Wire-shape pins for the JSON `/verifyBatch` emits.
///
/// The shared error path lives in [`persist_cts`], which returns
/// `(StatusCode, String)` internally rather than building a response. These tests
/// exist so that internal churn can never silently change what a client parses —
/// in particular that errors keep resolving under `data.message`, which is the
/// field SDK clients read.
#[cfg(test)]
mod tests {

    /// Both error-only counters exist at zero before anything fails, so their
    /// alert policies can be created up front. See `init_error_counters`.
    #[test]
    fn error_counters_are_published_at_zero_before_any_failure() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();

        metrics::with_local_recorder(&recorder, super::init_error_counters);

        let rendered = handle.render();
        for name in ["zk_verify_admission_rejected_total", "store_cts_retries_total"] {
            assert!(
                rendered.contains(&format!("{name} 0")),
                "{name} missing from a clean boot\n{rendered}"
            );
        }
    }
    use metrics::with_local_recorder;
    use serde_json::json;

    use super::*;

    #[test]
    fn batch_verify_success_shape_is_stable() {
        let response = BatchVerifyResponse::Success {
            ciphertexts: vec![CiphertextResponse { ct_hash: "0xaa".to_string(), ct_type: 6 }],
            signature: "0xbb".to_string(),
            recid: 0,
        };

        // An object with one batch-wide signature — not an array.
        assert_eq!(
            serde_json::to_value(&response).unwrap(),
            json!({
                "status": "success",
                "data": {
                    "ciphertexts": [{ "ct_hash": "0xaa", "ct_type": 6 }],
                    "signature": "0xbb",
                    "recid": 0
                }
            })
        );
    }

    #[test]
    fn batch_verify_error_shape_is_stable() {
        let response = BatchVerifyResponse::Error { message: "boom".to_string() };

        // Unchanged from what the removed per-ciphertext endpoint emitted, so a
        // client's `error.message` handling survives the migration.
        assert_eq!(
            serde_json::to_value(&response).unwrap(),
            json!({ "status": "error", "data": { "message": "boom" } })
        );
    }

    /// The batch-size metric exists to answer "what share of batches would be
    /// cheaper as one array-valued `InputVerified`?", i.e.
    /// `1 - (bucket{le="3"} / count)`. That query needs the metric rendered as a
    /// *bucketed histogram* with 3 as an exact edge — the default rendering is a
    /// summary, which only exposes quantiles and cannot answer it.
    #[test]
    fn batch_size_renders_as_a_histogram_split_on_the_onchain_break_even() {
        let recorder = metrics_builder().build_recorder();
        let handle = recorder.handle();

        metrics::with_local_recorder(&recorder, || {
            histogram!(BATCH_SIZE_METRIC).record(2.0);
            histogram!(BATCH_SIZE_METRIC).record(8.0);
        });

        let rendered = handle.render();
        let break_even_bucket = rendered
            .lines()
            .find(|l| {
                l.starts_with(&format!("{BATCH_SIZE_METRIC}_bucket")) && l.contains("le=\"3\"")
            })
            .unwrap_or_else(|| panic!("no le=\"3\" bucket in:\n{rendered}"));

        // Only the batch of 2 falls at or below the break-even edge.
        assert!(break_even_bucket.ends_with(" 1"), "unexpected count: {break_even_bucket}");
    }

    /// Every histogram must export as a histogram, not a summary. A summary
    /// still records and still looks fine on `/metrics`; it just answers none of
    /// the questions the metric exists for. Asserts on the `# TYPE` line, which
    /// is the exporter's own statement of what it chose.
    #[test]
    fn histograms_export_as_histograms_not_summaries() {
        let recorder = metrics_builder().build_recorder();
        let handle = recorder.handle();

        with_local_recorder(&recorder, || {
            for (name, _) in bucketed_metrics() {
                histogram!(name).record(42.0);
            }
        });

        let rendered = handle.render();

        for (name, _) in bucketed_metrics() {
            assert!(
                rendered.contains(&format!("# TYPE {name} histogram")),
                "{name} did not export as a histogram. If it is a new metric, add it to \
                 DURATION_MS_METRICS (or give it its own bucket list) — otherwise it silently \
                 falls back to a summary.\n{rendered}"
            );
            assert!(
                !rendered.contains(&format!("# TYPE {name} summary")),
                "{name} exported as a summary\n{rendered}"
            );
        }
    }

    /// Metric names passed to the histogram macro as string literals, production
    /// code only. Test modules are cut off first, or this would match the example
    /// names in its own neighbours' doc comments.
    fn histogram_literals(src: &str) -> Vec<String> {
        const NEEDLE: &str = "histogram!(\"";
        let production = match src.find("#[cfg(test)]") {
            Some(i) => &src[..i],
            None => src,
        };
        let mut out = Vec::new();
        let mut rest = production;
        while let Some(i) = rest.find(NEEDLE) {
            rest = &rest[i + NEEDLE.len()..];
            if let Some(end) = rest.find('"') {
                out.push(rest[..end].to_string());
            }
        }
        out
    }

    /// Catches the drift the test above cannot: that one iterates the same list
    /// it validates, so it says nothing about a metric nobody configured. The
    /// real regression is a new histogram added without touching
    /// `DURATION_MS_METRICS`, which then silently exports as a summary.
    #[test]
    fn every_histogram_in_the_crate_is_bucketed() {
        /// Left unbucketed on purpose: `storage_upload_bytes` predates this
        /// work, is already in `main` exporting as a summary, and no alert
        /// reads it. Bucketing it is a separate change.
        const UNBUCKETED: &[&str] = &["storage_upload_bytes"];

        const SOURCES: &[(&str, &str)] = &[
            ("api/mod.rs", include_str!("mod.rs")),
            ("telemetry.rs", include_str!("../telemetry.rs")),
            ("storage/gcs.rs", include_str!("../storage/gcs.rs")),
            ("storage/storage_manager.rs", include_str!("../storage/storage_manager.rs")),
            ("verifier/mod.rs", include_str!("../verifier/mod.rs")),
            ("server.rs", include_str!("../server.rs")),
        ];

        let configured: Vec<&str> = bucketed_metrics().into_iter().map(|(name, _)| name).collect();
        for (file, src) in SOURCES {
            for name in histogram_literals(src) {
                if UNBUCKETED.contains(&name.as_str()) {
                    continue;
                }
                assert!(
                    configured.contains(&name.as_str()),
                    "{file} records histogram \"{name}\" but it has no bucket list, so it exports \
                     as a summary: no _bucket series, no histogram_quantile(), and no aggregation \
                     across instances. Add it to DURATION_MS_METRICS."
                );
            }
        }
    }

    /// `histogram_quantile` interpolates within a bucket, so an alert threshold
    /// on an explicit edge is exact rather than estimated.
    #[test]
    fn duration_buckets_include_the_alert_threshold() {
        assert!(
            DURATION_MS_BUCKETS.contains(&30_000.0),
            "30s is the latency alert threshold and must be an explicit bucket boundary"
        );
    }
}

pub async fn track_http_metrics(req: Request, next: Next) -> impl IntoResponse {
    let start = Instant::now();
    let path = if let Some(matched_path) = req.extensions().get::<MatchedPath>() {
        matched_path.as_str().to_owned()
    } else {
        req.uri().path().to_owned()
    };
    let method = req.method().to_string();

    let response = next.run(req).await;

    let latency = start.elapsed().as_millis() as f64;
    let status = response.status().as_u16().to_string();

    let labels = [("method", method), ("path", path), ("status", status)];

    histogram!("http_request_duration_milliseconds", &labels).record(latency);

    response
}
