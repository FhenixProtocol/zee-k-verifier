//! Dependency health: one gauge per dependency, and the verifier's own verdict
//! over them.
//!
//! ```text
//! zk_verifier_dependency_up{dependency="store_cts"}   ct-server answers GET /Health
//! zk_verifier_dependency_up{dependency="storage"}     the object store answers a read
//! zk_verifier_healthy                                 the verifier's verdict
//! ```
//!
//! Why publish a verdict as well as the parts: the status page reads exactly
//! one series per service, so the policy for which dependency this service can
//! live without belongs here — in [`verdict`], one function, owned by the
//! service that knows — rather than being re-derived by every consumer. The
//! per-dependency gauges stay because an incident has to name what broke.
//!
//! **Fail closed.** Every series is published as 0 before the first probe runs,
//! so the window between "process up" and "first probe complete" reports
//! unhealthy rather than healthy-by-default. A probe that errors or times out
//! sets 0; it never leaves a stale 1 behind.
//!
//! No `keys` series: the CRS and key material load at boot or the process
//! exits, so the absence of this whole family already reports that.

use std::sync::Arc;
use std::time::Duration;

use metrics::gauge;
use rust_common::log::{debug, info, warn};

use crate::storage::StorageProvider;

/// `dependency` label for ct-server, reached over the PSC path.
const DEP_STORE_CTS: &str = "store_cts";
/// `dependency` label for the object store holding verified ciphertexts.
const DEP_STORAGE: &str = "storage";

/// Bounds a single probe. Deliberately short: a probe that hangs must not
/// delay the next round, and a dependency that cannot answer inside this is
/// down as far as a status page is concerned.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// What each round probes.
///
/// `storage` is `None` when the build carries no external-storage backend. In
/// that case no `storage` series is published at all — an absent series says
/// "not configured here", where a 0 would claim something is broken.
pub(crate) struct Dependencies {
    /// Reused across rounds so probes ride a warm connection pool rather than
    /// opening a fresh one every 15s.
    pub client: reqwest::Client,
    pub store_cts_endpoint: String,
    pub storage: Option<Arc<dyn StorageProvider>>,
}

impl Dependencies {
    /// The cheapest call that proves ct-server answers: its own health route,
    /// not a `StoreCts` round-trip. A probe must not write anything. A failure
    /// comes back as the reason; the loop logs it only on a state change.
    async fn probe_store_cts(&self) -> Result<(), String> {
        let url = format!("{}/Health", self.store_cts_endpoint.trim_end_matches('/'));
        match tokio::time::timeout(PROBE_TIMEOUT, self.client.get(&url).send()).await {
            Ok(Ok(response)) if response.status().is_success() => Ok(()),
            Ok(Ok(response)) => Err(format!("{url} answered {}", response.status())),
            Ok(Err(e)) => Err(format!("{url} failed: {e}")),
            Err(_) => Err(format!("{url} timed out after {PROBE_TIMEOUT:?}")),
        }
    }

    /// `None` when there is no backend to probe — see [`Dependencies::storage`].
    async fn probe_storage(&self) -> Option<Result<(), String>> {
        let storage = self.storage.as_ref()?;
        Some(match tokio::time::timeout(PROBE_TIMEOUT, storage.probe()).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(format!("{} probe failed: {e}", storage.backend_name())),
            Err(_) => {
                Err(format!("{} probe timed out after {PROBE_TIMEOUT:?}", storage.backend_name()))
            }
        })
    }
}

/// Log a probe result only when it differs from the previous round: one warn
/// naming the cause when a dependency goes down, one info when it recovers —
/// not a line per probe for as long as an outage lasts (`dependency-down`
/// already alerts on the gauge). The first round always logs, as the baseline
/// that tells a responder how the process came up.
fn log_transition(dependency: &str, previous: Option<bool>, result: &Result<(), String>) {
    if previous == Some(result.is_ok()) {
        return;
    }
    match result {
        Ok(()) => info!("health: {} is up", dependency),
        Err(reason) => warn!("health: {} is down: {}", dependency, reason),
    }
}

/// The verifier's own policy, in one place.
///
/// Both dependencies are load-bearing: a verify whose result cannot be
/// persisted or handed to ct-server has not really completed, so either being
/// down makes the service unhealthy. A dependency that is not configured for
/// this build cannot make it unhealthy.
fn verdict(store_cts_up: bool, storage_up: Option<bool>) -> bool {
    store_cts_up && storage_up.unwrap_or(true)
}

/// Gauges take f64; health has no middle state, so only 1.0 and 0.0 are used.
fn as_gauge(up: bool) -> f64 {
    if up {
        1.0
    } else {
        0.0
    }
}

fn publish(store_cts_up: bool, storage_up: Option<bool>) {
    gauge!("zk_verifier_dependency_up", "dependency" => DEP_STORE_CTS).set(as_gauge(store_cts_up));
    if let Some(up) = storage_up {
        gauge!("zk_verifier_dependency_up", "dependency" => DEP_STORAGE).set(as_gauge(up));
    }
    gauge!("zk_verifier_healthy").set(as_gauge(verdict(store_cts_up, storage_up)));
}

/// Start the probe loop as a detached task; it runs for the whole process
/// lifetime, so no `JoinHandle` is returned — a handle could only abort the
/// loop (dropping one detaches the task, it does not stop it), and no caller
/// should.
///
/// The global `metrics` recorder must already be installed — in otlp mode that
/// is a fanout, so every gauge here reaches both the text exposition and the
/// OTLP push.
pub(crate) fn spawn(deps: Dependencies, interval: Duration) {
    // Fail closed, before anything is probed. See the module docs.
    publish(false, deps.storage.as_ref().map(|_| false));

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        let mut prev_store_cts = None;
        let mut prev_storage = None;
        loop {
            ticker.tick().await;
            let store_cts = deps.probe_store_cts().await;
            log_transition(DEP_STORE_CTS, prev_store_cts, &store_cts);
            prev_store_cts = Some(store_cts.is_ok());

            let storage = deps.probe_storage().await;
            if let Some(result) = &storage {
                log_transition(DEP_STORAGE, prev_storage, result);
                prev_storage = Some(result.is_ok());
            }

            let (store_cts_up, storage_up) = (store_cts.is_ok(), storage.map(|r| r.is_ok()));
            debug!("health: store_cts={} storage={:?}", store_cts_up, storage_up);
            publish(store_cts_up, storage_up);
        }
    });
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use async_trait::async_trait;
    use axum::routing::get;
    use axum::Router;
    use metrics::with_local_recorder;
    use tokio::net::TcpListener;

    use super::*;
    use crate::storage::errors::StorageError;

    /// A throwaway HTTP server answering `/Health` with `status`, on an
    /// ephemeral port. Same shape the `server` tests use — axum is already a
    /// dependency, so a probe test needs no HTTP-mocking crate.
    async fn health_route_returning(status: u16) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let app = Router::new().route(
            "/Health",
            get(move || async move { axum::http::StatusCode::from_u16(status).unwrap() }),
        );
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://{addr}")
    }

    /// A backend whose probe fails on demand.
    ///
    /// `storage_manager`'s `MockStorage` lives in a private `#[cfg(test)] mod
    /// tests`, so it cannot be reached from another module's tests; this is the
    /// same shape reduced to what a probe assertion needs. `MockStorage` still
    /// implements `probe()` so the trait stays satisfied where it is used.
    struct StubStorage {
        fail: bool,
    }

    #[async_trait]
    impl StorageProvider for StubStorage {
        async fn upload(
            &self,
            _key: &str,
            _data: &[u8],
            _metadata: Option<&HashMap<String, String>>,
            _base_path: Option<&str>,
            _dynamic_path: Option<&str>,
        ) -> Result<(), StorageError> {
            Ok(())
        }

        fn backend_name(&self) -> &'static str {
            "stub"
        }

        async fn probe(&self) -> Result<(), StorageError> {
            if self.fail {
                return Err(StorageError::Generic("stub probe failure".to_string()));
            }
            Ok(())
        }
    }

    /// The rendered line carrying every one of `needles`.
    ///
    /// Matched by substring rather than compared whole: the recorder adds a
    /// global `service` label and does not promise label order, neither of
    /// which is what these tests are about.
    fn sample<'a>(rendered: &'a str, needles: &[&str]) -> &'a str {
        rendered
            .lines()
            // Skip `# TYPE`/`# HELP`: they carry the metric name too, and would
            // match ahead of the sample line.
            .filter(|line| !line.starts_with('#'))
            .find(|line| needles.iter().all(|n| line.contains(n)))
            .unwrap_or_else(|| panic!("no line matching {needles:?} in:\n{rendered}"))
    }

    fn deps(endpoint: String, storage: Option<Arc<dyn StorageProvider>>) -> Dependencies {
        Dependencies { client: reqwest::Client::new(), store_cts_endpoint: endpoint, storage }
    }

    /// The policy, spelled out: either dependency down makes the verdict 0, and
    /// an unconfigured dependency cannot drag it down.
    #[test]
    fn verdict_needs_every_configured_dependency() {
        assert!(verdict(true, Some(true)));
        assert!(!verdict(false, Some(true)));
        assert!(!verdict(true, Some(false)));
        assert!(!verdict(false, Some(false)));
        assert!(verdict(true, None), "an absent backend must not report unhealthy");
        assert!(!verdict(false, None));
    }

    /// A failing storage probe renders as 0 in the exposition the status page
    /// reads, and drags the verdict down with it.
    #[test]
    fn failing_storage_renders_zero() {
        let (recorder, handle) = crate::api::prometheus_recorder();
        with_local_recorder(&recorder, || publish(true, Some(false)));
        let rendered = handle.render();

        assert!(
            sample(&rendered, &["zk_verifier_dependency_up", "dependency=\"storage\""])
                .ends_with(" 0"),
            "expected a 0 storage series:\n{rendered}"
        );
        assert!(
            sample(&rendered, &["zk_verifier_healthy"]).ends_with(" 0"),
            "a down dependency must drag the verdict down:\n{rendered}"
        );
    }

    /// Nothing reports healthy before it has been probed.
    #[test]
    fn publishes_zero_before_the_first_probe() {
        let (recorder, handle) = crate::api::prometheus_recorder();
        with_local_recorder(&recorder, || publish(false, Some(false)));
        let rendered = handle.render();

        for needles in [
            vec!["zk_verifier_dependency_up", "dependency=\"store_cts\""],
            vec!["zk_verifier_dependency_up", "dependency=\"storage\""],
            vec!["zk_verifier_healthy"],
        ] {
            let line = sample(&rendered, &needles);
            assert!(line.ends_with(" 0"), "{needles:?} should be 0, got: {line}");
        }
    }

    /// An unconfigured backend publishes no storage series at all — absence
    /// means "not here", which a 0 would misreport as broken.
    #[test]
    fn absent_backend_publishes_no_storage_series() {
        let (recorder, handle) = crate::api::prometheus_recorder();
        with_local_recorder(&recorder, || publish(true, None));
        let rendered = handle.render();

        assert!(!rendered.contains("dependency=\"storage\""), "unexpected series:\n{rendered}");
        assert!(sample(&rendered, &["zk_verifier_healthy"]).ends_with(" 1"), "{rendered}");
    }

    #[tokio::test]
    async fn store_cts_probe_reads_the_health_route() {
        let base = health_route_returning(200).await;
        assert!(deps(base, None).probe_store_cts().await.is_ok());
    }

    #[tokio::test]
    async fn store_cts_probe_is_down_on_error_status() {
        let base = health_route_returning(503).await;
        assert!(deps(base, None).probe_store_cts().await.is_err());
    }

    /// Nothing listening at all — the transport error must read as down, not
    /// propagate out of the loop.
    #[tokio::test]
    async fn store_cts_probe_is_down_when_unreachable() {
        // Port 1 on loopback: reserved, never bound, refuses immediately.
        assert!(deps("http://127.0.0.1:1".to_string(), None).probe_store_cts().await.is_err());
    }

    #[tokio::test]
    async fn storage_probe_maps_failure_to_down() {
        let up: Arc<dyn StorageProvider> = Arc::new(StubStorage { fail: false });
        let down: Arc<dyn StorageProvider> = Arc::new(StubStorage { fail: true });

        let up_result = deps(String::new(), Some(up)).probe_storage().await;
        assert_eq!(up_result.map(|r| r.is_ok()), Some(true));
        let down_result = deps(String::new(), Some(down)).probe_storage().await;
        assert_eq!(down_result.map(|r| r.is_ok()), Some(false));
        assert!(deps(String::new(), None).probe_storage().await.is_none());
    }
}
