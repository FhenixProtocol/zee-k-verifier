//! OTLP push pipeline: the `metrics` facade recording into OpenTelemetry
//! instruments, exported straight to Google's Telemetry API. Chosen over
//! serving `/metrics` because nothing can scrape a VM in this unpeered VPC.
//!
//! Everything here is deliberately BLOCKING: the stable `PeriodicReader`
//! drives exports with `futures_executor::block_on` on its own plain thread,
//! where an async reqwest client has no reactor and panics. Blocking calls on
//! that thread are exactly what it expects.
//!
//! KEEP IN SYNC: `MetadataClient` and `GoogleAuthClient` are duplicated in
//! teecryptor (`src/metrics/otlp_http_client.rs`). The two repos sit on
//! different opentelemetry majors (0.31 here, 0.32 there), whose http types
//! are incompatible, so a shared crate can't carry one impl yet — a fix in
//! either copy almost certainly belongs in the other.

use std::time::Duration;

use metrics::KeyName;
use metrics_exporter_otel::OpenTelemetryRecorder;
use opentelemetry::metrics::MeterProvider as _;
use opentelemetry::KeyValue;
use opentelemetry_http::{Bytes, HttpClient, HttpError, Request, Response};
use opentelemetry_otlp::{MetricExporter, Protocol, WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::Resource;
use rust_common::log::{error, info};

use crate::api::bucketed_metrics;
use crate::config::MetricsConfig;

/// How often accumulated metrics are pushed. The Telemetry API floor is 5s.
const EXPORT_INTERVAL: Duration = Duration::from_secs(30);
/// Where every push goes. Deliberately NOT operator-settable (decision
/// 2026-09-03): with the endpoint out of the env-override surface, no
/// credentialed request can be redirected by configuration — changing it is a
/// code change, and therefore a new attested image.
const TELEMETRY_ENDPOINT: &str = "https://telemetry.googleapis.com/v1/metrics";
/// Becomes the `job` label on every pushed series — the name every alert in
/// monitoring/gcp/alerts scopes by.
const SERVICE_NAME: &str = "zee-k-verifier";
/// Per-request budget for one metadata read or OTLP POST.
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// Minimal blocking metadata-server client: an access token for the VM's
/// service account, and the VM's zone. `GCE_METADATA_HOST` overrides the host
/// (the same knob the google-cloud clients honor, so local mocks keep working).
#[derive(Debug)]
struct MetadataClient {
    base: String,
    client: reqwest::blocking::Client,
}

impl MetadataClient {
    fn new() -> Result<Self, HttpError> {
        let host = std::env::var("GCE_METADATA_HOST")
            .unwrap_or_else(|_| "metadata.google.internal".to_string());
        Ok(Self {
            base: format!("http://{host}/computeMetadata/v1"),
            client: reqwest::blocking::Client::builder().timeout(HTTP_TIMEOUT).build()?,
        })
    }

    fn get(&self, path: &str) -> Result<reqwest::blocking::Response, HttpError> {
        Ok(self
            .client
            .get(format!("{}{path}", self.base))
            .header("Metadata-Flavor", "Google")
            .send()?
            .error_for_status()?)
    }

    fn access_token(&self) -> Result<String, HttpError> {
        #[derive(serde::Deserialize)]
        struct Token {
            access_token: String,
        }
        Ok(self.get("/instance/service-accounts/default/token")?.json::<Token>()?.access_token)
    }

    /// The zone, published as `cloud.availability_zone` — the Telemetry API
    /// rejects points without a location. The raw value is
    /// `projects/<num>/zones/<zone>`.
    fn zone(&self) -> Result<String, HttpError> {
        let raw = self.get("/instance/zone")?.text()?;
        Ok(raw.rsplit('/').next().unwrap_or(&raw).to_string())
    }

    /// The VM name, published as `service.instance.id` — stable across
    /// container restarts on the same VM (unlike the container's `HOSTNAME`,
    /// which changes every restart).
    fn instance_name(&self) -> Result<String, HttpError> {
        Ok(self.get("/instance/name")?.text()?)
    }

    /// The project ID, published as `gcp.project_id`. The Telemetry API
    /// refuses every export whose resource lacks it (`400 Resource is missing
    /// required attribute "gcp.project_id"`): the attribute, not the
    /// credential or an `x-goog-user-project` header, is what routes the
    /// series into a project.
    fn project_id(&self) -> Result<String, HttpError> {
        Ok(self.get("/project/project-id")?.text()?)
    }
}

/// Bearer-per-request transport: Google tokens expire hourly, so the
/// exporter's static header hook cannot carry one; the metadata server caches
/// and refreshes behind the endpoint, so asking per export is cheap.
#[derive(Debug)]
struct GoogleAuthClient {
    metadata: MetadataClient,
    inner: reqwest::blocking::Client,
}

#[async_trait::async_trait]
impl HttpClient for GoogleAuthClient {
    async fn send_bytes(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        // Blocking on purpose — see the module docs.
        let (mut parts, body) = request.into_parts();
        // The destination is TELEMETRY_ENDPOINT — compiled in, never operator
        // input — so the SA token always rides. The host allow-list that used
        // to guard an env-supplied endpoint was removed with the env var.
        let token = self.metadata.access_token()?;
        parts.headers.insert(http::header::AUTHORIZATION, format!("Bearer {token}").parse()?);
        // The Telemetry API rejects any request over 200 points, wholesale, and
        // the series count grows with label combinations until every export
        // dies (staging hit it ~2h after boot, twice). Split and send
        // sequentially; the first rejected chunk is reported, the rest skipped.
        let pieces =
            crate::otel_split::split_request(&body, crate::otel_split::MAX_POINTS_PER_REQUEST)?;
        let mut response = None;
        for piece in pieces {
            let resp = self.inner.execute(reqwest::blocking::Request::try_from(
                Request::from_parts(parts.clone(), Bytes::from(piece)),
            )?)?;
            let ok = resp.status().is_success();
            response = Some(resp);
            if !ok {
                break;
            }
        }
        let response = response.expect("split_request never returns zero pieces");
        let status = response.status();
        let mut builder = http::Response::builder().status(status);
        if let Some(headers) = builder.headers_mut() {
            *headers = response.headers().clone();
        }
        let bytes = response.bytes()?;
        if !status.is_success() {
            // Log the body ourselves, at error level. opentelemetry-otlp
            // deliberately logs it at DEBUG only and propagates just "HTTP
            // export failed with status code: N", so the actionable half —
            // WHICH attribute the API rejected — never reaches an error log.
            // Staging lost 90 minutes to a 400 whose body read `Resource is
            // missing required attribute "gcp.project_id"`.
            let snippet: String = String::from_utf8_lossy(&bytes).chars().take(400).collect();
            error!("metrics: the Telemetry API rejected an OTLP export ({status}): {snippet}");
        }
        Ok(builder.body(bytes)?)
    }
}

/// Build the push pipeline and its `metrics` recorder, with histogram bounds
/// already registered. The caller installs it — usually fanned out with the
/// prometheus recorder, since only one global recorder may be set.
///
/// The provider must be held for the process lifetime: dropping it shuts the
/// exporter down and stops all exports.
pub(crate) fn build_pipeline(
    config: &MetricsConfig,
) -> Result<(SdkMeterProvider, OpenTelemetryRecorder), Box<dyn std::error::Error>> {
    // Blocking construction (metadata reads, blocking-client setup) runs on a
    // plain thread: `install` is called from async context, where blocking
    // reqwest refuses to run.
    let config = config.clone();
    let (provider, recorder) = std::thread::spawn(move || build(&config))
        .join()
        .map_err(|_| "metrics pipeline builder thread panicked")?
        .map_err(|e| -> Box<dyn std::error::Error> { e })?;

    // Bounds must precede the global install the caller performs: a
    // histogram's boundaries freeze the first time the instrument is created.
    for (name, bounds) in bucketed_metrics() {
        recorder.set_histogram_bounds(&KeyName::from_const_str(name), bounds.to_vec());
    }

    info!("metrics: OTLP push every {}s", EXPORT_INTERVAL.as_secs());
    Ok((provider, recorder))
}

fn build(
    config: &MetricsConfig,
) -> Result<(SdkMeterProvider, OpenTelemetryRecorder), Box<dyn std::error::Error + Send + Sync>> {
    let metadata = MetadataClient::new()?;
    let zone = metadata.zone()?;
    let instance = metadata.instance_name()?;
    let project = metadata.project_id()?;
    let exporter = MetricExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint(TELEMETRY_ENDPOINT)
        .with_http_client(GoogleAuthClient {
            metadata,
            inner: reqwest::blocking::Client::builder().timeout(HTTP_TIMEOUT).build()?,
        })
        .build()?;
    let reader = PeriodicReader::builder(exporter).with_interval(EXPORT_INTERVAL).build();

    // job <- service.name, instance <- service.instance.id,
    // location <- cloud.availability_zone, namespace <- service.namespace.
    // gcp.project_id is required by the Telemetry API; without it every export is a 400.
    let mut attributes = vec![
        KeyValue::new("service.instance.id", instance),
        KeyValue::new("cloud.availability_zone", zone),
        KeyValue::new("gcp.project_id", project),
    ];
    if let Some(env) = &config.env {
        attributes.push(KeyValue::new("service.namespace", env.clone()));
    }
    let resource =
        Resource::builder().with_service_name(SERVICE_NAME).with_attributes(attributes).build();

    let provider = SdkMeterProvider::builder().with_reader(reader).with_resource(resource).build();
    let recorder = OpenTelemetryRecorder::new(provider.meter(SERVICE_NAME));
    info!("metrics: OTLP push pipeline built for {TELEMETRY_ENDPOINT}");
    Ok((provider, recorder))
}

#[cfg(test)]
mod tests {
    use metrics::{Key, Level, Metadata, Recorder as _};
    use opentelemetry_sdk::metrics::InMemoryMetricExporter;

    use super::*;

    /// The bridge maps a facade gauge onto an observable instrument, so every
    /// collection re-samples the current value: `zk_verifier_up` set ONCE at
    /// boot keeps arriving on every export. `platform/metrics-target-down`
    /// alerts on the absence of exactly that behavior.
    #[test]
    fn gauge_set_once_is_resampled_on_every_collection() {
        let exporter = InMemoryMetricExporter::default();
        let reader = PeriodicReader::builder(exporter.clone())
            .with_interval(Duration::from_secs(3600))
            .build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        let recorder = OpenTelemetryRecorder::new(provider.meter(SERVICE_NAME));

        let key = Key::from_static_name("zk_verifier_up");
        let metadata = Metadata::new(module_path!(), Level::INFO, None);
        recorder.register_gauge(&key, &metadata).set(1.0);

        provider.force_flush().expect("first collection");
        provider.force_flush().expect("second collection");

        let exports = exporter.get_finished_metrics().expect("exported batches");
        assert_eq!(exports.len(), 2, "one batch per collection");
        for (i, rm) in exports.iter().enumerate() {
            let metric = rm
                .scope_metrics()
                .flat_map(|sm| sm.metrics())
                .find(|m| m.name() == "zk_verifier_up")
                .unwrap_or_else(|| panic!("zk_verifier_up missing from export {i}"));
            let value = match metric.data() {
                opentelemetry_sdk::metrics::data::AggregatedMetrics::F64(
                    opentelemetry_sdk::metrics::data::MetricData::Gauge(g),
                ) => g.data_points().next().expect("a data point").value(),
                other => panic!("unexpected aggregation for a gauge: {other:?}"),
            };
            assert_eq!(value, 1.0, "collection {i} re-sampled the gauge");
        }
    }
}
