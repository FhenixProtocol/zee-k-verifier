use std::path::Path;

use config::{Config as ConfigBuilder, ConfigError, File, FileFormat};
use rust_common::log::{info, warn};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub initial_delay_ms: u64,
    pub max_delay_ms: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self { max_retries: 5, initial_delay_ms: 100, max_delay_ms: 5000 }
    }
}

impl RetryConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.max_retries == 0 {
            return Err("max_retries must be greater than 0".to_string());
        }
        if self.max_delay_ms < self.initial_delay_ms {
            return Err("max_delay_ms must be greater than initial_delay_ms".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub keys: KeyConfig,
    pub store_cts: StoreCtsConfig,
    pub storage: Option<StorageConfig>,
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub health: HealthConfig,
}

/// Dependency health probing — see `crate::health`.
#[derive(Debug, Deserialize, Clone)]
pub struct HealthConfig {
    /// How often every dependency is probed. 15s is the shared default across
    /// the services the status page reads, so one page refresh sees the same
    /// freshness everywhere.
    #[serde(default = "default_probe_interval_secs")]
    pub probe_interval_secs: u64,
}

fn default_probe_interval_secs() -> u64 {
    15
}

impl Default for HealthConfig {
    fn default() -> Self {
        HealthConfig { probe_interval_secs: default_probe_interval_secs() }
    }
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
pub struct MetricsConfig {
    /// Push metrics over OTLP to the compiled-in Google Telemetry endpoint
    /// (`otel_push::TELEMETRY_ENDPOINT`) — a VM in this unpeered VPC has no
    /// scraper. The pull exposition on `server.metrics_port` is served either
    /// way. Off by default: local dev and stress tooling have no VM identity to
    /// push as.
    pub push: bool,
    /// Environment name, exported as `service.namespace`.
    pub env: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StorageConfig {
    #[serde(default = "default_backend")]
    pub backend: String,
    pub bucket: String,
    #[serde(default = "default_upload_timeout")]
    pub upload_timeout_secs: u64,
    #[serde(default)]
    pub retry_config: RetryConfig,
    #[serde(default = "default_endpoint")]
    pub storage_endpoint: String,
}

fn default_endpoint() -> String {
    "https://storage.googleapis.com".to_string()
}

fn default_backend() -> String {
    "none".to_string()
}

fn default_upload_timeout() -> u64 {
    30
}

impl StorageConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.bucket.is_empty() {
            return Err("GCS bucket name cannot be empty".to_string());
        }

        if self.upload_timeout_secs == 0 {
            return Err("upload_timeout_secs must be greater than 0".to_string());
        }

        if let Err(e) = self.retry_config.validate() {
            return Err(format!("retry_config is invalid: {}", e));
        }

        Ok(())
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub bind_address: String,
    pub bind_port: u16,
    pub metrics_port: u16,
}

#[cfg_attr(feature = "mock-keys", allow(dead_code))]
#[derive(Debug, Deserialize, Clone)]
pub struct KeyConfig {
    pub crs_path: String,
    pub pk_path: String,
    pub sk_path: String,
    pub signer_pk_path: String,
    /// Path to the published signer public key (compressed-SEC1 bytes), fetched
    /// alongside the TFHE artifacts. Used by the boot-time gate to confirm the
    /// loaded `signer_pk` matches the identity published in GCS.
    pub signer_pubkey_path: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StoreCtsConfig {
    pub endpoint: String,
}

pub struct Builder {
    /// Local-dev / standalone: read a single config file from `CONFIG_PATH`.
    config_path: String,
    /// Baked path (tdx-signer): `(base, overlay)` config TOML held IN MEMORY —
    /// compiled into the binary via `include_str!`, no filesystem. The overlay is
    /// layered on top of the base (hierarchical merge, later wins). `None` => use
    /// `config_path` (the dev path).
    baked: Option<(String, String)>,
}

impl Builder {
    pub fn new() -> Builder {
        let config_path = std::env::var("CONFIG_PATH").unwrap_or_else(|_| {
            warn!("CONFIG_PATH not set, using default: /app/config/config.toml");
            "/app/config/config.toml".to_string()
        });

        Builder { config_path, baked: None }
    }

    /// Build from in-memory baked config: a shared `base` plus a per-env `overlay`
    /// (both `include_str!`'d by the tdx-signer). No filesystem — the overlay's keys
    /// override the base's, keys it omits fall through (the `config` crate merges
    /// hierarchically). Used on the attested boot path instead of reading a file.
    pub fn from_baked(base: impl Into<String>, overlay: impl Into<String>) -> Builder {
        Builder { config_path: String::new(), baked: Some((base.into(), overlay.into())) }
    }

    pub fn build(self) -> Result<Config, ConfigError> {
        // Start with default values
        let mut builder = ConfigBuilder::builder()
            .set_default("server.bind_address", "0.0.0.0")?
            .set_default("server.bind_port", 3001)?
            .set_default("server.metrics_port", 9090)?
            .set_default("keys.crs_path", "./keys/crs")?
            .set_default("keys.pk_path", "./keys/pk")?
            .set_default("keys.sk_path", "./keys/sk")?
            .set_default("keys.signer_pk_path", "./keys/signer_pk")?
            .set_default("keys.signer_pubkey_path", "./keys/signer_public_key")?
            .set_default("store_cts.endpoint", "http://localhost:9449")?;

        match &self.baked {
            // Baked path: in-memory base then overlay (overlay wins, deep-merged).
            Some((base, overlay)) => {
                builder = builder.add_source(File::from_str(base, FileFormat::Toml));
                builder = builder.add_source(File::from_str(overlay, FileFormat::Toml));
            }
            // Dev/standalone: a single config file from CONFIG_PATH, if it exists.
            None => {
                let config_file = Path::new(&self.config_path);
                if config_file.exists() {
                    info!("Loading configuration from {}", config_file.display());
                    builder = builder.add_source(File::from(config_file));
                } else {
                    warn!("Configuration file {} not found, using defaults", config_file.display());
                }
            }
        }

        // Add in settings from environment variables (with a prefix of APP and '__' as separator)
        // E.g. `APP_SERVER__PORT=5001 would set `Config.server.port`
        builder = builder.add_source(config::Environment::with_prefix("APP").separator("__"));

        // Build the configuration
        builder.build()?.try_deserialize()
    }
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default stays no-push: local dev and the stress tools keep the pull
    /// exposition with zero configuration.
    #[test]
    fn metrics_push_default_is_off() {
        assert!(!MetricsConfig::default().push);
    }

    // The base + per-env overlay must DEEP-merge: an overlay that sets only
    // `[storage].bucket` must not wipe the base's `[storage].backend` /
    // `storage_endpoint`. If the `config` crate ever whole-table-replaced instead,
    // `backend` would silently fall back to its "none" default and the verifier
    // would boot without GCS — this locks the merge semantics the split relies on.
    #[test]
    fn overlay_deep_merges_onto_base_storage_table() {
        // Exercises the real baked boot path (in-memory base + overlay, no files).
        let base = r#"
[server]
bind_address = "0.0.0.0"
bind_port = 3001
metrics_port = 9090
[keys]
crs_path = "/k/crs"
pk_path = "/k/pk"
sk_path = "/k/sk"
signer_pk_path = "/k/spk"
signer_pubkey_path = "/k/spub"
[store_cts]
endpoint = "PLACEHOLDER"
[storage]
backend = "gcs"
storage_endpoint = "https://storage.googleapis.com"
"#;
        let overlay = "[storage]\nbucket = \"my-bucket\"\n";

        let cfg = Builder::from_baked(base, overlay).build().expect("layered build");

        let storage = cfg.storage.expect("storage section");
        assert_eq!(storage.bucket, "my-bucket", "overlay supplies bucket");
        assert_eq!(storage.backend, "gcs", "base backend survives the merge");
        assert_eq!(storage.storage_endpoint, "https://storage.googleapis.com");
        // A base key the overlay never mentions is untouched.
        assert_eq!(cfg.server.bind_port, 3001);
    }
}
