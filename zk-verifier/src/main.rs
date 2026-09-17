//! Local-dev entry point for the zk-verifier binary.
//!
//! Reads keys from disk per the loaded config (or `APP_KEYS__*_PATH` env vars)
//! and runs the HTTP server. For the production TDX deployment the binary in
//! `tdx-signer/` calls [`zk_verifier::run_server`] directly with `KeyMaterial`
//! it assembled from Secret Manager + the launcher-mounted volume.

use rust_common::log::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    rust_common::logger::init_default_logger("zk-verifier")?;
    info!("Starting ZK-Verifier server...");
    let config = zk_verifier::config::Builder::new().build()?;
    let keys = zk_verifier::load_keys_from_config(&config);
    zk_verifier::run_server(config, keys).await
}
