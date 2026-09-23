//! TDX launcher for `zk-verifier`.
//!
//! Boot flow inside a GCP Intel TDX Confidential Space VM:
//!   1. Resolve the reader source from the baked `COFHE_ENV` map (fail-closed —
//!      an unknown env aborts before any network call): the partner set, each
//!      partner's per-consumer WIF audience, and the public-material location.
//!   2. For EACH partner: ask the CS launcher for a TDX-attested OIDC JWT for
//!      that partner's audience and exchange it at STS for a federated access
//!      token. Each partner gates reads behind its own attested WIF provider —
//!      there is no shared keys-access SA to impersonate anymore. A partner
//!      whose federation fails is warned and excluded (the Shamir gather
//!      tolerates it); it does not abort the boot.
//!   3. Fetch the VM's attached compute-SA token from the metadata server —
//!      the public material is non-secret, so its GCS reads ride the plain
//!      compute SA.
//!   4. Reconstruct the secp256k1 zk-signer key across the partners (Shamir
//!      T-of-N) via the embedded `cofhe-keys` reader: gather every partner's
//!      share, filter liars by per-share digest, reconstruct, and validate
//!      against the published full-key digest. Share authenticity comes from the
//!      partner write-gate (consumer-side provenance verification is removed).
//!   5. Fetch the FHE public artifacts (`crs`, `public_key`, `computation_key`)
//!      as separate cofhe-native files from the public bucket, next to the
//!      manifest (the ceremony writes them there), and check each against the
//!      SHA-256 digest published in the bucket-sourced `PublicMaterial` manifest
//!      before trusting the bytes. NB: manifest integrity rests on bucket IAM,
//!      not attestation — a bucket writer could swap the manifest and artifacts
//!      together, so the CRS/FHE artifacts have no on-chain backstop. The
//!      published `zk_signer_address` comes from that same manifest. The runtime
//!      config is BAKED into the image per-env (`include_str!`, part of the attested
//!      digest) — a shared base + per-env overlay merged IN MEMORY, not fetched and
//!      not written to disk — with only `store_cts.endpoint` injected from the
//!      `STORE_CTS_ENDPOINT` env.
//!   6. Hand off to `zk_verifier::run_server`, which hard-fails unless the
//!      reconstructed signer's address matches the published `zk_signer_address`
//!      — an end-to-end check on the reconstruction. The verifier's HTTP API then
//!      comes up on `:3001` (verify) and `:9090` (metrics).
//!
//! Service-endpoint URLs are deliberately `const` — see the comment block
//! below — so they cannot be overridden via VM metadata.

mod attestation;
mod gcs;
mod key_source;

use anyhow::{Context, Result};
use cofhe_keys::reader::{PartnerAccess, PartnerRef};
use cofhe_keys::serialization::verify_artifact;
use k256::ecdsa::SigningKey;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use crate::attestation::AttestationClient;
use crate::gcs::Gcs;

// Service endpoint constants — intentionally NOT read from the environment.
// If an attacker with compute.instances.setMetadata could override these,
// they could redirect the STS exchange to an endpoint they control, capture
// the genuine TDX-attested JWTs, and replay them to real STS to mint the
// partners' federated read tokens. Holding these in code (and excluding them
// from the launcher's allow_env_override LABEL) closes that path.
const ATTESTATION_SOCKET: &str = "/run/container_launcher/teeserver.sock";
// The STS endpoint is `cofhe_keys::gcp_auth::DEFAULT_STS_URL` — a compile-time
// const in the shared client, for the same reason as the URLs below.
const SM_URL: &str = "https://secretmanager.googleapis.com";
// GCS host is const for the same reason as the STS URL: a workload owner with
// setMetadata must not be able to redirect it. The metadata host the `Gcs`
// client's ADC path uses is located via GCE_METADATA_HOST, which is likewise
// kept out of the Dockerfile's allow_env_override LABEL so it can't be
// redirected. The public-material bucket/object are baked into `cofhe-keys`'s
// env map — resolved from COFHE_ENV, never individually env-settable. The runtime
// config is baked into the image per-env too (no config bucket to fetch); only
// STORE_CTS_ENDPOINT stays env-supplied.
const GCS_STORAGE_URL: &str = "https://storage.googleapis.com";
// The GCE metadata-server base URL (the compute-SA token for the GCS reads
// comes from there) is `cofhe_keys::gcp_auth::DEFAULT_METADATA_URL` — a
// compile-time const like the rest: a setMetadata-capable operator must not
// be able to point the token fetch at a proxy.
// The zk-signer secret each partner holds a Shamir share of. Hardcoded (not
// operator-overridable) to keep the env-override surface minimal.
const ZK_SIGNER_SECRET: &str = "cofhe-tee-zk-signer";
// NOTE: consumer-side attestation provenance verification is GONE (it crashed on
// Google JWKS `kid` rotation and was redundant with the partner attested-WIF
// write-gate), along with the keygen-origin allowlist it carried. That allowlist
// was load-bearing only while the reader's data source (PARTNERS / PUBLIC_BUCKET /
// PUBLIC_OBJECT) was setMetadata-overridable; with the source baked into
// `cofhe-keys`'s env map and each partner gating reads behind its own attested WIF
// provider, the trust anchor is the partners' enforcement plus the on-chain
// signature check — not a per-ceremony pin here.
// cofhe-native object names for the FHE public artifacts, matching what the
// keygen writes (and what the sibling cofhe compute services read off the same
// gcsfuse-mounted bucket). The ceremony writes them alongside the manifest, so
// they're fetched as siblings of PUBLIC_OBJECT, then each is verified against its
// digest in the manifest.
const OBJ_SERVER_KEY: &str = "computation_key";
const OBJ_PUBLIC_KEY: &str = "public_key";
const OBJ_CRS: &str = "crs";

/// Object path for a sibling of `public_object` (same "directory", different
/// name) — the ceremony writes the FHE artifacts next to the manifest. Mirrors
/// the keygen's own `verify` tool so both sides agree on the layout.
fn sibling_object(public_object: &str, name: &str) -> String {
    match public_object.rfind('/') {
        Some(i) => format!("{}/{}", &public_object[..i], name),
        None => name.to_string(),
    }
}

/// Short fingerprint of an FHE artifact: first 4 bytes of its SHA-256, hex
/// encoded. Same 8-char form the cofhe-side services print, so telling whether
/// this verifier and the key server are on the same keyset is a comparison of
/// two log lines instead of a round-trip through proof verification.
///
/// Takes the digest published in the manifest rather than re-hashing the bytes:
/// `verify_artifact` has already checked those against each other and fails
/// closed, so by the time this is called the digest IS the hash of the artifact
/// we loaded — and no second pass over ~30 MB of key material is needed.
fn key_hash(digest: &[u8; 32]) -> String {
    digest[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// The shared BASE runtime config, baked into the image (embedded at compile time,
/// so it is part of the attested digest — never fetched at boot). The per-env
/// `env_overlay` is layered on top; `store_cts.endpoint` here is a placeholder the
/// launcher overrides from `STORE_CTS_ENDPOINT`.
const BASE_CONFIG: &str = include_str!("envs/base.toml");

/// The per-environment overlay — only the fields that differ from `BASE_CONFIG`
/// (today `storage.bucket` and `metrics.push`). Layered on top of the base by the zk-verifier
/// `Builder` (later wins). Selected by the blessed `COFHE_ENV`; bails on any env
/// with no baked overlay (kept in lockstep with `cofhe-keys`'s env map).
fn env_overlay(env: &str) -> Result<&'static str> {
    match env {
        "staging" => Ok(include_str!("envs/staging.toml")),
        "testnet" => Ok(include_str!("envs/testnet.toml")),
        "mainnet" => Ok(include_str!("envs/mainnet.toml")),
        other => anyhow::bail!("no baked runtime config overlay for environment {other:?}"),
    }
}

struct Config {
    /// Blessed environment selector (`staging` | `testnet`; `mainnet` once it
    /// onboards) — the ONLY reader-source input the operator supplies. Resolved
    /// fail-closed against the env map baked into `cofhe-keys`.
    env: String,
    /// Baked partner set for `env`, each stamped with the zk-signer secret id
    /// and its per-consumer WIF audience (`…/providers/zee-k-reader`). One share
    /// per partner; we reconstruct from any `threshold` good shares. Each
    /// partner's Secret Manager is read with ITS OWN federated token — there is
    /// no shared keys-access SA.
    partners: Vec<PartnerRef>,
    /// Shamir threshold T — minimum good shares required to reconstruct.
    threshold: u8,
    /// GCS bucket holding the public material (the digests reconstruction is
    /// validated against). From the baked triplet, not env.
    public_bucket: String,
    /// Public-material object name within `public_bucket` (baked, not env). The
    /// FHE artifacts are fetched as siblings of this object; the manifest at it
    /// carries their digests.
    public_object: String,
    /// The ct-server endpoint the verifier writes stored cts to. The ONE
    /// operator-supplied endpoint (`STORE_CTS_ENDPOINT`), mirroring teecryptor's
    /// `CT_SOURCE_URL`; injected into the baked zk-verifier config at boot.
    store_cts_endpoint: String,
}

impl Config {
    fn from_env() -> Result<Self> {
        fn env(key: &str) -> Result<String> {
            std::env::var(key).with_context(|| format!("env var {} not set", key))
        }

        // The reader source (partner set + audiences + public-material location +
        // Shamir threshold) is baked into cofhe-keys and selected by COFHE_ENV —
        // fail-closed, BEFORE any network call: an env outside the baked map errors
        // here.
        let env_name = env("COFHE_ENV")?;
        let baked = cofhe_keys::reader::lookup(&env_name)?;
        let partners = cofhe_keys::reader::partner_refs(baked, "zee-k", ZK_SIGNER_SECRET)?;

        // Threshold T is baked per-env in cofhe-keys — the SAME value the keygen
        // producer splits with, so split and reconstruct agree on T by construction
        // (no longer operator-supplied). Still validated fail-closed: the vsss Gf256
        // backend cannot reconstruct below MIN_THRESHOLD, and a T greater than the
        // baked partner count can never reconstruct — either means a broken baked map.
        let threshold = baked.shamir_threshold;
        if threshold < cofhe_keys::shamir::MIN_THRESHOLD {
            anyhow::bail!(
                "baked Shamir threshold must be >= {} (vsss Gf256 minimum)",
                cofhe_keys::shamir::MIN_THRESHOLD
            );
        }
        if threshold as usize > partners.len() {
            anyhow::bail!(
                "baked Shamir threshold ({}) exceeds the number of partners ({})",
                threshold,
                partners.len()
            );
        }

        Ok(Config {
            env: env_name,
            partners,
            threshold,
            public_bucket: baked.public_bucket.to_string(),
            public_object: baked.public_object.to_string(),
            store_cts_endpoint: env("STORE_CTS_ENDPOINT")?,
        })
    }
}

/// Pair each baked partner with the federation token minted for it, matched by
/// `project_id`. A partner with no token (its per-partner federation failed and
/// was excluded upstream) is simply OMITTED from the slice — the reader's
/// fault-tolerant gather reconstructs from the remaining T good shares.
fn partner_accesses<'a>(
    partners: &'a [PartnerRef],
    tokens: &'a [(String, String)],
) -> Vec<PartnerAccess<'a>> {
    partners
        .iter()
        .filter_map(|p| {
            tokens
                .iter()
                .find(|(project_id, _)| *project_id == p.project_id)
                .map(|(_, token)| PartnerAccess {
                    partner: p,
                    sm_token: token,
                })
        })
        .collect()
}

/// Reconstruct the zk-signer secret across the partners via the `cofhe-keys`
/// reader, then assemble the signing key. The GCP endpoints are compile-time
/// `const`s here (NOT env-overridable) so a `setMetadata`-capable operator cannot
/// redirect the reads. Each partner's Secret Manager share is read with that
/// partner's own federated token (`partner_tokens`, matched by project id — a
/// tokenless partner is omitted and overcome by the fault-tolerant gather); the
/// GCS public material is non-secret and read with the compute-SA `gcs_token`.
async fn reconstruct_signer(
    cfg: &Config,
    partner_tokens: &[(String, String)],
    gcs_token: &str,
) -> Result<(SigningKey, cofhe_keys::serialization::PublicMaterial)> {
    use cofhe_keys::gcs::GcsClient;
    use cofhe_keys::reader::{read_public, read_zk_signer, ReaderContext};
    use cofhe_keys::secrets::SecretManager;
    use cofhe_keys::serialization::PublicMaterial;

    let sm = SecretManager::new(SM_URL);
    let gcs = GcsClient::new(GCS_STORAGE_URL);

    let accesses = partner_accesses(&cfg.partners, partner_tokens);

    let ctx = ReaderContext {
        sm: &sm,
        gcs: &gcs,
        gcs_token,
        public_bucket: &cfg.public_bucket,
        public_object: &cfg.public_object,
    };

    let zk_signer_secret = read_zk_signer(&ctx, &accesses, cfg.threshold)
        .await
        .context("reconstruct zk-signer across partners")?;
    let signer_pk = key_source::assemble(zk_signer_secret)?;

    // Pull the same public material the reader validated the shares against. It
    // carries the FHE public artifacts (crs / compact_public_key / server_key) AND
    // the published zk_signer_address the boot gate checks — so the consumer needs no
    // separately-staged TFHE files or signer_public_key. Integrity rests on the
    // bucket IAM; the reconstructed signer is additionally checked against the
    // published zk_signer_address (see pubkey_match).
    let public_bytes = read_public(&gcs, gcs_token, &cfg.public_bucket, &cfg.public_object)
        .await
        .context("read public material")?;
    let public =
        PublicMaterial::from_canonical_bytes(&public_bytes).context("decode public material")?;
    Ok((signer_pk, public))
}

#[tokio::main]
async fn main() -> Result<()> {
    // google-cloud-storage (the verified-inputs client) uses rustls 0.23, which
    // panics later if no process-level CryptoProvider is set and both ring and
    // aws-lc-rs are linked. Install ring explicitly before any TLS use.
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install rustls ring CryptoProvider"))?;

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .json()
        .init();

    // Fail-closed before any network call: a COFHE_ENV outside the baked map errors
    // right here, inside from_env's lookup.
    let cfg = Config::from_env()?;
    info!(env = %cfg.env, partners = cfg.partners.len(), "resolved baked reader source");

    // Per-partner attested federation: each partner gates reads behind its own
    // WIF provider, so mint one attested JWT + STS exchange PER PARTNER (per
    // audience). A failing partner is warned and EXCLUDED, not fatal — the
    // reader's fault-tolerant gather reconstructs from the remaining T good
    // shares (an under-threshold outcome still aborts inside the reader).
    info!("federating per-partner attested access tokens");
    let attest = AttestationClient::new(ATTESTATION_SOCKET);
    let auth = cofhe_keys::gcp_auth::GcpAuth::new(cofhe_keys::gcp_auth::DEFAULT_STS_URL);
    let mut partner_tokens: Vec<(String, String)> = Vec::with_capacity(cfg.partners.len());
    for p in &cfg.partners {
        let token = async {
            let jwt = attest.fetch_token(&p.wip_audience).await?;
            auth.exchange(&p.wip_audience, &jwt).await
        }
        .await;
        match token {
            Ok(token) => partner_tokens.push((p.project_id.clone(), token)),
            Err(e) => warn!(
                partner = %p.project_id,
                error = format!("{e:#}"),
                "partner federation failed; excluding it from reconstruction"
            ),
        }
    }

    // The public material is non-secret: its GCS reads ride the VM's attached
    // compute SA, fetched from the (const-URL) metadata server.
    info!("fetching compute-SA token from the metadata server");
    let gcs_token =
        cofhe_keys::gcp_auth::MetadataClient::new(cofhe_keys::gcp_auth::DEFAULT_METADATA_URL)
            .token()
            .await?;

    info!("reconstructing zk-signer across partners (Shamir T-of-N)");
    let (signer_pk, public) = reconstruct_signer(&cfg, &partner_tokens, &gcs_token).await?;

    // Runtime config (NOT key material) is baked into the image per-env and merged
    // IN MEMORY from the compiled-in base + overlay — never fetched, never written to
    // disk — so a workload owner cannot swap the config the verifier runs on.
    info!("building runtime config from the baked base + per-env overlay (in-memory)");
    let mut zk_config =
        zk_verifier::config::Builder::from_baked(BASE_CONFIG, env_overlay(&cfg.env)?)
            .build()
            .map_err(|e| anyhow::anyhow!("zk-verifier config build failed: {e}"))?;
    // Inject the one operator-supplied endpoint over the baked placeholder. Done
    // here as a first-class value (mirrors teecryptor's CT_SOURCE_URL) rather than
    // via zk-verifier's generic APP__ config overlay, which is slated for removal.
    zk_config.store_cts.endpoint = cfg.store_cts_endpoint.clone();
    // Whether to push is baked per-env: `[metrics] push` is off unless an overlay
    // turns it on (nothing can scrape this VPC). The destination is compiled
    // into zk-verifier (otel_push::TELEMETRY_ENDPOINT), deliberately not
    // operator-settable: no credentialed request can be redirected by configuration.
    zk_config.metrics.env = Some(cfg.env.clone());

    let gcs = Gcs::new(GCS_STORAGE_URL)
        .await
        .context("building GCS client")?;

    // The FHE public artifacts are staged by the ceremony as separate cofhe-native
    // files RIGHT NEXT TO the manifest (the same layout the sibling cofhe compute
    // services read), so they're fetched from the public bucket as siblings of the
    // manifest object — NOT from the deployer's config bucket. Download each, then
    // check its bytes against the SHA-256 digest published in the bucket-sourced
    // manifest before trusting them. NB: the manifest is no longer attested — its
    // integrity rests on bucket IAM, so a bucket writer could swap the manifest
    // and artifacts together (the CRS/FHE artifacts have no on-chain backstop).
    // The boot gate below checks the reconstructed signer against the published
    // zk_signer_address carried in that same manifest.
    info!("fetching + verifying FHE public artifacts against the manifest digests");
    let crs_object = sibling_object(&cfg.public_object, OBJ_CRS);
    let crs_bytes = gcs
        .download_bytes(&cfg.public_bucket, &crs_object)
        .await
        .context("downloading crs from GCS")?;
    verify_artifact(&crs_bytes, &public.crs_digest, "crs")?;
    info!(
        "Key loaded: CRS from 'gs://{}/{}' (hash: {})",
        cfg.public_bucket,
        crs_object,
        key_hash(&public.crs_digest)
    );
    let pk_object = sibling_object(&cfg.public_object, OBJ_PUBLIC_KEY);
    let pk_bytes = gcs
        .download_bytes(&cfg.public_bucket, &pk_object)
        .await
        .context("downloading public_key from GCS")?;
    verify_artifact(&pk_bytes, &public.compact_public_key_digest, "public_key")?;
    info!(
        "Key loaded: Public Key from 'gs://{}/{}' (hash: {})",
        cfg.public_bucket,
        pk_object,
        key_hash(&public.compact_public_key_digest)
    );
    let sk_object = sibling_object(&cfg.public_object, OBJ_SERVER_KEY);
    let sk_bytes = gcs
        .download_bytes(&cfg.public_bucket, &sk_object)
        .await
        .context("downloading computation_key from GCS")?;
    verify_artifact(&sk_bytes, &public.server_key_digest, "computation_key")?;
    info!(
        "Key loaded: Server Key from 'gs://{}/{}' (hash: {})",
        cfg.public_bucket,
        sk_object,
        key_hash(&public.server_key_digest)
    );

    let (crs, pk, sk) = zk_verifier::deserialize_tfhe_artifacts(&crs_bytes, &pk_bytes, &sk_bytes)
        .map_err(|e| anyhow::anyhow!("deserialize TFHE artifacts: {e}"))?;

    info!("delegating to zk_verifier::run_server");
    let keys = zk_verifier::KeyMaterial {
        crs,
        pk,
        sk,
        signer_pk,
        expected_signer_address: Some(public.zk_signer_address),
    };
    zk_verifier::run_server(zk_config, keys)
        .await
        .map_err(|e| anyhow::anyhow!("zk-verifier server returned: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// RAII snapshot-restore for a fixed set of env vars. Clears them on
    /// construction so each test starts from a known-blank state.
    struct EnvGuard {
        snapshots: Vec<(&'static str, Option<String>)>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }
    const KEYS: &[&str] = &["COFHE_ENV", "STORE_CTS_ENDPOINT"];

    impl EnvGuard {
        fn new(keys: &[&'static str]) -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let snapshots: Vec<_> = keys.iter().map(|k| (*k, std::env::var(k).ok())).collect();
            for k in keys {
                std::env::remove_var(k);
            }
            Self {
                snapshots,
                _lock: lock,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (k, v) in &self.snapshots {
                match v {
                    Some(v) => std::env::set_var(k, v),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    /// Required envs for a valid config: the blessed environment selector and the
    /// ct-server endpoint. The partner set, per-partner WIF audiences, the
    /// public-material location, and the Shamir threshold are all resolved from the
    /// env selector against the map baked into `cofhe-keys` — nothing else to set here.
    fn set_required_envs() {
        std::env::set_var("COFHE_ENV", "testnet");
        std::env::set_var("STORE_CTS_ENDPOINT", "https://ct.example.test");
    }

    fn assert_from_env_errors_with(needle: &str) {
        match Config::from_env() {
            Ok(_) => panic!("expected error mentioning {needle:?}"),
            Err(e) => {
                let msg = format!("{e:#}");
                assert!(msg.contains(needle), "expected {needle:?}, got: {msg}");
            }
        }
    }

    #[test]
    fn config_env_testnet_resolves_baked_partners() {
        let _g = EnvGuard::new(KEYS);
        set_required_envs();
        let cfg = Config::from_env().expect("from_env");
        assert_eq!(cfg.env, "testnet");
        assert_eq!(cfg.threshold, 2);
        // The testnet triplet baked into cofhe-keys: 3 partners, each stamped
        // with the zk-signer secret and the per-consumer zee-k reader audience.
        assert_eq!(cfg.partners.len(), 3);
        assert_eq!(cfg.partners[0].project_id, "fhenix-testnet-tee-partner-1");
        for p in &cfg.partners {
            assert_eq!(p.secret_id, ZK_SIGNER_SECRET);
            assert!(
                p.wip_audience.ends_with("/providers/zee-k-reader"),
                "audience must be the per-consumer zee-k provider, got {}",
                p.wip_audience
            );
            assert!(p
                .wip_audience
                .contains("/workloadIdentityPools/cofhe-tee-reader-pool/"));
        }
        // Public-material location comes from the same baked triplet, not env.
        assert_eq!(cfg.public_bucket, "fhenix-testnet-v2");
        assert_eq!(
            cfg.public_object,
            "generator/keys/versionized/0/public-material"
        );
        // The one operator-supplied endpoint is captured verbatim.
        assert_eq!(cfg.store_cts_endpoint, "https://ct.example.test");
    }

    #[test]
    fn config_missing_env_errors() {
        let _g = EnvGuard::new(KEYS);
        set_required_envs();
        std::env::remove_var("COFHE_ENV");
        assert_from_env_errors_with("COFHE_ENV");
    }

    #[test]
    fn config_unknown_env_fails_closed() {
        let _g = EnvGuard::new(KEYS);
        set_required_envs();
        // Fail-closed: an env not in the baked map aborts at boot — no default,
        // no fallback. Matching is exact, so case variants are unknown envs too.
        for bad in ["prod", "Testnet", "Mainnet", ""] {
            std::env::set_var("COFHE_ENV", bad);
            assert_from_env_errors_with("unknown environment");
        }
    }

    #[test]
    fn metrics_push_matches_baked_overlays() {
        for env in ["staging", "testnet", "mainnet"] {
            let c =
                zk_verifier::config::Builder::from_baked(BASE_CONFIG, env_overlay(env).unwrap())
                    .build()
                    .unwrap();
            assert_eq!(c.metrics.push, env != "staging", "metrics push for {env}");
        }
    }

    /// Lockstep with the baked key SOURCE: every env in the shared `cofhe-keys` map
    /// must have a matching baked runtime-config overlay here. Driving the loop off
    /// `cofhe_keys::reader::env_names()` (the same list the reader resolves) means a
    /// new env added there can't ship without an overlay — this test fails first.
    #[test]
    fn env_overlay_covers_every_baked_key_env() {
        for name in cofhe_keys::reader::env_names() {
            assert!(
                env_overlay(name).is_ok(),
                "cofhe-keys bakes env {name:?} but there is no matching runtime-config overlay"
            );
        }
    }

    #[test]
    fn config_env_mainnet_resolves_baked_partners() {
        // The mainnet set is baked at six key-share holders, threshold 3. While any
        // slot is an unfilled placeholder, partner_refs fails closed, so
        // Config::from_env("mainnet") refuses rather than resolving a partial set.
        let src = cofhe_keys::reader::lookup("mainnet").expect("baked mainnet source");
        assert_eq!(src.partners.len(), 6);
        assert_eq!(src.partners[0].project_id, "fhenix-507307");
        assert_eq!(src.shamir_threshold, 3);

        let _g = EnvGuard::new(KEYS);
        set_required_envs();
        std::env::set_var("COFHE_ENV", "mainnet");
        assert!(
            Config::from_env().is_err(),
            "mainnet has open partner slots; from_env must fail closed"
        );
    }

    #[test]
    fn config_missing_store_cts_endpoint_errors() {
        let _g = EnvGuard::new(KEYS);
        set_required_envs();
        std::env::remove_var("STORE_CTS_ENDPOINT");
        assert_from_env_errors_with("STORE_CTS_ENDPOINT");
    }

    /// The zip seam between the per-partner federation loop and the reader: each
    /// baked partner is paired with ITS token by project id; a partner whose
    /// federation failed (no token) is simply omitted, and unknown token ids
    /// pair with nothing. Order follows the baked partner list.
    #[test]
    fn partner_accesses_zips_by_project_id_and_omits_tokenless() {
        let partners = vec![
            PartnerRef {
                project_id: "p1".into(),
                secret_id: ZK_SIGNER_SECRET.into(),
                wip_audience: "//a1".into(),
            },
            PartnerRef {
                project_id: "p2".into(),
                secret_id: ZK_SIGNER_SECRET.into(),
                wip_audience: "//a2".into(),
            },
            PartnerRef {
                project_id: "p3".into(),
                secret_id: ZK_SIGNER_SECRET.into(),
                wip_audience: "//a3".into(),
            },
        ];
        // p2 has no token (federation failed); tokens arrive out of order.
        let tokens = vec![
            ("p3".to_string(), "tok-3".to_string()),
            ("p1".to_string(), "tok-1".to_string()),
            ("nope".to_string(), "tok-x".to_string()),
        ];
        let accesses = partner_accesses(&partners, &tokens);
        assert_eq!(accesses.len(), 2);
        assert_eq!(accesses[0].partner.project_id, "p1");
        assert_eq!(accesses[0].sm_token, "tok-1");
        assert_eq!(accesses[1].partner.project_id, "p3");
        assert_eq!(accesses[1].sm_token, "tok-3");
    }

    #[test]
    fn sibling_object_derives_manifest_neighbor() {
        // Artifacts sit next to the manifest, under the same "directory".
        assert_eq!(
            sibling_object("keys/versionized/0/public-material", OBJ_CRS),
            "keys/versionized/0/crs"
        );
        // A bare manifest name (no directory) → the bare artifact name.
        assert_eq!(
            sibling_object("public-material", OBJ_SERVER_KEY),
            "computation_key"
        );
    }

    #[test]
    fn key_hash_is_first_four_digest_bytes_as_hex() {
        // Must stay byte-identical to what the cofhe services log for the same
        // artifact, otherwise the two sides can't be compared by eye.
        let mut digest = [0u8; 32];
        digest[..5].copy_from_slice(&[0x88, 0x1e, 0xb6, 0x02, 0xff]);
        assert_eq!(key_hash(&digest), "881eb602");
        assert_eq!(key_hash(&[0u8; 32]), "00000000");
    }
}
