//! Minimal Google Cloud Storage reader for the boot path.
//!
//! Confidential Space's `tee-mount` metadata only supports `type=tmpfs` — it
//! cannot bind-mount an attached persistent disk into the workload container
//! (the launcher fail-closes on `type=block-device`). So the TFHE public
//! artifacts and the runtime config, which the original design expected to
//! ride on a PD mounted at `/app/keys`, are instead pulled from a GCS bucket
//! at boot.
//!
//! Backed by the official `google-cloud-storage` client — the same one
//! `zk-verifier` uses (`zk-verifier/src/storage/gcs.rs`). Authentication is
//! ADC: the client resolves the VM's *attached* service-account token from the
//! GCE metadata server automatically — deliberately NOT the attested
//! keys-access SA used for `signer_pk`. The artifacts are public material and
//! the bucket is workload-owner-controlled, the same trust boundary the PD
//! carried (see `SECURITY-OVERVIEW.md`): a principal with write access to the
//! public bucket can swap the TFHE material. That stays `signer_pk`-safe (the
//! signer is partner-write-gated and matched to the published `zk_signer_address`),
//! but with consumer-side provenance verification removed, the artifacts' own
//! integrity now rests on bucket-write IAM — there is no on-chain backstop.
//!
//! The metadata host the ADC path talks to is located via `GCE_METADATA_HOST`,
//! which is intentionally absent from the Dockerfile's `allow_env_override`
//! LABEL — so a workload owner with `setMetadata` cannot redirect it, the same
//! hardening the const metadata URL (`cofhe_keys::gcp_auth::DEFAULT_METADATA_URL`)
//! gives the compute-SA token fetch in `main.rs`.

use anyhow::Result;
use google_cloud_storage::client::Storage;

pub struct Gcs {
    storage: Storage,
}

impl Gcs {
    /// Build a client. `endpoint` is the GCS data-plane host
    /// (`https://storage.googleapis.com` in prod; a fake-gcs URL in tests).
    /// ADC is always used for auth regardless of endpoint.
    pub async fn new(endpoint: &str) -> Result<Self> {
        let storage = Storage::builder()
            .with_endpoint(endpoint)
            .build()
            .await
            .map_err(|e| anyhow::anyhow!("building GCS Storage client: {e}"))?;
        Ok(Self { storage })
    }

    /// Download a single object fully into memory. Used for the FHE public
    /// artifacts, whose bytes must be hashed and checked against the manifest
    /// digests before they are trusted — so they can't just stream to disk.
    pub async fn download_bytes(&self, bucket: &str, object: &str) -> Result<Vec<u8>> {
        let parent = format!("projects/_/buckets/{bucket}");
        let mut reader = self
            .storage
            .read_object(parent, object.to_string())
            .send()
            .await
            .map_err(|e| {
                anyhow::anyhow!("GCS download request failed for gs://{bucket}/{object}: {e}")
            })?;

        let mut bytes = Vec::new();
        while let Some(chunk) = reader
            .next()
            .await
            .transpose()
            .map_err(|e| anyhow::anyhow!("reading body for {object}: {e}"))?
        {
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The official client resolves ADC (a metadata-server token) at send() time,
    // so it can't be exercised by a bare wiremock unit test the way the old
    // hand-rolled reader was — `with_endpoint` only redirects the data plane,
    // not auth. Mirror zk-verifier's approach (zk-verifier/src/storage/gcs.rs):
    // an #[ignore]-gated e2e test against `fake-gcs-server` + the mock metadata
    // server, run explicitly via:
    //
    //   docker compose up fake-gcs-server mock-gce-metadata -d
    //   GCE_METADATA_HOST=localhost:8080 \
    //     cargo test gcs::tests:: -- --ignored --nocapture
    //
    // (seed `my-bucket/crs` in fake-gcs first; the helper below assumes it).
    #[tokio::test]
    #[ignore = "requires fake-gcs-server + mock metadata; see module test comment"]
    async fn download_round_trips_object_bytes() {
        // GCE_METADATA_HOST must be set in the environment before this runs so
        // ADC resolves against the mock metadata server.
        let endpoint =
            std::env::var("FAKE_GCS_URL").unwrap_or_else(|_| "http://localhost:4443".to_string());
        let gcs = Gcs::new(&endpoint).await.expect("build client");

        let bytes = gcs
            .download_bytes("my-bucket", "crs")
            .await
            .expect("download");
        assert!(!bytes.is_empty());
    }
}
