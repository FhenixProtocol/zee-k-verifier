# zee-k-verifier

A TDX-attested deployment of the CoFHE **zk-verifier** service.

`zk-verifier` verifies TFHE zero-knowledge proofs and signs the verified ciphertext hashes with a secp256k1 key. This repository runs it inside an Intel TDX Confidential Space VM on GCP. GCP releases the signing key only to the exact pinned image running in the exact pinned project. Any external observer can confirm this through Google's Confidential Computing attestation chain.

## What's inside

| Path             | Purpose                                                              |
|------------------|----------------------------------------------------------------------|
| `tdx-signer/`    | Binary that runs inside the Confidential VM. Owns the TDX boot path. |
| `zk-verifier/`   | The verifier service. Hybrid Rust crate (library + binary).          |
| `rust-common/`   | Shared library: logger, ECDSA signer, TFHE-aware serde.              |

## Quickstart (local dev)

```bash
docker compose up zk-verifier
```

This starts the verifier on `:3001` (API) and `:9090` (metrics). It uses mock or file-loaded keys plus a `fake-gcs-server` emulator. For endpoint details see `zk-verifier/README.md`. For the local-dev configuration see `config/local/config.toml`. The production config is baked into the image per env — see `tdx-signer/src/envs/`.

`docker compose` does not exercise the TDX boot path. That path needs `/run/container_launcher/teeserver.sock` and a real GCP project. To deploy to TDX, see the gitops repo.

## Production deployment

The TDX deployment splits custody between the partners and the workload owner. It also uses one shared artifact-registry project:

- **Partners** (per-env baked set — staging N=5, testnet N=3) each hold one `cofhe-tee-zk-signer` Shamir share in their own Secret Manager. Each partner gates its own share behind its own attested WIF provider and CEL.
- **Workload owner** owns the Confidential VM and the firewall. The VM pulls its image from the shared artifact registry.
- **Shared artifact registry** holds the Artifact Registry and the GitHub Actions WIF that pushes images — **images only**. Terraform state lives per project in a `gs://<project>-tfstate` bucket, not here.

Neither side alone can release the keys to new code. One identity can also own every project and run the stack single-operator.

## Documentation

| Read | For |
|---|---|
| [`tdx-signer/SECURITY-OVERVIEW.md`](tdx-signer/SECURITY-OVERVIEW.md) | The trust model: custody split, boot handshake, what is pinned where, non-goals |
| [`zk-verifier/README.md`](zk-verifier/README.md) | The client API: request and response shapes, the signed digest, configuration |
| [`SECURITY.md`](SECURITY.md) | Reporting a vulnerability |

Deploy steps and alerting/on-call now live in the gitops repo.

## Trust model

The signing key is released to "this exact binary, in this exact compute project, **or nothing**". Intel TDX attests the hardware, Google's Confidential Computing service signs the attestation, and a CEL condition we wrote gates the release.

The runtime config is baked into the image per env, so it is part of the attested digest. The TFHE public material (CRS, public key, server key) is fetched at boot from the keygen's public bucket into tmpfs, because Confidential Space's `tee-mount` supports tmpfs only and cannot bind-mount a disk. The `image_digest` CEL does *not* gate that fetch:

- **The secret stays gated.** The only secret is `signer_pk`. It never leaves the attestation gate. The shares are partner-write-gated, and the reconstructed signer is matched to the published `zk_signer_address`, so the owner cannot forge a verifier signature.
- **The public artifacts rest on bucket IAM.** Consumer-side provenance verification was removed. A principal with write access to the public bucket can swap the manifest and the CRS/FHE artifacts together, and there is **no on-chain backstop** for them. The mitigation is tight write-IAM on that bucket. For `public_key` and `server_key` a functional check also applies: a result computed against substituted keys does not match the network's real keys, so a relying party that checks the verifier's signed output detects the swap. The CRS has no such check.

The image carries build provenance. Each build **on `main`** emits a keyless SLSA attestation, logged in the public Rekor log and served by GitHub on an API that needs no account. It does **not** gate the runtime — the digest pinned in each partner's CEL is still the whole enforcement. It gates the **pin**: before a partner pins a new digest, it runs `gh attestation verify` on its own machine and asserts the exact digest, the exact commit, this workflow and `refs/heads/main`. A non-zero exit means it does not pin. The build's job summary prints that command with every value filled in.

Full threat model: [`tdx-signer/SECURITY-OVERVIEW.md`](tdx-signer/SECURITY-OVERVIEW.md).
