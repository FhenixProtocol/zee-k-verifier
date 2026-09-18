# TDX Signer — Security Overview

The trust model of the TDX-attested zk-verifier: what the deployment guarantees,
how the boot handshake earns that guarantee, and what the guarantee does not
cover. The deploy steps live in the gitops repo.

## The custody split

The deployment splits across the **compute project** (workload owner) and the
**partner projects** that hold the signer shares. The partner set is baked per
env — staging N=5, testnet N=3.

| Role | Project | Owns |
|---|---|---|
| **Partners** (per-env baked set — staging N=5, testnet N=3) | Independent partner projects | Each holds a Secret Manager secret named `cofhe-tee-zk-signer` that carries one Shamir T-of-N share of the signer. The partner's **own attested WIF provider** gates it (`cofhe-tee-reader-pool/providers/zee-k-reader` plus the partner's CEL). Each partner grants `roles/secretmanager.secretAccessor` on its secret to that federated attested identity. There is no shared keys-access SA. |
| **Workload owner** | Compute project (`<COMPUTE_PROJECT_ID>`, owned by `<WORKLOAD_OWNER_EMAIL>`) | The Confidential VM, the firewall, and the verified-inputs (proofs) bucket the verifier writes to. The runtime config is baked into the image, so there is no config bucket. The TFHE artifacts come from the keygen's public bucket, whose location is baked per env and whose contents are digest-verified. |
| **Ops (shared)** | Shared artifact-registry project | The Artifact Registry and the GitHub Actions CI WIF that pushes images — images only. The VM pulls its image from there. The registry sits **outside** the key-release gate: integrity comes from the digest pinned in the partners' CELs, not from the registry. |

A keygen ceremony in the sibling `cofhe-tdx-keygen` repo writes the shares, **not**
this repo. The partner-onboarding Terraform in that same repo provisions each
partner's reader-side WIF gate. A legacy keys project from the earlier
custodian-mediated model is off the boot path and retires during the migration's
Part 2 cutover.

**Why split.** No single party can release the signer to new code. The workload
owner cannot change the IAM that gates the shares, because each partner controls
its own WIF CEL and grant. No partner can deploy an image into the pinned compute
project, and no partner alone holds enough shares. Reconstruction needs any T good
shares. New code reaching the key needs **≥ T partners** to repin the new digest in
their CELs.

## The partner-gate contract

Each partner gates reads on its `cofhe-tee-zk-signer` secret behind its **own**
attested WIF provider. The partner-onboarding Terraform, in the sibling
`cofhe-tdx-keygen` repo, creates three things:

1. The `cofhe-tee-reader-pool` workload identity pool.
2. The `zee-k-reader` provider, with the partner's CEL. The CEL pins the consumer
   image digest, the compute project, Intel-TDX, and STABLE.
3. The `roles/secretmanager.secretAccessor` grant to that federated attested
   principal.

Three properties follow:

- There is **no shared keys-access SA** and no cross-project grant to a fixed
  email. Each partner's grant targets its own pool's federated principal, so no
  other project's IAM can widen it.
- The per-partner WIF audiences the reader uses are **baked into the binary**
  (`cofhe-keys`' env map). There is nothing to exchange at deploy time.
- Per release, each partner **re-pins the new consumer image digest** in its own
  CEL through a partner-side `terraform apply`. Consent is explicit per image, per
  partner.

## The boot handshake

Time-ordered view of the handshake that reconstructs the signer from the
partner-held Shamir shares into TEE memory. Every request and response pair
originates from `tdx-signer` running inside the Confidential VM (see
`src/main.rs`). The CS launcher fans out to Intel silicon and Google's
Confidential Computing attester inside step 1. Everything after that is direct
HTTPS from the binary.

```mermaid
sequenceDiagram
    autonumber
    participant TS as tdx-signer<br/>(compute prj)
    participant CS as CS Launcher<br/>(in VM)
    participant CPU as Intel TDX<br/>(silicon)
    participant GCC as Google CC<br/>attester
    participant STS as Google STS
    participant SM as Secret Manager<br/>(N partner prjs)

    Note over TS,STS: Steps 1 + 2 run once PER PARTNER — each partner<br/>hosts its own attested WIF provider (its own audience)

    Note over TS,GCC: 1. Attestation — get a TDX-rooted OIDC JWT
    TS->>CS: GET /v1/token<br/>(audience = partner's WIF provider)
    CS->>CPU: request TDX quote
    CPU-->>CS: quote signed by CPU
    CS->>GCC: quote + CS measurements<br/>(image_digest, hwmodel,<br/>support_attributes,<br/>gce_project_id)
    GCC-->>CS: OIDC JWT<br/>(iss = confidentialcomputing.googleapis.com)
    CS-->>TS: JWT

    Note over TS,STS: 2. STS exchange — the PARTNER's CEL gate evaluates
    TS->>STS: POST /v1/token<br/>subject_token = JWT<br/>(audience = partner's WIF provider)
    alt CEL passes<br/>(digest + project + STABLE + TDX)
        STS-->>TS: partner-scoped federated access token
    else CEL fails
        STS--xTS: HTTP 400 "rejected by attribute condition"
        Note over TS: partner warned + EXCLUDED — the T-of-N gather<br/>tolerates it; an under-threshold outcome still aborts
    end

    Note over TS,SM: 3. Read + reconstruct the signer (Shamir T-of-N)
    loop each partner that federated
        TS->>SM: GET secrets/cofhe-tee-zk-signer:access<br/>Bearer = THAT partner's federated token
        SM-->>TS: one Shamir share
    end
    Note over TS: filter liars by per-share digest<br/>(authenticity comes from the partner write-gate —<br/>only the attested keygen enclave can write a partner's<br/>share; consumer-side provenance verification is removed,<br/>as is the keygen-origin allowlist) → reconstruct any T<br/>good shares → validate against published full-key digest<br/>→ build SigningKey

    Note over TS: 4. Assemble the baked runtime config in memory, then<br/>fetch the TFHE artifacts from the keygen's public<br/>bucket as the VM's ATTACHED SA (not this attested<br/>path). Each artifact is checked against its digest in<br/>the bucket-sourced manifest (manifest integrity rests<br/>on bucket IAM, not attestation); the reconstructed<br/>signer is checked against the manifest's<br/>zk_signer_address.
    Note over TS: SigningKey lives in TEE memory only.<br/>Hand off to zk_verifier::run_server.
```

Step 4's fetch is **not** part of the attested key-release chain. The VM's attached
service account reads the TFHE public material (`crs`, `public_key`,
`computation_key`) from the keygen's public bucket, next to the manifest, with the
bucket and object baked per env into `cofhe-keys`' env map. See *How do the TFHE
artifacts reach the VM?* below.

## What's hard-pinned where

| Pin | Where it lives | What it stops |
|---|---|---|
| `image_digest` (consumer / tdx-signer) | Each partner's CEL on its own `zee-k-reader` WIF provider | A different Dockerfile, or different bytes, federating a read token for any partner's share |
| Reader data source (partner set, per-partner WIF audiences, public-material bucket/object) | Baked into `cofhe-keys`' env map, selected by the fail-closed `COFHE_ENV` | A `setMetadata`-capable operator redirecting the reader at partner projects or a bucket they control. The old `PARTNERS`, `PUBLIC_BUCKET`, and `PUBLIC_OBJECT` env vars are gone |
| Runtime `config.toml` | Baked into the image per env, so it is part of the attested digest (see `src/envs/`) | An operator swapping the storage bucket or the retry and verify tuning at boot. There is no config bucket |
| Keygen-origin allowlist (`ALLOWED_KEYGEN_DIGESTS` / `ALLOWED_KEYGEN_GCE_PROJECT_IDS`) | **Removed.** It was load-bearing only while the reader's data source was operator-redirectable. With the source baked and each partner gating reads behind its own attested WIF provider, the trust anchor is the partners' enforcement plus the on-chain-signature invariant: the reconstructed signer must match the published `zk_signer_address` | — |
| `gce_project_id == <COMPUTE_PROJECT_ID>` (consumer) | Each partner's CEL on its WIF provider | Same image running in an attacker's GCP project |
| `hwmodel == GCP_INTEL_TDX`, `STABLE` in `support_attributes` | Each partner's CEL on its WIF provider | Non-TDX or pre-GA Confidential Space images |
| GCP endpoint URLs (STS, Secret Manager, GCS, metadata, attestation socket) | Held as `const` and excluded from the image's env-override allow-list (see `src/main.rs` and the `Dockerfile`) | The workload owner redirecting the exchange through `compute.instances.setMetadata` to capture and replay the JWTs |
| `job_workflow_ref` on the WIF binding | The CI push pool in the shared artifact-registry project | The build and push workflow being dispatched from a different ref or file |

## Boundary objects — what crosses, and which direction

One piece of information crosses the boundary each deploy:

1. **Consumer image digest** — workload owner → **each partner**. Every partner
   pins this **tdx-signer** image digest in its own WIF CEL condition. Without a
   matching pin at a partner, that partner's share is not released. Without ≥ T
   matching pins, the boot cannot reconstruct.

The image build produces it (see the gitops repo's deploy Step 1). Nothing flows back. The old
`wip_audience` and `keys_access_sa_email` boundary objects are gone: the
per-partner WIF audiences are baked into the binary, and there is no SA to
impersonate. The old keygen-digest const (`ALLOWED_KEYGEN_DIGESTS`) is likewise
removed, so a new keygen ceremony does not require a consumer release.

## What proves the running image came from our source code

The key-release gate is **digest-only**. Each partner's WIF CEL pins the exact
`image_digest`, plus the project, Intel-TDX, and STABLE. Only the exact reviewed
image bytes can federate a read token for any partner's share. The chain is:

1. **GitHub Actions** runs `build-zk-verifier-tdx.yml` (manual dispatch only) on a
   hosted runner.
2. The workflow uses **GCP Workload Identity Federation** scoped to *this exact
   workflow file at this exact ref* (`job_workflow_ref`) to push the image to
   Artifact Registry. No SA key sits in the repo.
3. Each partner pins the resulting digest in its own CEL. Only that digest can
   attest and receive that partner's share.

To run a different image an attacker needs two things: the ability to dispatch our
exact GitHub workflow (the `job_workflow_ref` pin), **and** the cooperation of ≥ T
partners to repin a new digest in their CELs.

The digest pinned in each partner's CEL is the whole **runtime** enforcement, and it
is what every claim in this document rests on. The attestation token carries no
repository, workflow or commit claim, so the CEL cannot prove where an image came
from — only which one runs.

That proof lives one step earlier. The build signs the pushed digest with keyless
Cosign, and the certificate binds the digest to this repository, this workflow, the
ref and the commit. Before a partner pins a digest it runs `cosign verify` against
the public Rekor log, asserting the exact digest and the exact commit, and it does
not pin on a non-zero exit. The check needs no Fhenix credential and no GitHub
account, so a partner trusts the public log rather than us.

Cosign stores the signature next to the image. The Artifact Registry repository
grants `allUsers` the reader role, which is what lets a partner read it. **That
public read is deliberate and the check depends on it.**

## Who signs the attestation report?

Three layers, each rooted in the layer below:

1. **Intel CPU (silicon)** — signs a TDX quote.
2. **Google's Confidential Computing service** — verifies the TDX quote, augments
   it with CS measurements (image digest, hardware model, support attributes), and
   signs an OIDC JWT.
3. **Google STS** (one exchange per partner, against that partner's own WIF
   provider) — verifies the JWT signature and evaluates that partner's CEL
   condition. A pass returns a partner-scoped federated token. A failure returns
   400, that partner is excluded, and the T-of-N gather tolerates it.

Trust assumption: Intel silicon, Google's Confidential Computing attester, and the
CEL each partner wrote. Anything past step 2 is a normal Google IAM call against
tokens those CELs have already gated.

## How do the TFHE artifacts reach the VM?

The signer, reconstructed from the partner shares, is the only secret behind the
attestation gate. The **TFHE public material** (`crs`, `public_key`,
`computation_key`) is **not** secret. It is fetched at boot as the VM's *attached*
service account, through the metadata server, and written into tmpfs at
`/app/keys`. That path is separate from the attested partner-share exchange. The
material comes from the **keygen's public bucket**. The bucket and manifest object
are baked per env into `cofhe-keys`' env map and selected by the fail-closed
`COFHE_ENV`, which is not env-settable. The ceremony writes the artifacts next to
the manifest.

The runtime **`config.toml` is baked into the image**, per env: a shared
`src/envs/base.toml` plus a per-env overlay, compiled in with `include_str!`. It is
therefore part of the attested digest, and it is assembled in memory at boot.
Nothing fetches config from GCS. There is no config bucket and no `/app/config`
mount. One owner-controlled runtime input remains: the ct-server endpoint, injected
as `STORE_CTS_ENDPOINT` (see below).

The artifacts are fetched rather than bind-mounted from a disk because
Confidential Space's `tee-mount` supports `type=tmpfs` only. It cannot bind-mount
a persistent disk into the workload container.

The signer identity is anchored to the `zk_signer_address` published in the
keygen's `public-material` manifest. The manifest is read from the keygen's public
bucket, and its location is baked into the binary, so an operator cannot redirect
it through metadata. At boot the enclave derives the address from the
reconstructed private key and hard-fails unless it matches
(`pubkey_match::verify_signer_matches_address`). The manifest bytes themselves are
**no longer attested**, because consumer-side provenance verification was removed:
it crashed on Google JWKS `kid` rotation, and it was redundant with the partner
write-gate. A defence chain that does not depend on manifest integrity keeps the
signer honest instead. The shares are partner-write-gated, so only the attested
keygen enclave can write a partner's Secret Manager version. The reconstruction is
liar-filtered against the published per-share digests and validated against the
full-key digest. The derived address is matched to the published
`zk_signer_address`. A wrong or foreign key fails that match and the on-chain
signature invariant, so it bricks the boot or has its results rejected. It never
silently redirects trust to an attacker-held key.

**Trust trade-off.** With provenance verification gone, the integrity of the
public material rests on **bucket IAM, not attestation**. A principal with write
access to the keygen's public bucket **can** swap the manifest and the FHE
artifacts (`crs`, `public_key`, `computation_key`) together. The per-artifact
digest check still runs, but it only proves the artifacts match *that* manifest,
and a rewritten manifest passes its own digests. For the **signer key** the effect
is bounded: the shares are partner-write-gated and cannot be silently substituted,
and a wrong reconstructed signer fails `pubkey_match` and the on-chain signature
invariant, so the boot fails or the results are rejected rather than accepted. The
**CRS and FHE public artifacts have no on-chain backstop**, so their integrity
rests on bucket-write IAM alone. This is the accepted trade-off of dropping
provenance, and the mitigation is tight write-IAM on the public bucket. The
runtime config — storage bucket, retry and verify tuning — is **baked into the
attested image**, so an operator cannot swap it at all. The only owner-controlled
data knob exposed through `tee-env-*` is `STORE_CTS_ENDPOINT`, the ct-server
endpoint the verifier writes to, and it carries no key material. `COFHE_ENV` only
selects among the baked, fail-closed reader sources, and the Shamir threshold T is
baked in `cofhe-keys`. Neither weakens the `setMetadata` guarantee below.

## Do we have a KMS?

**No.** We use **Secret Manager** in the partner projects (per-env baked set, each
holding one `cofhe-tee-zk-signer` share). The gate is IAM plus each partner's own
attested WIF provider plus the TDX attestation, not KMS encryption. On top of the
IAM gate, authenticity comes from the partner write-gate: only the attested keygen
enclave can write a partner's share. The reader liar-filters the shares against
the published per-share digests and validates the reconstruction against the
full-key digest before it trusts the result.

## Two distinct image digests

Two different `sha256:...` digests have appeared in this system historically. Only
the first is pinned today:

- **Consumer (tdx-signer) image digest** — pinned by each partner's WIF CEL. This
  is what gates key access: only the exact reviewed tdx-signer image can attest
  and federate a partner read token. Changing it means each partner re-pins its
  CEL (see the gitops repo's *Ship a new image* deploy step).
- **Keygen image digest(s)** — the old `ALLOWED_KEYGEN_DIGESTS` and
  `ALLOWED_KEYGEN_GCE_PROJECT_IDS` consts are **removed**. See *Why the
  keygen-origin allowlist was removed* below. Consumer-side provenance
  verification is also gone. Share authenticity now rests on the partner
  write-gate, and the reconstruction is liar-filtered against the published
  per-share digests and validated against the full-key digest.

## Why the keygen-origin allowlist was removed

Earlier revisions committed `ALLOWED_KEYGEN_DIGESTS` (trusted keygen image
digests) and `ALLOWED_KEYGEN_GCE_PROJECT_IDS` (the service projects the ceremony
could run in) as consts in `src/main.rs`. The project pin was load-bearing **only
because** the reader's data source (`PARTNERS` / `PUBLIC_BUCKET` /
`PUBLIC_OBJECT`) was operator-overridable through `tee-env-*` metadata. A
`setMetadata`-capable owner could point the reader at partner projects and a bucket
they control, populate them with the same allowlisted keygen image run in THEIR
project, and only the project pin rejected that attacker-run ceremony.

Both halves of that attack are now closed structurally:

- **Baked data source.** The partner set, the per-partner WIF audiences, and the
  public-material bucket and object are baked into `cofhe-keys`' env map and
  selected by the fail-closed `COFHE_ENV`. There is nothing left for `setMetadata`
  to redirect, because those env vars no longer exist.
- **Per-partner attested federation.** Each partner gates reads behind its own WIF
  provider and CEL. The enclave can read only the shares the real partners chose
  to release to the pinned image, so an attacker cannot substitute their own
  "partners".

With the data source unforgeable, the keygen-origin pin stopped carrying trust
weight, and it was removed. The invariant that ultimately anchors the signer
identity is the **on-chain signature check**: the reconstructed key must match the
published `zk_signer_address`, and relying parties verify the verifier's signed
outputs against it. A wrong key is a loud, visible break, never a silent forgery.
Consumer-side provenance verification used to sit here as a secondary sanity floor
on every share and on the manifest. It was removed because it crashed on Google
JWKS `kid` rotation and was redundant with the partner write-gate.

## Will the keys be released to a different Dockerfile?

**No — verified.** An image with a different SHA-256 digest hits STS and gets `400 "rejected by attribute condition"` at every partner. There is no federated token, so there is no Secret Manager call.

Only our CI produces the pinned digest, through the GitHub Actions workflow at the exact pinned `job_workflow_ref`. Each partner must repin any new digest in its own CEL, so a different image cannot silently receive keys. (See [what proves the running image came from our source code](#what-proves-the-running-image-came-from-our-source-code).) This is the **consumer (tdx-signer) digest**. The keygen-digest allowlist that used to be the second pinned digest is removed — see [two distinct image digests](#two-distinct-image-digests).

## Will the keys be released to the same image running in a different GCP project?

**Also no.** Each partner's CEL pins `gce_project_id == "<COMPUTE_PROJECT_ID>"`. Google's CS service emits JWTs with that claim only for VMs that actually run in that project. An attacker who built the same image in their own GCP project would carry `gce_project_id == "their-project"`, and STS rejects it at every partner.

## Out of scope — what the pin does not cover

- **Compromise of any single partner's identity.** A partner controls only its own
  share and its own read gate. It can neither reconstruct, which needs ≥ T shares,
  nor release other partners' shares. The T-of-N split is the mitigation, because
  no single identity can reconstruct the signer alone.
- **Collusion of ≥ T partners**, or compromise of ≥ T partners' secrets or read
  gates. An attacker who holds T good shares can reconstruct the signer. The
  mitigation is partner selection: choose partners so that no easily-coordinated
  subset reaches T.
- **Compromise of the workload owner's identity** (`<WORKLOAD_OWNER_EMAIL>`)
  alone. The owner can push a malicious image and try to run it. Each partner
  still has to repin the digest in its own CEL before that image can federate a
  read token, and ≥ T partners must do so before it can reconstruct. The split
  design *requires* the partners to cooperate for new code to reach the keys.

  > **Why this guarantee holds against `compute.instances.setMetadata`.** A naive design that let the workload owner override GCP endpoint URLs through `tee-env-*` metadata (STS, Secret Manager, GCS, the metadata server) would break this property. The owner could set `STS_URL` to a proxy they control, capture the genuine TDX-attested JWTs, and replay them to real STS to mint the partners' federated read tokens, all without any partner repinning a digest. Two deliberate choices close that path. First, the Dockerfile's `tee.launch_policy.allow_env_override` LABEL omits `STS_URL`, `SM_URL`, `GCS_STORAGE_URL`, `METADATA_URL`, and `ATTESTATION_SOCKET`. Second, the binary holds those values as `const`, so it does not read them from the environment at all. The reader's **data source** is immune for the same reason: the partner set, the per-partner WIF audiences, and the public-material location are baked into `cofhe-keys`' env map and selected by the fail-closed `COFHE_ENV`. The old `PARTNERS` / `PUBLIC_BUCKET` / `PUBLIC_OBJECT` overrides are gone, which is also what allowed the keygen-origin allowlist to be dropped (see *Why the keygen-origin allowlist was removed*). Re-evaluate this property before you add any of these back "for flexibility".
- **A malicious code change merged into the legitimate codebase**, then built,
  pushed, and repinned by ≥ T partners. Code review and signed commits cover that,
  and they are out of scope here.
- **The integrity of the keygen's public bucket**, per the trust trade-off above.
  The CRS and FHE public artifacts rest on bucket-write IAM, and the mitigation is
  tight write-IAM on that bucket.

The pin protects "this exact binary in this exact compute project, or nothing". It
does not prove the binary is free of bugs.

## Where the code lives

A short map into the crate. The boot sequence is narrated in *The boot handshake*
above; `src/main.rs` is its source of truth.

- `src/attestation.rs`, `src/gcp_auth.rs` — TDX attestation and per-partner STS
  federation. The Secret Manager client and the Shamir reader live in the embedded
  `cofhe-keys` crate.
- `src/gcs.rs` — the boot-time GCS fetch of the TFHE artifacts.
- `src/envs/` — the baked runtime config, merged in memory at boot.
- `src/main.rs` — the boot sequence, end to end.
- `compute/` — Terraform for the compute-side project: the Confidential VM, the
  firewall, and the runtime SA.
- `keys/` — Terraform for the legacy keys-side project. It is off the boot path and
  retires during the migration.
