# syntax=docker/dockerfile:1.7

# Build stage. The build context must be the repo root because `tdx-signer/`
# path-depends on `../zk-verifier/` and (transitively) `../rust-common/`.
#
#   docker build -f tdx-signer/Dockerfile -t tdx-zk-verifier:test .
FROM rust:1.92-slim-bookworm AS build
RUN rustup toolchain install nightly-2025-10-15

# Build deps: pkg-config + libssl-dev for reqwest's rustls-tls feature chain
# and any -sys crates pulled by the tfhe transitive tree; git so cargo
# (git-fetch-with-cli) can fetch the public cofhe-keys dep at build; cmake for
# aws-lc-sys — the rustls crypto provider cofhe-keys uses for its pinned
# TLS 1.3 + X25519MLKEM768 googleapis egress.
RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev git ca-certificates cmake && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY tdx-signer/  tdx-signer/
COPY zk-verifier/ zk-verifier/
COPY rust-common/ rust-common/

WORKDIR /src/tdx-signer
# cofhe-keys is fetched from the public cofhe-tdx-keygen repo over https — no
# credential needed. git-fetch-with-cli (tdx-signer/.cargo/config.toml) makes
# cargo shell out to git.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/tdx-signer/target \
    CARGO_NET_GIT_FETCH_WITH_CLI=true \
    cargo build --release --locked --bin tdx-signer && \
    cp target/release/tdx-signer /tdx-signer

# Runtime stage. Plain debian-slim — has shell; the CS launcher socket needs
# root, so we deliberately do NOT add a non-root USER.
FROM debian:bookworm-slim
RUN apt-get update && \
    apt-get install -y libssl3 ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /tdx-signer /tdx-signer

# /app/keys is a tmpfs mountpoint at runtime (Confidential Space's tee-mount is
# tmpfs-only — it cannot bind-mount a persistent disk). We leave it empty so the
# build artifact carries no key material; the launcher fetches the TFHE artifacts
# (crs, pk, sk) from the baked public bucket at boot (see src/gcs.rs, src/main.rs).
# The runtime config is NOT fetched or written to disk — it is baked into the binary
# (include_str!) and merged IN MEMORY (zk-verifier config::Builder::from_baked), so
# there is no /app/config anymore.
RUN mkdir -p /app/keys

# Launcher policy: env vars the operator may override via VM metadata. Note
# the STS / SM / GCS / metadata / attestation-socket URLs are NOT in this
# list — they are `const` in the binary so a workload owner with
# `compute.instances.setMetadata` cannot redirect the attested-token exchange
# (or the key/config fetch) to a proxy. COFHE_ENV is the ONLY reader-source input:
# it selects a blessed environment from the map BAKED into cofhe-keys (partner
# set + per-partner WIF audiences + public-material bucket/object + Shamir
# threshold), fail-closed on anything else — so a setMetadata-capable operator
# can pick a blessed env but can never point the reader at partners/buckets they
# control (the old SA_EMAIL/WIP_AUDIENCE/PARTNERS/PUBLIC_BUCKET/PUBLIC_OBJECT and
# SHAMIR_THRESHOLD/CONFIG_BUCKET/PREFIX knobs are gone — the threshold and the
# whole runtime config.toml are baked per-env into the image, and the FHE
# artifacts come from the baked public bucket digest-pinned to the manifest).
# The ZK_SIGNER_SECRET name stays a hardcoded const for the same reason.
# STORE_CTS_ENDPOINT is the one operator-supplied endpoint — the ct-server the
# verifier writes stored cts to (mirrors teecryptor's CT_SOURCE_URL); it is
# injected into the baked config at boot.
# VERIFY_CONCURRENCY / MAX_INFLIGHT only tune the local /verify CPU gate +
# admission cap (see zk-verifier api::AppState) — pure resource-limit knobs, no
# security surface — so they are exposed to let operators size them per machine
# type without rebuilding the image. WITHOUT them here the launcher SILENTLY
# DROPS the tee-env-* metadata and the binary falls back to its built-in
# defaults.
LABEL "tee.launch_policy.allow_env_override"="COFHE_ENV,STORE_CTS_ENDPOINT,RUST_LOG,VERIFY_CONCURRENCY,MAX_INFLIGHT"

# Allow the launcher to mount tmpfs at the legacy /app/keys dir (kept for the
# zk-verifier config's key paths; the FHE artifacts are deserialized in-memory).
# tee-mount only supports tmpfs. The runtime config no longer needs a mount — it is
# baked in-memory, not written to /app/config.
# NOTE: a single path here. If a second is ever added this becomes COLON-separated
# (a comma is parsed as one literal path and every real mount is then rejected).
LABEL "tee.launch_policy.allow_mount_destinations"="/app/keys"

LABEL "tee.launch_policy.log_redirect"="always"

EXPOSE 3001 9090
ENTRYPOINT ["/tdx-signer"]
