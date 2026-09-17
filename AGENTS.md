# AGENTS.md

zee-k-verifier is a TDX-attested deployment of CoFHE's zk-verifier. A binary in
`tdx-signer/` boots inside an Intel TDX Confidential Space VM, attests,
reconstructs its signing key from multi-partner Shamir shares, and serves the
verification API.

Start here:

- `README.md` — orientation and local-dev quickstart.
- `tdx-signer/SECURITY-OVERVIEW.md` — the trust model, custody split, boot handshake.
- `zk-verifier/README.md` — the client API and the signed batch-digest.

Layout:

- `tdx-signer/` — the binary that runs in the Confidential VM (attestation, token
  exchange, Secret Manager client, the launcher that delegates HTTP to zk-verifier).
- `zk-verifier/` — hybrid crate: a library consumed by `tdx-signer`, plus a thin
  local-dev binary.
- `rust-common/` — shared logger, signing primitives, and a safe-serde wrapper.

The three crates are independent, with no top-level workspace. The toolchain is
pinned in `rust-toolchain.toml`.

Build and test, per crate: `cargo fmt --check`, `cargo clippy --no-deps -- -D warnings`,
`cargo build --release`, `cargo test`. Local dev: `docker compose up zk-verifier`
(verifier on `:3001`, metrics on `:9090`). The TDX boot path is not exercised locally.

Writing docs and comments: active voice, present tense, one idea per sentence,
simple words. State facts and their mitigations, not warnings. Never claim an
audit that has not happened.
