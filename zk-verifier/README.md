# ZK-Verifier

## Overview

The ZK-Verifier service verifies ZK proofs for FHE ciphertexts and signs the verified batch.

It stores the verified ciphertexts and proofs in Google Cloud Storage (GCS), so a client can audit and retrieve them later.

This document describes the integration points for client applications. For exact request, response, and byte-level types, follow the pointers into the code — the code owns those shapes.

## API Endpoints

| Endpoint               | Method | Description                                                       |
| ---------------------- | ------ | ----------------------------------------------------------------- |
| `/verifyBatch`         | POST   | Verify proven ciphertexts and return ONE signature covering the batch |
| `/signerAddress`       | GET    | Get the EVM address of the signer                                 |
| `/healthz`             | GET    | Liveness probe                                                    |
| `/GetNetworkPublicKey` | GET    | Get encryption public key _(mock-keys builds only)_              |
| `/crs`                 | GET    | Get common reference string _(mock-keys builds only)_           |
| `/metrics`             | GET    | Metrics exposition on the metrics port (see [Metrics](#metrics)) |

The routes are defined in `zk-verifier/src/api/mod.rs` (`create_router`).

## Client Integration

### Request

`POST /verifyBatch` verifies a whole `ProvenCompactCiphertextList` and returns one signature covering the batch. It is the only verification endpoint.

The request fields are defined by `VerifyRequest` in `zk-verifier/src/api/mod.rs`.

Two contracts a client must honor:

- `contract_address` is **required**. The service binds it into every signed message. A verified input cannot be replayed into a different contract.
- The service rejects a `packed_list` with **zero ciphertexts** with `400`. A batch of zero has no digest to commit to. Folding zero hashes yields the constant `keccak256("")`, so a signature over it would say nothing about the account, the chain, or the request.

When you build the `ProvenCompactCiphertextList`, construct its metadata bytes in this order:

```
[security_zone (1 byte)][account_addr (bytes)][chain_id (32 bytes, big-endian)]
```

### Response

The success and error shapes are defined by `BatchVerifyResponse` and `CiphertextResponse` in `zk-verifier/src/api/mod.rs`.

Three contracts a client must honor:

- `data` is an **object** with one signature for the whole batch. It is not an array of per-ciphertext signatures.
- The `ciphertexts` array follows submission order. Index `i` maps to ciphertext `i` in the submitted `packed_list`. That order is load-bearing, because the digest folds `hash_i` in this exact sequence.
- Each entry carries `ct_hash` and `ct_type` only. The response does not echo `security_zone`, `account_addr`, `chain_id`, or `contract_address`. Take those from the request you sent.

The `signature` is the 64-byte `r || s` in hex. `recid` is the recovery id (`0–3`). Append `recid` as the 65th byte for the EVM `r || s || v` form.

### The signed digest

The service creates ONE signature over the whole batch. The digest is a hash of hashes: one keccak256 commitment per ciphertext, folded by a second keccak256 in `ciphertexts` order.

The exact pre-image byte layout of each `hash_i`, and the fold that produces the batch digest, live in `zk-verifier/src/signer/ecdsa.rs` (`ct_message_hash` and `sign_batch`). The field encoding rules (integers big-endian, bytes and strings raw) live in `rust-common/src/signing/message_builder.rs`.

Three properties follow from that layout:

- **Order matters.** A different `hash_i` order produces a different digest, which is invalid.
- **`ct_type` is part of the pre-image.** The response gives it per ciphertext.
- **The contract binding needs no batch-level field.** `contract_address` sits inside every `hash_i`, so the batch digest inherits it. The same ciphertexts bound to a different contract produce a different digest, and the signature does not recover.

`ct_hash_i` is `keccak256(ct_bytes_i)` of the raw **compressed** ciphertext bytes. It is the same value returned in `ciphertexts[i].ct_hash`, and it is what gets signed.

### Verifying the signature

1. Get the signer's EVM address from `/signerAddress`.
2. Rebuild each `hash_i` from the request fields and the returned `ciphertexts` (layout in `src/signer/ecdsa.rs`).
3. Fold the hashes, in `ciphertexts` order, into the batch digest.
4. Recover the signer from the batch digest, the signature, and `recid`.
5. Confirm the recovered address matches the signer address.

One signature covers the whole batch, so it verifies all-or-nothing. To prove a single ciphertext's inclusion, you need the full ordered `ciphertexts` set.

**recid and `ecrecover`.** Ethereum's `ecrecover` expects `v = 27` or `28`, but the API returns `recid` as `0–3`. Add `27` either on the client before you submit to a contract, or inside the contract if you pass the raw `recid`.

## Storage

With external storage on, the service stores each verified ciphertext and its proof in GCS, so a client can audit them later.

- The object-path layout (`cofhe/v{n}/chain/…/security-zone/…`) is built in `zk-verifier/src/storage/storage_manager.rs`.
- The stored object formats (`StoredCiphertext`, `StoredProof`, and their metadata) are defined in `zk-verifier/src/storage/types.rs`.
- The stored ciphertext hash embeds metadata in bytes 30–31 (ct type plus a trivially-encrypted flag, then security zone). That adjustment is `adjust_hash_for_metadata` in `zk-verifier/src/api/mod.rs`.

The `StoreCts` request shape is defined by `StoreCtsRequest` in `zk-verifier/src/api/mod.rs`.

## Behavior notes

- Signature verification uses the EVM ECDSA scheme (secp256k1 with keccak256).
- The service runs the external writes in parallel: the `StoreCts` call and the GCS writes. Any failure fails the whole request, and the client must retry.
- Writes retry with exponential backoff.
- A partial failure can orphan objects. If the `StoreCts` call fails after the GCS writes succeed, those GCS objects remain. The client gets an error and should retry.

## Metrics

The metric names, types, and buckets are defined in `zk-verifier/src/api/mod.rs`.

Serving depends on the metrics mode (see `zk-verifier/src/config.rs`):

- `prometheus`: the metrics port serves the text exposition.
- `otlp` (production): the series push to the configured OTLP endpoint, and the port stays reachable over an IAP tunnel as a debug surface for a failed push.

`/verifyBatch` is the only verification endpoint, so `zk_verify_batch_size_ciphertexts` holds the full distribution of real batch sizes. A single-input encrypt is a batch of one.

Its buckets sit around the on-chain break-even for `TaskManager`'s `InputVerified` event shape. Up to 3 inputs, one event per input is cheaper. From 4 up, a single array-valued event wins. This query gives the share of traffic that would be cheaper under the array shape:

```promql
1 - (
  sum(rate(zk_verify_batch_size_ciphertexts_bucket{le="3"}[1h]))
  /
  sum(rate(zk_verify_batch_size_ciphertexts_count[1h]))
)
```

## Verification script

A standalone script audits a stored ciphertext against its stored proof:

```bash
cargo run --bin verify-stored-ct <adjusted_ct_hash> <chain_id>
```

It fetches the ciphertext and proof from GCS, verifies the ZK proof with TFHE.rs, and confirms the hash matches the stored metadata. The steps live in `zk-verifier/scripts/verify_stored_ct.rs`.

## Running locally

```bash
docker run -p 3001:3001 \
  -e RUST_LOG=trace \
  -v ./config/local:/app/config \
  -v ./keys:/app/keys \
  ghcr.io/fhenixprotocol/zk-verifier:<tag>
```

## Configuration

The service reads configuration from environment variables (highest priority), then a `config.toml` file, then built-in defaults.

- The config schema, the env-var names and their mapping, and the defaults are defined in `zk-verifier/src/config.rs`.
- A worked local-dev `config.toml` lives at `config/local/config.toml`.
- The production config is baked into the image per env — see `tdx-signer/src/envs/`.

The required key files (`crs`, FHE public key, FHE server key, and the signer's private signing key) are listed in `KeyConfig` in `zk-verifier/src/config.rs`. Keep the signer key readable only by the service.
