//! End-to-end smoke test + on-chain value generator for `POST /verifyBatch`.
//!
//! Generates a valid `ProvenCompactCiphertextList` against the *deployed* TFHE
//! keys (the fixed dev keys), sends it to a running zk-verifier, then:
//!   1. checks the single batch signature recovers to the verifier's signer, and
//!   2. prints the exact values to pass to the on-chain
//!      `TaskManager.batchVerifyInputs(BatchedEncryptedInput[] inputs, address sender, bytes signature)`
//!      where `BatchedEncryptedInput` is `(uint256 ctHash, uint8 securityZone, uint8 utype)`.
//!
//! The signed digest is reconstructed here the same way the verifier
//! (`signer/ecdsa.rs`) and the contract (`TaskManager.inputMessageHash`) do it:
//!   h_i   = keccak256(ct_hash_i || ct_type_i || security_zone || account
//!                     || chain_id_padded || contract)
//!   batch = keccak256(h_0 || h_1 || ... || h_n)
//! so a green run here means the same recovery will succeed in Solidity. Note
//! `contract` is the consuming contract (`--contract`): the batch signature only
//! recovers when that contract is the one calling `batchVerifyInputs`.
//!
//! Usage (host, against the compose-published port):
//!   cargo run --release --bin smoke-verify-batch -- \
//!     --url http://localhost:3001 \
//!     --crs ../../cofhe/deployments/keys/dev/crs \
//!     --pk  ../../cofhe/deployments/keys/dev/public_key \
//!     --account 0x1111111111111111111111111111111111111111 \
//!     --contract 0x2222222222222222222222222222222222222222 \
//!     --security-zone 0 --chain-id 11155111 --values 42,7
//!
//! Note: the endpoint persists the verified cts (store-cts + external storage)
//! before returning success, so ct-server and fake-gcs-server must be healthy.

use std::error::Error;

use clap::Parser;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use tfhe::zk::{CompactPkeCrs, ZkComputeLoad};
use tfhe::{CompactPublicKey, ProvenCompactCiphertextList};

/// EVM `v = recid + 27` (matches rust_common SignatureVFormat::Evm / OZ ECDSA.recover).
const EVM_V_OFFSET: u8 = 27;

#[derive(Parser, Debug)]
#[command(about = "Generate a proven CT list, hit /verifyBatch, emit on-chain values")]
struct Args {
    /// Base URL of the running zk-verifier.
    #[arg(long, default_value = "http://localhost:3001")]
    url: String,
    /// Path to the CRS the verifier loaded (must match, or the proof is rejected).
    #[arg(long, default_value = "../../cofhe/deployments/keys/dev/crs")]
    crs: String,
    /// Path to the compact public key the verifier loaded.
    #[arg(long, default_value = "../../cofhe/deployments/keys/dev/public_key")]
    pk: String,
    /// Account the inputs are bound to (the `sender` on-chain). 20-byte 0x address.
    #[arg(long, default_value = "0x1111111111111111111111111111111111111111")]
    account: String,
    /// Contract the inputs may be consumed by, bound into every per-ct message
    /// hash. Must be the contract that will call `batchVerifyInputs`, or the
    /// on-chain signer recovery fails. 20-byte 0x address.
    #[arg(long, default_value = "0x2222222222222222222222222222222222222222")]
    contract: String,
    /// Security zone.
    #[arg(long, default_value_t = 0)]
    security_zone: u8,
    /// Chain id.
    #[arg(long, default_value_t = 11155111)]
    chain_id: u32,
    /// Clear values to encrypt into the batch (comma-separated).
    #[arg(long, value_delimiter = ',', default_value = "42,7")]
    values: Vec<u64>,
    /// FHE type to encrypt the values as: uint8|uint16|uint32|uint64|uint128.
    #[arg(long = "type", default_value = "uint64")]
    fhe_type: String,
    /// Machine mode: send all progress/diagnostics to stderr and print ONLY the
    /// on-chain args JSON (sender, signature, inputs) to stdout. For scripting.
    #[arg(long)]
    json: bool,
}

/// keccak256 of raw-concatenated inputs — mirrors both the signer's
/// SigningMessageBuilder and the contract's abi.encodePacked.
fn per_ct_message_hash(
    ct_hash: &[u8],
    ct_type: u8,
    security_zone: u8,
    account: &[u8],
    chain_id: u32,
    contract: &[u8],
) -> [u8; 32] {
    let mut chain_id_padded = [0u8; 32];
    chain_id_padded[28..].copy_from_slice(&chain_id.to_be_bytes());

    let mut buf = Vec::new();
    buf.extend_from_slice(ct_hash); // 32
    buf.push(ct_type); // 1
    buf.push(security_zone); // 1
    buf.extend_from_slice(account); // 20
    buf.extend_from_slice(&chain_id_padded); // 32
    buf.extend_from_slice(contract); // 20 — the consuming contract, appended last
    Keccak256::digest(&buf).into()
}

/// The metadata the ZK proof is bound to (verifier::reconstruct_metadata):
/// security_zone || account || chain_id_padded.
fn reconstruct_metadata(account: &[u8], security_zone: u8, chain_id: u32) -> Vec<u8> {
    let mut chain_id_padded = [0u8; 32];
    chain_id_padded[28..].copy_from_slice(&chain_id.to_be_bytes());

    let mut m = Vec::new();
    m.push(security_zone);
    m.extend_from_slice(account);
    m.extend_from_slice(&chain_id_padded);
    m
}

/// Recover the 20-byte EVM address that signed `digest`.
fn recover_evm_address(
    digest: &[u8; 32],
    rs: &[u8],
    recid: u8,
) -> Result<[u8; 20], Box<dyn Error>> {
    let sig = Signature::from_slice(rs)?;
    let recid = RecoveryId::from_byte(recid).ok_or("invalid recovery id")?;
    let vk = VerifyingKey::recover_from_prehash(digest, &sig, recid)?;
    let point = vk.to_encoded_point(false);
    let pubkey = &point.as_bytes()[1..]; // drop 0x04, keep X||Y (64 bytes)
    let hash = Keccak256::digest(pubkey);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    Ok(addr)
}

fn strip0x(s: &str) -> &str {
    s.strip_prefix("0x").unwrap_or(s)
}

fn load<T>(path: &str, what: &str) -> Result<T, Box<dyn Error>>
where
    T: serde::de::DeserializeOwned + tfhe_versionable::Unversionize + tfhe::named::Named,
{
    let bytes = std::fs::read(path).map_err(|e| format!("reading {what} '{path}': {e}"))?;
    rust_common::safe_serde::deserialize(&bytes)
        .map_err(|e| format!("deserializing {what} '{path}': {e}").into())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let account_bytes = hex::decode(strip0x(&args.account))?;
    if account_bytes.len() != 20 {
        return Err(format!("account must be 20 bytes, got {}", account_bytes.len()).into());
    }
    let contract_bytes = hex::decode(strip0x(&args.contract))?;
    if contract_bytes.len() != 20 {
        return Err(format!("contract must be 20 bytes, got {}", contract_bytes.len()).into());
    }
    if args.values.is_empty() {
        return Err("need at least one --values entry".into());
    }

    eprintln!("Loading CRS + public key (must match the verifier's)...");
    let crs: CompactPkeCrs = load(&args.crs, "CRS")?;
    let pk: CompactPublicKey = load(&args.pk, "public key")?;

    eprintln!("Building proven CT list for values {:?} as {}...", args.values, args.fhe_type);
    let metadata = reconstruct_metadata(&account_bytes, args.security_zone, args.chain_id);
    let mut builder = ProvenCompactCiphertextList::builder(&pk);
    for &v in &args.values {
        // Push each value as the requested FHE type; the concrete Rust type
        // determines the ct_type the verifier reports (and signs over).
        match args.fhe_type.as_str() {
            "uint8" => builder.push(v as u8),
            "uint16" => builder.push(v as u16),
            "uint32" => builder.push(v as u32),
            "uint64" => builder.push(v),
            "uint128" => builder.push(v as u128),
            other => return Err(format!("unsupported --type '{other}'").into()),
        };
    }
    let proven = builder
        .build_with_proof_packed(&crs, &metadata, ZkComputeLoad::Verify)
        .map_err(|e| format!("build_with_proof_packed failed: {e:?}"))?;
    let packed_hex = hex::encode(
        rust_common::safe_serde::serialize(&proven)
            .map_err(|e| format!("serialize proven list: {e}"))?,
    );

    let body = json!({
        "packed_list": packed_hex,
        "account_addr": args.account,
        "security_zone": args.security_zone,
        "chain_id": args.chain_id,
        "contract_address": args.contract,
    });

    let client = reqwest::Client::new();

    // Signer address the batch signature must recover to.
    let signer_addr: Value =
        client.get(format!("{}/signerAddress", args.url)).send().await?.json().await?;
    let expected_signer =
        signer_addr["address"].as_str().ok_or("no signer address in response")?.to_lowercase();

    eprintln!("POST {}/verifyBatch ...", args.url);
    let resp = client.post(format!("{}/verifyBatch", args.url)).json(&body).send().await?;
    let status = resp.status();
    let batch: Value = resp.json().await?;
    if batch["status"] != "success" {
        return Err(format!("verifyBatch returned {status}: {batch}").into());
    }

    let data = &batch["data"];
    let sig_hex = data["signature"].as_str().ok_or("no signature")?;
    let recid = data["recid"].as_u64().ok_or("no recid")? as u8;
    let rs = hex::decode(strip0x(sig_hex))?;
    if rs.len() != 64 {
        return Err(format!("expected 64-byte r||s, got {}", rs.len()).into());
    }

    let ciphertexts = data["ciphertexts"].as_array().ok_or("no ciphertexts")?;

    // Reconstruct the batch digest exactly like the signer + contract do.
    let mut concat = Vec::new();
    let mut onchain_inputs = Vec::new();
    let mut cast_tuples = Vec::new();
    for out in ciphertexts {
        let ct_hash_hex = out["ct_hash"].as_str().ok_or("ciphertext missing ct_hash")?;
        let ct_type = out["ct_type"].as_u64().ok_or("ciphertext missing ct_type")? as u8;
        let ct_hash = hex::decode(strip0x(ct_hash_hex))?;
        concat.extend_from_slice(&per_ct_message_hash(
            &ct_hash,
            ct_type,
            args.security_zone,
            &account_bytes,
            args.chain_id,
            &contract_bytes,
        ));
        // BatchedEncryptedInput = (uint256 ctHash, uint8 securityZone, uint8 utype).
        onchain_inputs.push(json!({
            "ctHash": ct_hash_hex,
            "securityZone": args.security_zone,
            "utype": ct_type,
        }));
        cast_tuples.push(format!("({ct_hash_hex},{},{ct_type})", args.security_zone));
    }
    let batch_digest: [u8; 32] = Keccak256::digest(&concat).into();

    // Verify the signature recovers to the verifier's signer.
    let recovered = recover_evm_address(&batch_digest, &rs, recid)?;
    let recovered_hex = format!("0x{}", hex::encode(recovered));
    let ok = recovered_hex == expected_signer;

    // EVM-format 65-byte signature: r || s || v  (v = recid + 27).
    let mut evm_sig = rs.clone();
    evm_sig.push(recid + EVM_V_OFFSET);
    let evm_sig_hex = format!("0x{}", hex::encode(&evm_sig));

    let onchain = json!({
        "_call": "TaskManager.batchVerifyInputs(inputs, sender, signature)",
        "sender": args.account,
        // Not an argument to batchVerifyInputs — the signature only recovers when
        // the CALLING contract is this address, since it is bound into every hash.
        "_caller_must_be": args.contract,
        "signature": evm_sig_hex,     // 65-byte r||s||v
        "inputs": onchain_inputs,
    });

    if args.json {
        // Machine mode: diagnostics to stderr, ONLY the JSON to stdout.
        eprintln!(
            "ciphertexts={} digest=0x{} signer={recovered_hex} valid={ok}",
            ciphertexts.len(),
            hex::encode(batch_digest)
        );
        println!("{}", serde_json::to_string(&onchain)?);
    } else {
        println!("\n──────── result ────────");
        println!("ciphertexts:        {}", ciphertexts.len());
        println!("bound to contract:  {}", args.contract);
        println!("batch digest:       0x{}", hex::encode(batch_digest));
        println!("expected signer:    {expected_signer}");
        println!("recovered signer:   {recovered_hex}");
        println!("signature valid:    {}", if ok { "✅ YES" } else { "❌ NO" });

        println!("\n──────── on-chain args (batchVerifyInputs) ────────");
        println!("{}", serde_json::to_string_pretty(&onchain)?);

        // Copy-paste cast argument (BatchedEncryptedInput[] = (uint256,uint8,uint8)[]).
        println!("\n──────── cast (dry-run) ────────");
        println!(
            "cast call <TASK_MANAGER> \\\n  \
             \"batchVerifyInputs((uint256,uint8,uint8)[],address,bytes)(uint256[])\" \\\n  \
             \"[{}]\" \\\n  {} \\\n  {} \\\n  --rpc-url <RPC>",
            cast_tuples.join(","),
            args.account,
            evm_sig_hex,
        );
    }

    if !ok {
        return Err("recovered signer does not match /signerAddress".into());
    }
    Ok(())
}
