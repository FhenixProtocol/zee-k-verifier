//! Derive the signer public key from a private signing key.
//!
//! Operator tool: reads a 32-byte secp256k1 private key (the `signer_pk` raw
//! scalar, as pushed to Secret Manager) and writes its compressed-SEC1 public
//! key (33 bytes) — the `signer_public_key` artifact that gets uploaded to the
//! GCS bucket next to the TFHE keys. zk-verifier checks the two match at boot.
//!
//! Usage:
//!   derive-signer-pubkey <private_key_path> <output_pubkey_path>

use std::process;

use k256::ecdsa::SigningKey;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: {} <private_key_path> <output_pubkey_path>", args[0]);
        process::exit(2);
    }
    let (priv_path, out_path) = (&args[1], &args[2]);

    let priv_bytes = std::fs::read(priv_path).unwrap_or_else(|e| {
        eprintln!("error: reading private key '{priv_path}': {e}");
        process::exit(1);
    });

    let signing_key = SigningKey::from_slice(&priv_bytes).unwrap_or_else(|e| {
        eprintln!("error: '{priv_path}' is not a valid 32-byte secp256k1 key: {e}");
        process::exit(1);
    });

    // Compressed-SEC1 is what the boot-time gate parses and compares against.
    let pubkey = signing_key.verifying_key().to_encoded_point(true).as_bytes().to_vec();

    std::fs::write(out_path, &pubkey).unwrap_or_else(|e| {
        eprintln!("error: writing pubkey '{out_path}': {e}");
        process::exit(1);
    });

    println!("wrote {} bytes (compressed-SEC1 public key) to {out_path}", pubkey.len());
}
