//! stress-verify — local load generator for the `/verifyBatch` concurrency
//! hardening.
//!
//! Off-the-shelf load tools can't exercise `/verifyBatch` because every request needs
//! a real, fully-proven `ProvenCompactCiphertextList` bound to the verifier's own
//! CRS + public key + metadata. This tool closes that gap:
//!
//!   1. `gen-keys` — generate a matched TFHE keyset (crs / pk / sk) plus a
//!      secp256k1 signer key, written in the exact on-disk format the server
//!      loads (see `zk_verifier::load_tfhe_artifacts`). Point the server at the
//!      output dir and it boots with these keys.
//!   2. `mint` — mint N valid `/verifyBatch` request bodies against that keyset. Each
//!      body carries a distinct `account_addr` (distinct ct_hash) so a
//!      storage-enabled server stores to unique keys; a storage-compiled-out
//!      (`--no-default-features`) server just returns 200.
//!   3. `run` — drive concurrent load at a running verifier, reporting latency
//!      percentiles, a status histogram (200 / 503 / 5xx), an optional
//!      `/signerAddress` responsiveness probe (the runtime-starvation canary),
//!      and a `/metrics` diff (`zk_verify_admission_rejected_total`,
//!      `zk_verify_in_flight`).
//!
//! Build with `--no-default-features` so storage + store-cts are compiled out and
//! valid proofs return 200 with no external services.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use k256::ecdsa::SigningKey;
use rand::RngCore;
use tfhe::zk::{CompactPkeCrs, ZkComputeLoad};
use tfhe::{ClientKey, CompactPublicKey, CompressedServerKey, ProvenCompactCiphertextList};
use zk_verifier::Verifier;

#[derive(Parser)]
#[command(
    name = "stress-verify",
    about = "Local load generator for the /verifyBatch concurrency hardening"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a matched TFHE keyset + signer key into <out>/ (crs, pk, sk,
    /// signer_pk, signer_public_key) — the exact names + format the server loads.
    GenKeys {
        /// Output directory (created if missing). Run the server from here.
        #[arg(long, default_value = "./keys")]
        out: PathBuf,
        /// CRS max message capacity. Two u64 ciphertexts need >= 64; larger is
        /// slower to mint. Default 256 leaves headroom.
        #[arg(long, default_value_t = 256)]
        crs_max_messages: usize,
    },
    /// Mint N valid /verifyBatch request bodies against the keyset in <keys>/.
    Mint {
        /// Directory holding crs + pk (from `gen-keys`).
        #[arg(long, default_value = "./keys")]
        keys: PathBuf,
        /// Number of distinct payloads to mint.
        #[arg(long, default_value_t = 8)]
        count: usize,
        /// Output corpus file (JSON array of request-body strings).
        #[arg(long, default_value = "./corpus.json")]
        out: PathBuf,
        #[arg(long, default_value_t = 1)]
        security_zone: u8,
        #[arg(long, default_value_t = 11155111)]
        chain_id: u32,
    },
    /// Drive concurrent load at a running verifier and report results.
    Run {
        /// Base URL of the verify API (e.g. http://127.0.0.1:3001).
        #[arg(long, default_value = "http://127.0.0.1:3001")]
        url: String,
        /// Metrics base URL (e.g. http://127.0.0.1:9090). Omit to skip the diff.
        #[arg(long)]
        metrics_url: Option<String>,
        /// Corpus file from `mint`.
        #[arg(long, default_value = "./corpus.json")]
        corpus: PathBuf,
        /// Number of concurrent in-flight requests.
        #[arg(long, default_value_t = 32)]
        concurrency: usize,
        /// Total number of requests to send.
        #[arg(long, default_value_t = 200)]
        requests: usize,
        /// Also poll /signerAddress every 100ms during the load (starvation canary).
        #[arg(long, default_value_t = false)]
        probe: bool,
    },
}

fn tfhe_config() -> tfhe::Config {
    // Identical to verifier::Verifier::{PARAMS,CPK_PARAMS,CASTING_PARAMS} (which
    // are mock-keys-gated, so not reachable in a --no-default-features build).
    // The server verifies against the crs+pk we ship, so what matters is that
    // crs / pk / sk / proof are all built from this one config.
    use tfhe::shortint::parameters;
    let params = parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    let cpk_params = parameters::v0_11::compact_public_key_only::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    let casting_params = parameters::v0_11::key_switching::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    tfhe::ConfigBuilder::with_custom_parameters(params)
        .use_dedicated_compact_public_key_parameters((cpk_params, casting_params))
        .build()
}

fn read_versioned<T>(path: &Path) -> T
where
    T: serde::de::DeserializeOwned + tfhe::Unversionize + tfhe::named::Named,
{
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    rust_common::safe_serde::deserialize(&bytes)
        .unwrap_or_else(|e| panic!("deserialize {}: {e}", path.display()))
}

fn write_versioned<T>(path: &Path, value: &T)
where
    T: serde::Serialize + tfhe::Versionize + tfhe::named::Named,
{
    let bytes = rust_common::safe_serde::serialize(value)
        .unwrap_or_else(|e| panic!("serialize {}: {e}", path.display()));
    std::fs::write(path, bytes).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}

fn gen_keys(out: &Path, crs_max_messages: usize) {
    std::fs::create_dir_all(out).expect("create out dir");
    let config = tfhe_config();

    eprintln!("generating CRS (max_messages={crs_max_messages}) ...");
    let crs = CompactPkeCrs::from_config(config, crs_max_messages).expect("build CRS");
    let client_key = ClientKey::generate(config);
    let pk = CompactPublicKey::try_new(&client_key).expect("build public key");
    eprintln!("compressing server key ...");
    let sk = CompressedServerKey::new(&client_key);

    write_versioned(&out.join("crs"), &crs);
    write_versioned(&out.join("pk"), &pk);
    write_versioned(&out.join("sk"), &sk);

    // Signer: raw 32-byte scalar + compressed-SEC1 pubkey, matching the server's
    // boot-time signer_pk / signer_public_key check.
    let signing_key = SigningKey::random(&mut rand::thread_rng());
    std::fs::write(out.join("signer_pk"), signing_key.to_bytes()).expect("write signer_pk");
    let pubkey = signing_key.verifying_key().to_encoded_point(true).as_bytes().to_vec();
    std::fs::write(out.join("signer_public_key"), &pubkey).expect("write signer_public_key");

    println!("wrote keyset to {}", out.display());
    println!("  crs / pk / sk / signer_pk / signer_public_key");
    println!();
    println!("run the server against it (storage compiled out):");
    println!(
        "  (cd {} && VERIFY_CONCURRENCY=<n> MAX_INFLIGHT=<n> RUST_LOG=info \\\n     \
         CONFIG_PATH=/dev/null <path-to>/zk-verifier)",
        out.display()
    );
}

fn mint(keys: &Path, count: usize, out: &Path, security_zone: u8, chain_id: u32) {
    let crs: CompactPkeCrs = read_versioned(&keys.join("crs"));
    let pk: CompactPublicKey = read_versioned(&keys.join("pk"));

    let mut bodies = Vec::with_capacity(count);
    for i in 0..count {
        // Distinct 20-byte account address per payload -> distinct metadata + ct_hash.
        let account_addr = format!("0x{:040x}", i + 1);
        bodies.push(mint_body(&pk, &crs, &account_addr, security_zone, chain_id));
        eprintln!("minted {}/{}", i + 1, count);
    }

    std::fs::write(out, serde_json::to_string(&bodies).expect("serialize corpus"))
        .expect("write corpus");
    println!("wrote {} payloads to {}", bodies.len(), out.display());
}

/// Placeholder consuming contract for minted load-test payloads. The signatures
/// are never recovered on-chain here, so the value only has to be a valid 20-byte
/// address.
const STRESS_CONTRACT_ADDR: &str = "0x2222222222222222222222222222222222222222";

fn mint_body(
    pk: &CompactPublicKey,
    crs: &CompactPkeCrs,
    account_addr: &str,
    security_zone: u8,
    chain_id: u32,
) -> String {
    let account_addr_bytes =
        hex::decode(account_addr.strip_prefix("0x").unwrap_or(account_addr)).expect("hex addr");
    // Identical binding to what the verifier reconstructs on the server side.
    let metadata = Verifier::reconstruct_metadata(&account_addr_bytes, security_zone, chain_id);

    let mut rng = rand::thread_rng();
    let proven = ProvenCompactCiphertextList::builder(pk)
        .push(rng.next_u64())
        .push(rng.next_u64())
        .build_with_proof_packed(crs, &metadata, ZkComputeLoad::Verify)
        .expect("build proof");

    let packed_hex =
        hex::encode(rust_common::safe_serde::serialize(&proven).expect("serialize proof"));
    // `contract_address` is required — the consuming contract is bound into every
    // signed message. Any address works for load generation: it only has to be
    // present and 20 bytes, since nothing here recovers the signature on-chain.
    format!(
        r#"{{"packed_list":"{}","account_addr":"{}","security_zone":{},"chain_id":{},"contract_address":"{}"}}"#,
        packed_hex, account_addr, security_zone, chain_id, STRESS_CONTRACT_ADDR
    )
}

async fn run(
    url: String,
    metrics_url: Option<String>,
    corpus_path: PathBuf,
    concurrency: usize,
    requests: usize,
    probe: bool,
) {
    let corpus: Vec<String> =
        serde_json::from_str(&std::fs::read_to_string(&corpus_path).expect("read corpus"))
            .expect("parse corpus");
    assert!(!corpus.is_empty(), "corpus is empty");
    let corpus = Arc::new(corpus);

    let client = Arc::new(
        reqwest::Client::builder()
            .timeout(Duration::from_secs(300))
            .pool_max_idle_per_host(concurrency)
            .build()
            .expect("build http client"),
    );
    let verify_url = Arc::new(format!("{}/verifyBatch", url.trim_end_matches('/')));
    let signer_url = format!("{}/signerAddress", url.trim_end_matches('/'));

    // Live self-check: one request must succeed before we trust the results.
    match client
        .post(verify_url.as_str())
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(corpus[0].clone())
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => eprintln!("self-check: /verifyBatch returned 200 ✓"),
        Ok(r) => {
            let s = r.status();
            let t = r.text().await.unwrap_or_default();
            panic!(
                "self-check FAILED: /verifyBatch returned {s}: {t}\n(keyset/proof mismatch — \
                 regenerate keys + corpus, and confirm the server loaded THIS keyset)"
            );
        }
        Err(e) => panic!("self-check FAILED: could not reach {verify_url}: {e}"),
    }

    // Metrics snapshot before.
    let before = match &metrics_url {
        Some(m) => scrape(&client, m).await,
        None => None,
    };

    // /signerAddress starvation probe.
    let stop = Arc::new(AtomicBool::new(false));
    let probe_handle = if probe {
        let client = client.clone();
        let stop = stop.clone();
        Some(tokio::spawn(async move {
            let mut samples: Vec<(u128, u16)> = Vec::new();
            while !stop.load(Ordering::Relaxed) {
                let t = Instant::now();
                let status = match client.get(&signer_url).send().await {
                    Ok(r) => {
                        let s = r.status().as_u16();
                        let _ = r.bytes().await;
                        s
                    }
                    Err(_) => 0,
                };
                samples.push((t.elapsed().as_millis(), status));
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            samples
        }))
    } else {
        None
    };

    // Load: `concurrency` workers pull from a shared counter until `requests` sent.
    let counter = Arc::new(AtomicUsize::new(0));
    let wall = Instant::now();
    let mut workers = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let client = client.clone();
        let verify_url = verify_url.clone();
        let corpus = corpus.clone();
        let counter = counter.clone();
        workers.push(tokio::spawn(async move {
            let mut out: Vec<(u128, u16)> = Vec::new();
            loop {
                let i = counter.fetch_add(1, Ordering::Relaxed);
                if i >= requests {
                    break;
                }
                let body = corpus[i % corpus.len()].clone();
                let t = Instant::now();
                let status = match client
                    .post(verify_url.as_str())
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(body)
                    .send()
                    .await
                {
                    Ok(r) => {
                        let s = r.status().as_u16();
                        let _ = r.bytes().await; // drain so the connection is reusable
                        s
                    }
                    Err(_) => 0,
                };
                out.push((t.elapsed().as_millis(), status));
            }
            out
        }));
    }

    let mut results: Vec<(u128, u16)> = Vec::with_capacity(requests);
    for w in workers {
        results.extend(w.await.expect("worker panicked"));
    }
    let elapsed = wall.elapsed();

    stop.store(true, Ordering::Relaxed);
    let probe_samples = match probe_handle {
        Some(h) => h.await.expect("probe panicked"),
        None => Vec::new(),
    };

    let after = match &metrics_url {
        Some(m) => scrape(&client, m).await,
        None => None,
    };

    report(&results, elapsed, concurrency, &probe_samples, before, after);
}

async fn scrape(client: &reqwest::Client, metrics_url: &str) -> Option<String> {
    let url = format!("{}/metrics", metrics_url.trim_end_matches('/'));
    match client.get(&url).send().await {
        Ok(r) => r.text().await.ok(),
        Err(_) => None,
    }
}

fn scrape_metric(body: &str, name: &str) -> Option<f64> {
    for line in body.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix(name) {
            if rest.starts_with('{') || rest.starts_with(' ') {
                if let Some(tok) = line.rsplit(' ').next() {
                    if let Ok(v) = tok.parse::<f64>() {
                        return Some(v);
                    }
                }
            }
        }
    }
    None
}

fn percentile(sorted: &[u128], p: f64) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((p / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn report(
    results: &[(u128, u16)],
    elapsed: Duration,
    concurrency: usize,
    probe: &[(u128, u16)],
    before: Option<String>,
    after: Option<String>,
) {
    let total = results.len();
    let secs = elapsed.as_secs_f64();

    // Status histogram.
    let mut statuses: std::collections::BTreeMap<u16, usize> = std::collections::BTreeMap::new();
    for (_, s) in results {
        *statuses.entry(*s).or_insert(0) += 1;
    }

    // Latency percentiles: overall, and 200-only (503 sheds are fast and skew it).
    let mut all: Vec<u128> = results.iter().map(|(l, _)| *l).collect();
    all.sort_unstable();
    let mut ok: Vec<u128> = results.iter().filter(|(_, s)| *s == 200).map(|(l, _)| *l).collect();
    ok.sort_unstable();

    println!("\n══════════════════════ stress-verify results ══════════════════════");
    println!("requests        : {total}");
    println!("concurrency     : {concurrency}");
    println!("wall time       : {:.2}s", secs);
    println!("throughput      : {:.1} req/s", total as f64 / secs);
    println!();
    println!("status histogram:");
    for (s, n) in &statuses {
        let label = match s {
            0 => "conn-error".to_string(),
            code => code.to_string(),
        };
        println!("  {label:>10} : {n}");
    }
    println!();
    println!("latency (ms)    :   all         200-only");
    println!("  p50           : {:>6}      {:>6}", percentile(&all, 50.0), percentile(&ok, 50.0));
    println!("  p90           : {:>6}      {:>6}", percentile(&all, 90.0), percentile(&ok, 90.0));
    println!("  p99           : {:>6}      {:>6}", percentile(&all, 99.0), percentile(&ok, 99.0));
    println!(
        "  max           : {:>6}      {:>6}",
        all.last().copied().unwrap_or(0),
        ok.last().copied().unwrap_or(0)
    );

    if !probe.is_empty() {
        let mut pl: Vec<u128> = probe.iter().map(|(l, _)| *l).collect();
        pl.sort_unstable();
        let bad = probe.iter().filter(|(_, s)| *s != 200).count();
        println!();
        println!("/signerAddress probe (runtime-starvation canary), {} samples:", probe.len());
        println!(
            "  p50 {} ms | p99 {} ms | max {} ms | non-200: {}",
            percentile(&pl, 50.0),
            percentile(&pl, 99.0),
            pl.last().copied().unwrap_or(0),
            bad
        );
    }

    if let (Some(b), Some(a)) = (before, after) {
        let rej_b = scrape_metric(&b, "zk_verify_admission_rejected_total").unwrap_or(0.0);
        let rej_a = scrape_metric(&a, "zk_verify_admission_rejected_total").unwrap_or(0.0);
        let inflight = scrape_metric(&a, "zk_verify_in_flight").unwrap_or(0.0);
        println!();
        println!("metrics:");
        println!("  zk_verify_admission_rejected_total : +{} (during run)", rej_a - rej_b);
        println!("  zk_verify_in_flight (after)        : {inflight}");
    }
    println!("════════════════════════════════════════════════════════════════════\n");

    // Compact, machine-parseable one-liner for comparison scripts.
    let s200 = statuses.get(&200).copied().unwrap_or(0);
    let s503 = statuses.get(&503).copied().unwrap_or(0);
    let s5xx: usize =
        statuses.iter().filter(|(c, _)| **c >= 500 && **c != 503).map(|(_, n)| *n).sum();
    let sconn = statuses.get(&0).copied().unwrap_or(0);
    let (pp50, pp99, pmax, pbad) = if probe.is_empty() {
        (0, 0, 0, 0)
    } else {
        let mut pl: Vec<u128> = probe.iter().map(|(l, _)| *l).collect();
        pl.sort_unstable();
        (
            percentile(&pl, 50.0),
            percentile(&pl, 99.0),
            pl.last().copied().unwrap_or(0),
            probe.iter().filter(|(_, s)| *s != 200).count(),
        )
    };
    println!(
        "SUMMARY thrpt={:.1} p50_200={} p99_200={} max_200={} s200={} s503={} s5xx={} sconn={} \
         probe_p50={} probe_p99={} probe_max={} probe_bad={}",
        total as f64 / secs,
        percentile(&ok, 50.0),
        percentile(&ok, 99.0),
        ok.last().copied().unwrap_or(0),
        s200,
        s503,
        s5xx,
        sconn,
        pp50,
        pp99,
        pmax,
        pbad
    );
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::GenKeys { out, crs_max_messages } => gen_keys(&out, crs_max_messages),
        Command::Mint { keys, count, out, security_zone, chain_id } => {
            mint(&keys, count, &out, security_zone, chain_id)
        }
        Command::Run { url, metrics_url, corpus, concurrency, requests, probe } => {
            run(url, metrics_url, corpus, concurrency, requests, probe).await
        }
    }
}
