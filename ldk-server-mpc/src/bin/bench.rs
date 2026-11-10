//! `ldk-server-mpc-bench`: measures DKG and signing latency.
//!
//! - `--mode inproc` runs `--parties` cb-mpc parties in this process, one thread each, joined
//!   by an in-memory transport; the first `--threshold` of them sign (pure protocol cost).
//! - `--mode remote` goes through the full path: MpcClient -> a party service -> a quorum of
//!   party services over TCP, exactly as LDK Server does.

use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use clap::Parser;
use ldk_server_mpc::bitcoin::secp256k1::{Message, Secp256k1};
use ldk_server_mpc::client::MpcClient;
use ldk_server_mpc::mp::{self, Threshold};
use ldk_server_mpc::transport::LocalMesh;

#[derive(Parser, Debug)]
struct Args {
	#[arg(long, default_value = "inproc")]
	mode: String,
	/// Client address of a party to send requests to (remote mode).
	#[arg(long)]
	party: Option<SocketAddr>,
	/// Number of parties (inproc mode).
	#[arg(long, default_value_t = 4)]
	parties: usize,
	/// Number of parties that sign (inproc mode).
	#[arg(long, default_value_t = 3)]
	threshold: usize,
	/// Number of signatures to produce.
	#[arg(long, default_value_t = 50)]
	signs: usize,
	/// Number of DKGs to run (inproc) / keys to create (remote).
	#[arg(long, default_value_t = 3)]
	dkgs: usize,
	/// Concurrent signing threads (remote mode; each thread uses its own key).
	#[arg(long, default_value_t = 1)]
	concurrency: usize,
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
	if sorted.is_empty() {
		return Duration::ZERO;
	}
	let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
	sorted[idx.min(sorted.len() - 1)]
}

fn report(label: &str, mut samples: Vec<Duration>, total: Duration) {
	samples.sort();
	let n = samples.len();
	let mean = samples.iter().sum::<Duration>() / (n.max(1) as u32);
	println!(
		"{label}: n={n} mean={:.1}ms p50={:.1}ms p95={:.1}ms p99={:.1}ms min={:.1}ms max={:.1}ms throughput={:.2}/s",
		mean.as_secs_f64() * 1e3,
		percentile(&samples, 0.50).as_secs_f64() * 1e3,
		percentile(&samples, 0.95).as_secs_f64() * 1e3,
		percentile(&samples, 0.99).as_secs_f64() * 1e3,
		samples.first().map(|d| d.as_secs_f64() * 1e3).unwrap_or(0.0),
		samples.last().map(|d| d.as_secs_f64() * 1e3).unwrap_or(0.0),
		n as f64 / total.as_secs_f64().max(1e-9)
	);
}

/// Runs `f(party position, transport)` for every party of a session on its own thread.
fn run_parties<R: Send + 'static>(
	n: usize, f: impl Fn(usize, &LocalMesh) -> R + Send + Sync + Clone + 'static,
) -> Vec<R> {
	let handles: Vec<_> = LocalMesh::new(n, Duration::from_secs(60))
		.into_iter()
		.enumerate()
		.map(|(i, mesh)| {
			let f = f.clone();
			thread::spawn(move || f(i, &mesh))
		})
		.collect();
	handles.into_iter().map(|h| h.join().unwrap()).collect()
}

fn inproc(args: &Args) {
	let secp = Secp256k1::new();
	let ac =
		Threshold::new((0..args.parties).map(|i| format!("party-{i}")).collect(), args.threshold)
			.expect("valid --parties / --threshold");
	let mut dkg_samples = Vec::new();
	let dkg_start = Instant::now();
	let mut shares = Vec::new();
	for _ in 0..args.dkgs.max(1) {
		let t0 = Instant::now();
		let ac2 = ac.clone();
		shares = run_parties(args.parties, move |i, mesh| mp::dkg(&ac2, i, mesh).unwrap());
		dkg_samples.push(t0.elapsed());
	}
	report("dkg (inproc)", dkg_samples, dkg_start.elapsed());

	let pk = ldk_server_mpc::bitcoin::secp256k1::PublicKey::from_slice(
		&shares[0].public_key_compressed().unwrap(),
	)
	.unwrap();
	// The first `threshold` parties sign.
	let quorum: Vec<usize> = (0..args.threshold).collect();
	let shares = Arc::new(shares);
	let mut sign_samples = Vec::new();
	let sign_start = Instant::now();
	for i in 0..args.signs {
		let mut digest = [0u8; 32];
		digest[..8].copy_from_slice(&(i as u64).to_be_bytes());
		let (ac2, quorum2, shares2) = (ac.clone(), quorum.clone(), Arc::clone(&shares));
		let t0 = Instant::now();
		let mut out = run_parties(quorum.len(), move |pos, mesh| {
			mp::sign(&ac2, &quorum2, pos, &shares2[quorum2[pos]], &digest, 0, mesh).unwrap()
		});
		sign_samples.push(t0.elapsed());
		let der = out.remove(0).expect("receiver gets the signature");
		let mut sig = ldk_server_mpc::bitcoin::secp256k1::ecdsa::Signature::from_der(&der).unwrap();
		sig.normalize_s();
		secp.verify_ecdsa(&Message::from_digest(digest), &sig, &pk).unwrap();
	}
	report("sign (inproc)", sign_samples, sign_start.elapsed());
}

fn remote(args: &Args) {
	let addr = args.party.expect("--party required in remote mode");
	let client = MpcClient::new(addr);
	client.ping().expect("ping the party");
	let secp = Secp256k1::new();

	let mut dkg_samples = Vec::new();
	let dkg_start = Instant::now();
	let mut keys = Vec::new();
	for i in 0..args.dkgs.max(args.concurrency).max(1) {
		let mut key_id = [0u8; 32];
		key_id[..8].copy_from_slice(
			&std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH)
				.unwrap()
				.as_nanos()
				.to_be_bytes()[8..],
		);
		key_id[8..16].copy_from_slice(&(i as u64).to_be_bytes());
		let t0 = Instant::now();
		let pk = client.ensure_key(&key_id).expect("ensure_key");
		dkg_samples.push(t0.elapsed());
		keys.push((key_id, pk));
	}
	report("dkg (remote, full path)", dkg_samples, dkg_start.elapsed());

	let per_thread = args.signs / args.concurrency.max(1);
	let sign_start = Instant::now();
	let mut handles = Vec::new();
	for t in 0..args.concurrency.max(1) {
		let client = client.clone();
		let (key_id, pk) = keys[t % keys.len()];
		handles.push(thread::spawn(move || {
			let secp = Secp256k1::new();
			let mut samples = Vec::new();
			for i in 0..per_thread {
				let mut digest = [0u8; 32];
				digest[..8].copy_from_slice(&((t * 1_000_000 + i) as u64).to_be_bytes());
				let t0 = Instant::now();
				client.sign(&secp, &key_id, &digest, None, Some(&pk)).expect("sign");
				samples.push(t0.elapsed());
			}
			samples
		}));
	}
	let mut all = Vec::new();
	for h in handles {
		all.extend(h.join().unwrap());
	}
	let total = sign_start.elapsed();
	report(&format!("sign (remote, full path, concurrency={})", args.concurrency), all, total);
	let _ = secp;
}

fn main() {
	let args = Args::parse();
	match args.mode.as_str() {
		"inproc" => inproc(&args),
		"remote" => remote(&args),
		other => {
			eprintln!("unknown mode {other}");
			std::process::exit(2);
		},
	}
}
