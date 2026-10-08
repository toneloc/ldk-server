//! `ldk-server-mpc-bench`: measures DKG and signing latency.
//!
//! - `--mode inproc` runs both cb-mpc roles in this process on two threads connected by an
//!   in-memory transport (pure protocol cost).
//! - `--mode remote` goes through the full path: MpcClient -> P1 service -> P2 service over
//!   TCP, exactly as LDK Server does.

use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use clap::Parser;
use ldk_server_mpc::bitcoin::secp256k1::{Message, Secp256k1};
use ldk_server_mpc::cbmpc::{Job, Party};
use ldk_server_mpc::client::MpcClient;
use ldk_server_mpc::transport::ChannelTransport;

#[derive(Parser, Debug)]
struct Args {
	#[arg(long, default_value = "inproc")]
	mode: String,
	/// Address of P1 (remote mode).
	#[arg(long)]
	party_a: Option<SocketAddr>,
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

fn inproc(args: &Args) {
	let secp = Secp256k1::new();
	let timeout = Duration::from_secs(60);
	let mut dkg_samples = Vec::new();
	let dkg_start = Instant::now();
	let mut blobs = Vec::new();
	for _ in 0..args.dkgs.max(1) {
		let (ta, tb) = ChannelTransport::pair(timeout);
		let t0 = Instant::now();
		let h = thread::spawn(move || Job::new(Party::P2, "a", "b", &tb).dkg().unwrap());
		let blob_a = Job::new(Party::P1, "a", "b", &ta).dkg().unwrap();
		let blob_b = h.join().unwrap();
		dkg_samples.push(t0.elapsed());
		assert_eq!(
			blob_a.public_key_compressed().unwrap(),
			blob_b.public_key_compressed().unwrap()
		);
		blobs.push((Arc::new(blob_a), Arc::new(blob_b)));
	}
	report("dkg (inproc)", dkg_samples, dkg_start.elapsed());

	let (blob_a, blob_b) = blobs[0].clone();
	let pk = ldk_server_mpc::bitcoin::secp256k1::PublicKey::from_slice(
		&blob_a.public_key_compressed().unwrap(),
	)
	.unwrap();
	let mut sign_samples = Vec::new();
	let sign_start = Instant::now();
	for i in 0..args.signs {
		let (ta, tb) = ChannelTransport::pair(timeout);
		let mut digest = [0u8; 32];
		digest[..8].copy_from_slice(&(i as u64).to_be_bytes());
		let bb = Arc::clone(&blob_b);
		let t0 = Instant::now();
		let h =
			thread::spawn(move || Job::new(Party::P2, "a", "b", &tb).sign(&bb, &digest).unwrap());
		let der = Job::new(Party::P1, "a", "b", &ta).sign(&blob_a, &digest).unwrap().unwrap();
		h.join().unwrap();
		sign_samples.push(t0.elapsed());
		let mut sig = ldk_server_mpc::bitcoin::secp256k1::ecdsa::Signature::from_der(&der).unwrap();
		sig.normalize_s();
		secp.verify_ecdsa(&Message::from_digest(digest), &sig, &pk).unwrap();
	}
	report("sign (inproc)", sign_samples, sign_start.elapsed());
}

fn remote(args: &Args) {
	let addr = args.party_a.expect("--party-a required in remote mode");
	let client = MpcClient::new(addr);
	client.ping().expect("ping P1");
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
