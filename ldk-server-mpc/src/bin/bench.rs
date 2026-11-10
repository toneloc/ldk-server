//! `ldk-server-mpc-bench`: measures DKG and signing latency.
//!
//! - `--mode inproc` runs `--parties` cb-mpc parties in this process, one thread each, joined
//!   by an in-memory transport; the first `--threshold` of them sign (pure protocol cost).
//! - `--mode remote` goes through the full path: MpcClient -> a party service -> a quorum of
//!   party services over TCP, exactly as LDK Server does.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use clap::Parser;
use ldk_server_mpc::bitcoin::secp256k1::{Message, Secp256k1};
use ldk_server_mpc::cbmpc::TransportError;
use ldk_server_mpc::client::MpcClient;
use ldk_server_mpc::mp::{self, MpTransport, Threshold};
use ldk_server_mpc::protocol::{Derivation, SignItem, SigningContext, SigningOp};
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
	/// The parties' `--auth-key-file`, if they use one (remote mode).
	#[arg(long)]
	auth_key_file: Option<std::path::PathBuf>,
	/// Also time requests that carry this many signatures each (remote mode).
	#[arg(long, default_value_t = 1)]
	batch: usize,
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

/// Counts what one party sends, to size the protocol's network cost.
struct Counting<'a> {
	inner: &'a LocalMesh,
	messages: AtomicU64,
	bytes: AtomicU64,
}

impl MpTransport for Counting<'_> {
	fn send(&self, peer: usize, msg: &[u8]) -> Result<(), TransportError> {
		self.messages.fetch_add(1, Ordering::Relaxed);
		self.bytes.fetch_add(msg.len() as u64, Ordering::Relaxed);
		self.inner.send(peer, msg)
	}

	fn recv(&self, peer: usize) -> Result<Vec<u8>, TransportError> {
		self.inner.recv(peer)
	}
}

/// CPU time this thread has used so far (Linux only; zero elsewhere).
fn thread_cpu() -> Duration {
	std::fs::read_to_string("/proc/thread-self/schedstat")
		.ok()
		.and_then(|s| s.split_whitespace().next().and_then(|n| n.parse::<u64>().ok()))
		.map(Duration::from_nanos)
		.unwrap_or_default()
}

/// Where a signature's time goes: wall time, each party's CPU time, and what each sends.
/// With every party in one process the wall time is inflated when there are fewer cores than
/// parties; a party's CPU time is what it would need on a machine of its own.
fn profile(args: &Args) {
	let ac =
		Threshold::new((0..args.parties).map(|i| format!("party-{i}")).collect(), args.threshold)
			.expect("valid --parties / --threshold");
	let ac2 = ac.clone();
	let shares =
		Arc::new(run_parties(args.parties, move |i, mesh| mp::dkg(&ac2, i, mesh).unwrap()));
	let quorum: Vec<usize> = (0..args.threshold).collect();
	let (mut wall, mut cpu, mut messages, mut bytes) = (Vec::new(), Vec::new(), 0u64, 0u64);
	for i in 0..args.signs {
		let mut digest = [0u8; 32];
		digest[..8].copy_from_slice(&(i as u64).to_be_bytes());
		let (ac2, quorum2, shares2) = (ac.clone(), quorum.clone(), Arc::clone(&shares));
		let t0 = Instant::now();
		let out = run_parties(quorum.len(), move |pos, mesh| {
			let counting =
				Counting { inner: mesh, messages: AtomicU64::new(0), bytes: AtomicU64::new(0) };
			let c0 = thread_cpu();
			mp::sign(&ac2, &quorum2, pos, &shares2[quorum2[pos]], &digest, 0, &counting).unwrap();
			(thread_cpu() - c0, counting.messages.into_inner(), counting.bytes.into_inner())
		});
		wall.push(t0.elapsed());
		for (c, m, b) in out {
			cpu.push(c);
			messages += m;
			bytes += b;
		}
	}
	let total = wall.iter().sum();
	report("sign wall time", wall, total);
	let total = cpu.iter().sum();
	report("sign CPU time per party", cpu, total);
	let per_party = (args.signs * args.threshold) as u64;
	println!(
		"each party sends {} messages, {:.0} KiB per signature",
		messages / per_party,
		bytes as f64 / per_party as f64 / 1024.0
	);
}

fn remote(args: &Args) {
	let addr = args.party.expect("--party required in remote mode");
	let mut client = MpcClient::new(addr);
	if let Some(path) = &args.auth_key_file {
		let psk = ldk_server_mpc::secure::load_or_create_key_file(path).expect("auth key file");
		client = client.with_psk(psk);
	}
	client.ping().expect("ping the party");
	let secp = Secp256k1::new();

	let mut dkg_samples = Vec::new();
	let dkg_start = Instant::now();
	let mut keys = Vec::new();
	for i in 0..args.dkgs.max(args.concurrency).max(args.batch).max(1) {
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

	// One request carrying several signatures on different keys, as a commitment update with
	// HTLCs does (the funding signature plus one per HTLC).
	if args.batch > 1 {
		let mut samples = Vec::new();
		let start = Instant::now();
		for i in 0..(args.signs / args.batch).max(3) {
			let items: Vec<SignItem> = (0..args.batch)
				.map(|n| {
					let mut digest = [0xb7u8; 32];
					digest[..8].copy_from_slice(&((i * 1_000 + n) as u64).to_be_bytes());
					SignItem {
						key_id: keys[n % keys.len()].0,
						derivation: Derivation::None,
						digest,
						context: SigningContext { op: Some(SigningOp::Test), ..Default::default() },
						splice: None,
					}
				})
				.collect();
			let pks: Vec<_> = (0..args.batch).map(|n| keys[n % keys.len()].1).collect();
			let t0 = Instant::now();
			client.sign_batch(&secp, None, items, Some(&pks)).expect("sign batch");
			samples.push(t0.elapsed());
		}
		report(
			&format!("request with {} signatures (remote, full path)", args.batch),
			samples,
			start.elapsed(),
		);
	}
}

fn main() {
	let args = Args::parse();
	match args.mode.as_str() {
		"inproc" => inproc(&args),
		"remote" => remote(&args),
		"profile" => profile(&args),
		other => {
			eprintln!("unknown mode {other}");
			std::process::exit(2);
		},
	}
}
