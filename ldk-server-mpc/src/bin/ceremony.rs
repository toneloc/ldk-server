//! `ldk-server-mpc-ceremony`: the offline ceremony that makes channel kits.
//!
//! Run it on an air-gapped machine. It is the only place the master seed of the revocation
//! secrets ever exists whole, and only for the length of one run:
//!
//! ```text
//! # Once: create the master seed and split it among custodians (any 3 of 5 rebuild it).
//! ldk-server-mpc-ceremony new-seed --threshold 3 --pieces 5 --out-dir ./pieces
//!
//! # Each ceremony: custodians bring their piece files; make kits for new channels.
//! ldk-server-mpc-ceremony new-kits --piece pieces/piece-1.txt --piece pieces/piece-3.txt \
//!     --piece pieces/piece-4.txt --fingerprint <printed by new-seed> \
//!     --tdh2-public-key tdh2.pub --kits 100 --states 50000 --out-dir ./kits
//!
//! # Refill a channel's kit before it runs out (same pieces, same kit id).
//! ldk-server-mpc-ceremony refill --piece ... --fingerprint ... --tdh2-public-key tdh2.pub \
//!     --kit <kit id hex> --from-state 50000 --states 50000 --out-dir ./kits
//! ```
//!
//! `tdh2.pub` is written by Party A to its keystore after the parties' key generation. Copy the
//! resulting `.kit` files to the kit directory of **both** parties; they hold only public points
//! and ciphertexts.

use std::fs;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use hex_conservative::FromHex;
use ldk_server_mpc::bitcoin::secp256k1::rand::{thread_rng, RngCore};
use ldk_server_mpc::kit::{
	combine_seed, generate_segment, seed_fingerprint, segment_file_name, split_seed, KitId,
	SeedPiece, INITIAL_COMMITMENT_NUMBER,
};

#[derive(Parser, Debug)]
#[command(
	name = "ldk-server-mpc-ceremony",
	about = "Offline ceremony: master seed custody and channel kits for ldk-server-mpc"
)]
struct Args {
	#[command(subcommand)]
	command: Command,
}

#[derive(Parser, Debug)]
struct SeedArgs {
	/// A custodian's piece file. Repeat for each piece; the threshold number is needed.
	#[arg(long = "piece", required = true)]
	pieces: Vec<PathBuf>,
	/// The seed fingerprint printed by `new-seed`. The run stops if the rebuilt seed differs.
	#[arg(long)]
	fingerprint: String,
	/// The parties' joint TDH2 public key file (`tdh2.pub` from Party A's keystore).
	#[arg(long)]
	tdh2_public_key: PathBuf,
	/// Directory to write the kit files to.
	#[arg(long)]
	out_dir: PathBuf,
}

#[derive(Subcommand, Debug)]
enum Command {
	/// Creates the master seed and splits it into custodian pieces. The seed is not stored.
	NewSeed {
		/// How many pieces rebuild the seed.
		#[arg(long)]
		threshold: u8,
		/// How many pieces to make.
		#[arg(long)]
		pieces: u8,
		/// Directory to write `piece-<n>.txt` files to; give each to a different custodian.
		#[arg(long)]
		out_dir: PathBuf,
	},
	/// Makes kits for channels that do not exist yet.
	NewKits {
		#[command(flatten)]
		seed: SeedArgs,
		/// How many kits to make.
		#[arg(long)]
		kits: u32,
		/// How many channel states each kit covers before it needs a refill.
		#[arg(long)]
		states: u32,
	},
	/// Extends an existing kit with further channel states.
	Refill {
		#[command(flatten)]
		seed: SeedArgs,
		/// The kit to extend (hex id, the first part of its file names).
		#[arg(long)]
		kit: String,
		/// How many states the kit already covers; the new segment starts after them.
		#[arg(long)]
		from_state: u64,
		/// How many further states to add.
		#[arg(long)]
		states: u32,
	},
}

fn fail(msg: impl AsRef<str>) -> ! {
	eprintln!("error: {}", msg.as_ref());
	std::process::exit(1);
}

fn rebuild_seed(args: &SeedArgs) -> ([u8; 32], Vec<u8>) {
	let pieces: Vec<SeedPiece> = args
		.pieces
		.iter()
		.map(|path| {
			let text = fs::read_to_string(path)
				.unwrap_or_else(|e| fail(format!("cannot read {}: {e}", path.display())));
			SeedPiece::from_hex(&text).unwrap_or_else(|e| fail(format!("{}: {e}", path.display())))
		})
		.collect();
	let seed = combine_seed(&pieces).unwrap_or_else(|e| fail(e));
	if seed_fingerprint(&seed) != args.fingerprint.trim() {
		fail("the pieces do not rebuild the expected seed (too few pieces, or a wrong one)");
	}
	let pk_hex = fs::read_to_string(&args.tdh2_public_key)
		.unwrap_or_else(|e| fail(format!("cannot read {}: {e}", args.tdh2_public_key.display())));
	let public_key = Vec::<u8>::from_hex(pk_hex.trim())
		.unwrap_or_else(|e| fail(format!("bad TDH2 public key file: {e}")));
	fs::create_dir_all(&args.out_dir)
		.unwrap_or_else(|e| fail(format!("cannot create {}: {e}", args.out_dir.display())));
	(seed, public_key)
}

fn write_segment(
	out_dir: &Path, seed: &[u8; 32], kit_id: &KitId, public_key: &[u8], first_index: u64,
	states: u32,
) {
	let segment =
		generate_segment(seed, kit_id, public_key, first_index, states).unwrap_or_else(|e| fail(e));
	let path = out_dir.join(segment_file_name(kit_id, first_index));
	if path.exists() {
		fail(format!("{} already exists", path.display()));
	}
	fs::write(&path, segment).unwrap_or_else(|e| fail(format!("{}: {e}", path.display())));
	println!("{}", path.display());
}

fn main() {
	match Args::parse().command {
		Command::NewSeed { threshold, pieces, out_dir } => {
			let mut seed = [0u8; 32];
			thread_rng().fill_bytes(&mut seed);
			let split = split_seed(&seed, threshold, pieces, |b| thread_rng().fill_bytes(b))
				.unwrap_or_else(|e| fail(e));
			fs::create_dir_all(&out_dir)
				.unwrap_or_else(|e| fail(format!("cannot create {}: {e}", out_dir.display())));
			for piece in &split {
				let path = out_dir.join(format!("piece-{}.txt", piece.number));
				if path.exists() {
					fail(format!("{} already exists", path.display()));
				}
				fs::write(&path, piece.to_hex())
					.unwrap_or_else(|e| fail(format!("{}: {e}", path.display())));
			}
			println!("seed fingerprint: {}", seed_fingerprint(&seed));
			println!(
				"wrote {pieces} pieces to {}; any {threshold} rebuild the seed",
				out_dir.display()
			);
			seed.fill(0);
		},
		Command::NewKits { seed: seed_args, kits, states } => {
			let (mut seed, public_key) = rebuild_seed(&seed_args);
			for _ in 0..kits {
				let mut kit_id = [0u8; 32];
				thread_rng().fill_bytes(&mut kit_id);
				write_segment(
					&seed_args.out_dir,
					&seed,
					&kit_id,
					&public_key,
					INITIAL_COMMITMENT_NUMBER,
					states,
				);
			}
			seed.fill(0);
		},
		Command::Refill { seed: seed_args, kit, from_state, states } => {
			let kit_id =
				<KitId>::from_hex(kit.trim()).unwrap_or_else(|e| fail(format!("bad kit id: {e}")));
			if from_state > INITIAL_COMMITMENT_NUMBER {
				fail("--from-state is out of range");
			}
			let (mut seed, public_key) = rebuild_seed(&seed_args);
			write_segment(
				&seed_args.out_dir,
				&seed,
				&kit_id,
				&public_key,
				INITIAL_COMMITMENT_NUMBER - from_state,
				states,
			);
			seed.fill(0);
		},
	}
}
