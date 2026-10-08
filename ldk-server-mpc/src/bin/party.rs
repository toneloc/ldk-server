//! `ldk-server-mpc-party`: one MPC party (P1 or P2) wrapping Coinbase cb-mpc ECDSA-2P.
//!
//! Example (two processes on one machine):
//!
//! ```text
//! ldk-server-mpc-party --role p2 --listen 127.0.0.1:7702 --keystore ./mpc-b
//! ldk-server-mpc-party --role p1 --listen 127.0.0.1:7701 --peer 127.0.0.1:7702 --keystore ./mpc-a
//! ```

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use ldk_server_mpc::cbmpc::Party;
use ldk_server_mpc::party::{PartyConfig, PartyService};
use ldk_server_mpc::policy::{PayoutAllowlist, PolicyConfig};

#[derive(Parser, Debug)]
#[command(
	name = "ldk-server-mpc-party",
	about = "Coinbase cb-mpc 2-of-2 ECDSA party for LDK Server"
)]
struct Args {
	/// Role of this party: p1 (serves LDK Server, obtains signatures) or p2.
	#[arg(long, env = "LDK_MPC_ROLE")]
	role: Party,
	/// Address to listen on.
	#[arg(long, env = "LDK_MPC_LISTEN")]
	listen: SocketAddr,
	/// Address of P2 (required for p1).
	#[arg(long, env = "LDK_MPC_PEER")]
	peer: Option<SocketAddr>,
	/// Directory where this party's key shares are stored.
	#[arg(long, env = "LDK_MPC_KEYSTORE")]
	keystore: PathBuf,
	/// Stable unique identifier of party 1 (cb-mpc pid). Must match on both parties.
	#[arg(long, env = "LDK_MPC_P1_NAME", default_value = "ldk-server-mpc-party-a")]
	p1_name: String,
	/// Stable unique identifier of party 2 (cb-mpc pid). Must match on both parties.
	#[arg(long, env = "LDK_MPC_P2_NAME", default_value = "ldk-server-mpc-party-b")]
	p2_name: String,
	/// Per-message I/O timeout (seconds) for the inter-party protocol.
	#[arg(long, default_value_t = 30)]
	protocol_timeout_secs: u64,
	/// I/O timeout (seconds) for client connections.
	#[arg(long, default_value_t = 180)]
	client_timeout_secs: u64,
	/// Log level: error, warn, info, debug, trace.
	#[arg(long, env = "LDK_MPC_LOG", default_value = "info")]
	log_level: log::LevelFilter,
	/// Account-level BIP 84 xpub whose addresses are the only allowed payout destinations for
	/// cooperative closes and sweeps (LDK Server writes it to `<storage>/onchain_wallet_xpub`).
	/// Repeatable.
	#[arg(long, env = "LDK_MPC_PAYOUT_XPUB", value_delimiter = ',')]
	payout_xpub: Vec<String>,
	/// Explicit allowed payout address. Repeatable.
	#[arg(long, value_delimiter = ',')]
	payout_address: Vec<String>,
	/// How many addresses per xpub chain to allow-list.
	#[arg(long, default_value_t = 2000)]
	payout_lookahead: u32,
	/// Maximum drop of our channel balance between two consecutive signed commitments, in sats.
	#[arg(long)]
	max_balance_decrease_sat: Option<u64>,
	/// Maximum a cooperative close may pay us below our last tracked balance, in sats.
	#[arg(long, default_value_t = 10_000)]
	max_closing_fee_sat: u64,
	/// 32-byte pre-shared key file authenticating/encrypting the LDK Server link (Party A).
	/// Created if missing; copy it to LDK Server (`[mpc] auth_key_path`).
	#[arg(long, env = "LDK_MPC_AUTH_KEY_FILE")]
	auth_key_file: Option<PathBuf>,
	/// 32-byte pre-shared key file authenticating/encrypting the Party A ⇄ Party B link.
	/// Created if missing; must have the same content on both parties.
	#[arg(long, env = "LDK_MPC_PEER_AUTH_KEY_FILE")]
	peer_auth_key_file: Option<PathBuf>,
	/// 32-byte key file encrypting key shares and the master secret at rest. Created if
	/// missing. Keep it separate from the keystore.
	#[arg(long, env = "LDK_MPC_SHARE_KEY_FILE")]
	share_key_file: Option<PathBuf>,
}

struct StderrLogger;

impl log::Log for StderrLogger {
	fn enabled(&self, _: &log::Metadata<'_>) -> bool {
		true
	}
	fn log(&self, record: &log::Record<'_>) {
		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_millis())
			.unwrap_or(0);
		eprintln!("{now} {:<5} {}: {}", record.level(), record.target(), record.args());
	}
	fn flush(&self) {}
}

static LOGGER: StderrLogger = StderrLogger;

fn main() {
	let args = Args::parse();
	let _ = log::set_logger(&LOGGER);
	log::set_max_level(args.log_level);

	let mut payout = PayoutAllowlist::default();
	for xpub in &args.payout_xpub {
		let xpub = match xpub.parse() {
			Ok(x) => x,
			Err(e) => {
				eprintln!("invalid --payout-xpub {xpub}: {e}");
				std::process::exit(2);
			},
		};
		if let Err(e) = payout.add_bip84_xpub(&xpub, args.payout_lookahead) {
			eprintln!("failed to derive payout addresses: {e}");
			std::process::exit(2);
		}
	}
	for addr in &args.payout_address {
		if let Err(e) = payout.add_address(addr) {
			eprintln!("invalid --payout-address {addr}: {e}");
			std::process::exit(2);
		}
	}
	let policy = PolicyConfig {
		payout: if payout.is_empty() { None } else { Some(payout) },
		max_holder_balance_decrease_sat: args.max_balance_decrease_sat,
		max_closing_fee_sat: args.max_closing_fee_sat,
	};

	let load_key = |path: &Option<PathBuf>, what: &str| -> Option<[u8; 32]> {
		path.as_ref().map(|p| match ldk_server_mpc::secure::load_or_create_key_file(p) {
			Ok(k) => k,
			Err(e) => {
				eprintln!("failed to load {what} key file {}: {e}", p.display());
				std::process::exit(2);
			},
		})
	};
	let client_psk = load_key(&args.auth_key_file, "auth");
	let peer_psk = load_key(&args.peer_auth_key_file, "peer auth");
	let share_key = load_key(&args.share_key_file, "share");

	let cfg = PartyConfig {
		party: args.role,
		listen_addr: args.listen,
		peer_addr: args.peer,
		keystore_dir: args.keystore,
		p1_name: args.p1_name,
		p2_name: args.p2_name,
		protocol_timeout: Duration::from_secs(args.protocol_timeout_secs),
		client_timeout: Duration::from_secs(args.client_timeout_secs),
		policy,
		client_psk,
		peer_psk,
		share_key,
	};
	let service = match PartyService::new(cfg) {
		Ok(s) => s,
		Err(e) => {
			eprintln!("failed to start party: {e}");
			std::process::exit(1);
		},
	};
	if let Err(e) = service.serve() {
		eprintln!("party service failed: {e}");
		std::process::exit(1);
	}
}
