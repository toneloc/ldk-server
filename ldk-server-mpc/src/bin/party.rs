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

	let cfg = PartyConfig {
		party: args.role,
		listen_addr: args.listen,
		peer_addr: args.peer,
		keystore_dir: args.keystore,
		p1_name: args.p1_name,
		p2_name: args.p2_name,
		protocol_timeout: Duration::from_secs(args.protocol_timeout_secs),
		client_timeout: Duration::from_secs(args.client_timeout_secs),
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
