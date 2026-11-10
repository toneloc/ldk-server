//! `ldk-server-mpc-party`: one MPC party. Every party runs this same program; any
//! `--threshold` of them can sign.
//!
//! Each party first prints its identity key, and the operators exchange them:
//!
//! ```text
//! ldk-server-mpc-party --keystore ./mpc-a --print-identity
//! ```
//!
//! Then every party is started with the same `--party` list (name=address=identity, same
//! order everywhere) and its own `--name`:
//!
//! ```text
//! ldk-server-mpc-party --name a --threshold 3 --listen 127.0.0.1:7701 --keystore ./mpc-a \
//!   --party a=127.0.0.1:7711=<id a> --party b=127.0.0.1:7712=<id b> \
//!   --party c=127.0.0.1:7713=<id c> --party d=127.0.0.1:7714=<id d>
//! ```

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use hex_conservative::{DisplayHex, FromHex};
use ldk_server_mpc::mesh::{Identity, PartyInfo};
use ldk_server_mpc::party::{PartyConfig, PartyService};
use ldk_server_mpc::policy::{PayoutAllowlist, PolicyConfig};
use ldk_server_mpc::secure::AtRestKey;
use ldk_server_mpc::vls::{GuardConfig, OutflowLimit};

#[derive(Parser, Debug)]
#[command(
	name = "ldk-server-mpc-party",
	about = "Coinbase cb-mpc threshold ECDSA party for LDK Server"
)]
struct Args {
	/// This party's name: one of the names in `--party`.
	#[arg(long, env = "LDK_MPC_NAME", required_unless_present = "print_identity")]
	name: Option<String>,
	/// A party as `name=address=identity`: its stable unique name (the cb-mpc party id), the
	/// address it accepts the other parties on, and its identity public key (hex, from
	/// `--print-identity`). Give every party, this one included, in the same order on every
	/// party.
	#[arg(long = "party", env = "LDK_MPC_PARTIES", value_delimiter = ',')]
	parties: Vec<String>,
	/// How many parties must agree to sign or to release a revocation secret.
	#[arg(long, env = "LDK_MPC_THRESHOLD", required_unless_present = "print_identity")]
	threshold: Option<usize>,
	/// Address to accept LDK Server's requests on.
	#[arg(long, env = "LDK_MPC_LISTEN", required_unless_present = "print_identity")]
	listen: Option<SocketAddr>,
	/// Directory where this party's key shares are stored.
	#[arg(long, env = "LDK_MPC_KEYSTORE")]
	keystore: PathBuf,
	/// This party's identity key file. Created if missing. Defaults to
	/// `<keystore>/identity.key`.
	#[arg(long, env = "LDK_MPC_IDENTITY_FILE")]
	identity_file: Option<PathBuf>,
	/// Print this party's identity public key (creating the key if needed) and exit.
	#[arg(long)]
	print_identity: bool,
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
	/// The network the channels are on: bitcoin, testnet, signet or regtest. It selects the
	/// limits the validator applies to commitments (stricter on bitcoin).
	#[arg(long, env = "LDK_MPC_NETWORK", default_value = "bitcoin")]
	network: ldk_server_mpc::bitcoin::Network,
	/// The most that may leave our channel balances per hour, in sats, over all channels:
	/// payments of our own (forwards do not count), fees, and anything else that lowers what
	/// a commitment leaves us. Each party keeps its own count. Unlimited if neither this nor
	/// the per-day limit is set.
	#[arg(long, env = "LDK_MPC_MAX_OUTFLOW_SAT_PER_HOUR")]
	max_outflow_sat_per_hour: Option<u64>,
	/// The same limit, per day.
	#[arg(long, env = "LDK_MPC_MAX_OUTFLOW_SAT_PER_DAY")]
	max_outflow_sat_per_day: Option<u64>,
	/// Maximum drop of our channel balance between two consecutive signed commitments, in sats.
	#[arg(long)]
	max_balance_decrease_sat: Option<u64>,
	/// Maximum a cooperative close may pay us below our last tracked balance, in sats.
	#[arg(long, default_value_t = 10_000)]
	max_closing_fee_sat: u64,
	/// 32-byte pre-shared key file authenticating/encrypting the link from LDK Server.
	/// Created if missing; LDK Server (`[mpc] auth_key_path`) and every party it may talk to
	/// need the same file.
	#[arg(long, env = "LDK_MPC_AUTH_KEY_FILE")]
	auth_key_file: Option<PathBuf>,
	/// Optional 32-byte pre-shared key file mixed into the links between parties, on top of
	/// their identity keys. Created if missing; must have the same content on every party.
	#[arg(long, env = "LDK_MPC_PEER_AUTH_KEY_FILE")]
	peer_auth_key_file: Option<PathBuf>,
	/// 32-byte key file encrypting key shares at rest. Created if missing. Keep it separate
	/// from the keystore.
	#[arg(long, env = "LDK_MPC_SHARE_KEY_FILE")]
	share_key_file: Option<PathBuf>,
	/// Directory of channel kits (encrypted revocation secrets) made by
	/// `ldk-server-mpc-ceremony`. Both parties need a copy of every kit. Defaults to
	/// `<keystore>/kits`.
	#[arg(long, env = "LDK_MPC_KIT_DIR")]
	kit_dir: Option<PathBuf>,
	/// Threads each signing session may use for its oblivious transfers, the most expensive
	/// step of a signature. Leave at 1 unless this machine has cores to spare: the threads of
	/// concurrent sessions add up.
	#[arg(long, env = "LDK_MPC_OT_THREADS", default_value_t = 1, value_parser = clap::value_parser!(u8).range(1..=64))]
	ot_threads: u8,
}

struct StderrLogger;

impl log::Log for StderrLogger {
	fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
		// The embedded validator reports every payment it sees at info level.
		!metadata.target().starts_with("lightning_signer") || metadata.level() <= log::Level::Warn
	}
	fn log(&self, record: &log::Record<'_>) {
		if !self.enabled(record.metadata()) {
			return;
		}
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
	// cb-mpc reads this once, on its first signature. Nothing else is running yet.
	std::env::set_var("CBMPC_BASE_OT_THREADS", args.ot_threads.to_string());

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
	let outflow = match (args.max_outflow_sat_per_hour, args.max_outflow_sat_per_day) {
		(Some(sat), None) => OutflowLimit::PerHour { sat },
		(None, Some(sat)) => OutflowLimit::PerDay { sat },
		(None, None) => OutflowLimit::Unlimited,
		(Some(_), Some(_)) => {
			eprintln!("set the outflow limit per hour or per day, not both");
			std::process::exit(2);
		},
	};
	let policy = PolicyConfig {
		payout: if payout.is_empty() { None } else { Some(payout) },
		max_holder_balance_decrease_sat: args.max_balance_decrease_sat,
		max_closing_fee_sat: args.max_closing_fee_sat,
		commitment_validation: Some(GuardConfig { network: args.network, outflow }),
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

	let fail = |msg: String| -> ! {
		eprintln!("{msg}");
		std::process::exit(2);
	};
	let identity_file =
		args.identity_file.clone().unwrap_or_else(|| args.keystore.join("identity.key"));
	let at_rest = share_key.as_ref().map(AtRestKey::new);
	let identity = Identity::load_or_create(&identity_file, at_rest.as_ref()).unwrap_or_else(|e| {
		fail(format!("failed to load identity key {}: {e}", identity_file.display()))
	});
	if args.print_identity {
		println!("{}", identity.public_key().as_hex());
		return;
	}

	let parties: Vec<PartyInfo> = args
		.parties
		.iter()
		.map(|spec| {
			let parts: Vec<&str> = spec.split('=').collect();
			let [name, addr, id] = parts[..] else {
				fail(format!("invalid --party '{spec}': expected name=address=identity"));
			};
			PartyInfo {
				name: name.to_string(),
				addr: addr
					.parse()
					.unwrap_or_else(|e| fail(format!("invalid address in --party '{spec}': {e}"))),
				identity: <[u8; 32]>::from_hex(id)
					.unwrap_or_else(|e| fail(format!("invalid identity in --party '{spec}': {e}"))),
			}
		})
		.collect();
	let name = args.name.clone().expect("required by clap");
	let lead_tdh2 = parties.first().map(|p| p.name == name).unwrap_or(false);

	let cfg = PartyConfig {
		name,
		parties,
		threshold: args.threshold.expect("required by clap"),
		identity,
		listen_addr: args.listen.expect("required by clap"),
		keystore_dir: args.keystore,
		protocol_timeout: Duration::from_secs(args.protocol_timeout_secs),
		client_timeout: Duration::from_secs(args.client_timeout_secs),
		policy,
		client_psk,
		peer_psk,
		share_key,
		kit_dir: args.kit_dir,
	};
	let service = match PartyService::new(cfg) {
		Ok(s) => s,
		Err(e) => {
			eprintln!("failed to start party: {e}");
			std::process::exit(1);
		},
	};
	if lead_tdh2 && service.tdh2_public_key().is_none() {
		// The offline ceremony needs the joint TDH2 public key (`<keystore>/tdh2.pub`) before it
		// can make kits. The first party in the list generates it with the others as soon as
		// all of them are reachable.
		let service = std::sync::Arc::clone(&service);
		std::thread::spawn(move || loop {
			match service.ensure_tdh2() {
				Ok(_) => break,
				Err(e) => log::warn!("TDH2 key generation not done yet: {}", e.message),
			}
			std::thread::sleep(Duration::from_secs(2));
		});
	}
	match service.kits().unbound_count() {
		Ok(0) => log::warn!(
			"no unused channel kits in {}: new channels cannot open until the ceremony adds some",
			service.kits().dir().display()
		),
		Ok(n) => log::info!("{n} unused channel kits available"),
		Err(e) => log::warn!("cannot read the kit directory: {e}"),
	}
	if let Err(e) = service.serve() {
		eprintln!("party service failed: {e}");
		std::process::exit(1);
	}
}
