// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! End-to-end tests of LDK Server with Coinbase cb-mpc threshold MPC-backed channel keys, on
//! regtest. Four MPC party processes are started, any three of which must agree to sign or to
//! release a revocation secret, and the offline ceremony tool makes their
//! channel kits (threshold-encrypted revocation secrets); server A is configured with `[mpc]`
//! and opens a channel to a plain server B.

use std::io::{BufRead, BufReader};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use e2e_tests::{
	close_channel, find_available_port, mine_and_sync, mpc_ceremony_binary_path,
	mpc_party_binary_path, run_cli, send_bolt11_payment, setup_funded_channel, splice_txid,
	wait_for_channels, wait_for_event, wait_for_force_close_claims, LdkServerHandle, TestBitcoind,
	TestConfigBuilder,
};
use hex_conservative::FromHex;
use ldk_node::bitcoin::consensus::encode::deserialize;
use ldk_node::bitcoin::secp256k1::PublicKey;
use ldk_node::bitcoin::Transaction;
use ldk_server_client::ldk_server_grpc::api::{
	Bolt11ReceiveRequest, Bolt11SendRequest, GetBalancesRequest, SpliceOutRequest,
};
use ldk_server_client::ldk_server_grpc::events::event_envelope::Event;
use ldk_server_client::ldk_server_grpc::types::BalanceSource;

const PARTIES: usize = 4;
const THRESHOLD: usize = 3;

/// Four MPC party processes, any three of which must agree, each with its own keystore.
struct MpcParties {
	children: Vec<Option<Child>>,
	/// Where each party takes LDK Server's requests, and where it takes the other parties.
	client_addrs: Vec<String>,
	peer_addrs: Vec<String>,
	keystores: Vec<PathBuf>,
	/// Each party's identity public key (hex), as printed by `--print-identity`.
	identities: Vec<String>,
	/// Key files: client PSK (LDK Server <-> parties) and each party's share key (at rest).
	keys_dir: PathBuf,
	/// BIP 84 account xpub of server A's on-chain wallet, allow-listed on every party.
	payout_xpub: Option<String>,
	/// An address allow-listed on one party only, as `(party, address)`.
	rogue_payout: Option<(usize, String)>,
	/// The parties' limit on what may leave our channel balances per day, in sat.
	outflow_per_day: Option<u64>,
}

fn wait_for_port(addr: &str) {
	let start = Instant::now();
	while TcpStream::connect(addr).is_err() {
		assert!(start.elapsed() < Duration::from_secs(20), "MPC party at {addr} did not start");
		std::thread::sleep(Duration::from_millis(100));
	}
}

impl MpcParties {
	fn start() -> Self {
		#[allow(deprecated)]
		let keys_dir = tempfile::tempdir().unwrap().into_path();
		#[allow(deprecated)]
		let keystores: Vec<PathBuf> =
			(0..PARTIES).map(|_| tempfile::tempdir().unwrap().into_path()).collect();
		let addr = || format!("127.0.0.1:{}", find_available_port());
		// Each party creates its identity key and prints the public half; the operators
		// exchange those before any party starts.
		let identities = keystores
			.iter()
			.enumerate()
			.map(|(i, keystore)| {
				let out = Command::new(mpc_party_binary_path())
					.arg("--keystore")
					.arg(keystore)
					.arg("--share-key-file")
					.arg(keys_dir.join(format!("share-{i}.key")))
					.arg("--print-identity")
					.output()
					.unwrap();
				assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
				String::from_utf8(out.stdout).unwrap().trim().to_string()
			})
			.collect();
		let mut parties = MpcParties {
			children: (0..PARTIES).map(|_| None).collect(),
			client_addrs: (0..PARTIES).map(|_| addr()).collect(),
			peer_addrs: (0..PARTIES).map(|_| addr()).collect(),
			keystores,
			identities,
			keys_dir,
			payout_xpub: None,
			rogue_payout: None,
			outflow_per_day: None,
		};
		// One party first: LDK Server only needs to reach a party at startup. The others
		// start once the server has exported its wallet xpub (see `start_rest`), so every
		// party can allow-list it.
		parties.spawn(0);
		parties
	}

	fn spawn(&mut self, i: usize) {
		let mut cmd = Command::new(mpc_party_binary_path());
		cmd.args(["--name", &format!("party-{i}"), "--threshold", &THRESHOLD.to_string()]);
		cmd.args(["--listen", &self.client_addrs[i]]);
		cmd.args(["--network", "regtest"]);
		if let Some(sat) = self.outflow_per_day {
			cmd.args(["--max-outflow-sat-per-day", &sat.to_string()]);
		}
		cmd.arg("--keystore").arg(&self.keystores[i]);
		for p in 0..PARTIES {
			cmd.arg("--party")
				.arg(format!("party-{p}={}={}", self.peer_addrs[p], self.identities[p]));
		}
		cmd.arg("--auth-key-file").arg(self.keys_dir.join("client.psk"));
		cmd.arg("--share-key-file").arg(self.keys_dir.join(format!("share-{i}.key")));
		if let Some(xpub) = &self.payout_xpub {
			cmd.args(["--payout-xpub", xpub, "--payout-lookahead", "200"]);
			// Pay-per-update cap generous enough for the test payments (10M msat max per hop).
			cmd.args(["--max-balance-decrease-sat", "20000"]);
		}
		if let Some((party, address)) = &self.rogue_payout {
			if *party == i {
				cmd.args(["--payout-address", address]);
			}
		}
		let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
		let stderr = child.stderr.take().unwrap();
		let tag = format!("mpc-{i}");
		std::thread::spawn(move || {
			for line in BufReader::new(stderr).lines().map_while(Result::ok) {
				eprintln!("[{tag}] {line}");
			}
		});
		self.children[i] = Some(child);
		wait_for_port(&self.client_addrs[i]);
		wait_for_port(&self.peer_addrs[i]);
	}

	fn kill(&mut self, i: usize) {
		if let Some(mut child) = self.children[i].take() {
			let _ = child.kill();
			let _ = child.wait();
		}
	}

	/// Starts the remaining parties, and restarts the first, with `payout_xpub` allow-listed.
	fn start_rest(&mut self, payout_xpub: &str) {
		self.payout_xpub = Some(payout_xpub.to_string());
		self.kill(0);
		for i in 0..PARTIES {
			self.spawn(i);
		}
	}

	/// Kills every party and starts them again on the same keystores.
	fn restart(&mut self) {
		for i in 0..PARTIES {
			self.kill(i);
		}
		for i in 0..PARTIES {
			self.spawn(i);
		}
	}

	fn client_psk_path(&self) -> PathBuf {
		self.keys_dir.join("client.psk")
	}

	fn share_count(dir: &Path) -> usize {
		// Shares are encrypted at rest; only count them.
		std::fs::read_dir(dir)
			.unwrap()
			.filter_map(|e| e.ok())
			.filter(|e| e.path().extension().map(|x| x == "share").unwrap_or(false))
			.count()
	}

	/// Joint public keys of all shares held by the first party (derived from the shares).
	fn first_party_pubkeys(&self) -> Vec<PublicKey> {
		let mut keys = Vec::new();
		for entry in std::fs::read_dir(&self.keystores[0]).unwrap().filter_map(|e| e.ok()) {
			if entry.path().extension().map(|x| x == "share").unwrap_or(false) {
				let bytes = std::fs::read(entry.path()).unwrap();
				assert!(
					ldk_server_mpc::secure::AtRestKey::is_encrypted(&bytes),
					"share not encrypted"
				);
				let share_key: [u8; 32] =
					std::fs::read(self.keys_dir.join("share-0.key")).unwrap().try_into().unwrap();
				let plain =
					ldk_server_mpc::secure::AtRestKey::new(&share_key).open(&bytes).unwrap();
				let share = ldk_server_mpc::mp::KeyShare(plain);
				keys.push(PublicKey::from_slice(&share.public_key_compressed().unwrap()).unwrap());
			}
		}
		keys
	}

	/// Runs the offline ceremony with the real tool: a master seed split among three
	/// custodians, two of whom then make `kits` channel kits. Every party gets a copy.
	fn run_ceremony(&self, kits: u32, states: u32) {
		let tdh2_pub = self.keystores[0].join("tdh2.pub");
		let start = Instant::now();
		while !tdh2_pub.exists() {
			assert!(
				start.elapsed() < Duration::from_secs(60),
				"the parties did not generate their TDH2 key"
			);
			std::thread::sleep(Duration::from_millis(200));
		}
		let dir = self.keys_dir.join("ceremony");
		let ceremony = |args: &[&str]| {
			let out = Command::new(mpc_ceremony_binary_path()).args(args).output().unwrap();
			assert!(
				out.status.success(),
				"ceremony {args:?} failed: {}",
				String::from_utf8_lossy(&out.stderr)
			);
			String::from_utf8(out.stdout).unwrap()
		};
		let pieces = dir.join("pieces");
		let out = ceremony(&[
			"new-seed",
			"--threshold",
			"2",
			"--pieces",
			"3",
			"--out-dir",
			pieces.to_str().unwrap(),
		]);
		let fingerprint = out
			.lines()
			.find_map(|l| l.strip_prefix("seed fingerprint: "))
			.expect("fingerprint printed")
			.to_string();
		let kit_dir = dir.join("kits");
		ceremony(&[
			"new-kits",
			"--piece",
			pieces.join("piece-1.txt").to_str().unwrap(),
			"--piece",
			pieces.join("piece-3.txt").to_str().unwrap(),
			"--fingerprint",
			&fingerprint,
			"--tdh2-public-key",
			tdh2_pub.to_str().unwrap(),
			"--kits",
			&kits.to_string(),
			"--states",
			&states.to_string(),
			"--out-dir",
			kit_dir.to_str().unwrap(),
		]);
		for keystore in &self.keystores {
			let dest = keystore.join("kits");
			std::fs::create_dir_all(&dest).unwrap();
			for entry in std::fs::read_dir(&kit_dir).unwrap().filter_map(|e| e.ok()) {
				std::fs::copy(entry.path(), dest.join(entry.file_name())).unwrap();
			}
		}
	}

	/// How many kits a party has bound to a channel.
	fn bound_kits(keystore: &Path) -> usize {
		std::fs::read_dir(keystore.join("kits"))
			.unwrap()
			.filter_map(|e| e.ok())
			.filter(|e| e.path().extension().map(|x| x == "bound").unwrap_or(false))
			.count()
	}
}

impl Drop for MpcParties {
	fn drop(&mut self) {
		for i in 0..PARTIES {
			self.kill(i);
		}
		for keystore in &self.keystores {
			let _ = std::fs::remove_dir_all(keystore);
		}
		let _ = std::fs::remove_dir_all(&self.keys_dir);
	}
}

/// Starts the MPC-backed server, then every party with the server's wallet xpub allow-listed.
async fn start_mpc_server(bitcoind: &TestBitcoind, parties: &mut MpcParties) -> LdkServerHandle {
	let party_address = parties.client_addrs.join(",");
	let auth_key_path = parties.client_psk_path();
	let server = LdkServerHandle::start_with_config(bitcoind, move |params| {
		let mut config = TestConfigBuilder::new(params).alias(Some("mpc-node")).build();
		// The on-chain wallet gets its own mnemonic so it is not derivable from the node seed.
		let wallet_mnemonic = params.storage_dir.join("onchain_wallet_mnemonic");
		config = config.replacen(
			"[node]\n",
			&format!("[node]\nonchain_wallet_mnemonic_path = \"{}\"\n", wallet_mnemonic.display()),
			1,
		);
		config.push_str(&format!(
			"\n[mpc]\nparty_address = \"{party_address}\"\ncoverage = \"all\"\nauth_key_path = \"{}\"\n",
			auth_key_path.display()
		));
		config
	})
	.await;
	let xpub = std::fs::read_to_string(server.storage_dir.join("onchain_wallet_xpub")).unwrap();
	parties.start_rest(xpub.trim());
	// With every party up they generate their joint TDH2 key; the ceremony then makes the
	// kits a channel needs before it can open.
	parties.run_ceremony(2, 400);
	server
}

/// Asserts the MPC server's on-chain wallet mnemonic exists and differs from the node mnemonic.
fn assert_separate_wallet_mnemonic(server: &LdkServerHandle) {
	let node = std::fs::read_to_string(server.storage_dir.join("keys_mnemonic")).unwrap();
	let wallet =
		std::fs::read_to_string(server.storage_dir.join("onchain_wallet_mnemonic")).unwrap();
	assert_eq!(wallet.trim().split_whitespace().count(), 24);
	assert_ne!(node, wallet, "on-chain wallet mnemonic must differ from the node mnemonic");
}

/// Returns the 2-of-2 funding redeem script pubkeys of the first input spending a P2WSH
/// funding output (witness: `0 sig sig redeemscript`).
fn funding_multisig_pubkeys(tx: &Transaction) -> Vec<PublicKey> {
	for input in &tx.input {
		let witness: Vec<&[u8]> = input.witness.iter().collect();
		if witness.len() == 4 && witness[0].is_empty() {
			let script = witness[3];
			// OP_2 <33-byte pk> <33-byte pk> OP_2 OP_CHECKMULTISIG
			if script.len() == 71 && script[0] == 0x52 && script[1] == 33 && script[35] == 33 {
				return vec![
					PublicKey::from_slice(&script[2..35]).unwrap(),
					PublicKey::from_slice(&script[36..69]).unwrap(),
				];
			}
		}
	}
	panic!("no 2-of-2 funding input found in tx {}", tx.compute_txid());
}

/// Waits for a transaction spending the given funding outpoint to appear in the mempool and
/// returns it (fetched while still unconfirmed, as the test bitcoind has no txindex).
async fn wait_for_spender(bitcoind: &TestBitcoind, funding_txid: &str, vout: u32) -> Transaction {
	let start = Instant::now();
	loop {
		let mempool: Vec<String> = bitcoind.bitcoind.client.call("getrawmempool", &[]).unwrap();
		for txid in &mempool {
			let raw: String = bitcoind
				.bitcoind
				.client
				.call("getrawtransaction", &[txid.as_str().into()])
				.unwrap();
			let tx: Transaction = deserialize(&Vec::<u8>::from_hex(&raw).unwrap()).unwrap();
			if tx.input.iter().any(|i| {
				i.previous_output.txid.to_string() == funding_txid && i.previous_output.vout == vout
			}) {
				return tx;
			}
		}
		assert!(
			start.elapsed() < Duration::from_secs(60),
			"no spend of {funding_txid}:{vout} seen"
		);
		tokio::time::sleep(Duration::from_millis(200)).await;
	}
}

#[tokio::test]
async fn test_mpc_channel_open_pay_and_coop_close() {
	let bitcoind = TestBitcoind::new();
	let mut parties = MpcParties::start();
	let server_a = start_mpc_server(&bitcoind, &mut parties).await;
	let server_b = LdkServerHandle::start(&bitcoind).await;

	assert_separate_wallet_mnemonic(&server_a);
	let user_channel_id = setup_funded_channel(&bitcoind, &server_a, &server_b, 100_000).await;

	// Five distributed keys (funding, payment, delayed-payment, HTLC, revocation) were
	// generated for the channel and each of the four parties holds one share of each.
	for keystore in &parties.keystores {
		assert_eq!(MpcParties::share_count(keystore), 5);
	}
	let mpc_pubkeys = parties.first_party_pubkeys();
	assert_eq!(mpc_pubkeys.len(), 5);
	// The channel took one of the two kits, on every party, and no party holds a seed for
	// the revocation secrets.
	for keystore in &parties.keystores {
		assert_eq!(MpcParties::bound_kits(keystore), 1);
		assert!(!keystore.join("master.secret").exists());
	}

	// Payments in both directions (each commitment update is signed via MPC on server A).
	send_bolt11_payment(&server_a, &server_b, 10_000_000).await;
	send_bolt11_payment(&server_b, &server_a, 3_000_000).await;

	// Restart the MPC parties: shares must be restored from disk and signing must resume.
	parties.restart();
	send_bolt11_payment(&server_a, &server_b, 1_000_000).await;

	// Any three of the four parties are enough. With the last party down, payments go
	// through in both directions; the same with the first party down, the one LDK Server
	// was talking to.
	parties.kill(3);
	send_bolt11_payment(&server_a, &server_b, 1_000_000).await;
	send_bolt11_payment(&server_b, &server_a, 500_000).await;
	parties.spawn(3);
	parties.kill(0);
	send_bolt11_payment(&server_a, &server_b, 1_000_000).await;
	send_bolt11_payment(&server_b, &server_a, 500_000).await;
	parties.spawn(0);

	// Restart LDK Server: channel signers are re-derived through the MPC service.
	let mut server_a = server_a;
	server_a.restart().await;
	let channels = wait_for_channels(&server_a, 1, Duration::from_secs(30)).await;
	let funding = channels[0].funding_txo.clone().expect("funding txo");
	send_bolt11_payment(&server_b, &server_a, 500_000).await;
	assert_eq!(MpcParties::share_count(&parties.keystores[0]), 5, "no new keys after restart");

	let balances_before = server_a.client().get_balances(GetBalancesRequest {}).await.unwrap();

	// Cooperative close: the closing transaction is signed with the MPC funding key.
	close_channel(&server_a, &server_b, &user_channel_id).await;
	let closing_tx = wait_for_spender(&bitcoind, &funding.txid, funding.vout).await;
	// The closing transaction spends the 2-of-2 whose redeem script contains the MPC
	// aggregate public key, i.e. the funding key was genuinely the DKG'd key.
	let pubkeys = funding_multisig_pubkeys(&closing_tx);
	mine_and_sync(&bitcoind, &[&server_a, &server_b], 6).await;
	wait_for_channels(&server_a, 0, Duration::from_secs(30)).await;
	assert!(
		pubkeys.iter().any(|pk| mpc_pubkeys.contains(pk)),
		"closing tx multisig {pubkeys:?} does not contain any MPC key {mpc_pubkeys:?}"
	);

	let balances_after = server_a.client().get_balances(GetBalancesRequest {}).await.unwrap();
	e2e_tests::assert_recovered_balance(&balances_before, &balances_after);
	let _ = run_cli(&server_a, &["list-channels"]);
}

#[tokio::test]
async fn test_mpc_channel_force_close() {
	let bitcoind = TestBitcoind::new();
	let mut parties = MpcParties::start();
	let server_a = start_mpc_server(&bitcoind, &mut parties).await;
	let server_b = LdkServerHandle::start(&bitcoind).await;

	let user_channel_id = setup_funded_channel(&bitcoind, &server_a, &server_b, 100_000).await;
	send_bolt11_payment(&server_a, &server_b, 5_000_000).await;
	// The payment is reported once the preimage is back, a few signing rounds before the HTLC
	// is gone from both commitments. Let those finish, so the force-closed commitment carries
	// balances only and each side ends with the single claim checked below.
	tokio::time::sleep(Duration::from_secs(5)).await;
	let channels = wait_for_channels(&server_a, 1, Duration::from_secs(30)).await;
	let funding = channels[0].funding_txo.clone().expect("funding txo");
	let mpc_pubkeys = parties.first_party_pubkeys();

	// Holder force-close: our commitment transaction is signed with the MPC funding key and
	// broadcast by server A.
	let output = run_cli(&server_a, &["force-close-channel", &user_channel_id, server_b.node_id()]);
	assert!(output.is_object());
	let commitment_tx = wait_for_spender(&bitcoind, &funding.txid, funding.vout).await;
	let pubkeys = funding_multisig_pubkeys(&commitment_tx);
	assert!(
		pubkeys.iter().any(|pk| mpc_pubkeys.contains(pk)),
		"commitment tx not signed under MPC key"
	);

	wait_for_force_close_claims(
		&bitcoind,
		&[
			(&server_a, BalanceSource::HolderForceClosed),
			(&server_b, BalanceSource::CounterpartyForceClosed),
		],
		Duration::from_secs(60),
	)
	.await;
	let _ = commitment_tx;
}

#[tokio::test]
async fn test_mpc_splice() {
	let bitcoind = TestBitcoind::new();
	let mut parties = MpcParties::start();
	let server_a = start_mpc_server(&bitcoind, &mut parties).await;
	let server_b = LdkServerHandle::start(&bitcoind).await;

	let user_channel_id = setup_funded_channel(&bitcoind, &server_a, &server_b, 100_000).await;
	send_bolt11_payment(&server_a, &server_b, 10_000_000).await;
	tokio::time::sleep(Duration::from_secs(5)).await;
	let mut events = server_a.client().subscribe_events().await.unwrap();
	let mut events_b = server_b.client().subscribe_events().await.unwrap();
	let confirm = || async {
		mine_and_sync(&bitcoind, &[&server_a, &server_b], 6).await;
		tokio::time::sleep(Duration::from_secs(5)).await;
	};

	// We add funds: the parties sign the old funding output away and follow the channel to
	// the new one, which holds a freshly generated distributed key.
	run_cli(&server_a, &["splice-in", &user_channel_id, server_b.node_id(), "50000sat"]);
	splice_txid(&mut events).await;
	confirm().await;
	for keystore in &parties.keystores {
		assert_eq!(MpcParties::share_count(keystore), 6, "one more funding key");
	}
	send_bolt11_payment(&server_a, &server_b, 1_000_000).await;
	tokio::time::sleep(Duration::from_secs(5)).await;

	// The counterparty adds funds: our balance does not change, so there is nothing to object to.
	let channels_b = run_cli(&server_b, &["list-channels"]);
	let user_channel_id_b = channels_b["channels"][0]["user_channel_id"].as_str().unwrap();
	run_cli(&server_b, &["splice-in", user_channel_id_b, server_a.node_id(), "20000sat"]);
	splice_txid(&mut events_b).await;
	confirm().await;
	send_bolt11_payment(&server_b, &server_a, 1_000_000).await;
	tokio::time::sleep(Duration::from_secs(5)).await;

	// We take funds out to our own wallet, whose addresses the parties allow.
	run_cli(&server_a, &["splice-out", &user_channel_id, server_b.node_id(), "10000sat"]);
	splice_txid(&mut events).await;
	confirm().await;
	send_bolt11_payment(&server_a, &server_b, 1_000_000).await;
	tokio::time::sleep(Duration::from_secs(5)).await;

	// A splice-out to an address the parties do not know as ours is turned down before it
	// starts, and the channel carries on.
	let foreign: String =
		bitcoind.bitcoind.client.call("getnewaddress", &["".into(), "bech32".into()]).unwrap();
	let splice_out_to_foreign = || async {
		server_a
			.client()
			.splice_out(SpliceOutRequest {
				user_channel_id: user_channel_id.clone(),
				counterparty_node_id: server_b.node_id().to_string(),
				address: Some(foreign.clone()),
				splice_amount_sats: 10_000,
			})
			.await
	};
	let err = splice_out_to_foreign().await.unwrap_err();
	assert!(err.to_string().contains("payout allow-list"), "{err}");
	send_bolt11_payment(&server_a, &server_b, 1_000_000).await;
	tokio::time::sleep(Duration::from_secs(5)).await;

	// Now what a compromised host would do, with one party on its side: that party has the
	// address on its list, so the splice starts. The parties sign the splice transaction, but
	// the other three refuse the first commitment on the new funding output, which would
	// leave us 10,000 sat short. Without that commitment the counterparty never signs the
	// splice, and nothing reaches the chain.
	parties.rogue_payout = Some((0, foreign.clone()));
	parties.kill(0);
	parties.spawn(0);
	let funding_before =
		run_cli(&server_a, &["list-channels"])["channels"][0]["funding_txo"].clone();
	splice_out_to_foreign().await.unwrap();
	let negotiated = tokio::time::timeout(Duration::from_secs(8), splice_txid(&mut events)).await;
	assert!(negotiated.is_err(), "a splice-out to a foreign address went through");
	let mempool: Vec<String> = bitcoind.bitcoind.client.call("getrawmempool", &[]).unwrap();
	assert!(mempool.is_empty(), "something was broadcast: {mempool:?}");
	let funding_after =
		run_cli(&server_a, &["list-channels"])["channels"][0]["funding_txo"].clone();
	assert_eq!(funding_after, funding_before);
}

#[tokio::test]
async fn test_mpc_outflow_limit() {
	let bitcoind = TestBitcoind::new();
	let mut parties = MpcParties::start();
	// Every party lets at most 15,000 sat a day leave our channel balances.
	parties.outflow_per_day = Some(15_000);
	let server_a = start_mpc_server(&bitcoind, &mut parties).await;
	let server_b = LdkServerHandle::start(&bitcoind).await;
	setup_funded_channel(&bitcoind, &server_a, &server_b, 100_000).await;

	// 10,000 sat out fits. What comes in does not count, and does not buy more room.
	send_bolt11_payment(&server_a, &server_b, 10_000_000).await;
	send_bolt11_payment(&server_b, &server_a, 3_000_000).await;
	tokio::time::sleep(Duration::from_secs(5)).await;

	// 8,000 more would make 18,000. This is the payment a compromised LDK Server would
	// send to itself: the parties do not sign the commitment that carries it, so the
	// counterparty never sees it.
	let mut received = server_b.client().subscribe_events().await.unwrap();
	let invoice = server_b
		.client()
		.bolt11_receive(Bolt11ReceiveRequest {
			amount_msat: Some(8_000_000),
			description: None,
			expiry_secs: 3600,
		})
		.await
		.unwrap();
	server_a
		.client()
		.bolt11_send(Bolt11SendRequest {
			invoice: invoice.invoice,
			amount_msat: None,
			route_parameters: None,
		})
		.await
		.unwrap();
	let arrived = tokio::time::timeout(
		Duration::from_secs(10),
		wait_for_event(&mut received, |event| matches!(event, Event::PaymentReceived(_))),
	)
	.await;
	assert!(arrived.is_err(), "a payment beyond the outflow limit went through");
}
