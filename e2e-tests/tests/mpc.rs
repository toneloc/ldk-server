// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! End-to-end tests of LDK Server with Coinbase cb-mpc 2-of-2 MPC-backed channel funding
//! keys, on regtest. Two MPC party processes are started; server A is configured with
//! `[mpc]` and opens a channel to a plain server B.

use std::io::{BufRead, BufReader};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use e2e_tests::{
	close_channel, find_available_port, mine_and_sync, mpc_party_binary_path, run_cli,
	send_bolt11_payment, setup_funded_channel, wait_for_channels, wait_for_force_close_claims,
	LdkServerHandle, TestBitcoind, TestConfigBuilder,
};
use hex_conservative::FromHex;
use ldk_node::bitcoin::consensus::encode::deserialize;
use ldk_node::bitcoin::secp256k1::PublicKey;
use ldk_node::bitcoin::Transaction;
use ldk_server_client::ldk_server_grpc::api::GetBalancesRequest;
use ldk_server_client::ldk_server_grpc::types::BalanceSource;

/// Two MPC party processes (P2 then P1) with their own keystores.
struct MpcParties {
	p1: Option<Child>,
	p2: Option<Child>,
	p1_addr: String,
	p2_addr: String,
	keystore_a: PathBuf,
	keystore_b: PathBuf,
}

fn spawn_party(role: &str, listen: &str, peer: Option<&str>, keystore: &Path) -> Child {
	let mut cmd = Command::new(mpc_party_binary_path());
	cmd.args(["--role", role, "--listen", listen, "--keystore", keystore.to_str().unwrap()]);
	if let Some(peer) = peer {
		cmd.args(["--peer", peer]);
	}
	let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
	let stderr = child.stderr.take().unwrap();
	let tag = format!("mpc-{role}");
	std::thread::spawn(move || {
		for line in BufReader::new(stderr).lines().map_while(Result::ok) {
			eprintln!("[{tag}] {line}");
		}
	});
	child
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
		let keystore_a = tempfile::tempdir().unwrap().into_path();
		#[allow(deprecated)]
		let keystore_b = tempfile::tempdir().unwrap().into_path();
		let p1_addr = format!("127.0.0.1:{}", find_available_port());
		let p2_addr = format!("127.0.0.1:{}", find_available_port());
		let mut parties =
			MpcParties { p1: None, p2: None, p1_addr, p2_addr, keystore_a, keystore_b };
		parties.spawn_all();
		parties
	}

	fn spawn_all(&mut self) {
		self.p2 = Some(spawn_party("p2", &self.p2_addr, None, &self.keystore_b));
		wait_for_port(&self.p2_addr);
		self.p1 = Some(spawn_party("p1", &self.p1_addr, Some(&self.p2_addr), &self.keystore_a));
		wait_for_port(&self.p1_addr);
	}

	fn kill_all(&mut self) {
		for child in [self.p1.take(), self.p2.take()].into_iter().flatten() {
			let mut child = child;
			let _ = child.kill();
			let _ = child.wait();
		}
	}

	/// Kills both parties and starts them again on the same keystores.
	fn restart(&mut self) {
		self.kill_all();
		self.spawn_all();
	}

	fn share_count(dir: &Path) -> usize {
		std::fs::read_dir(dir)
			.unwrap()
			.filter_map(|e| e.ok())
			.filter(|e| e.path().extension().map(|x| x == "share").unwrap_or(false))
			.count()
	}

	/// Aggregate public keys of all shares held by party A (derived from the share blobs).
	fn party_a_pubkeys(&self) -> Vec<PublicKey> {
		let mut keys = Vec::new();
		for entry in std::fs::read_dir(&self.keystore_a).unwrap().filter_map(|e| e.ok()) {
			if entry.path().extension().map(|x| x == "share").unwrap_or(false) {
				let blob = ldk_server_mpc::cbmpc::KeyBlob(std::fs::read(entry.path()).unwrap());
				keys.push(PublicKey::from_slice(&blob.public_key_compressed().unwrap()).unwrap());
			}
		}
		keys
	}
}

impl Drop for MpcParties {
	fn drop(&mut self) {
		self.kill_all();
		let _ = std::fs::remove_dir_all(&self.keystore_a);
		let _ = std::fs::remove_dir_all(&self.keystore_b);
	}
}

async fn start_mpc_server(bitcoind: &TestBitcoind, parties: &MpcParties) -> LdkServerHandle {
	let party_address = parties.p1_addr.clone();
	LdkServerHandle::start_with_config(bitcoind, move |params| {
		let mut config = TestConfigBuilder::new(params).alias(Some("mpc-node")).build();
		// The on-chain wallet gets its own mnemonic so it is not derivable from the node seed.
		let wallet_mnemonic = params.storage_dir.join("onchain_wallet_mnemonic");
		config = config.replacen(
			"[node]\n",
			&format!("[node]\nonchain_wallet_mnemonic_path = \"{}\"\n", wallet_mnemonic.display()),
			1,
		);
		config.push_str(&format!("\n[mpc]\nparty_address = \"{party_address}\"\n"));
		config
	})
	.await
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
	let server_a = start_mpc_server(&bitcoind, &parties).await;
	let server_b = LdkServerHandle::start(&bitcoind).await;

	assert_separate_wallet_mnemonic(&server_a);
	let user_channel_id = setup_funded_channel(&bitcoind, &server_a, &server_b, 100_000).await;

	// Exactly one distributed key was generated and each party holds one share.
	assert_eq!(MpcParties::share_count(&parties.keystore_a), 1);
	assert_eq!(MpcParties::share_count(&parties.keystore_b), 1);
	let mpc_pubkeys = parties.party_a_pubkeys();
	assert_eq!(mpc_pubkeys.len(), 1);

	// Payments in both directions (each commitment update is signed via MPC on server A).
	send_bolt11_payment(&server_a, &server_b, 10_000_000).await;
	send_bolt11_payment(&server_b, &server_a, 3_000_000).await;

	// Restart the MPC parties: shares must be restored from disk and signing must resume.
	parties.restart();
	send_bolt11_payment(&server_a, &server_b, 1_000_000).await;

	// Restart LDK Server: channel signers are re-derived through the MPC service.
	let mut server_a = server_a;
	server_a.restart().await;
	let channels = wait_for_channels(&server_a, 1, Duration::from_secs(30)).await;
	let funding = channels[0].funding_txo.clone().expect("funding txo");
	send_bolt11_payment(&server_b, &server_a, 500_000).await;
	assert_eq!(MpcParties::share_count(&parties.keystore_a), 1, "no new keys after restart");

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
		pubkeys.contains(&mpc_pubkeys[0]),
		"closing tx multisig {pubkeys:?} does not contain MPC key {}",
		mpc_pubkeys[0]
	);

	let balances_after = server_a.client().get_balances(GetBalancesRequest {}).await.unwrap();
	e2e_tests::assert_recovered_balance(&balances_before, &balances_after);
	let _ = run_cli(&server_a, &["list-channels"]);
}

#[tokio::test]
async fn test_mpc_channel_force_close() {
	let bitcoind = TestBitcoind::new();
	let parties = MpcParties::start();
	let server_a = start_mpc_server(&bitcoind, &parties).await;
	let server_b = LdkServerHandle::start(&bitcoind).await;

	let user_channel_id = setup_funded_channel(&bitcoind, &server_a, &server_b, 100_000).await;
	send_bolt11_payment(&server_a, &server_b, 5_000_000).await;
	let channels = wait_for_channels(&server_a, 1, Duration::from_secs(30)).await;
	let funding = channels[0].funding_txo.clone().expect("funding txo");
	let mpc_pubkeys = parties.party_a_pubkeys();

	// Holder force-close: our commitment transaction is signed with the MPC funding key and
	// broadcast by server A.
	let output = run_cli(&server_a, &["force-close-channel", &user_channel_id, server_b.node_id()]);
	assert!(output.is_object());
	let commitment_tx = wait_for_spender(&bitcoind, &funding.txid, funding.vout).await;
	let pubkeys = funding_multisig_pubkeys(&commitment_tx);
	assert!(pubkeys.contains(&mpc_pubkeys[0]), "commitment tx not signed under MPC key");

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
