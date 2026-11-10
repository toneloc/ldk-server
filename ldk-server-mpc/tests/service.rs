//! End-to-end tests of the party services over TCP: a client and four parties, any three of
//! which must agree.

use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use ldk_server_mpc::bitcoin::secp256k1::{Message, Secp256k1};
use ldk_server_mpc::client::{ClientError, MpcClient};
use ldk_server_mpc::mesh::{Identity, PartyInfo};
use ldk_server_mpc::party::{PartyConfig, PartyService};
use ldk_server_mpc::protocol::{ErrorCode, SigningContext, SigningOp};

fn tmp_dir(name: &str) -> PathBuf {
	let mut d = std::env::temp_dir();
	let nanos =
		std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
	d.push(format!("ldk-server-mpc-test-{name}-{nanos}"));
	d
}

/// Keys used to secure a cluster's links and shares, if any.
#[derive(Clone, Copy, Default)]
struct Keys {
	client_psk: Option<[u8; 32]>,
	peer_psk: Option<[u8; 32]>,
	share_key: Option<[u8; 32]>,
}

/// A set of parties on loopback. A party can be stopped and started again on the same
/// keystore, addresses and identity.
struct Cluster {
	threshold: usize,
	infos: Vec<PartyInfo>,
	identities: Vec<Vec<u8>>,
	client_addrs: Vec<SocketAddr>,
	dirs: Vec<PathBuf>,
	keys: Keys,
	parties: Vec<Option<Arc<PartyService>>>,
	/// Listeners bound when the addresses were picked, held until the party first starts so
	/// no other test can take the port in between: (clients, parties).
	bound: Vec<Option<(TcpListener, TcpListener)>>,
}

impl Cluster {
	fn start(name: &str, n: usize, threshold: usize) -> Cluster {
		Self::start_with(name, n, threshold, Keys::default())
	}

	fn start_with(name: &str, n: usize, threshold: usize, keys: Keys) -> Cluster {
		let listeners: Vec<(TcpListener, TcpListener)> = (0..n)
			.map(|_| {
				let bind = || TcpListener::bind("127.0.0.1:0").unwrap();
				(bind(), bind())
			})
			.collect();
		let identities: Vec<(Identity, Vec<u8>)> =
			(0..n).map(|_| Identity::generate().unwrap()).collect();
		let infos: Vec<PartyInfo> = identities
			.iter()
			.enumerate()
			.map(|(i, (id, _))| PartyInfo {
				name: format!("party-{i}"),
				addr: listeners[i].1.local_addr().unwrap(),
				identity: id.public_key(),
			})
			.collect();
		let mut cluster = Cluster {
			threshold,
			infos,
			identities: identities.into_iter().map(|(_, pkcs8)| pkcs8).collect(),
			client_addrs: listeners.iter().map(|l| l.0.local_addr().unwrap()).collect(),
			dirs: (0..n).map(|i| tmp_dir(&format!("{name}-{i}"))).collect(),
			keys,
			parties: (0..n).map(|_| None).collect(),
			bound: listeners.into_iter().map(Some).collect(),
		};
		for i in 0..n {
			cluster.up(i);
		}
		cluster
	}

	fn config(&self, i: usize) -> PartyConfig {
		PartyConfig {
			name: self.infos[i].name.clone(),
			parties: self.infos.clone(),
			threshold: self.threshold,
			identity: Identity::from_pkcs8(&self.identities[i]).unwrap(),
			listen_addr: self.client_addrs[i],
			keystore_dir: self.dirs[i].clone(),
			protocol_timeout: Duration::from_secs(20),
			client_timeout: Duration::from_secs(60),
			policy: Default::default(),
			client_psk: self.keys.client_psk,
			peer_psk: self.keys.peer_psk,
			share_key: self.keys.share_key,
			kit_dir: None,
		}
	}

	/// Starts party `i`.
	fn up(&mut self, i: usize) {
		let svc = PartyService::new(self.config(i)).unwrap();
		let bind = |addr: SocketAddr| {
			let start = Instant::now();
			loop {
				match TcpListener::bind(addr) {
					Ok(l) => return l,
					Err(e) => {
						assert!(start.elapsed() < Duration::from_secs(10), "bind {addr}: {e}")
					},
				}
				thread::sleep(Duration::from_millis(50));
			}
		};
		let (clients, peers) = match self.bound[i].take() {
			Some(listeners) => listeners,
			None => (bind(self.client_addrs[i]), bind(self.infos[i].addr)),
		};
		let s = Arc::clone(&svc);
		thread::spawn(move || s.serve_on(clients, peers).unwrap());
		self.parties[i] = Some(svc);
	}

	/// Stops party `i`: it no longer accepts clients or other parties.
	fn down(&mut self, i: usize) {
		let svc = self.parties[i].take().expect("party is up");
		svc.request_shutdown();
		// The listeners close once their accept loops have seen the shutdown.
		let start = Instant::now();
		while std::net::TcpStream::connect(self.infos[i].addr).is_ok()
			|| std::net::TcpStream::connect(self.client_addrs[i]).is_ok()
		{
			assert!(start.elapsed() < Duration::from_secs(10), "party {i} did not stop");
			thread::sleep(Duration::from_millis(20));
		}
	}

	fn party(&self, i: usize) -> &Arc<PartyService> {
		self.parties[i].as_ref().expect("party is up")
	}

	/// A client that sends its requests to party `i` only.
	fn client_of(&self, i: usize) -> MpcClient {
		let client = MpcClient::new(self.client_addrs[i]);
		match self.keys.client_psk {
			Some(psk) => client.with_psk(psk),
			None => client,
		}
	}

	/// A client that knows every party, as LDK Server does.
	fn client(&self) -> MpcClient {
		let client = MpcClient::with_parties(self.client_addrs.clone());
		match self.keys.client_psk {
			Some(psk) => client.with_psk(psk),
			None => client,
		}
	}

	fn shares(&self, i: usize) -> usize {
		ldk_server_mpc::party::KeyStore::open(&self.dirs[i]).unwrap().count().unwrap()
	}
}

fn verify(
	pk: &ldk_server_mpc::bitcoin::secp256k1::PublicKey, digest: [u8; 32],
	sig: &ldk_server_mpc::bitcoin::secp256k1::ecdsa::Signature,
) {
	Secp256k1::new().verify_ecdsa(&Message::from_digest(digest), sig, pk).unwrap();
}

#[test]
fn keygen_sign_and_restore_over_tcp() {
	let secp = Secp256k1::new();
	let mut cluster = Cluster::start("basic", 4, 3);
	let client = cluster.client();
	client.ping().unwrap();

	let key_id = [0x11u8; 32];
	let pk = client.ensure_key(&key_id).unwrap();
	// Idempotent: a second call returns the same key without a new key generation.
	assert_eq!(client.ensure_key(&key_id).unwrap(), pk);
	// Every party stored exactly one share and agrees on the key, whichever one is asked.
	for i in 0..4 {
		assert_eq!(cluster.shares(i), 1);
		assert_eq!(cluster.client_of(i).get_public_key(&key_id).unwrap(), pk);
	}

	let digest = [0xabu8; 32];
	let ctx = SigningContext { op: Some(SigningOp::Test), ..Default::default() };
	let sig = client.sign(&secp, &key_id, &digest, Some(ctx), Some(&pk)).unwrap();
	verify(&pk, digest, &sig);
	// Low-S enforced.
	let mut normalized = sig;
	normalized.normalize_s();
	assert_eq!(normalized, sig);
	// Any party can lead.
	for i in 0..4 {
		let digest = [0xb0 + i as u8; 32];
		let sig = cluster.client_of(i).sign(&secp, &key_id, &digest, None, Some(&pk)).unwrap();
		verify(&pk, digest, &sig);
	}

	// Restart every party on its keystore: shares are restored.
	for i in 0..4 {
		cluster.down(i);
		cluster.up(i);
	}
	assert_eq!(client.get_public_key(&key_id).unwrap(), pk, "key share restored after restart");
	let sig = client.sign(&secp, &key_id, &[0xcdu8; 32], None, Some(&pk)).unwrap();
	verify(&pk, [0xcdu8; 32], &sig);
}

#[test]
fn signing_survives_one_party_down_but_not_two() {
	let secp = Secp256k1::new();
	let mut cluster = Cluster::start("down", 4, 3);
	let client = cluster.client();
	let key_id = [0x21u8; 32];
	let pk = client.ensure_key(&key_id).unwrap();

	// Whichever single party is down, the other three sign.
	for dead in [3, 1, 0] {
		cluster.down(dead);
		let digest = [0x30 + dead as u8; 32];
		// The client knows every party, so it also gets past a dead leader.
		let sig = client.sign(&secp, &key_id, &digest, None, Some(&pk)).unwrap();
		verify(&pk, digest, &sig);
		cluster.up(dead);
	}

	// With two parties down no quorum exists.
	cluster.down(2);
	cluster.down(3);
	let err = client.sign(&secp, &key_id, &[0x3fu8; 32], None, Some(&pk)).unwrap_err();
	assert!(matches!(err, ClientError::Remote { code: ErrorCode::PeerUnavailable, .. }), "{err}");
	// Back to three: signing resumes.
	cluster.up(2);
	let sig = client.sign(&secp, &key_id, &[0x40u8; 32], None, Some(&pk)).unwrap();
	verify(&pk, [0x40u8; 32], &sig);
}

#[test]
fn key_generation_needs_every_party_and_stores_nothing_otherwise() {
	let mut cluster = Cluster::start("keygen-all", 4, 3);
	cluster.down(2);
	let client = cluster.client_of(0);
	let err = client.ensure_key(&[0x41u8; 32]).unwrap_err();
	assert!(matches!(err, ClientError::Remote { code: ErrorCode::PeerUnavailable, .. }), "{err}");
	for i in 0..4 {
		assert_eq!(cluster.shares(i), 0, "party {i} stored a share of a key that was never made");
	}
	cluster.up(2);
	client.ensure_key(&[0x41u8; 32]).unwrap();
	for i in 0..4 {
		assert_eq!(cluster.shares(i), 1);
	}
}

#[test]
fn invalid_key_id_is_rejected() {
	let secp = Secp256k1::new();
	let cluster = Cluster::start("badkey", 4, 3);
	let client = cluster.client();
	let err = client.get_public_key(&[9u8; 32]).unwrap_err();
	assert!(matches!(err, ClientError::Remote { code: ErrorCode::KeyNotFound, .. }), "{err}");
	let err = client.sign(&secp, &[9u8; 32], &[0u8; 32], None, None).unwrap_err();
	assert!(matches!(err, ClientError::Remote { code: ErrorCode::KeyNotFound, .. }), "{err}");
}

#[test]
fn unreachable_parties_and_timeouts_are_bounded() {
	// Nothing listening on this port.
	let free = TcpListener::bind("127.0.0.1:0").unwrap();
	let addr = free.local_addr().unwrap();
	drop(free);
	let client = MpcClient::new(addr).with_timeouts(
		Duration::from_millis(500),
		Duration::from_millis(500),
		Duration::from_millis(500),
	);
	assert!(matches!(client.ping().unwrap_err(), ClientError::Io(_)));

	// A "party" that accepts connections but never answers.
	let listener = TcpListener::bind("127.0.0.1:0").unwrap();
	let addr = listener.local_addr().unwrap();
	thread::spawn(move || {
		let mut held = Vec::new();
		for c in listener.incoming() {
			held.push(c);
		}
	});
	let client = MpcClient::new(addr).with_timeouts(
		Duration::from_secs(1),
		Duration::from_millis(300),
		Duration::from_millis(300),
	);
	let secp = Secp256k1::new();
	let t0 = Instant::now();
	let err = client.sign(&secp, &[1u8; 32], &[2u8; 32], None, None).unwrap_err();
	assert!(err.is_timeout(), "{err}");
	assert!(t0.elapsed() < Duration::from_secs(3));
}

#[test]
fn repeated_and_concurrent_requests() {
	let cluster = Cluster::start("concurrent", 4, 3);
	let client = cluster.client();
	let secp = Secp256k1::new();

	// Several keys, created concurrently.
	let mut handles = Vec::new();
	for i in 0..3u8 {
		let client = client.clone();
		handles.push(thread::spawn(move || {
			let key_id = [i; 32];
			(key_id, client.ensure_key(&key_id).unwrap())
		}));
	}
	let keys: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
	let mut pks: Vec<_> = keys.iter().map(|(_, pk)| *pk).collect();
	pks.dedup();
	assert_eq!(pks.len(), 3, "distinct keys");

	// Concurrent signing on the same key and on different keys, through different leaders.
	let mut handles = Vec::new();
	for (n, (key_id, pk)) in keys.iter().cycle().take(6).enumerate() {
		let client = cluster.client_of(n % 4);
		let (key_id, pk) = (*key_id, *pk);
		handles.push(thread::spawn(move || {
			let secp = Secp256k1::new();
			for j in 0..3u8 {
				let mut digest = [j; 32];
				digest[0] = n as u8;
				let sig = client.sign(&secp, &key_id, &digest, None, Some(&pk)).unwrap();
				verify(&pk, digest, &sig);
			}
		}));
	}
	for h in handles {
		h.join().unwrap();
	}

	// Repeated sequential signing.
	let (key_id, pk) = keys[0];
	for j in 0..5u8 {
		let digest = [0xf0 + j; 32];
		let sig = client.sign(&secp, &key_id, &digest, None, Some(&pk)).unwrap();
		verify(&pk, digest, &sig);
	}
}

#[test]
fn a_party_that_lost_its_keystore_cannot_regenerate_a_key() {
	let mut cluster = Cluster::start("lost", 4, 3);
	let key_id = [0x55u8; 32];
	let pk = cluster.client().ensure_key(&key_id).unwrap();

	// Party 0 comes back with an empty keystore and is asked for the key again.
	cluster.down(0);
	cluster.dirs[0] = tmp_dir("lost-0-fresh");
	cluster.up(0);
	let err = cluster.client_of(0).ensure_key(&key_id).unwrap_err();
	assert!(matches!(err, ClientError::Remote { code: ErrorCode::KeyMismatch, .. }), "{err}");
	assert_eq!(cluster.shares(1), 1);
	// The other three still sign with the original key.
	let secp = Secp256k1::new();
	let sig = cluster.client_of(1).sign(&secp, &key_id, &[0x56u8; 32], None, Some(&pk)).unwrap();
	verify(&pk, [0x56u8; 32], &sig);
}

#[test]
fn secured_links_and_encrypted_shares() {
	use ldk_server_mpc::secure::AtRestKey;
	let keys = Keys {
		client_psk: Some([0xa1u8; 32]),
		peer_psk: Some([0xb2u8; 32]),
		share_key: Some([0xc3u8; 32]),
	};
	let mut cluster = Cluster::start_with("secure", 3, 2, keys);
	cluster.party(0).ensure_tdh2().unwrap();
	let secp = Secp256k1::new();

	// Correct PSK: works end to end.
	let client = cluster.client();
	let key_id = [0x61u8; 32];
	let pk = client.ensure_key(&key_id).unwrap();
	let sig = client.sign(&secp, &key_id, &[0x62u8; 32], None, Some(&pk)).unwrap();
	verify(&pk, [0x62u8; 32], &sig);

	// Key shares, including the TDH2 share, are encrypted on disk.
	for dir in &cluster.dirs {
		assert!(dir.join("tdh2.keyshare").exists());
		for entry in std::fs::read_dir(dir).unwrap().filter_map(|e| e.ok()) {
			let name = entry.file_name().to_string_lossy().to_string();
			if name.ends_with(".share") || name == "tdh2.keyshare" {
				let bytes = std::fs::read(entry.path()).unwrap();
				assert!(AtRestKey::is_encrypted(&bytes), "{name} not encrypted");
				assert!(AtRestKey::new(&keys.share_key.unwrap()).open(&bytes).is_ok());
			}
		}
	}

	// Wrong / missing client PSK: rejected before any request is served.
	let bad = MpcClient::new(cluster.client_addrs[0]).with_psk([0xffu8; 32]);
	assert!(matches!(bad.ping().unwrap_err(), ClientError::Io(_)));
	assert!(MpcClient::new(cluster.client_addrs[0]).ping().is_err());

	// A party with the wrong group PSK cannot take part, so (2 of 3) the others carry on.
	cluster.down(2);
	cluster.keys.peer_psk = Some([0x00u8; 32]);
	cluster.up(2);
	let sig = cluster.client_of(0).sign(&secp, &key_id, &[0x63u8; 32], None, Some(&pk)).unwrap();
	verify(&pk, [0x63u8; 32], &sig);
	let err =
		cluster.client_of(2).sign(&secp, &key_id, &[0x64u8; 32], None, Some(&pk)).unwrap_err();
	assert!(matches!(err, ClientError::Remote { code: ErrorCode::PeerUnavailable, .. }), "{err}");

	// Restart with the wrong share key: the shares cannot be read.
	cluster.down(1);
	cluster.keys.share_key = Some([0x00u8; 32]);
	assert!(PartyService::new(cluster.config(1)).is_err(), "wrong share key must fail");
}

// ---------------------------------------------------------------------------
// Revocation secrets: kits, joint release, and compromised hosts and parties
// ---------------------------------------------------------------------------

mod revocation {
	use ldk_server_mpc::bitcoin::absolute::LockTime;
	use ldk_server_mpc::bitcoin::consensus::encode::serialize;
	use ldk_server_mpc::bitcoin::hashes::Hash;
	use ldk_server_mpc::bitcoin::secp256k1::{PublicKey, SecretKey};
	use ldk_server_mpc::bitcoin::transaction::Version;
	use ldk_server_mpc::bitcoin::{
		sighash, Amount, EcdsaSighashType, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
		Txid, Witness,
	};
	use ldk_server_mpc::kit::{
		combine_seed, generate_segment, segment_file_name, split_seed, INITIAL_COMMITMENT_NUMBER,
	};
	use ldk_server_mpc::protocol::{
		CounterpartyKeys, Derivation, HolderProof, KeyKind, SessionAck, SessionOp, SessionStart,
		SignItem,
	};
	use lightning::ln::chan_utils::{self, CounterpartyCommitmentSecrets};
	use lightning::types::features::ChannelTypeFeatures;
	use lightning::util::ser::Writeable;

	use super::*;

	const TOP: u64 = INITIAL_COMMITMENT_NUMBER;
	const VALUE: u64 = 100_000;

	struct Channel {
		cluster: Cluster,
		client: MpcClient,
		id: [u8; 32],
		funding: PublicKey,
		payment: PublicKey,
		cp_funding: SecretKey,
		cp_payment: PublicKey,
	}

	impl Channel {
		fn funding_script(&self) -> ScriptBuf {
			let secp = Secp256k1::new();
			chan_utils::make_funding_redeemscript(
				&self.funding,
				&PublicKey::from_secret_key(&secp, &self.cp_funding),
			)
		}

		fn counterparty_keys(&self) -> CounterpartyKeys {
			let secp = Secp256k1::new();
			let other =
				PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[9u8; 32]).unwrap());
			CounterpartyKeys {
				funding_pubkey: PublicKey::from_secret_key(&secp, &self.cp_funding).serialize(),
				revocation_basepoint: other.serialize(),
				payment_point: self.cp_payment.serialize(),
				delayed_payment_basepoint: other.serialize(),
				htlc_basepoint: other.serialize(),
			}
		}

		fn commitment_tx(&self, number: u64, outputs: Vec<TxOut>) -> Transaction {
			let factor = chan_utils::get_commitment_transaction_number_obscure_factor(
				&self.payment,
				&self.cp_payment,
				true,
			);
			let obscured = factor ^ (TOP - number);
			Transaction {
				version: Version::TWO,
				lock_time: LockTime::from_consensus((0x20 << 24) | (obscured & 0xff_ffff) as u32),
				input: vec![TxIn {
					previous_output: OutPoint { txid: Txid::all_zeros(), vout: 0 },
					script_sig: ScriptBuf::new(),
					sequence: Sequence((0x80 << 24) | (obscured >> 24) as u32),
					witness: Witness::new(),
				}],
				output: outputs,
			}
		}

		fn sighash(&self, tx: &Transaction) -> [u8; 32] {
			sighash::SighashCache::new(tx)
				.p2wsh_signature_hash(
					0,
					&self.funding_script(),
					Amount::from_sat(VALUE),
					EcdsaSighashType::All,
				)
				.unwrap()
				.to_byte_array()
		}

		/// Has the parties sign the counterparty's commitment, as LDK does on every update.
		fn sign_counterparty_commitment(&self, number: u64) {
			let features = ChannelTypeFeatures::only_static_remote_key();
			let to_us = chan_utils::get_countersigner_payment_script(&features, &self.payment);
			let tx = self.commitment_tx(
				number,
				vec![TxOut { value: Amount::from_sat(60_000), script_pubkey: to_us }],
			);
			let context = SigningContext {
				op: Some(SigningOp::CounterpartyCommitment),
				channel_keys_id: Some([1u8; 32]),
				channel_value_satoshis: Some(VALUE),
				commitment_number: Some(number),
				channel_type_features: Some(features.encode()),
				counterparty_keys: Some(self.counterparty_keys()),
				holder_selected_contest_delay: Some(144),
				counterparty_selected_contest_delay: Some(144),
				transaction: Some(serialize(&tx)),
				input_index: 0,
				input_value_sat: VALUE,
				witness_script: Some(self.funding_script().to_bytes()),
				sighash_type: 0x01,
				per_commitment_point: Some(self.cp_payment.serialize()),
				..Default::default()
			};
			let item = SignItem {
				key_id: [0xf1; 32],
				derivation: Derivation::None,
				digest: self.sighash(&tx),
				context,
				splice: None,
			};
			self.client
				.sign_batch(&Secp256k1::new(), Some(self.id), vec![item], Some(&[self.funding]))
				.unwrap();
		}

		/// Our commitment `number` as the counterparty would sign it.
		fn holder_proof(&self, number: u64, signer: &SecretKey) -> HolderProof {
			let tx = self.commitment_tx(
				number,
				vec![TxOut {
					value: Amount::from_sat(60_000),
					script_pubkey: ScriptBuf::new_op_return([1u8]),
				}],
			);
			let msg = Message::from_digest(self.sighash(&tx));
			HolderProof {
				transaction: serialize(&tx),
				counterparty_sig: Secp256k1::new().sign_ecdsa(&msg, signer).serialize_compact(),
			}
		}

		fn validate(&self, number: u64) {
			let proof = self.holder_proof(number, &self.cp_funding);
			self.client.holder_commitment_validated(&self.id, number, Some(proof)).unwrap();
		}

		fn release(&self, idx: u64) -> Result<[u8; 32], ClientError> {
			self.client.release_commitment_secret(&self.id, idx, None)
		}

		/// One channel update: the parties sign the counterparty's new commitment, the
		/// counterparty signs ours (`old - 1`), and we revoke `old`.
		fn update(&self, old: u64) -> [u8; 32] {
			self.sign_counterparty_commitment(old - 1);
			self.validate(old - 1);
			self.release(old).unwrap()
		}

		/// A request to sign our own commitment `number` for broadcast.
		fn holder_commitment_item(&self, number: u64) -> SignItem {
			let tx = self.commitment_tx(
				number,
				vec![TxOut {
					value: Amount::from_sat(60_000),
					script_pubkey: ScriptBuf::new_op_return([1u8]),
				}],
			);
			let point = self.client.per_commitment_point(&self.id, number).unwrap();
			let context = SigningContext {
				op: Some(SigningOp::HolderCommitment),
				channel_keys_id: Some([1u8; 32]),
				channel_value_satoshis: Some(VALUE),
				commitment_number: Some(number),
				channel_type_features: Some(ChannelTypeFeatures::only_static_remote_key().encode()),
				counterparty_keys: Some(self.counterparty_keys()),
				holder_selected_contest_delay: Some(144),
				counterparty_selected_contest_delay: Some(144),
				transaction: Some(serialize(&tx)),
				input_index: 0,
				input_value_sat: VALUE,
				witness_script: Some(self.funding_script().to_bytes()),
				sighash_type: 0x01,
				per_commitment_point: Some(point.serialize()),
				..Default::default()
			};
			SignItem {
				key_id: [0xf1; 32],
				derivation: Derivation::None,
				digest: self.sighash(&tx),
				context,
				splice: None,
			}
		}

		fn sign_holder_commitment(&self, number: u64) -> Result<(), ClientError> {
			let item = self.holder_commitment_item(number);
			self.client
				.sign_batch(&Secp256k1::new(), Some(self.id), vec![item], Some(&[self.funding]))
				.map(|_| ())
		}
	}

	/// Starts four parties (any three must agree), runs the ceremony for `kits` kits of
	/// `states` states each, and creates the channel's keys.
	fn channel(name: &str, kits: u8, states: u32) -> Channel {
		let cluster = Cluster::start(name, 4, 3);
		let client = cluster.client();

		// The parties generate their joint TDH2 key and each publishes the public key.
		cluster.party(0).ensure_tdh2().unwrap();
		let tdh2_pub = cluster.party(0).tdh2_public_key().unwrap();
		for i in 0..4 {
			assert_eq!(cluster.party(i).tdh2_public_key().unwrap(), tdh2_pub);
			let published = std::fs::read_to_string(cluster.dirs[i].join("tdh2.pub")).unwrap();
			assert_eq!(published, hex(&tdh2_pub));
		}

		// The offline ceremony: custodians rebuild the master seed and make the kits. Every
		// party gets a copy of every kit file.
		let pieces = split_seed(&[0x5eu8; 32], 2, 3, |b| b.fill(0x17)).unwrap();
		let seed = combine_seed(&pieces[1..]).unwrap();
		for k in 0..kits {
			let kit_id = [0xa0 + k; 32];
			let segment = generate_segment(&seed, &kit_id, &tdh2_pub, TOP, states).unwrap();
			for dir in &cluster.dirs {
				std::fs::write(dir.join("kits").join(segment_file_name(&kit_id, TOP)), &segment)
					.unwrap();
			}
		}

		let id = [0xc1u8; 32];
		let key = |n: u8, kind: KeyKind| client.ensure_channel_key(&[n; 32], &id, kind).unwrap();
		let funding = key(0xf1, KeyKind::Funding);
		let payment = key(0xf2, KeyKind::Payment);
		key(0xf3, KeyKind::DelayedPayment);
		let secp = Secp256k1::new();
		Channel {
			cluster,
			client,
			id,
			funding,
			payment,
			cp_funding: SecretKey::from_slice(&[0x66u8; 32]).unwrap(),
			cp_payment: PublicKey::from_secret_key(
				&secp,
				&SecretKey::from_slice(&[0x55u8; 32]).unwrap(),
			),
		}
	}

	fn hex(bytes: &[u8]) -> String {
		bytes.iter().map(|b| format!("{b:02x}")).collect()
	}

	fn point_of(secret: &[u8; 32]) -> PublicKey {
		PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(secret).unwrap())
	}

	fn denied(err: ClientError) -> String {
		match err {
			ClientError::Remote { code: ErrorCode::PolicyDenied, message } => message,
			other => panic!("expected a policy denial, got {other}"),
		}
	}

	/// What party `to` answers when party `from` asks it directly, as a compromised party
	/// that ignores its own policy would.
	fn ask_as(cluster: &Cluster, from: usize, to: usize, op: SessionOp) -> SessionAck {
		let mut link = cluster.party(from).roster().connect(to).unwrap();
		let start = SessionStart { session: [7u8; 16], members: vec![from as u8, to as u8], op };
		link.write_frame(&start.encode()).unwrap();
		SessionAck::decode(&link.read_frame().unwrap()).unwrap()
	}

	#[test]
	fn secrets_are_released_in_order_and_fit_the_shachain() {
		let ch = channel("release", 1, 12);
		// No party stores a seed or a secret.
		for dir in &ch.cluster.dirs {
			assert!(!dir.join("master.secret").exists());
		}

		let p0 = ch.client.per_commitment_point(&ch.id, TOP).unwrap();
		assert_eq!(ch.client.per_commitment_point(&ch.id, TOP).unwrap(), p0, "stable");
		// Every party bound the same kit to the channel and serves the same points.
		let kit = ch.cluster.party(0).policy().kit_of(&ch.id).unwrap().unwrap();
		for i in 0..4 {
			assert_eq!(ch.cluster.party(i).policy().kit_of(&ch.id).unwrap(), Some(kit));
			assert_eq!(ch.cluster.client_of(i).per_commitment_point(&ch.id, TOP).unwrap(), p0);
		}

		// Nothing is releasable before a newer state is validated.
		assert!(denied(ch.release(TOP).unwrap_err()).contains("no holder commitment validated"));
		ch.client.holder_commitment_validated(&ch.id, TOP, None).unwrap();
		assert!(ch.release(TOP).is_err());

		// Ten channel updates. The counterparty's shachain store accepts every secret.
		let mut peer = CounterpartyCommitmentSecrets::new();
		for i in 0..10u64 {
			let old = TOP - i;
			let point = ch.client.per_commitment_point(&ch.id, old).unwrap();
			let secret = ch.update(old);
			assert_eq!(point_of(&secret), point);
			// A retry, through another party, gives the same secret.
			let again = ch.cluster.client_of(2).release_commitment_secret(&ch.id, old, None);
			assert_eq!(again.unwrap(), secret);
			peer.provide_secret(old, secret).expect("fits the shachain");
			// The state that is now current, and every later one, stay sealed.
			assert!(ch.release(old - 1).is_err());
			assert!(ch.release(old - 2).is_err());
		}
	}

	#[test]
	fn the_hosts_word_does_not_release_a_secret() {
		let ch = channel("hostword", 1, 6);
		ch.client.per_commitment_point(&ch.id, TOP).unwrap();
		ch.sign_counterparty_commitment(TOP - 1);

		// A compromised host claims the next state was validated: with no proof, with a
		// signature that is not the counterparty's, and with a real signature on another state.
		let msg = denied(ch.client.holder_commitment_validated(&ch.id, TOP - 1, None).unwrap_err());
		assert!(msg.contains("needs the counterparty's signature"), "{msg}");
		let forged = ch.holder_proof(TOP - 1, &SecretKey::from_slice(&[0x99u8; 32]).unwrap());
		let msg = denied(
			ch.client.holder_commitment_validated(&ch.id, TOP - 1, Some(forged)).unwrap_err(),
		);
		assert!(msg.contains("not signed by the counterparty"), "{msg}");
		let other_state = ch.holder_proof(TOP - 1, &ch.cp_funding);
		let msg = denied(
			ch.client.holder_commitment_validated(&ch.id, TOP - 2, Some(other_state)).unwrap_err(),
		);
		assert!(msg.contains("is not holder commitment"), "{msg}");

		// So the current state's secret stays sealed, whichever party is asked.
		for i in 0..4 {
			assert!(ch.cluster.client_of(i).release_commitment_secret(&ch.id, TOP, None).is_err());
		}
	}

	#[test]
	fn a_compromised_party_cannot_release_or_rebind_on_its_own() {
		let ch = channel("rogue", 1, 6);
		ch.client.per_commitment_point(&ch.id, TOP).unwrap();
		ch.update(TOP);

		// Party 3 is compromised: it ignores its own policy and asks the others directly for
		// the current state, a future state, and a validation without proof.
		for to in 0..3 {
			for idx in [TOP - 1, TOP - 3] {
				let op = SessionOp::ReleaseSecret { channel: ch.id, idx, newer: None };
				match ask_as(&ch.cluster, 3, to, op) {
					SessionAck::Error { code, .. } => assert_eq!(code, ErrorCode::PolicyDenied),
					SessionAck::Ok { .. } => panic!("party {to} released secret {idx}"),
				}
			}
			let claim = SessionOp::HolderCommitmentValidated {
				channel: ch.id,
				commitment_number: TOP - 2,
				proof: None,
			};
			assert!(matches!(ask_as(&ch.cluster, 3, to, claim), SessionAck::Error { .. }));
			// It may not swap the channel's kit for another either.
			let swap = SessionOp::BindKit { channel: ch.id, kit_id: [0xee; 32] };
			assert!(matches!(ask_as(&ch.cluster, 3, to, swap), SessionAck::Error { .. }));
		}

		// It cannot speak for another party: the leader of a session must be the party that
		// proved its identity on the link.
		let mut link = ch.cluster.party(3).roster().connect(0).unwrap();
		let start = SessionStart {
			session: [8u8; 16],
			members: vec![1, 0],
			op: SessionOp::ReleaseSecret { channel: ch.id, idx: TOP, newer: None },
		};
		link.write_frame(&start.encode()).unwrap();
		assert!(matches!(
			SessionAck::decode(&link.read_frame().unwrap()).unwrap(),
			SessionAck::Error { code: ErrorCode::BadRequest, .. }
		));

		// For the one state that may be released, another party's answer alone is not the
		// secret: it takes three.
		let op = SessionOp::ReleaseSecret { channel: ch.id, idx: TOP, newer: None };
		let partial = match ask_as(&ch.cluster, 3, 0, op) {
			SessionAck::Ok { payload } => payload,
			SessionAck::Error { message, .. } => panic!("{message}"),
		};
		let secret = ch.release(TOP).unwrap();
		assert!(!partial.windows(32).any(|w| w == secret));
	}

	#[test]
	fn a_channel_keeps_working_with_one_party_down() {
		let mut ch = channel("three", 1, 12);
		ch.client.per_commitment_point(&ch.id, TOP).unwrap();
		let mut peer = CounterpartyCommitmentSecrets::new();
		peer.provide_secret(TOP, ch.update(TOP)).unwrap();

		// Each party in turn is down for one update, the leader included.
		for (n, dead) in [3usize, 0, 2, 1].into_iter().enumerate() {
			ch.cluster.down(dead);
			let old = TOP - 1 - n as u64;
			peer.provide_secret(old, ch.update(old)).expect("fits the shachain");
			ch.cluster.up(dead);
		}

		// With two down, nothing is signed and nothing is released.
		ch.cluster.down(0);
		ch.cluster.down(1);
		assert!(ch.release(TOP - 4).is_err());
		assert!(ch.sign_holder_commitment(TOP - 5).is_err());
	}

	#[test]
	fn a_party_that_missed_updates_catches_up_from_the_proof() {
		let mut ch = channel("stale", 1, 12);
		ch.client.per_commitment_point(&ch.id, TOP).unwrap();
		ch.update(TOP);

		// Party 3 is down for two updates.
		ch.cluster.down(3);
		ch.update(TOP - 1);
		ch.update(TOP - 2);
		ch.cluster.up(3);
		fn validated(ch: &Channel, i: usize) -> Option<u64> {
			ch.cluster.party(i).policy().channel_state(&ch.id).unwrap().validated_holder_commitment
		}
		assert_eq!(validated(&ch, 0), Some(TOP - 3));
		assert_eq!(validated(&ch, 3), Some(TOP - 1), "party 3 missed two validations");

		// Now party 2 goes down, so every quorum includes the stale party 3. Asked on its
		// outdated record alone it refuses to release, and no quorum agrees.
		ch.cluster.down(2);
		assert!(ch.release(TOP - 2).is_err());
		// With the newer commitment and the counterparty's signature in the request, it
		// checks them itself, catches up, and the release goes through.
		let newer = (TOP - 3, ch.holder_proof(TOP - 3, &ch.cp_funding));
		ch.client.release_commitment_secret(&ch.id, TOP - 2, Some(newer)).unwrap();
		assert_eq!(validated(&ch, 3), Some(TOP - 3));

		// A forged "newer" proof teaches it nothing.
		let forged = ch.holder_proof(TOP - 4, &SecretKey::from_slice(&[0x99u8; 32]).unwrap());
		let res = ch.client.release_commitment_secret(&ch.id, TOP - 3, Some((TOP - 4, forged)));
		assert!(res.is_err());
		assert_eq!(validated(&ch, 3), Some(TOP - 3));

		// The channel carries on with parties 0, 1 and 3.
		ch.update(TOP - 3);
	}

	#[test]
	fn a_stale_party_cannot_be_used_to_broadcast_a_revoked_state() {
		let mut ch = channel("fork", 1, 12);
		ch.client.per_commitment_point(&ch.id, TOP).unwrap();
		ch.update(TOP);

		// Party 3 misses the update that revokes TOP - 1, so its record still says TOP - 1 is
		// the latest state.
		ch.cluster.down(3);
		ch.update(TOP - 1);
		ch.cluster.up(3);

		// A compromised host now asks for the revoked state to be signed for broadcast (the
		// counterparty, holding its secret, could then take the whole channel). Every quorum
		// holds at least two parties that saw the revocation, and they refuse; so does the
		// request when it is led by the stale party itself.
		let msg = denied(ch.sign_holder_commitment(TOP - 1).unwrap_err());
		assert!(msg.contains("older than validated"), "{msg}");
		let stale = ch.cluster.client_of(3);
		let err = stale
			.sign_batch(
				&Secp256k1::new(),
				Some(ch.id),
				vec![ch.holder_commitment_item(TOP - 1)],
				None,
			)
			.unwrap_err();
		assert!(denied(err).contains("older than validated"));
		// The current state can still be signed.
		ch.sign_holder_commitment(TOP - 2).unwrap();
	}

	#[test]
	fn a_state_signed_for_broadcast_is_never_revoked() {
		let ch = channel("signedstate", 1, 12);
		ch.client.per_commitment_point(&ch.id, TOP).unwrap();
		ch.update(TOP);

		// The latest state is signed for broadcast, as for a force close.
		ch.sign_holder_commitment(TOP - 1).unwrap();

		// A compromised host keeps the channel going instead and asks for that state's
		// secret: with it, the counterparty could take the whole channel once the signed
		// commitment is broadcast. The parties accept the next state but keep the secret.
		ch.sign_counterparty_commitment(TOP - 2);
		ch.validate(TOP - 2);
		let msg = denied(ch.release(TOP - 1).unwrap_err());
		assert!(msg.contains("signed for broadcast"), "{msg}");
		for i in 0..4 {
			let msg = denied(
				ch.cluster
					.client_of(i)
					.release_commitment_secret(&ch.id, TOP - 1, None)
					.unwrap_err(),
			);
			assert!(msg.contains("signed for broadcast"), "party {i}: {msg}");
		}
		// Nor that of any later state.
		ch.sign_counterparty_commitment(TOP - 3);
		ch.validate(TOP - 3);
		assert!(ch.release(TOP - 2).is_err());
	}

	#[test]
	fn a_channel_cannot_open_without_a_kit_or_run_past_one() {
		// No kits: the first point request fails, and nothing was bound.
		let ch = channel("nokit", 0, 1);
		assert!(ch.client.per_commitment_point(&ch.id, TOP).is_err());
		assert_eq!(ch.cluster.party(0).policy().kit_of(&ch.id).unwrap(), None);

		// A kit of three states serves three points and then asks for a refill.
		let ch = channel("short", 1, 3);
		for i in 0..3 {
			ch.client.per_commitment_point(&ch.id, TOP - i).unwrap();
		}
		let err = ch.client.per_commitment_point(&ch.id, TOP - 3).unwrap_err();
		assert!(err.to_string().contains("refill"), "{err}");

		// The refill ceremony adds a segment to every party; the channel carries on.
		let kit = ch.cluster.party(0).policy().kit_of(&ch.id).unwrap().unwrap();
		let tdh2_pub = ch.cluster.party(0).tdh2_public_key().unwrap();
		let pieces = split_seed(&[0x5eu8; 32], 2, 3, |b| b.fill(0x17)).unwrap();
		let seed = combine_seed(&pieces[..2]).unwrap();
		let segment = generate_segment(&seed, &kit, &tdh2_pub, TOP - 3, 3).unwrap();
		for i in 0..4 {
			let dir = ch.cluster.party(i).kits().dir().to_path_buf();
			std::fs::write(dir.join(segment_file_name(&kit, TOP - 3)), &segment).unwrap();
		}
		ch.client.per_commitment_point(&ch.id, TOP - 3).unwrap();
	}

	#[test]
	fn two_channels_get_different_kits() {
		let ch = channel("two", 2, 2);
		let other = [0xc2u8; 32];
		ch.client.per_commitment_point(&ch.id, TOP).unwrap();
		ch.client.per_commitment_point(&other, TOP).unwrap();
		let a = ch.cluster.party(0).policy().kit_of(&ch.id).unwrap().unwrap();
		let b = ch.cluster.party(0).policy().kit_of(&other).unwrap().unwrap();
		assert_ne!(a, b);
		// A third channel finds the pool empty.
		assert!(ch.client.per_commitment_point(&[0xc3u8; 32], TOP).is_err());
	}

	/// A splice of the channel's funding output into `script`, and requests about it.
	struct SpliceCase<'a> {
		ch: &'a Channel,
		key: PublicKey,
		script: ScriptBuf,
		tx: Transaction,
	}

	impl<'a> SpliceCase<'a> {
		const NEW_VALUE: u64 = 150_000;

		fn new(ch: &'a Channel) -> Self {
			let key = ch.client.ensure_channel_key(&[0xf4; 32], &ch.id, KeyKind::SplicedFunding);
			let key = key.unwrap();
			// The counterparty's funding key changes with a splice as well.
			let script = chan_utils::make_funding_redeemscript(&key, &ch.cp_payment);
			let tx = Transaction {
				version: Version::TWO,
				lock_time: LockTime::ZERO,
				input: vec![TxIn {
					previous_output: OutPoint { txid: Txid::all_zeros(), vout: 0 },
					script_sig: ScriptBuf::new(),
					sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
					witness: Witness::new(),
				}],
				output: vec![TxOut {
					value: Amount::from_sat(Self::NEW_VALUE),
					script_pubkey: script.to_p2wsh(),
				}],
			};
			SpliceCase { ch, key, script, tx }
		}

		/// Our signature on the funding output the splice spends.
		fn sign_splice(&self) -> Result<(), ClientError> {
			let ch = self.ch;
			let context = SigningContext {
				op: Some(SigningOp::SpliceSharedInput),
				channel_keys_id: Some([1u8; 32]),
				transaction: Some(serialize(&self.tx)),
				input_index: 0,
				input_value_sat: VALUE,
				witness_script: Some(ch.funding_script().to_bytes()),
				sighash_type: 0x01,
				..Default::default()
			};
			let item = SignItem {
				key_id: [0xf1; 32],
				derivation: Derivation::None,
				digest: ch.sighash(&self.tx),
				context,
				splice: None,
			};
			ch.client
				.sign_batch(&Secp256k1::new(), Some(ch.id), vec![item], Some(&[ch.funding]))
				.map(|_| ())
		}

		/// The counterparty's commitment `number` on the new funding output.
		fn sign_commitment(&self, number: u64) -> Result<(), ClientError> {
			self.sign_commitment_via(&self.ch.client, number)
		}

		fn sign_commitment_via(&self, client: &MpcClient, number: u64) -> Result<(), ClientError> {
			let ch = self.ch;
			let features = ChannelTypeFeatures::only_static_remote_key();
			let to_us = chan_utils::get_countersigner_payment_script(&features, &ch.payment);
			let mut tx = ch.commitment_tx(
				number,
				vec![TxOut { value: Amount::from_sat(60_000), script_pubkey: to_us }],
			);
			tx.input[0].previous_output = OutPoint { txid: self.tx.compute_txid(), vout: 0 };
			let mut counterparty_keys = ch.counterparty_keys();
			counterparty_keys.funding_pubkey = ch.cp_payment.serialize();
			let context = SigningContext {
				op: Some(SigningOp::CounterpartyCommitment),
				channel_keys_id: Some([1u8; 32]),
				commitment_number: Some(number),
				channel_type_features: Some(features.encode()),
				counterparty_keys: Some(counterparty_keys),
				holder_selected_contest_delay: Some(144),
				counterparty_selected_contest_delay: Some(144),
				transaction: Some(serialize(&tx)),
				input_index: 0,
				input_value_sat: Self::NEW_VALUE,
				witness_script: Some(self.script.to_bytes()),
				sighash_type: 0x01,
				per_commitment_point: Some(ch.cp_payment.serialize()),
				..Default::default()
			};
			let digest = sighash::SighashCache::new(&tx)
				.p2wsh_signature_hash(
					0,
					&self.script,
					Amount::from_sat(Self::NEW_VALUE),
					EcdsaSighashType::All,
				)
				.unwrap()
				.to_byte_array();
			let item = SignItem {
				key_id: [0xf4; 32],
				derivation: Derivation::None,
				digest,
				context,
				splice: None,
			};
			client
				.sign_batch(&Secp256k1::new(), Some(ch.id), vec![item], Some(&[self.key]))
				.map(|_| ())
		}
	}

	#[test]
	fn no_party_follows_a_channel_to_a_funding_output_without_a_splice() {
		let ch = channel("nosplice", 1, 6);
		ch.client.per_commitment_point(&ch.id, TOP).unwrap();
		ch.sign_counterparty_commitment(TOP - 1);
		ch.validate(TOP - 1);
		let splice = SpliceCase::new(&ch);
		// A compromised host names a new funding output. Whichever party it asks, and
		// whichever quorum that party tries, the answer is no.
		let msg = denied(splice.sign_commitment(TOP - 1).unwrap_err());
		assert!(msg.contains("no splice"), "{msg}");
		for i in 0..4 {
			let st = ch.cluster.party(i).policy().channel_state(&ch.id).unwrap();
			assert_eq!(st.fundings.len(), 1, "party {i}");
		}
		// After the splice itself was signed, they do.
		splice.sign_splice().unwrap();
		splice.sign_commitment(TOP - 1).unwrap();
	}

	#[test]
	fn a_party_that_missed_a_splice_is_shown_the_parties_signature() {
		let mut ch = channel("splicelag", 1, 6);
		ch.client.per_commitment_point(&ch.id, TOP).unwrap();
		ch.sign_counterparty_commitment(TOP - 1);
		ch.validate(TOP - 1);
		// Generating the new funding key needs every party; the splice does not.
		let (key, script, tx) = {
			let splice = SpliceCase::new(&ch);
			(splice.key, splice.script.clone(), splice.tx.clone())
		};
		ch.cluster.down(3);
		{
			let splice = SpliceCase { ch: &ch, key, script: script.clone(), tx: tx.clone() };
			splice.sign_splice().unwrap();
			splice.sign_commitment(TOP - 1).unwrap();
		}

		// The party that was away comes back and another one leaves, so the next update needs
		// it. It never saw the splice. Asked first, it refuses; the host moves on to the next
		// party, which leads and shows it the splice transaction with the parties' own
		// signature. Then it follows.
		ch.cluster.up(3);
		ch.cluster.down(1);
		let fundings_known_to =
			|i: usize| ch.cluster.party(i).policy().channel_state(&ch.id).unwrap().fundings.len();
		// (The notice about the last signature may still reach it now that it is back, in
		// which case it knows already and simply leads.)
		let lagging_first = MpcClient::with_parties(vec![
			ch.cluster.client_addrs[3],
			ch.cluster.client_addrs[0],
			ch.cluster.client_addrs[2],
		]);
		let splice = SpliceCase { ch: &ch, key, script, tx };
		splice.sign_commitment_via(&lagging_first, TOP - 2).unwrap();
		assert_eq!(fundings_known_to(3), 2);
		// From here on it can lead as well.
		splice.sign_commitment_via(&ch.cluster.client_of(3), TOP - 3).unwrap();
	}
}
