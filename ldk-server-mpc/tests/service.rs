//! End-to-end tests of the party services over TCP: client -> P1 -> P2.

use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use ldk_server_mpc::bitcoin::secp256k1::{Message, Secp256k1};
use ldk_server_mpc::cbmpc::Party;
use ldk_server_mpc::client::{ClientError, MpcClient};
use ldk_server_mpc::party::{PartyConfig, PartyService};
use ldk_server_mpc::protocol::{ErrorCode, SigningContext, SigningOp};

fn tmp_dir(name: &str) -> PathBuf {
	let mut d = std::env::temp_dir();
	let nanos =
		std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
	d.push(format!("ldk-server-mpc-test-{name}-{nanos}"));
	d
}

struct Pair {
	p1: Arc<PartyService>,
	p2: Arc<PartyService>,
	p1_addr: SocketAddr,
}

fn start_party(
	party: Party, peer: Option<SocketAddr>, keystore: PathBuf,
) -> (Arc<PartyService>, SocketAddr) {
	let listener = TcpListener::bind("127.0.0.1:0").unwrap();
	let addr = listener.local_addr().unwrap();
	let cfg = PartyConfig {
		party,
		listen_addr: addr,
		peer_addr: peer,
		keystore_dir: keystore,
		p1_name: "test-party-a".into(),
		p2_name: "test-party-b".into(),
		protocol_timeout: Duration::from_secs(30),
		client_timeout: Duration::from_secs(60),
		policy: Default::default(),
		client_psk: None,
		peer_psk: None,
		share_key: None,
		kit_dir: None,
	};
	let svc = PartyService::new(cfg).unwrap();
	let s = Arc::clone(&svc);
	thread::spawn(move || s.serve_on(listener).unwrap());
	(svc, addr)
}

fn start_pair(ks_a: PathBuf, ks_b: PathBuf) -> Pair {
	let (p2, p2_addr) = start_party(Party::P2, None, ks_b);
	let (p1, p1_addr) = start_party(Party::P1, Some(p2_addr), ks_a);
	Pair { p1, p2, p1_addr }
}

#[test]
fn dkg_sign_and_restore_over_tcp() {
	let secp = Secp256k1::new();
	let ks_a = tmp_dir("a");
	let ks_b = tmp_dir("b");
	let pair = start_pair(ks_a.clone(), ks_b.clone());
	let client = MpcClient::new(pair.p1_addr);
	client.ping().unwrap();

	let key_id = [0x11u8; 32];
	let pk = client.ensure_key(&key_id).unwrap();
	// Idempotent: second call returns the same key without a new DKG.
	assert_eq!(client.ensure_key(&key_id).unwrap(), pk);
	assert_eq!(client.get_public_key(&key_id).unwrap(), pk);
	// Both parties persisted exactly one share each and agree on the key.
	assert_eq!(pair.p1.store().count().unwrap(), 1);
	assert_eq!(pair.p2.store().count().unwrap(), 1);
	assert_eq!(pair.p2.public_key(&key_id).unwrap(), pk);

	let digest = [0xabu8; 32];
	let ctx = SigningContext { op: Some(SigningOp::Test), ..Default::default() };
	let sig = client.sign(&secp, &key_id, &digest, Some(ctx), Some(&pk)).unwrap();
	secp.verify_ecdsa(&Message::from_digest(digest), &sig, &pk).unwrap();
	// Low-S enforced.
	let mut normalized = sig;
	normalized.normalize_s();
	assert_eq!(normalized, sig);

	// Restart both services (new processes in spirit: fresh service objects, same keystores).
	pair.p1.request_shutdown();
	pair.p2.request_shutdown();
	let pair2 = start_pair(ks_a.clone(), ks_b.clone());
	let client2 = MpcClient::new(pair2.p1_addr);
	assert_eq!(client2.get_public_key(&key_id).unwrap(), pk, "key share restored after restart");
	let digest2 = [0xcdu8; 32];
	let sig2 = client2.sign(&secp, &key_id, &digest2, None, Some(&pk)).unwrap();
	secp.verify_ecdsa(&Message::from_digest(digest2), &sig2, &pk).unwrap();

	let _ = std::fs::remove_dir_all(ks_a);
	let _ = std::fs::remove_dir_all(ks_b);
}

#[test]
fn invalid_key_id_is_rejected() {
	let secp = Secp256k1::new();
	let pair = start_pair(tmp_dir("a2"), tmp_dir("b2"));
	let client = MpcClient::new(pair.p1_addr);
	let err = client.get_public_key(&[9u8; 32]).unwrap_err();
	assert!(matches!(err, ClientError::Remote { code: ErrorCode::KeyNotFound, .. }), "{err}");
	let err = client.sign(&secp, &[9u8; 32], &[0u8; 32], None, None).unwrap_err();
	assert!(matches!(err, ClientError::Remote { code: ErrorCode::KeyNotFound, .. }), "{err}");
}

#[test]
fn mpc_process_unavailable() {
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

	// P1 up but P2 down: DKG must fail with PeerUnavailable, and no share may be persisted.
	let p2_dummy = TcpListener::bind("127.0.0.1:0").unwrap();
	let p2_addr = p2_dummy.local_addr().unwrap();
	drop(p2_dummy);
	let ks = tmp_dir("a3");
	let (p1, p1_addr) = start_party(Party::P1, Some(p2_addr), ks);
	let client = MpcClient::new(p1_addr);
	let err = client.ensure_key(&[1u8; 32]).unwrap_err();
	assert!(matches!(err, ClientError::Remote { code: ErrorCode::PeerUnavailable, .. }), "{err}");
	assert_eq!(p1.store().count().unwrap(), 0);
}

#[test]
fn signing_timeout_is_bounded() {
	// A "service" that accepts connections but never answers.
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
	let pair = start_pair(tmp_dir("a4"), tmp_dir("b4"));
	let client = MpcClient::new(pair.p1_addr);
	let secp = Secp256k1::new();

	// Several keys, created concurrently.
	let mut handles = Vec::new();
	for i in 0..4u8 {
		let client = client.clone();
		handles.push(thread::spawn(move || {
			let key_id = [i; 32];
			(key_id, client.ensure_key(&key_id).unwrap())
		}));
	}
	let keys: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
	let mut pks: Vec<_> = keys.iter().map(|(_, pk)| *pk).collect();
	pks.dedup();
	assert_eq!(pks.len(), 4, "distinct keys");

	// Concurrent signing on the same key (serialized server-side) and on different keys.
	let mut handles = Vec::new();
	for (n, (key_id, pk)) in keys.iter().cycle().take(8).enumerate() {
		let client = client.clone();
		let (key_id, pk) = (*key_id, *pk);
		handles.push(thread::spawn(move || {
			let secp = Secp256k1::new();
			for j in 0..3u8 {
				let mut digest = [j; 32];
				digest[0] = n as u8;
				let sig = client.sign(&secp, &key_id, &digest, None, Some(&pk)).unwrap();
				secp.verify_ecdsa(&Message::from_digest(digest), &sig, &pk).unwrap();
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
		secp.verify_ecdsa(&Message::from_digest(digest), &sig, &pk).unwrap();
	}
}

#[test]
fn p2_refuses_dkg_for_existing_key_id() {
	// Simulates P1 losing its keystore while P2 still holds a share for the same id.
	let ks_a = tmp_dir("a5");
	let ks_b = tmp_dir("b5");
	let pair = start_pair(ks_a.clone(), ks_b.clone());
	let client = MpcClient::new(pair.p1_addr);
	let key_id = [0x55u8; 32];
	client.ensure_key(&key_id).unwrap();
	pair.p1.request_shutdown();
	pair.p2.request_shutdown();

	let ks_a_fresh = tmp_dir("a5-fresh");
	let (p2, p2_addr) = start_party(Party::P2, None, ks_b);
	let (_p1, p1_addr) = start_party(Party::P1, Some(p2_addr), ks_a_fresh);
	let client = MpcClient::new(p1_addr);
	let err = client.ensure_key(&key_id).unwrap_err();
	assert!(matches!(err, ClientError::Remote { code: ErrorCode::KeyMismatch, .. }), "{err}");
	assert_eq!(p2.store().count().unwrap(), 1);
}

#[test]
fn psk_secured_links_and_encrypted_shares() {
	use ldk_server_mpc::secure::AtRestKey;
	let client_psk = [0xa1u8; 32];
	let peer_psk = [0xb2u8; 32];
	let share_key = [0xc3u8; 32];
	let ks_a = tmp_dir("sa");
	let ks_b = tmp_dir("sb");
	let start = |party: Party, peer: Option<SocketAddr>, keystore: PathBuf| {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let addr = listener.local_addr().unwrap();
		let cfg = PartyConfig {
			party,
			listen_addr: addr,
			peer_addr: peer,
			keystore_dir: keystore,
			p1_name: "test-party-a".into(),
			p2_name: "test-party-b".into(),
			protocol_timeout: Duration::from_secs(30),
			client_timeout: Duration::from_secs(60),
			policy: Default::default(),
			client_psk: Some(client_psk),
			peer_psk: Some(peer_psk),
			share_key: Some(share_key),
			kit_dir: None,
		};
		let svc = PartyService::new(cfg).unwrap();
		let s = Arc::clone(&svc);
		thread::spawn(move || s.serve_on(listener).unwrap());
		(svc, addr)
	};
	let (_p2, p2_addr) = start(Party::P2, None, ks_b.clone());
	let (p1, p1_addr) = start(Party::P1, Some(p2_addr), ks_a.clone());
	p1.ensure_tdh2().unwrap();
	let secp = Secp256k1::new();

	// Correct PSK: works end to end.
	let client = MpcClient::new(p1_addr).with_psk(client_psk);
	let key_id = [0x61u8; 32];
	let pk = client.ensure_key(&key_id).unwrap();
	let sig = client.sign(&secp, &key_id, &[0x62u8; 32], None, Some(&pk)).unwrap();
	secp.verify_ecdsa(&Message::from_digest([0x62u8; 32]), &sig, &pk).unwrap();

	// Key shares, including the TDH2 share, are encrypted on disk.
	for dir in [&ks_a, &ks_b] {
		assert!(dir.join("tdh2.keyshare").exists());
		for entry in std::fs::read_dir(dir).unwrap().filter_map(|e| e.ok()) {
			let name = entry.file_name().to_string_lossy().to_string();
			if name.ends_with(".share") || name == "tdh2.keyshare" {
				let bytes = std::fs::read(entry.path()).unwrap();
				assert!(AtRestKey::is_encrypted(&bytes), "{name} not encrypted");
				assert!(AtRestKey::new(&share_key).open(&bytes).is_ok());
			}
		}
	}

	// Wrong / missing PSK: rejected before any request is served.
	let bad = MpcClient::new(p1_addr).with_psk([0xffu8; 32]);
	assert!(matches!(bad.ping().unwrap_err(), ClientError::Io(_)));
	let plain = MpcClient::new(p1_addr);
	assert!(plain.ping().is_err());

	// Restart with the wrong share key: shares cannot be read.
	let listener = TcpListener::bind("127.0.0.1:0").unwrap();
	let cfg = PartyConfig {
		party: Party::P2,
		listen_addr: listener.local_addr().unwrap(),
		peer_addr: None,
		keystore_dir: ks_b.clone(),
		p1_name: "test-party-a".into(),
		p2_name: "test-party-b".into(),
		protocol_timeout: Duration::from_secs(30),
		client_timeout: Duration::from_secs(60),
		policy: Default::default(),
		client_psk: None,
		peer_psk: Some(peer_psk),
		share_key: Some([0x00u8; 32]),
		kit_dir: None,
	};
	assert!(PartyService::new(cfg).is_err(), "wrong share key must fail to open the TDH2 share");
}

// ---------------------------------------------------------------------------
// Revocation secrets: kits, joint release, and a compromised Party A
// ---------------------------------------------------------------------------

mod revocation {
	use std::net::TcpStream;

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
	use ldk_server_mpc::secure::Conn;
	use lightning::ln::chan_utils::{self, CounterpartyCommitmentSecrets};
	use lightning::types::features::ChannelTypeFeatures;
	use lightning::util::ser::Writeable;

	use super::*;

	const TOP: u64 = INITIAL_COMMITMENT_NUMBER;
	const VALUE: u64 = 100_000;

	struct Channel {
		pair: Pair,
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
	}

	/// Starts both parties, runs the ceremony for `kits` kits of `states` states each, and
	/// creates the channel's keys.
	fn channel(name: &str, kits: u8, states: u32) -> Channel {
		let ks_a = tmp_dir(&format!("{name}-a"));
		let ks_b = tmp_dir(&format!("{name}-b"));
		let pair = start_pair(ks_a.clone(), ks_b.clone());
		let client = MpcClient::new(pair.p1_addr);

		// The parties generate their joint TDH2 key; Party A publishes the public key.
		pair.p1.ensure_tdh2().unwrap();
		let tdh2_pub = pair.p1.tdh2_public_key().unwrap();
		assert_eq!(pair.p2.tdh2_public_key().unwrap(), tdh2_pub);
		let published = std::fs::read_to_string(ks_a.join("tdh2.pub")).unwrap();
		assert_eq!(published, hex(&tdh2_pub));

		// The offline ceremony: custodians rebuild the master seed and make the kits. Both
		// parties get a copy of every kit file.
		let pieces = split_seed(&[0x5eu8; 32], 2, 3, |b| b.fill(0x17)).unwrap();
		let seed = combine_seed(&pieces[1..]).unwrap();
		for k in 0..kits {
			let kit_id = [0xa0 + k; 32];
			let segment = generate_segment(&seed, &kit_id, &tdh2_pub, TOP, states).unwrap();
			for ks in [&ks_a, &ks_b] {
				std::fs::write(ks.join("kits").join(segment_file_name(&kit_id, TOP)), &segment)
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
			pair,
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

	/// What Party B answers when asked directly, as a compromised Party A would.
	fn ask_party_b(pair: &Pair, op: SessionOp) -> SessionAck {
		let addr = pair.p2.config().listen_addr;
		let stream = TcpStream::connect(addr).unwrap();
		let mut conn = Conn::new(stream, None, true).unwrap();
		conn.write_frame(&SessionStart { op }.encode()).unwrap();
		SessionAck::decode(&conn.read_frame().unwrap()).unwrap()
	}

	#[test]
	fn secrets_are_released_in_order_and_fit_the_shachain() {
		let ch = channel("release", 1, 12);
		// No party stores a seed or a secret.
		for dir in
			[ch.pair.p1.config().keystore_dir.clone(), ch.pair.p2.config().keystore_dir.clone()]
		{
			assert!(!dir.join("master.secret").exists());
		}

		let p0 = ch.client.per_commitment_point(&ch.id, TOP).unwrap();
		assert_eq!(ch.client.per_commitment_point(&ch.id, TOP).unwrap(), p0, "stable");
		// Both parties bound the same kit to the channel.
		let kit = ch.pair.p1.policy().kit_of(&ch.id).unwrap().unwrap();
		assert_eq!(ch.pair.p2.policy().kit_of(&ch.id).unwrap(), Some(kit));

		// Nothing is releasable before a newer state is validated.
		assert!(denied(ch.client.release_commitment_secret(&ch.id, TOP).unwrap_err())
			.contains("no holder commitment validated"));
		ch.client.holder_commitment_validated(&ch.id, TOP, None).unwrap();
		assert!(ch.client.release_commitment_secret(&ch.id, TOP).is_err());

		// Ten channel updates: the counterparty signs our new state, then we revoke the old
		// one. The counterparty's shachain store accepts every secret.
		let mut peer = CounterpartyCommitmentSecrets::new();
		for i in 0..10u64 {
			let old = TOP - i;
			ch.sign_counterparty_commitment(old - 1);
			let point = ch.client.per_commitment_point(&ch.id, old).unwrap();
			ch.validate(old - 1);
			let secret = ch.client.release_commitment_secret(&ch.id, old).unwrap();
			assert_eq!(point_of(&secret), point);
			assert_eq!(ch.client.release_commitment_secret(&ch.id, old).unwrap(), secret, "retry");
			peer.provide_secret(old, secret).expect("fits the shachain");
			// The state that is now current, and every later one, stay sealed.
			assert!(ch.client.release_commitment_secret(&ch.id, old - 1).is_err());
			assert!(ch.client.release_commitment_secret(&ch.id, old - 2).is_err());
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

		// So the current state's secret stays sealed.
		assert!(ch.client.release_commitment_secret(&ch.id, TOP).is_err());
	}

	#[test]
	fn party_b_decides_for_itself() {
		let ch = channel("rogue-a", 1, 6);
		ch.client.per_commitment_point(&ch.id, TOP).unwrap();
		ch.sign_counterparty_commitment(TOP - 1);
		ch.validate(TOP - 1);

		// A compromised Party A skips its own policy and asks Party B directly for the
		// current state, a future state, and a validation without proof.
		for idx in [TOP - 1, TOP - 3] {
			match ask_party_b(&ch.pair, SessionOp::ReleaseSecret { channel: ch.id, idx }) {
				SessionAck::Error { code, .. } => assert_eq!(code, ErrorCode::PolicyDenied),
				SessionAck::Ok { .. } => panic!("Party B released secret {idx}"),
			}
		}
		let claim = SessionOp::HolderCommitmentValidated {
			channel: ch.id,
			commitment_number: TOP - 2,
			proof: None,
		};
		assert!(matches!(ask_party_b(&ch.pair, claim), SessionAck::Error { .. }));
		// It may not swap the channel's kit for another either.
		let swap = SessionOp::BindKit { channel: ch.id, kit_id: [0xee; 32] };
		assert!(matches!(ask_party_b(&ch.pair, swap), SessionAck::Error { .. }));

		// For the one state that may be released, Party B's answer alone is not the secret:
		// Party A needs its own share to finish the decryption.
		let partial =
			match ask_party_b(&ch.pair, SessionOp::ReleaseSecret { channel: ch.id, idx: TOP }) {
				SessionAck::Ok { payload } => payload,
				SessionAck::Error { message, .. } => panic!("{message}"),
			};
		let secret = ch.client.release_commitment_secret(&ch.id, TOP).unwrap();
		assert!(!partial.windows(32).any(|w| w == secret));
	}

	#[test]
	fn a_channel_cannot_open_without_a_kit_or_run_past_one() {
		// No kits: the first point request fails, and nothing was bound.
		let ch = channel("nokit", 0, 1);
		assert!(ch.client.per_commitment_point(&ch.id, TOP).is_err());
		assert_eq!(ch.pair.p1.policy().kit_of(&ch.id).unwrap(), None);

		// A kit of three states serves three points and then asks for a refill.
		let ch = channel("short", 1, 3);
		for i in 0..3 {
			ch.client.per_commitment_point(&ch.id, TOP - i).unwrap();
		}
		let err = ch.client.per_commitment_point(&ch.id, TOP - 3).unwrap_err();
		assert!(err.to_string().contains("refill"), "{err}");

		// The refill ceremony adds a segment to both parties; the channel carries on.
		let kit = ch.pair.p1.policy().kit_of(&ch.id).unwrap().unwrap();
		let tdh2_pub = ch.pair.p1.tdh2_public_key().unwrap();
		let pieces = split_seed(&[0x5eu8; 32], 2, 3, |b| b.fill(0x17)).unwrap();
		let seed = combine_seed(&pieces[..2]).unwrap();
		let segment = generate_segment(&seed, &kit, &tdh2_pub, TOP - 3, 3).unwrap();
		for svc in [&ch.pair.p1, &ch.pair.p2] {
			std::fs::write(svc.kits().dir().join(segment_file_name(&kit, TOP - 3)), &segment)
				.unwrap();
		}
		ch.client.per_commitment_point(&ch.id, TOP - 3).unwrap();
	}

	#[test]
	fn two_channels_get_different_kits() {
		let ch = channel("two", 2, 2);
		let other = [0xc2u8; 32];
		ch.client.per_commitment_point(&ch.id, TOP).unwrap();
		ch.client.per_commitment_point(&other, TOP).unwrap();
		let a = ch.pair.p1.policy().kit_of(&ch.id).unwrap().unwrap();
		let b = ch.pair.p1.policy().kit_of(&other).unwrap().unwrap();
		assert_ne!(a, b);
		// A third channel finds the pool empty.
		assert!(ch.client.per_commitment_point(&[0xc3u8; 32], TOP).is_err());
	}
}
