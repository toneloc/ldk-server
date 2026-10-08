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
	let ctx = SigningContext {
		op: Some(SigningOp::CounterpartyCommitment),
		channel_keys_id: Some(key_id),
		channel_value_satoshis: Some(50_000),
		..Default::default()
	};
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
