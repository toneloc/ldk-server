//! Standalone Coinbase cb-mpc 2-of-2 ECDSA test: DKG + sign + verify, both roles in-process.

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use ldk_server_mpc::bitcoin::secp256k1::ecdsa::Signature;
use ldk_server_mpc::bitcoin::secp256k1::{Message, PublicKey, Secp256k1};
use ldk_server_mpc::cbmpc::{Job, KeyBlob, Party};
use ldk_server_mpc::transport::ChannelTransport;

fn run_dkg() -> (KeyBlob, KeyBlob) {
	let (ta, tb) = ChannelTransport::pair(Duration::from_secs(60));
	let h = thread::spawn(move || Job::new(Party::P2, "party-a", "party-b", &tb).dkg().unwrap());
	let a = Job::new(Party::P1, "party-a", "party-b", &ta).dkg().unwrap();
	let b = h.join().unwrap();
	(a, b)
}

fn run_sign(
	a: &Arc<KeyBlob>, b: &Arc<KeyBlob>, digest: [u8; 32],
) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
	let (ta, tb) = ChannelTransport::pair(Duration::from_secs(60));
	let b = Arc::clone(b);
	let h = thread::spawn(move || {
		Job::new(Party::P2, "party-a", "party-b", &tb).sign(&b, &digest).unwrap()
	});
	let sa = Job::new(Party::P1, "party-a", "party-b", &ta).sign(a, &digest).unwrap();
	let sb = h.join().unwrap();
	(sa, sb)
}

#[test]
fn dkg_and_sign_verify_against_aggregate_key() {
	let secp = Secp256k1::new();
	let (a, b) = run_dkg();

	// Both parties agree on the aggregate public key.
	let pk_a = a.public_key_compressed().unwrap();
	let pk_b = b.public_key_compressed().unwrap();
	assert_eq!(pk_a, pk_b);
	assert_eq!(pk_a.len(), 33);
	let pk = PublicKey::from_slice(&pk_a).unwrap();

	// Each party holds a distinct share blob (neither contains the full key; the blobs
	// are opaque, so the strongest black-box check is that they differ).
	assert_ne!(a.0, b.0);

	let (a, b) = (Arc::new(a), Arc::new(b));
	let digest = [0x42u8; 32];
	let (sig_a, sig_b) = run_sign(&a, &b, digest);
	// Only P1 obtains the signature.
	assert!(sig_b.is_none());
	let der = sig_a.expect("P1 gets signature");
	let mut sig = Signature::from_der(&der).unwrap();
	sig.normalize_s();
	secp.verify_ecdsa(&Message::from_digest(digest), &sig, &pk).unwrap();

	// A different digest does not verify with this signature.
	assert!(secp.verify_ecdsa(&Message::from_digest([0x43u8; 32]), &sig, &pk).is_err());
}

#[test]
fn repeated_and_concurrent_signing() {
	let secp = Secp256k1::new();
	let (a, b) = run_dkg();
	let pk = PublicKey::from_slice(&a.public_key_compressed().unwrap()).unwrap();
	let (a, b) = (Arc::new(a), Arc::new(b));

	// Repeated sequential signing with the same key.
	for i in 0..5u8 {
		let digest = [i; 32];
		let (sig, _) = run_sign(&a, &b, digest);
		let mut sig = Signature::from_der(&sig.unwrap()).unwrap();
		sig.normalize_s();
		secp.verify_ecdsa(&Message::from_digest(digest), &sig, &pk).unwrap();
	}

	// Concurrent signing sessions (distinct sessions, same key).
	let mut handles = Vec::new();
	for i in 10..14u8 {
		let (a, b) = (Arc::clone(&a), Arc::clone(&b));
		handles.push(thread::spawn(move || {
			let digest = [i; 32];
			let (sig, _) = run_sign(&a, &b, digest);
			(digest, sig.unwrap())
		}));
	}
	for h in handles {
		let (digest, der) = h.join().unwrap();
		let mut sig = Signature::from_der(&der).unwrap();
		sig.normalize_s();
		secp.verify_ecdsa(&Message::from_digest(digest), &sig, &pk).unwrap();
	}
}

#[test]
fn sign_with_mismatched_shares_fails() {
	let (a1, _b1) = run_dkg();
	let (_a2, b2) = run_dkg();
	let (a1, b2) = (Arc::new(a1), Arc::new(b2));
	let (ta, tb) = ChannelTransport::pair(Duration::from_secs(60));
	let digest = [1u8; 32];
	let b = Arc::clone(&b2);
	let h = thread::spawn(move || Job::new(Party::P2, "party-a", "party-b", &tb).sign(&b, &digest));
	let ra = Job::new(Party::P1, "party-a", "party-b", &ta).sign(&a1, &digest);
	let rb = h.join().unwrap();
	assert!(ra.is_err() || rb.is_err(), "mismatched shares must not produce a signature");
}

#[test]
fn transport_failure_is_reported() {
	let (a, _b) = run_dkg();
	// P2 side dropped: P1's recv times out quickly.
	let (ta, tb) = ChannelTransport::pair(Duration::from_millis(200));
	drop(tb);
	let err = Job::new(Party::P1, "party-a", "party-b", &ta).sign(&a, &[0u8; 32]).unwrap_err();
	assert!(matches!(err, ldk_server_mpc::cbmpc::ProtocolError::Transport(_)), "{err}");
}
