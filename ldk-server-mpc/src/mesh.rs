//! Authenticated links between the parties, and the mesh a multi-party session runs over.
//!
//! Every party has an Ed25519 identity key and knows the others' public keys (the roster).
//! A link starts with the encrypted handshake of [`crate::secure`]; each end then signs a value
//! only the two ends of that connection share, together with both names and a digest of the
//! roster. So a party knows which party it is talking to, a signature cannot be replayed on
//! another connection, and two parties with different rosters cannot talk at all.
//!
//! A session among several parties needs a link between every pair. The party that leads the
//! session dials the others; the others then dial each other ([`JoinRegistry`] pairs those
//! connections with their session). Each link gets a reader thread ([`Link`]), so a party
//! that is sending a large protocol message never blocks one that is doing the same.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use bitcoin::hashes::{sha256, Hash, HashEngine};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};

use crate::cbmpc::TransportError;
use crate::mp::{MpTransport, Threshold};
use crate::secure::{AtRestKey, SecureStream, SecureWriter};

/// Used as the handshake key when no group pre-shared key is configured. The handshake then
/// only provides encryption; the identity signatures provide authentication either way.
const NO_PSK: [u8; 32] = *b"ldk-server-mpc/mesh/no-group-psk";

/// How long to wait for another party to accept a connection. A party that does not answer
/// within this is treated as down, so a host that silently drops packets cannot stall every
/// request for the whole protocol timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// A party's Ed25519 identity key.
pub struct Identity {
	keypair: Ed25519KeyPair,
}

impl Identity {
	/// A fresh identity and its PKCS#8 encoding for storage.
	pub fn generate() -> io::Result<(Self, Vec<u8>)> {
		let doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
			.map_err(|_| io::Error::other("identity key generation failed"))?;
		Ok((Self::from_pkcs8(doc.as_ref())?, doc.as_ref().to_vec()))
	}

	pub fn from_pkcs8(bytes: &[u8]) -> io::Result<Self> {
		Ed25519KeyPair::from_pkcs8(bytes)
			.map(|keypair| Identity { keypair })
			.map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad identity key"))
	}

	/// Loads the identity key file, or creates it (mode `0600`, sealed with `at_rest` when
	/// given) if it does not exist.
	pub fn load_or_create(path: &Path, at_rest: Option<&AtRestKey>) -> io::Result<Self> {
		match fs::read(path) {
			Ok(bytes) => {
				let bytes = match (at_rest, AtRestKey::is_encrypted(&bytes)) {
					(Some(k), true) => k.open(&bytes)?,
					(None, true) => {
						return Err(io::Error::new(
							io::ErrorKind::PermissionDenied,
							"identity key is encrypted but no share key is configured",
						))
					},
					(_, false) => bytes,
				};
				Self::from_pkcs8(&bytes)
			},
			Err(e) if e.kind() == io::ErrorKind::NotFound => {
				let (identity, pkcs8) = Self::generate()?;
				let stored = match at_rest {
					Some(k) => k.seal(&pkcs8)?,
					None => pkcs8,
				};
				if let Some(parent) = path.parent() {
					fs::create_dir_all(parent)?;
				}
				use std::io::Write;
				let mut f = fs::OpenOptions::new().write(true).create_new(true).open(path)?;
				#[cfg(unix)]
				{
					use std::os::unix::fs::PermissionsExt;
					f.set_permissions(fs::Permissions::from_mode(0o600))?;
				}
				f.write_all(&stored)?;
				f.sync_all()?;
				Ok(identity)
			},
			Err(e) => Err(e),
		}
	}

	pub fn public_key(&self) -> [u8; 32] {
		self.keypair.public_key().as_ref().try_into().expect("Ed25519 public keys are 32 bytes")
	}

	fn sign(&self, msg: &[u8]) -> [u8; 64] {
		self.keypair.sign(msg).as_ref().try_into().expect("Ed25519 signatures are 64 bytes")
	}
}

/// What every party knows about one party.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartyInfo {
	/// The cb-mpc party identifier. Stable and unique.
	pub name: String,
	/// Where the party accepts links from the other parties.
	pub addr: SocketAddr,
	/// Its Ed25519 identity public key.
	pub identity: [u8; 32],
}

/// The parties, the threshold, and this party's place among them. Every party must be
/// configured with the same parties in the same order and the same threshold.
pub struct Roster {
	pub parties: Vec<PartyInfo>,
	pub me: usize,
	ac: Threshold,
	identity: Identity,
	group_psk: Option<[u8; 32]>,
	timeout: Duration,
	digest: [u8; 32],
}

impl Roster {
	pub fn new(
		parties: Vec<PartyInfo>, threshold: usize, me: &str, identity: Identity,
		group_psk: Option<[u8; 32]>, timeout: Duration,
	) -> Result<Self, String> {
		let ac = Threshold::new(parties.iter().map(|p| p.name.clone()).collect(), threshold)?;
		if parties.len() > u8::MAX as usize {
			return Err("too many parties".into());
		}
		let me = ac.index_of(me).ok_or_else(|| format!("'{me}' is not one of the parties"))?;
		if parties[me].identity != identity.public_key() {
			return Err("this party's identity key does not match its entry in the roster".into());
		}
		let mut engine = sha256::Hash::engine();
		engine.input(b"ldk-server-mpc/roster/v1");
		engine.input(&(threshold as u32).to_be_bytes());
		for p in &parties {
			engine.input(&(p.name.len() as u32).to_be_bytes());
			engine.input(p.name.as_bytes());
			engine.input(&p.identity);
		}
		let digest = sha256::Hash::from_engine(engine).to_byte_array();
		Ok(Roster { parties, me, ac, identity, group_psk, timeout, digest })
	}

	pub fn ac(&self) -> &Threshold {
		&self.ac
	}

	pub fn name(&self) -> &str {
		&self.parties[self.me].name
	}

	pub fn len(&self) -> usize {
		self.parties.len()
	}

	pub fn is_empty(&self) -> bool {
		self.parties.is_empty()
	}

	pub fn timeout(&self) -> Duration {
		self.timeout
	}

	fn auth_message(
		&self, binding: &[u8; 32], initiator: usize, acceptor: usize, role: u8,
	) -> Vec<u8> {
		let mut msg = b"ldk-server-mpc/peer-auth/v1".to_vec();
		msg.extend_from_slice(binding);
		msg.extend_from_slice(&self.digest);
		msg.push(initiator as u8);
		msg.push(acceptor as u8);
		msg.push(role);
		msg
	}

	fn verify(&self, party: usize, msg: &[u8], sig: &[u8]) -> io::Result<()> {
		UnparsedPublicKey::new(&ED25519, &self.parties[party].identity).verify(msg, sig).map_err(
			|_| {
				io::Error::new(
					io::ErrorKind::PermissionDenied,
					format!("party '{}' failed to prove its identity", self.parties[party].name),
				)
			},
		)
	}

	fn psk(&self) -> &[u8; 32] {
		self.group_psk.as_ref().unwrap_or(&NO_PSK)
	}

	/// Opens an authenticated link to party `peer`.
	pub fn connect(&self, peer: usize) -> io::Result<SecureStream> {
		if peer == self.me || peer >= self.parties.len() {
			return Err(io::Error::new(io::ErrorKind::InvalidInput, "no such peer"));
		}
		let stream = TcpStream::connect_timeout(
			&self.parties[peer].addr,
			self.timeout.min(CONNECT_TIMEOUT),
		)?;
		stream.set_nodelay(true)?;
		stream.set_read_timeout(Some(self.timeout))?;
		stream.set_write_timeout(Some(self.timeout))?;
		let mut link = SecureStream::handshake(stream, self.psk(), true)?;
		let binding = link.binding();
		let mut hello = vec![self.me as u8];
		hello.extend_from_slice(
			&self.identity.sign(&self.auth_message(&binding, self.me, peer, b'i')),
		);
		link.write_frame(&hello)?;
		let reply = link.read_frame()?;
		self.verify(peer, &self.auth_message(&binding, self.me, peer, b'r'), &reply)?;
		Ok(link)
	}

	/// Accepts a link from another party and returns it with that party's index.
	pub fn accept(&self, stream: TcpStream) -> io::Result<(SecureStream, usize)> {
		stream.set_nodelay(true)?;
		stream.set_read_timeout(Some(self.timeout))?;
		stream.set_write_timeout(Some(self.timeout))?;
		let mut link = SecureStream::handshake(stream, self.psk(), false)?;
		let binding = link.binding();
		let hello = link.read_frame()?;
		if hello.len() != 65 {
			return Err(io::Error::new(io::ErrorKind::InvalidData, "bad peer hello"));
		}
		let peer = hello[0] as usize;
		if peer == self.me || peer >= self.parties.len() {
			return Err(io::Error::new(io::ErrorKind::PermissionDenied, "unknown peer"));
		}
		self.verify(peer, &self.auth_message(&binding, peer, self.me, b'i'), &hello[1..])?;
		link.write_frame(&self.identity.sign(&self.auth_message(&binding, peer, self.me, b'r')))?;
		Ok((link, peer))
	}
}

/// One end of a link in a session: writes go straight out, reads come from a queue filled by
/// a reader thread.
pub struct Link {
	writer: Mutex<SecureWriter>,
	inbox: Mutex<Receiver<io::Result<Vec<u8>>>>,
	timeout: Duration,
}

impl Link {
	pub fn new(stream: SecureStream, timeout: Duration) -> io::Result<Self> {
		let (mut reader, writer) = stream.split()?;
		let (tx, rx) = channel();
		thread::spawn(move || loop {
			let frame = reader.read_frame();
			let stop = frame.is_err();
			if tx.send(frame).is_err() || stop {
				break;
			}
		});
		Ok(Link { writer: Mutex::new(writer), inbox: Mutex::new(rx), timeout })
	}

	pub fn send(&self, msg: &[u8]) -> io::Result<()> {
		self.writer.lock().map_err(|_| io::Error::other("poisoned"))?.write_frame(msg)
	}

	pub fn recv(&self) -> io::Result<Vec<u8>> {
		self.recv_timeout(self.timeout)
	}

	pub fn recv_timeout(&self, timeout: Duration) -> io::Result<Vec<u8>> {
		let inbox = self.inbox.lock().map_err(|_| io::Error::other("poisoned"))?;
		match inbox.recv_timeout(timeout) {
			Ok(frame) => frame,
			Err(e) => Err(io::Error::new(io::ErrorKind::TimedOut, e.to_string())),
		}
	}
}

impl Drop for Link {
	fn drop(&mut self) {
		// Ends the reader thread, which is blocked in a read on the other half.
		if let Ok(writer) = self.writer.lock() {
			writer.shutdown();
		}
	}
}

/// A session's links, indexed by the other member's position in the session's member list.
pub struct Mesh {
	links: Vec<Option<Link>>,
}

impl Mesh {
	pub fn new(members: usize) -> Self {
		Mesh { links: (0..members).map(|_| None).collect() }
	}

	pub fn set(&mut self, position: usize, link: Link) {
		self.links[position] = Some(link);
	}

	pub fn link(&self, position: usize) -> io::Result<&Link> {
		self.links
			.get(position)
			.and_then(|l| l.as_ref())
			.ok_or_else(|| io::Error::other(format!("no link to session member {position}")))
	}
}

impl MpTransport for Mesh {
	fn send(&self, peer: usize, msg: &[u8]) -> Result<(), TransportError> {
		self.link(peer).and_then(|l| l.send(msg)).map_err(Into::into)
	}

	fn recv(&self, peer: usize) -> Result<Vec<u8>, TransportError> {
		self.link(peer).and_then(|l| l.recv()).map_err(Into::into)
	}
}

pub type SessionId = [u8; 16];

/// Where links dialed by other session members wait for the session that expects them. A join
/// can arrive before or after this party has learned of the session from its leader.
#[derive(Default)]
pub struct JoinRegistry {
	waiting: Mutex<HashMap<(SessionId, usize), (SecureStream, Instant)>>,
	arrived: Condvar,
}

impl JoinRegistry {
	/// Hands in a link from party `from` for `session`.
	pub fn deposit(&self, session: SessionId, from: usize, link: SecureStream, keep: Duration) {
		let mut waiting = self.waiting.lock().unwrap();
		let now = Instant::now();
		waiting.retain(|_, (_, at)| now.duration_since(*at) < keep);
		waiting.insert((session, from), (link, now));
		self.arrived.notify_all();
	}

	/// Waits for the link from party `from` for `session`.
	pub fn take(
		&self, session: SessionId, from: usize, timeout: Duration,
	) -> io::Result<SecureStream> {
		let deadline = Instant::now() + timeout;
		let mut waiting = self.waiting.lock().unwrap();
		loop {
			if let Some((link, _)) = waiting.remove(&(session, from)) {
				return Ok(link);
			}
			let now = Instant::now();
			if now >= deadline {
				return Err(io::Error::new(
					io::ErrorKind::TimedOut,
					"a session member did not connect",
				));
			}
			waiting = self.arrived.wait_timeout(waiting, deadline - now).unwrap().0;
		}
	}
}

#[cfg(test)]
pub(crate) mod test_util {
	use std::net::TcpListener;

	use super::*;

	/// `n` rosters on loopback with fresh identities, and each party's listener.
	pub fn rosters(n: usize, k: usize) -> Vec<(Roster, TcpListener)> {
		let listeners: Vec<TcpListener> =
			(0..n).map(|_| TcpListener::bind("127.0.0.1:0").unwrap()).collect();
		let identities: Vec<Identity> = (0..n).map(|_| Identity::generate().unwrap().0).collect();
		let parties: Vec<PartyInfo> = (0..n)
			.map(|i| PartyInfo {
				name: format!("party-{i}"),
				addr: listeners[i].local_addr().unwrap(),
				identity: identities[i].public_key(),
			})
			.collect();
		identities
			.into_iter()
			.zip(listeners)
			.enumerate()
			.map(|(i, (identity, listener))| {
				let roster = Roster::new(
					parties.clone(),
					k,
					&format!("party-{i}"),
					identity,
					None,
					Duration::from_secs(10),
				)
				.unwrap();
				(roster, listener)
			})
			.collect()
	}
}

#[cfg(test)]
mod tests {
	use super::test_util::rosters;
	use super::*;

	#[test]
	fn parties_authenticate_each_other() {
		let mut all = rosters(3, 2);
		let (r2, l2) = all.pop().unwrap();
		let (r1, _l1) = all.pop().unwrap();
		let (r0, _l0) = all.pop().unwrap();

		let server = thread::spawn(move || {
			let (stream, _) = l2.accept().unwrap();
			let (mut link, peer) = r2.accept(stream).unwrap();
			assert_eq!(peer, 0);
			assert_eq!(link.read_frame().unwrap(), b"hello");
			link.write_frame(b"world").unwrap();
			// The next caller claims to be party 0 but holds party 1's key.
			let (stream, _) = l2.accept().unwrap();
			assert!(r2.accept(stream).is_err());
		});
		let mut link = r0.connect(2).unwrap();
		link.write_frame(b"hello").unwrap();
		assert_eq!(link.read_frame().unwrap(), b"world");

		// Party 1 dials party 2 while claiming index 0.
		let impostor = Roster {
			parties: r1.parties.clone(),
			me: 0,
			ac: r1.ac.clone(),
			identity: r1.identity,
			group_psk: None,
			timeout: Duration::from_secs(10),
			digest: r1.digest,
		};
		assert!(impostor.connect(2).is_err());
		server.join().unwrap();
		assert!(r0.connect(0).is_err(), "cannot dial itself");
	}

	#[test]
	fn different_rosters_do_not_connect() {
		let mut a = rosters(3, 2);
		let (r2, l2) = a.pop().unwrap();
		let r0 = a.remove(0).0;
		// Party 0 believes the threshold is 3.
		let other = Roster::new(
			r0.parties.clone(),
			3,
			"party-0",
			Identity { keypair: r0.identity.keypair },
			None,
			Duration::from_secs(10),
		)
		.unwrap();
		let server = thread::spawn(move || {
			let (stream, _) = l2.accept().unwrap();
			assert!(r2.accept(stream).is_err());
		});
		assert!(other.connect(2).is_err());
		server.join().unwrap();
	}

	#[test]
	fn roster_rejects_a_foreign_identity() {
		let (stranger, _) = Identity::generate().unwrap();
		let all = rosters(2, 2);
		let res = Roster::new(
			all[0].0.parties.clone(),
			2,
			"party-0",
			stranger,
			None,
			Duration::from_secs(1),
		);
		assert!(res.is_err());
	}

	#[test]
	fn joins_wait_for_their_session() {
		let mut all = rosters(2, 2);
		let (r1, l1) = all.pop().unwrap();
		let (r0, _l0) = all.pop().unwrap();
		let registry = std::sync::Arc::new(JoinRegistry::default());
		let reg = std::sync::Arc::clone(&registry);
		let acceptor = thread::spawn(move || {
			let (stream, _) = l1.accept().unwrap();
			let (link, peer) = r1.accept(stream).unwrap();
			reg.deposit([7u8; 16], peer, link, Duration::from_secs(30));
		});
		let dialed = r0.connect(1).unwrap();
		let link = registry.take([7u8; 16], 0, Duration::from_secs(10)).unwrap();
		acceptor.join().unwrap();
		assert!(registry.take([7u8; 16], 0, Duration::from_millis(50)).is_err(), "taken once");
		assert!(registry.take([8u8; 16], 0, Duration::from_millis(50)).is_err());

		// Both ends can send large frames at the same time without blocking each other.
		let a = Link::new(dialed, Duration::from_secs(10)).unwrap();
		let b = Link::new(link, Duration::from_secs(10)).unwrap();
		let big = vec![0x5au8; 4 * 1024 * 1024];
		let big2 = big.clone();
		let t = thread::spawn(move || {
			b.send(&big2).unwrap();
			b.recv().unwrap().len()
		});
		a.send(&big).unwrap();
		assert_eq!(a.recv().unwrap().len(), big.len());
		assert_eq!(t.join().unwrap(), big.len());
	}
}
