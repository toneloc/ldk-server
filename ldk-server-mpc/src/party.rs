//! The MPC party service.
//!
//! Every party runs the same process. Each holds only its own shares of the channel keys, its
//! share of the joint TDH2 decryption key, a copy of the channel kits (public per-commitment
//! points and encrypted per-commitment secrets, see [`crate::kit`]) and its own policy state.
//! No party holds a whole key, a per-commitment secret or the seed they come from. LDK Server
//! holds none of this.
//!
//! Any `threshold` of the parties can sign or release a secret. Each one applies its own policy
//! first, from its own record of the channel, so a request has to convince a quorum of
//! independent validators and not just the party it was sent to.
//!
//! - **Clients** (LDK Server) send a [`Request`] to any party. That party *leads*: it applies
//!   its policy, picks a quorum, and opens a session with the other members.
//! - **Signing** runs cb-mpc's threshold ECDSA among the quorum over a mesh of authenticated
//!   links ([`crate::mesh`]). If a member is down or refuses, the leader tries another quorum.
//!   Parties left out are told what was signed so their record keeps up.
//! - **Key generation** needs every party. Shares are stored only once the leader has
//!   confirmed that all parties computed the same public key.
//! - **Releasing a per-commitment secret** collects partial decryptions from the parties whose
//!   policy allows it; a quorum of them recovers the secret.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::rand::{thread_rng, RngCore};
use bitcoin::secp256k1::{All, Message, PublicKey, Scalar, Secp256k1, SecretKey};
use hex_conservative::DisplayHex;

use crate::cbmpc::{CbmpcError, ProtocolError, TransportError};
use crate::kit::{self, KitId, KitStore};
use crate::mesh::{Identity, JoinRegistry, Link, Mesh, PartyInfo, Roster, SessionId};
use crate::mp::{self, KeyShare, MpTransport};
use crate::policy::{Authorized, ChannelPolicy, KeyLookup, PolicyConfig, PolicyError};
use crate::protocol::{
	frame_kind, ChannelId, Derivation, ErrorCode, FrameKind, HolderProof, KeyId, KeyKind, MeshJoin,
	Request, Response, SessionAck, SessionDone, SessionOp, SessionStart, SignItem, FRAME_COMMIT,
	FRAME_GO,
};
use crate::secure::{AtRestKey, Conn, SecureStream};
use crate::tdh2::{self, Tdh2Key};

/// Warn when a channel's kit has this many commitment numbers left.
const LOW_KIT_WARNING: u64 = 256;

pub struct PartyConfig {
	/// This party's name; one of `parties`.
	pub name: String,
	/// Every party, this one included, in the same order on every party. A party accepts
	/// links from the others on its `addr`.
	pub parties: Vec<PartyInfo>,
	/// How many parties must agree to sign or to release a secret.
	pub threshold: usize,
	/// This party's identity key; its public key must be this party's entry in `parties`.
	pub identity: Identity,
	/// Where this party accepts client requests (LDK Server).
	pub listen_addr: SocketAddr,
	pub keystore_dir: PathBuf,
	/// Per-message I/O timeout for the links between parties.
	pub protocol_timeout: Duration,
	/// I/O timeout for client connections.
	pub client_timeout: Duration,
	pub policy: PolicyConfig,
	/// Pre-shared key authenticating and encrypting the LDK Server ⇄ party link.
	pub client_psk: Option<[u8; 32]>,
	/// Optional pre-shared key all parties share, mixed into the links between them. The
	/// parties authenticate each other with their identity keys either way.
	pub peer_psk: Option<[u8; 32]>,
	/// Key encrypting key shares at rest.
	pub share_key: Option<[u8; 32]>,
	/// Directory of channel kits made by the offline ceremony. Defaults to `<keystore>/kits`.
	pub kit_dir: Option<PathBuf>,
}

/// On-disk key-share store: one file per key, `<hex key_id>.share`.
pub struct KeyStore {
	dir: PathBuf,
	cache: Mutex<HashMap<KeyId, Arc<KeyShare>>>,
	at_rest: Option<AtRestKey>,
}

impl KeyStore {
	pub fn open(dir: &Path) -> io::Result<Self> {
		Self::open_with_key(dir, None)
	}

	/// With a share key, key shares are AES-256-GCM encrypted at rest; the share key itself
	/// should live on a different medium (or a KMS/HSM) than the shares.
	pub fn open_with_key(dir: &Path, share_key: Option<[u8; 32]>) -> io::Result<Self> {
		fs::create_dir_all(dir)?;
		Ok(KeyStore {
			dir: dir.to_path_buf(),
			cache: Mutex::new(HashMap::new()),
			at_rest: share_key.map(|k| AtRestKey::new(&k)),
		})
	}

	fn unseal(&self, bytes: Vec<u8>, what: &str) -> io::Result<Vec<u8>> {
		match (&self.at_rest, AtRestKey::is_encrypted(&bytes)) {
			(Some(k), true) => k.open(&bytes),
			(Some(_), false) => {
				log::warn!("{what} is stored unencrypted although a share key is configured");
				Ok(bytes)
			},
			(None, true) => Err(io::Error::new(
				io::ErrorKind::PermissionDenied,
				format!("{what} is encrypted but no share key is configured"),
			)),
			(None, false) => Ok(bytes),
		}
	}

	fn seal(&self, bytes: &[u8]) -> io::Result<Vec<u8>> {
		match &self.at_rest {
			Some(k) => k.seal(bytes),
			None => Ok(bytes.to_vec()),
		}
	}

	fn write_new(&self, path: &Path, tmp: &Path, contents: &[u8]) -> io::Result<()> {
		if path.exists() {
			return Err(io::Error::new(io::ErrorKind::AlreadyExists, "key share already exists"));
		}
		{
			use std::io::Write;
			let _ = fs::remove_file(tmp);
			let mut f = fs::OpenOptions::new().write(true).create_new(true).open(tmp)?;
			#[cfg(unix)]
			{
				use std::os::unix::fs::PermissionsExt;
				f.set_permissions(fs::Permissions::from_mode(0o600))?;
			}
			f.write_all(&self.seal(contents)?)?;
			f.sync_all()?;
		}
		fs::rename(tmp, path)
	}

	fn path(&self, key_id: &KeyId) -> PathBuf {
		self.dir.join(format!("{}.share", key_id.as_hex()))
	}

	pub fn get(&self, key_id: &KeyId) -> io::Result<Option<Arc<KeyShare>>> {
		if let Some(b) = self.cache.lock().unwrap().get(key_id) {
			return Ok(Some(Arc::clone(b)));
		}
		match fs::read(self.path(key_id)) {
			Ok(bytes) => {
				let share = Arc::new(KeyShare(self.unseal(bytes, "key share")?));
				self.cache.lock().unwrap().insert(*key_id, Arc::clone(&share));
				Ok(Some(share))
			},
			Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
			Err(e) => Err(e),
		}
	}

	/// Atomically persists a new share. Refuses to overwrite an existing share.
	pub fn insert_new(&self, key_id: &KeyId, share: KeyShare) -> io::Result<Arc<KeyShare>> {
		let tmp = self.dir.join(format!("{}.share.tmp", key_id.as_hex()));
		self.write_new(&self.path(key_id), &tmp, &share.0)?;
		let share = Arc::new(share);
		self.cache.lock().unwrap().insert(*key_id, Arc::clone(&share));
		Ok(share)
	}

	pub fn count(&self) -> io::Result<usize> {
		Ok(fs::read_dir(&self.dir)?
			.filter_map(|e| e.ok())
			.filter(|e| e.path().extension().map(|x| x == "share").unwrap_or(false))
			.count())
	}

	/// This party's share of the joint TDH2 key, if the key generation has run.
	pub fn load_tdh2(&self) -> io::Result<Option<Tdh2Key>> {
		match fs::read(self.dir.join("tdh2.keyshare")) {
			Ok(bytes) => {
				let bytes = self.unseal(bytes, "TDH2 key share")?;
				Tdh2Key::decode(&bytes)
					.map(Some)
					.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
			},
			Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
			Err(e) => Err(e),
		}
	}

	/// Persists this party's TDH2 key share, and the joint public key in `tdh2.pub` for the
	/// offline ceremony to encrypt to. Refuses to overwrite an existing share.
	pub fn insert_tdh2(&self, key: &Tdh2Key) -> io::Result<()> {
		fs::write(self.dir.join("tdh2.pub"), key.public_key.as_hex().to_string())?;
		self.write_new(
			&self.dir.join("tdh2.keyshare"),
			&self.dir.join("tdh2.keyshare.tmp"),
			&key.encode(),
		)
	}
}

impl KeyLookup for KeyStore {
	fn public_key(&self, key_id: &KeyId) -> Option<PublicKey> {
		let share = self.get(key_id).ok()??;
		PublicKey::from_slice(&share.public_key_compressed().ok()?).ok()
	}
}

#[derive(Debug)]
pub struct ServiceError {
	pub code: ErrorCode,
	pub message: String,
}

impl ServiceError {
	fn new(code: ErrorCode, message: impl Into<String>) -> Self {
		ServiceError { code, message: message.into() }
	}

	fn unavailable(e: impl std::fmt::Display) -> Self {
		ServiceError::new(ErrorCode::PeerUnavailable, e.to_string())
	}
}

impl From<io::Error> for ServiceError {
	fn from(e: io::Error) -> Self {
		ServiceError::new(ErrorCode::Internal, e.to_string())
	}
}

impl From<PolicyError> for ServiceError {
	fn from(e: PolicyError) -> Self {
		ServiceError::new(ErrorCode::PolicyDenied, e.to_string())
	}
}

impl From<ProtocolError> for ServiceError {
	fn from(e: ProtocolError) -> Self {
		match e {
			ProtocolError::Transport(t) => ServiceError::unavailable(t),
			ProtocolError::Cbmpc(c) => ServiceError::new(ErrorCode::ProtocolFailed, c.to_string()),
		}
	}
}

impl From<CbmpcError> for ServiceError {
	fn from(e: CbmpcError) -> Self {
		ServiceError::new(ErrorCode::ProtocolFailed, e.to_string())
	}
}

/// A session's mesh as cb-mpc sees it when the protocol's party list is the whole roster:
/// the library addresses peers by roster index, the mesh by position in the member list.
struct ByRosterIndex<'a> {
	mesh: &'a Mesh,
	position: Vec<usize>,
}

impl MpTransport for ByRosterIndex<'_> {
	fn send(&self, peer: usize, msg: &[u8]) -> Result<(), TransportError> {
		self.mesh.send(self.position[peer], msg)
	}

	fn recv(&self, peer: usize) -> Result<Vec<u8>, TransportError> {
		self.mesh.recv(self.position[peer])
	}
}

pub struct PartyService {
	roster: Roster,
	listen_addr: SocketAddr,
	keystore_dir: PathBuf,
	client_timeout: Duration,
	client_psk: Option<[u8; 32]>,
	store: KeyStore,
	policy: ChannelPolicy,
	kits: Arc<KitStore>,
	tdh2: Mutex<Option<Arc<Tdh2Key>>>,
	joins: JoinRegistry,
	key_locks: Mutex<HashMap<KeyId, Arc<Mutex<()>>>>,
	secp: Secp256k1<All>,
	shutdown: AtomicBool,
}

impl PartyService {
	pub fn new(cfg: PartyConfig) -> io::Result<Arc<Self>> {
		let store = KeyStore::open_with_key(&cfg.keystore_dir, cfg.share_key)?;
		if cfg.share_key.is_none() {
			log::warn!("no share key configured: key shares are stored unencrypted");
		}
		let roster = Roster::new(
			cfg.parties,
			cfg.threshold,
			&cfg.name,
			cfg.identity,
			cfg.peer_psk,
			cfg.protocol_timeout,
		)
		.map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
		let kit_dir = cfg.kit_dir.clone().unwrap_or_else(|| cfg.keystore_dir.join("kits"));
		let kits = Arc::new(KitStore::open(&kit_dir)?);
		let policy =
			ChannelPolicy::open(&cfg.keystore_dir, cfg.policy.clone(), Some(Arc::clone(&kits)))?;
		let tdh2 = store.load_tdh2()?.map(Arc::new);
		Ok(Arc::new(PartyService {
			roster,
			listen_addr: cfg.listen_addr,
			keystore_dir: cfg.keystore_dir,
			client_timeout: cfg.client_timeout,
			client_psk: cfg.client_psk,
			store,
			policy,
			kits,
			tdh2: Mutex::new(tdh2),
			joins: JoinRegistry::default(),
			key_locks: Mutex::new(HashMap::new()),
			secp: Secp256k1::new(),
			shutdown: AtomicBool::new(false),
		}))
	}

	pub fn roster(&self) -> &Roster {
		&self.roster
	}

	pub fn name(&self) -> &str {
		self.roster.name()
	}

	pub fn listen_addr(&self) -> SocketAddr {
		self.listen_addr
	}

	pub fn keystore_dir(&self) -> &Path {
		&self.keystore_dir
	}

	pub fn store(&self) -> &KeyStore {
		&self.store
	}

	pub fn policy(&self) -> &ChannelPolicy {
		&self.policy
	}

	pub fn kits(&self) -> &KitStore {
		&self.kits
	}

	fn timeout(&self) -> Duration {
		self.roster.timeout()
	}

	fn others(&self) -> Vec<usize> {
		(0..self.roster.len()).filter(|i| *i != self.roster.me).collect()
	}

	fn key_lock(&self, key_id: &KeyId) -> Arc<Mutex<()>> {
		let mut locks = self.key_locks.lock().unwrap();
		Arc::clone(locks.entry(*key_id).or_insert_with(|| Arc::new(Mutex::new(()))))
	}

	fn tdh2_key(&self) -> Option<Arc<Tdh2Key>> {
		self.tdh2.lock().unwrap().clone()
	}

	/// The joint TDH2 public key, if the key generation has run.
	pub fn tdh2_public_key(&self) -> Option<Vec<u8>> {
		self.tdh2_key().map(|k| k.public_key.clone())
	}

	/// Stops serving. Connections in progress finish on their own.
	pub fn request_shutdown(&self) {
		self.shutdown.store(true, Ordering::SeqCst);
		// Wake both accept loops so they notice.
		let _ = TcpStream::connect_timeout(&self.listen_addr, Duration::from_millis(200));
		let _ = TcpStream::connect_timeout(
			&self.roster.parties[self.roster.me].addr,
			Duration::from_millis(200),
		);
	}

	// -----------------------------------------------------------------------
	// Serving
	// -----------------------------------------------------------------------

	/// Binds both listeners and serves forever (or until `request_shutdown`).
	pub fn serve(self: &Arc<Self>) -> io::Result<()> {
		let clients = TcpListener::bind(self.listen_addr)?;
		let peers = TcpListener::bind(self.roster.parties[self.roster.me].addr)?;
		self.serve_on(clients, peers)
	}

	pub fn serve_on(self: &Arc<Self>, clients: TcpListener, peers: TcpListener) -> io::Result<()> {
		log::info!(
			"mpc party {} ({} of {} parties must agree): clients on {}, parties on {}, keystore {}, {} shares, payout allow-list {}",
			self.name(),
			self.roster.ac().k,
			self.roster.len(),
			clients.local_addr()?,
			peers.local_addr()?,
			self.keystore_dir.display(),
			self.store.count().unwrap_or(0),
			self.policy.config().payout.as_ref().map(|p| p.len()).unwrap_or(0)
		);
		let svc = Arc::clone(self);
		let peer_loop = thread::spawn(move || {
			svc.accept_loop(peers, |svc, stream| svc.handle_peer_connection(stream))
		});
		self.accept_loop(clients, |svc, stream| svc.handle_client_connection(stream));
		let _ = peer_loop.join();
		Ok(())
	}

	fn accept_loop(
		self: &Arc<Self>, listener: TcpListener,
		handler: impl Fn(Arc<Self>, TcpStream) -> io::Result<()> + Send + Sync + Copy + 'static,
	) {
		for conn in listener.incoming() {
			if self.shutdown.load(Ordering::SeqCst) {
				break;
			}
			match conn {
				Ok(stream) => {
					let svc = Arc::clone(self);
					thread::spawn(move || {
						if let Err(e) = handler(svc, stream) {
							log::debug!("connection ended: {e}");
						}
					});
				},
				Err(e) => log::warn!("accept failed: {e}"),
			}
		}
	}

	fn handle_client_connection(self: Arc<Self>, stream: TcpStream) -> io::Result<()> {
		stream.set_nodelay(true)?;
		stream.set_read_timeout(Some(self.client_timeout))?;
		stream.set_write_timeout(Some(self.client_timeout))?;
		let mut conn = Conn::new(stream, self.client_psk.as_ref(), false)?;
		let first = conn.read_frame()?;
		let resp = match Request::decode(&first) {
			Ok(req) => self.handle_request(req),
			Err(e) => Response::Error { code: ErrorCode::BadRequest, message: e.to_string() },
		};
		conn.write_frame(&resp.encode())
	}

	fn handle_peer_connection(self: Arc<Self>, stream: TcpStream) -> io::Result<()> {
		let (mut link, peer) = self.roster.accept(stream)?;
		let first = link.read_frame()?;
		match frame_kind(&first) {
			FrameKind::SessionStart => match SessionStart::decode(&first) {
				Ok(start) => self.handle_session(link, peer, start),
				Err(e) => link.write_frame(
					&SessionAck::Error { code: ErrorCode::BadRequest, message: e.to_string() }
						.encode(),
				),
			},
			FrameKind::MeshJoin => {
				let join = MeshJoin::decode(&first)
					.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
				self.joins.deposit(join.session, peer, link, self.timeout() * 4);
				Ok(())
			},
			_ => Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected frame from a party")),
		}
	}

	// -----------------------------------------------------------------------
	// Client requests: this party leads
	// -----------------------------------------------------------------------

	fn handle_request(self: &Arc<Self>, req: Request) -> Response {
		let res: Result<Response, ServiceError> = match req {
			Request::Ping => Ok(Response::Pong),
			Request::EnsureKey { key_id, channel } => self
				.ensure_key(&key_id, channel)
				.map(|pk| Response::PublicKey { pubkey: pk.serialize().to_vec() }),
			Request::GetPublicKey { key_id } => self
				.public_key(&key_id)
				.map(|pk| Response::PublicKey { pubkey: pk.serialize().to_vec() }),
			Request::GetPerCommitmentPoint { channel, idx } => self
				.per_commitment_point(&channel, idx)
				.map(|pk| Response::PublicKey { pubkey: pk.serialize().to_vec() }),
			Request::ReleaseCommitmentSecret { channel, idx, newer } => self
				.release_commitment_secret(&channel, idx, newer)
				.map(|secret| Response::Secret { secret }),
			Request::HolderCommitmentValidated { channel, commitment_number, proof } => {
				let mine = self
					.policy
					.holder_commitment_validated(
						&channel,
						commitment_number,
						proof.as_ref(),
						&self.store,
					)
					.map_err(ServiceError::from);
				self.notify_all(
					mine,
					SessionOp::HolderCommitmentValidated { channel, commitment_number, proof },
				)
				.map(|_| Response::Ack)
			},
			Request::CounterpartyRevocationValidated { channel, idx, secret } => {
				let mine = self
					.policy
					.counterparty_revocation_validated(&channel, idx, &secret)
					.map_err(ServiceError::from);
				self.notify_all(
					mine,
					SessionOp::CounterpartyRevocationValidated { channel, idx, secret },
				)
				.map(|_| Response::Ack)
			},
			Request::Sign { request_id, channel, items } => {
				self.sign_batch(channel, items).map(|sigs| Response::Signatures {
					request_id,
					sigs: sigs.iter().map(|s| s.serialize_compact()).collect(),
				})
			},
		};
		match res {
			Ok(r) => r,
			Err(e) => {
				log::warn!("request failed: {:?}: {}", e.code, e.message);
				Response::Error { code: e.code, message: e.message }
			},
		}
	}

	fn pubkey_of(&self, share: &KeyShare) -> Result<PublicKey, ServiceError> {
		let bytes = share.public_key_compressed()?;
		PublicKey::from_slice(&bytes)
			.map_err(|e| ServiceError::new(ErrorCode::Internal, format!("bad pubkey: {e}")))
	}

	pub fn public_key(&self, key_id: &KeyId) -> Result<PublicKey, ServiceError> {
		match self.store.get(key_id)? {
			Some(share) => self.pubkey_of(&share),
			None => Err(ServiceError::new(ErrorCode::KeyNotFound, "unknown key id")),
		}
	}

	fn new_session() -> SessionId {
		let mut id = [0u8; 16];
		thread_rng().fill_bytes(&mut id);
		id
	}

	/// Opens a link to `peer`, starts a session with it and returns the link and its answer.
	fn start_with(
		&self, peer: usize, start: &SessionStart,
	) -> Result<(SecureStream, Vec<u8>), ServiceError> {
		let name = &self.roster.parties[peer].name;
		let mut link = self
			.roster
			.connect(peer)
			.map_err(|e| ServiceError::unavailable(format!("party '{name}': {e}")))?;
		link.write_frame(&start.encode())
			.map_err(|e| ServiceError::unavailable(format!("party '{name}': {e}")))?;
		let ack = link
			.read_frame()
			.map_err(|e| ServiceError::unavailable(format!("party '{name}': {e}")))?;
		match SessionAck::decode(&ack) {
			Ok(SessionAck::Ok { payload }) => Ok((link, payload)),
			Ok(SessionAck::Error { code, message }) => {
				Err(ServiceError::new(code, format!("party '{name}' refused: {message}")))
			},
			Err(e) => Err(ServiceError::new(ErrorCode::ProtocolFailed, e.to_string())),
		}
	}

	/// Runs a non-interactive op on `peer` and returns its answer.
	fn ask(&self, peer: usize, op: SessionOp) -> Result<Vec<u8>, ServiceError> {
		let start = SessionStart {
			session: Self::new_session(),
			members: vec![self.roster.me as u8, peer as u8],
			op,
		};
		self.start_with(peer, &start).map(|(_, payload)| payload)
	}

	/// Runs a non-interactive op on every other party at once.
	fn ask_others(&self, op: &SessionOp) -> Vec<(usize, Result<Vec<u8>, ServiceError>)> {
		thread::scope(|scope| {
			let handles: Vec<_> = self
				.others()
				.into_iter()
				.map(|peer| (peer, scope.spawn(move || self.ask(peer, op.clone()))))
				.collect();
			handles
				.into_iter()
				.map(|(peer, h)| {
					let res = h.join().unwrap_or_else(|_| {
						Err(ServiceError::new(ErrorCode::Internal, "request thread panicked"))
					});
					(peer, res)
				})
				.collect()
		})
	}

	/// Tells every other party of a state change this party has already judged (`mine`).
	/// Succeeds if a quorum accepted it, so the parties can later act on it together.
	fn notify_all(
		&self, mine: Result<(), ServiceError>, op: SessionOp,
	) -> Result<(), ServiceError> {
		let theirs = self.ask_others(&op).into_iter().map(|(peer, res)| {
			res.map(|_| ()).inspect_err(|e| {
				log::warn!("party '{}': {}", self.roster.parties[peer].name, e.message)
			})
		});
		let mut accepted = 0;
		let mut refusal: Option<ServiceError> = None;
		for res in std::iter::once(mine).chain(theirs) {
			match res {
				Ok(()) => accepted += 1,
				Err(e) => {
					if refusal.is_none() || e.code == ErrorCode::PolicyDenied {
						refusal = Some(e);
					}
				},
			}
		}
		if accepted >= self.roster.ac().k {
			Ok(())
		} else {
			Err(refusal.unwrap_or_else(|| ServiceError::unavailable("no quorum reachable")))
		}
	}

	/// Starts an interactive session with `members` (roster indices, this party first): every
	/// other member must accept before anyone is told to go. Returns the mesh, indexed by
	/// position in `members`. On failure, names the member that caused it if one did.
	fn lead(
		&self, members: &[usize], op: SessionOp,
	) -> Result<Mesh, (Option<usize>, ServiceError)> {
		let start = SessionStart {
			session: Self::new_session(),
			members: members.iter().map(|m| *m as u8).collect(),
			op,
		};
		let mut links = Vec::new();
		for peer in &members[1..] {
			let (link, _) = self.start_with(*peer, &start).map_err(|e| (Some(*peer), e))?;
			links.push(link);
		}
		let mut mesh = Mesh::new(members.len());
		for (i, mut link) in links.into_iter().enumerate() {
			link.write_frame(FRAME_GO)
				.map_err(|e| (Some(members[i + 1]), ServiceError::unavailable(e)))?;
			let link = Link::new(link, self.timeout())
				.map_err(|e| (Some(members[i + 1]), ServiceError::from(e)))?;
			mesh.set(i + 1, link);
		}
		Ok(mesh)
	}

	fn read_done(&self, mesh: &Mesh, position: usize) -> Result<Vec<u8>, ServiceError> {
		let frame =
			mesh.link(position).and_then(|l| l.recv()).map_err(ServiceError::unavailable)?;
		SessionDone::decode(&frame)
			.map(|d| d.pubkey)
			.map_err(|e| ServiceError::new(ErrorCode::ProtocolFailed, e.to_string()))
	}

	/// All parties, this one first, and each party's position in that list.
	fn everyone(&self) -> (Vec<usize>, Vec<usize>) {
		let mut members = vec![self.roster.me];
		members.extend(self.others());
		let mut position = vec![0; self.roster.len()];
		for (pos, party) in members.iter().enumerate() {
			position[*party] = pos;
		}
		(members, position)
	}

	/// Leads a key generation among all parties: runs `protocol`, checks every party reports
	/// the same public value as `public(&result)`, and only then tells them to store.
	fn lead_keygen<T>(
		&self, op: SessionOp, protocol: impl FnOnce(&dyn MpTransport) -> Result<T, ProtocolError>,
		public: impl Fn(&T) -> Result<Vec<u8>, ServiceError>,
	) -> Result<T, ServiceError> {
		let (members, position) = self.everyone();
		let mesh = self.lead(&members, op).map_err(|(_, e)| e)?;
		let result = protocol(&ByRosterIndex { mesh: &mesh, position })?;
		let ours = public(&result)?;
		for (pos, party) in members.iter().enumerate().skip(1) {
			if self.read_done(&mesh, pos)? != ours {
				return Err(ServiceError::new(
					ErrorCode::KeyMismatch,
					format!(
						"party '{}' computed a different public key",
						self.roster.parties[*party].name
					),
				));
			}
		}
		for pos in 1..members.len() {
			mesh.link(pos).and_then(|l| l.send(FRAME_COMMIT)).map_err(ServiceError::unavailable)?;
		}
		Ok(result)
	}

	/// Returns the key's public key, generating the key with all parties first if this party
	/// has no share of it.
	pub fn ensure_key(
		&self, key_id: &KeyId, channel: Option<(ChannelId, KeyKind)>,
	) -> Result<PublicKey, ServiceError> {
		let lock = self.key_lock(key_id);
		let _guard = lock.lock().unwrap();
		if let Some(share) = self.store.get(key_id)? {
			if let Some((c, k)) = channel {
				self.policy.register_key(&c, k, key_id)?;
			}
			return self.pubkey_of(&share);
		}
		log::info!("generating key {} ({:?})", key_id.as_hex(), channel.map(|c| c.1));
		let share = self.lead_keygen(
			SessionOp::Dkg { key_id: *key_id, channel },
			|transport| mp::dkg(self.roster.ac(), self.roster.me, transport),
			|share| Ok(share.public_key_compressed()?),
		)?;
		let pk = self.pubkey_of(&share)?;
		self.store.insert_new(key_id, share)?;
		if let Some((c, k)) = channel {
			self.policy.register_key(&c, k, key_id)?;
		}
		log::info!("key {} generated: {}", key_id.as_hex(), pk);
		Ok(pk)
	}

	/// Returns this party's TDH2 key share, running the key generation with all parties first
	/// if there is none yet.
	pub fn ensure_tdh2(&self) -> Result<Arc<Tdh2Key>, ServiceError> {
		let mut slot = self.tdh2.lock().unwrap();
		if let Some(key) = slot.as_ref() {
			return Ok(Arc::clone(key));
		}
		log::info!("generating the TDH2 key for revocation secrets");
		let key = self.lead_keygen(
			SessionOp::Tdh2Dkg,
			|transport| tdh2::dkg(self.roster.ac(), self.roster.me, transport),
			|key| Ok(key.public_key.clone()),
		)?;
		self.store.insert_tdh2(&key)?;
		log::info!("TDH2 key generated: {}", key.public_key.as_hex());
		let key = Arc::new(key);
		*slot = Some(Arc::clone(&key));
		Ok(key)
	}

	/// The kit of `channel`, taking an unused one from the pool on first use and having every
	/// other party bind the same kit.
	fn kit_for(&self, channel: &ChannelId) -> Result<KitId, ServiceError> {
		if let Some(kit_id) = self.policy.kit_of(channel)? {
			return Ok(kit_id);
		}
		let key = self.ensure_tdh2()?;
		let kit_id = self.kits.bind_unbound(channel, &key.public_key).map_err(|e| {
			ServiceError::new(ErrorCode::KeyNotFound, format!("no kit for this channel: {e}"))
		})?;
		for (_, res) in self.ask_others(&SessionOp::BindKit { channel: *channel, kit_id }) {
			res?;
		}
		self.policy.bind_kit(channel, &kit_id)?;
		log::info!("bound kit {} to channel {}", kit_id.as_hex(), channel.as_hex());
		Ok(kit_id)
	}

	/// The per-commitment point for `idx`, from the channel's kit.
	fn per_commitment_point(
		&self, channel: &ChannelId, idx: u64,
	) -> Result<PublicKey, ServiceError> {
		let kit_id = self.kit_for(channel)?;
		let point = self.policy.per_commitment_point(channel, idx)?;
		if let Ok(left) = self.kits.remaining(&kit_id, idx) {
			if left <= LOW_KIT_WARNING && left % 16 == 0 {
				log::warn!(
					"kit {} of channel {} has {left} commitment numbers left: run the refill ceremony",
					kit_id.as_hex(),
					channel.as_hex()
				);
			}
		}
		Ok(point)
	}

	/// This party's partial decryption of the secret for `idx`, if its policy allows the
	/// release. `newer` lets it catch up on a validation it missed.
	fn partial_release(
		&self, channel: &ChannelId, idx: u64, newer: Option<&(u64, HolderProof)>,
	) -> Result<Vec<u8>, PolicyError> {
		if let Some((number, proof)) = newer {
			// A refusal here (for one, a commitment older than the one already recorded) is
			// not an answer to the release itself; the check below is.
			let _ =
				self.policy.holder_commitment_validated(channel, *number, Some(proof), &self.store);
		}
		let key =
			self.tdh2_key().ok_or_else(|| PolicyError("no TDH2 key share on this party".into()))?;
		// Decrypt only our own copy of the entry we authorized, never a ciphertext supplied
		// by another party.
		let (kit_id, entry) = self.policy.authorize_release(channel, idx)?;
		key.partial_decrypt(&entry.ciphertext, &kit::label(&kit_id, idx))
			.map_err(|e| PolicyError(format!("partial decryption failed: {e}")))
	}

	/// Recovers the per-commitment secret for `idx` from the partial decryptions of the
	/// parties whose policy allows the release; a quorum is needed. The result is checked
	/// against the per-commitment point before it is returned.
	fn release_commitment_secret(
		&self, channel: &ChannelId, idx: u64, newer: Option<(u64, HolderProof)>,
	) -> Result<[u8; 32], ServiceError> {
		let key = self.tdh2_key().ok_or_else(|| {
			ServiceError::new(ErrorCode::KeyNotFound, "no TDH2 key share on this party")
		})?;
		let (kit_id, entry) = self.policy.kit_entry(channel, idx)?;
		let label = kit::label(&kit_id, idx);
		let k = self.roster.ac().k;

		let mut partials: Vec<(String, Vec<u8>)> = Vec::new();
		let mut refusal: Option<ServiceError> = None;
		let mine = self.partial_release(channel, idx, newer.as_ref()).map_err(ServiceError::from);
		let theirs = self.ask_others(&SessionOp::ReleaseSecret { channel: *channel, idx, newer });
		for (party, res) in std::iter::once((self.roster.me, mine)).chain(theirs) {
			match res {
				Ok(partial) => partials.push((self.roster.parties[party].name.clone(), partial)),
				Err(e) => {
					log::warn!(
						"party '{}' did not contribute to releasing secret {idx}: {}",
						self.roster.parties[party].name,
						e.message
					);
					if refusal.is_none() || e.code == ErrorCode::PolicyDenied {
						refusal = Some(e);
					}
				},
			}
		}
		if partials.len() < k {
			return Err(refusal.unwrap_or_else(|| ServiceError::unavailable("no quorum reachable")));
		}
		partials.truncate(k);
		let secret: [u8; 32] = key
			.combine(self.roster.ac(), &entry.ciphertext, &label, &partials)?
			.try_into()
			.map_err(|_| ServiceError::new(ErrorCode::ProtocolFailed, "bad secret length"))?;
		let point = SecretKey::from_slice(&secret)
			.map(|sk| PublicKey::from_secret_key(&self.secp, &sk))
			.map_err(|e| ServiceError::new(ErrorCode::ProtocolFailed, e.to_string()))?;
		if point != entry.point {
			return Err(ServiceError::new(
				ErrorCode::ProtocolFailed,
				"decrypted secret does not match its per-commitment point",
			));
		}
		Ok(secret)
	}

	/// Derives the share to sign with and the expected derived public key.
	fn derive(
		&self, share: &KeyShare, derivation: &Derivation,
	) -> Result<(KeyShare, PublicKey), ServiceError> {
		let base = self.pubkey_of(share)?;
		match derivation {
			Derivation::None => Ok((share.clone(), base)),
			Derivation::Additive { tweak } => {
				let derived = share.derive_additive_tweak(tweak)?;
				let scalar = Scalar::from_be_bytes(*tweak)
					.map_err(|_| ServiceError::new(ErrorCode::BadRequest, "bad tweak"))?;
				let pk = base
					.add_exp_tweak(&self.secp, &scalar)
					.map_err(|e| ServiceError::new(ErrorCode::BadRequest, e.to_string()))?;
				Ok((derived, pk))
			},
			Derivation::MulAdd { mul, add } => {
				let derived = share.derive_mul_add(mul, add)?;
				let m = Scalar::from_be_bytes(*mul)
					.map_err(|_| ServiceError::new(ErrorCode::BadRequest, "bad mul"))?;
				let a = Scalar::from_be_bytes(*add)
					.map_err(|_| ServiceError::new(ErrorCode::BadRequest, "bad add"))?;
				let pk = base
					.mul_tweak(&self.secp, &m)
					.and_then(|p| p.add_exp_tweak(&self.secp, &a))
					.map_err(|e| ServiceError::new(ErrorCode::BadRequest, e.to_string()))?;
				Ok((derived, pk))
			},
		}
	}

	/// Checks every item against this party's policy, so that a refusal signs nothing.
	fn authorize_all(
		&self, channel: Option<&ChannelId>, items: &[SignItem],
	) -> Result<Vec<Authorized>, ServiceError> {
		let mut auths = Vec::with_capacity(items.len());
		for item in items {
			if self.store.get(&item.key_id)?.is_none() {
				return Err(ServiceError::new(ErrorCode::KeyNotFound, "unknown key id"));
			}
			auths.push(self.policy.authorize(channel, item, &self.store)?);
		}
		Ok(auths)
	}

	/// Every way to complete a quorum around this party, as roster indices with this party
	/// first: `k - 1` of the others, lowest indices first.
	fn quorums(&self) -> Vec<Vec<usize>> {
		fn choose(pool: &[usize], n: usize) -> Vec<Vec<usize>> {
			if n == 0 {
				return vec![Vec::new()];
			}
			let mut out = Vec::new();
			for (i, first) in pool.iter().enumerate() {
				for mut rest in choose(&pool[i + 1..], n - 1) {
					rest.insert(0, *first);
					out.push(rest);
				}
			}
			out
		}
		choose(&self.others(), self.roster.ac().k - 1)
			.into_iter()
			.map(|rest| {
				let mut quorum = vec![self.roster.me];
				quorum.extend(rest);
				quorum
			})
			.collect()
	}

	fn names(&self, parties: &[usize]) -> Vec<&str> {
		parties.iter().map(|p| self.roster.parties[*p].name.as_str()).collect()
	}

	/// Signs every item with a quorum this party leads: its own policy first, then each
	/// member's. If a member is unreachable or refuses, the next quorum is tried.
	pub fn sign_batch(
		self: &Arc<Self>, channel: Option<ChannelId>, items: Vec<SignItem>,
	) -> Result<Vec<Signature>, ServiceError> {
		if items.is_empty() {
			return Err(ServiceError::new(ErrorCode::BadRequest, "empty sign request"));
		}
		let auths = self.authorize_all(channel.as_ref(), &items)?;

		// One signing session per key at a time on this leader (cb-mpc advises against many
		// parallel signing sessions on one key).
		let mut key_ids: Vec<KeyId> = items.iter().map(|i| i.key_id).collect();
		key_ids.sort();
		key_ids.dedup();
		let locks: Vec<_> = key_ids.iter().map(|id| self.key_lock(id)).collect();
		let _guards: Vec<_> = locks.iter().map(|l| l.lock().unwrap()).collect();

		let mut down: Vec<usize> = Vec::new();
		let mut last_error = ServiceError::unavailable("no quorum reachable");
		for quorum in self.quorums() {
			if quorum.iter().any(|p| down.contains(p)) {
				continue;
			}
			match self.sign_with_quorum(&quorum, channel, &items) {
				Ok(sigs) => {
					for auth in auths {
						self.policy.commit(auth)?;
					}
					if let Some(channel) = channel {
						self.inform_observers(&quorum, channel, items);
					}
					return Ok(sigs);
				},
				Err((culprit, e)) => {
					log::warn!("signing with {:?} failed: {}", self.names(&quorum), e.message);
					if let (Some(peer), ErrorCode::PeerUnavailable) = (culprit, e.code) {
						down.push(peer);
					}
					if e.code == ErrorCode::PolicyDenied
						|| last_error.code != ErrorCode::PolicyDenied
					{
						last_error = e;
					}
				},
			}
		}
		Err(last_error)
	}

	fn sign_with_quorum(
		&self, quorum: &[usize], channel: Option<ChannelId>, items: &[SignItem],
	) -> Result<Vec<Signature>, (Option<usize>, ServiceError)> {
		let mesh = self.lead(quorum, SessionOp::Sign { channel, items: items.to_vec() })?;
		let mut sigs = Vec::with_capacity(items.len());
		for item in items {
			let sig = self.sign_item(quorum, 0, item, &mesh).map_err(|e| (None, e))?.ok_or_else(
				|| (None, ServiceError::new(ErrorCode::ProtocolFailed, "leader got no signature")),
			)?;
			sigs.push(sig);
		}
		// A member that fails after the signatures exist cannot take them back; its record of
		// the channel just lags until the next request it takes part in.
		for (pos, party) in quorum.iter().enumerate().skip(1) {
			if let Err(e) = self.read_done(&mesh, pos) {
				log::warn!(
					"party '{}' did not confirm the signing session: {}",
					self.roster.parties[*party].name,
					e.message
				);
			}
		}
		Ok(sigs)
	}

	/// Signs one item as member `position` of `quorum`. The leader (position 0) gets the
	/// signature, verified against the derived public key and normalized to low-S.
	fn sign_item(
		&self, quorum: &[usize], position: usize, item: &SignItem, mesh: &Mesh,
	) -> Result<Option<Signature>, ServiceError> {
		let share = self
			.store
			.get(&item.key_id)?
			.ok_or_else(|| ServiceError::new(ErrorCode::KeyNotFound, "unknown key id"))?;
		let (derived, expected_pk) = self.derive(&share, &item.derivation)?;
		let der = mp::sign(self.roster.ac(), quorum, position, &derived, &item.digest, 0, mesh)?;
		let Some(der) = der else { return Ok(None) };
		let mut sig = Signature::from_der(&der)
			.map_err(|e| ServiceError::new(ErrorCode::ProtocolFailed, format!("bad DER: {e}")))?;
		sig.normalize_s();
		self.secp.verify_ecdsa(&Message::from_digest(item.digest), &sig, &expected_pk).map_err(
			|e| {
				ServiceError::new(
					ErrorCode::ProtocolFailed,
					format!("signature failed to verify: {e}"),
				)
			},
		)?;
		Ok(Some(sig))
	}

	/// Tells the parties outside `quorum` what was signed, without waiting for them.
	fn inform_observers(
		self: &Arc<Self>, quorum: &[usize], channel: ChannelId, items: Vec<SignItem>,
	) {
		let observers: Vec<usize> =
			self.others().into_iter().filter(|p| !quorum.contains(p)).collect();
		if observers.is_empty() {
			return;
		}
		let svc = Arc::clone(self);
		thread::spawn(move || {
			for peer in observers {
				let op = SessionOp::Observe { channel, items: items.clone() };
				if let Err(e) = svc.ask(peer, op) {
					log::debug!(
						"party '{}' did not record the signing: {}",
						svc.roster.parties[peer].name,
						e.message
					);
				}
			}
		});
	}

	// -----------------------------------------------------------------------
	// Sessions led by another party
	// -----------------------------------------------------------------------

	fn handle_session(
		&self, mut link: SecureStream, leader: usize, start: SessionStart,
	) -> io::Result<()> {
		let members: Vec<usize> = start.members.iter().map(|m| *m as usize).collect();
		let n = self.roster.len();
		let position = members.iter().position(|m| *m == self.roster.me);
		let well_formed = members.first() == Some(&leader)
			&& members.iter().all(|m| *m < n)
			&& members.iter().enumerate().all(|(i, m)| !members[..i].contains(m));
		let (Some(position), true) = (position, well_formed) else {
			let ack = SessionAck::Error {
				code: ErrorCode::BadRequest,
				message: "bad session member list".into(),
			};
			return link.write_frame(&ack.encode());
		};

		match start.op {
			SessionOp::Dkg { key_id, channel } => {
				let ready = if members.len() != n {
					Err(ServiceError::new(
						ErrorCode::BadRequest,
						"key generation needs every party",
					))
				} else if self.store.get(&key_id)?.is_some() {
					// Another party lost its share but we still have ours: refuse rather than
					// generate a different key under the same id.
					Err(ServiceError::new(
						ErrorCode::KeyMismatch,
						"this party already holds a share for this key id",
					))
				} else {
					Ok(())
				};
				self.member_keygen(
					link,
					&start.session,
					&members,
					position,
					ready,
					|transport| mp::dkg(self.roster.ac(), self.roster.me, transport),
					|share| Ok(share.public_key_compressed()?),
					|share| {
						self.store.insert_new(&key_id, share)?;
						if let Some((c, k)) = channel {
							self.policy.register_key(&c, k, &key_id)?;
						}
						log::info!("key {} generated", key_id.as_hex());
						Ok(())
					},
				)
			},
			SessionOp::Tdh2Dkg => {
				// If this party is leading a TDH2 key generation of its own right now, say so
				// instead of waiting on it: two leaders waiting on each other would both time out.
				let Ok(mut slot) = self.tdh2.try_lock() else {
					let ack = SessionAck::Error {
						code: ErrorCode::PeerUnavailable,
						message: "busy with another TDH2 key generation".into(),
					};
					return link.write_frame(&ack.encode());
				};
				let ready = if members.len() != n {
					Err(ServiceError::new(
						ErrorCode::BadRequest,
						"key generation needs every party",
					))
				} else if slot.is_some() {
					// A different key would orphan every kit encrypted to the one we hold.
					Err(ServiceError::new(
						ErrorCode::KeyMismatch,
						"this party already holds a TDH2 key share",
					))
				} else {
					Ok(())
				};
				self.member_keygen(
					link,
					&start.session,
					&members,
					position,
					ready,
					|transport| tdh2::dkg(self.roster.ac(), self.roster.me, transport),
					|key| Ok(key.public_key.clone()),
					|key| {
						self.store.insert_tdh2(&key)?;
						log::info!("TDH2 key generated: {}", key.public_key.as_hex());
						*slot = Some(Arc::new(key));
						Ok(())
					},
				)
			},
			SessionOp::Sign { channel, items } => {
				self.member_sign(link, &start.session, &members, position, channel, items)
			},
			SessionOp::BindKit { channel, kit_id } => {
				let res = self.bind_kit_as_member(&channel, &kit_id).map(|_| Vec::new());
				Self::reply(link, res)
			},
			SessionOp::ReleaseSecret { channel, idx, newer } => {
				Self::reply(link, self.partial_release(&channel, idx, newer.as_ref()))
			},
			SessionOp::HolderCommitmentValidated { channel, commitment_number, proof } => {
				let res = self
					.policy
					.holder_commitment_validated(
						&channel,
						commitment_number,
						proof.as_ref(),
						&self.store,
					)
					.map(|_| Vec::new());
				Self::reply(link, res)
			},
			SessionOp::CounterpartyRevocationValidated { channel, idx, secret } => {
				let res = self
					.policy
					.counterparty_revocation_validated(&channel, idx, &secret)
					.map(|_| Vec::new());
				Self::reply(link, res)
			},
			SessionOp::Observe { channel, items } => {
				let res = self.authorize_all(Some(&channel), &items).and_then(|auths| {
					for auth in auths {
						self.policy.commit(auth)?;
					}
					Ok(())
				});
				let ack = match res {
					Ok(()) => SessionAck::ok(),
					Err(e) => SessionAck::Error { code: e.code, message: e.message },
				};
				link.write_frame(&ack.encode())
			},
		}
	}

	fn reply(mut link: SecureStream, res: Result<Vec<u8>, PolicyError>) -> io::Result<()> {
		let ack = match res {
			Ok(payload) => SessionAck::Ok { payload },
			Err(e) => {
				log::warn!("refusing request: {e}");
				SessionAck::Error { code: ErrorCode::PolicyDenied, message: e.to_string() }
			},
		};
		link.write_frame(&ack.encode())
	}

	/// Accepts or refuses an interactive session and, once the leader says go, links up with
	/// the other members: this party dials the members after it in the list and waits for the
	/// ones before it.
	fn join_mesh(
		&self, mut link: SecureStream, session: &SessionId, members: &[usize], position: usize,
		ready: Result<(), ServiceError>,
	) -> io::Result<Option<Mesh>> {
		if let Err(e) = ready {
			log::warn!("refusing session: {}", e.message);
			link.write_frame(&SessionAck::Error { code: e.code, message: e.message }.encode())?;
			return Ok(None);
		}
		link.write_frame(&SessionAck::ok().encode())?;
		if link.read_frame()? != FRAME_GO {
			return Err(io::Error::new(io::ErrorKind::InvalidData, "expected the leader's go"));
		}
		let mut mesh = Mesh::new(members.len());
		mesh.set(0, Link::new(link, self.timeout())?);
		for (other, party) in members.iter().enumerate().skip(1) {
			if other == position {
				continue;
			}
			let link = if position < other {
				let mut link = self.roster.connect(*party)?;
				link.write_frame(&MeshJoin { session: *session }.encode())?;
				link
			} else {
				self.joins.take(*session, *party, self.timeout())?
			};
			mesh.set(other, Link::new(link, self.timeout())?);
		}
		Ok(Some(mesh))
	}

	/// A key generation led by another party: run the protocol, report the public value, and
	/// store the result only when the leader confirms every party got the same one.
	#[allow(clippy::too_many_arguments)]
	fn member_keygen<T>(
		&self, link: SecureStream, session: &SessionId, members: &[usize], position: usize,
		ready: Result<(), ServiceError>,
		protocol: impl FnOnce(&dyn MpTransport) -> Result<T, ProtocolError>,
		public: impl Fn(&T) -> Result<Vec<u8>, ServiceError>,
		store: impl FnOnce(T) -> Result<(), ServiceError>,
	) -> io::Result<()> {
		let Some(mesh) = self.join_mesh(link, session, members, position, ready)? else {
			return Ok(());
		};
		let mut by_roster = vec![0; self.roster.len()];
		for (pos, party) in members.iter().enumerate() {
			by_roster[*party] = pos;
		}
		let result = protocol(&ByRosterIndex { mesh: &mesh, position: by_roster })
			.map_err(|e| io::Error::other(e.to_string()))?;
		let pubkey = public(&result).map_err(|e| io::Error::other(e.message))?;
		let leader = mesh.link(0)?;
		leader.send(&SessionDone { pubkey }.encode())?;
		if leader.recv()? != FRAME_COMMIT {
			return Err(io::Error::new(io::ErrorKind::InvalidData, "expected the leader's commit"));
		}
		store(result).map_err(|e| io::Error::other(e.message))
	}

	/// A signing session led by another party: this party's own policy decides whether it
	/// takes part.
	fn member_sign(
		&self, link: SecureStream, session: &SessionId, members: &[usize], position: usize,
		channel: Option<ChannelId>, items: Vec<SignItem>,
	) -> io::Result<()> {
		let prepared = if !self.roster.ac().is_quorum(members) {
			Err(ServiceError::new(ErrorCode::BadRequest, "not enough parties to sign"))
		} else if items.is_empty() {
			Err(ServiceError::new(ErrorCode::BadRequest, "empty sign request"))
		} else {
			self.authorize_all(channel.as_ref(), &items)
		};
		let (ready, auths) = match prepared {
			Ok(auths) => (Ok(()), auths),
			Err(e) => (Err(e), Vec::new()),
		};
		let Some(mesh) = self.join_mesh(link, session, members, position, ready)? else {
			return Ok(());
		};
		for item in &items {
			self.sign_item(members, position, item, &mesh)
				.map_err(|e| io::Error::other(e.message))?;
		}
		for auth in auths {
			self.policy.commit(auth).map_err(|e| io::Error::other(e.to_string()))?;
		}
		mesh.link(0)?.send(&SessionDone { pubkey: Vec::new() }.encode())
	}

	/// Binds a kit the leader chose, provided our copy exists and was encrypted to the TDH2
	/// key we hold a share of.
	fn bind_kit_as_member(&self, channel: &ChannelId, kit_id: &KitId) -> Result<(), PolicyError> {
		let key =
			self.tdh2_key().ok_or_else(|| PolicyError("no TDH2 key share on this party".into()))?;
		let kit_key = self
			.kits
			.public_key_id(kit_id, kit::INITIAL_COMMITMENT_NUMBER)
			.map_err(|e| PolicyError(format!("kit read failed: {e}")))?
			.ok_or_else(|| PolicyError("this party has no copy of that kit".into()))?;
		if kit_key != kit::public_key_id(&key.public_key) {
			return Err(PolicyError("kit was not encrypted to this party's TDH2 key".into()));
		}
		self.policy.bind_kit(channel, kit_id)
	}
}
