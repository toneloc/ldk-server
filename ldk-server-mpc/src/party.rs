//! The MPC party service (v2).
//!
//! One process runs as P1 (Party A) or P2 (Party B). Each party holds only its own cb-mpc
//! key-share blobs plus the policy state; Party B additionally holds the master secret from
//! which per-channel commitment seeds are derived. No Lightning channel state beyond the
//! policy counters is stored.
//!
//! - **Party A (P1)** accepts client [`Request`]s. For `Sign` it runs the policy itself,
//!   derives the signing share locally (additive / mul-add tweaks), opens one session per item
//!   to Party B in parallel and drives the cb-mpc protocol as the P1 role (the only role that
//!   obtains signatures). Requests that need the commitment seed are forwarded to Party B.
//! - **Party B (P2)** accepts sessions from Party A only, runs the policy independently, and
//!   plays the P2 role.
//!
//! Signing sessions for the same key are serialized with a per-key mutex, following cb-mpc's
//! guidance to avoid many parallel signing sessions on one key.

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
use bitcoin::secp256k1::{All, Message, PublicKey, Scalar, Secp256k1};
use hex_conservative::DisplayHex;

use crate::cbmpc::{Job, KeyBlob, Party, ProtocolError};
use crate::policy::{ChannelPolicy, KeyLookup, PolicyConfig, PolicyError};
use crate::protocol::{
	frame_kind, ChannelId, Derivation, ErrorCode, FrameKind, KeyId, KeyKind, Reader, Request,
	Response, SessionAck, SessionDone, SessionOp, SessionStart, SignItem, Writer,
};
use crate::secure::{AtRestKey, Conn};
use crate::transport::TcpTransport;

#[derive(Clone, Debug)]
pub struct PartyConfig {
	pub party: Party,
	pub listen_addr: SocketAddr,
	/// Address of P2, required when `party == P1`.
	pub peer_addr: Option<SocketAddr>,
	pub keystore_dir: PathBuf,
	/// Stable unique party identifiers used as cb-mpc `pid`s.
	pub p1_name: String,
	pub p2_name: String,
	/// Per-message I/O timeout for the inter-party protocol transport.
	pub protocol_timeout: Duration,
	/// I/O timeout for client connections.
	pub client_timeout: Duration,
	pub policy: PolicyConfig,
	/// Pre-shared key authenticating and encrypting the LDK Server ⇄ Party A link.
	pub client_psk: Option<[u8; 32]>,
	/// Pre-shared key authenticating and encrypting the Party A ⇄ Party B link.
	pub peer_psk: Option<[u8; 32]>,
	/// Key encrypting share blobs and the master secret at rest.
	pub share_key: Option<[u8; 32]>,
}

/// On-disk key-share store: one file per key, `<hex key_id>.share`.
///
/// Blobs are stored unencrypted for this proof of concept. cb-mpc's guidance is to encrypt
/// them at rest (envelope encryption with an external KMS/HSM); see README "Remaining work".
pub struct KeyStore {
	dir: PathBuf,
	cache: Mutex<HashMap<KeyId, Arc<KeyBlob>>>,
	at_rest: Option<AtRestKey>,
}

impl KeyStore {
	pub fn open(dir: &Path) -> io::Result<Self> {
		Self::open_with_key(dir, None)
	}

	/// With a share key, blobs and the master secret are AES-256-GCM encrypted at rest; the
	/// share key itself should live on a different medium (or a KMS/HSM) than the shares.
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

	fn path(&self, key_id: &KeyId) -> PathBuf {
		self.dir.join(format!("{}.share", key_id.as_hex()))
	}

	pub fn get(&self, key_id: &KeyId) -> io::Result<Option<Arc<KeyBlob>>> {
		if let Some(b) = self.cache.lock().unwrap().get(key_id) {
			return Ok(Some(Arc::clone(b)));
		}
		match fs::read(self.path(key_id)) {
			Ok(bytes) => {
				let blob = Arc::new(KeyBlob(self.unseal(bytes, "key share")?));
				self.cache.lock().unwrap().insert(*key_id, Arc::clone(&blob));
				Ok(Some(blob))
			},
			Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
			Err(e) => Err(e),
		}
	}

	/// Atomically persists a new share. Refuses to overwrite an existing share.
	pub fn insert_new(&self, key_id: &KeyId, blob: KeyBlob) -> io::Result<Arc<KeyBlob>> {
		let path = self.path(key_id);
		if path.exists() {
			return Err(io::Error::new(io::ErrorKind::AlreadyExists, "key share already exists"));
		}
		let tmp = self.dir.join(format!("{}.share.tmp", key_id.as_hex()));
		{
			let mut f = fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
			use std::io::Write;
			f.write_all(&self.seal(&blob.0)?)?;
			f.sync_all()?;
		}
		fs::rename(&tmp, &path)?;
		let blob = Arc::new(blob);
		self.cache.lock().unwrap().insert(*key_id, Arc::clone(&blob));
		Ok(blob)
	}

	pub fn count(&self) -> io::Result<usize> {
		Ok(fs::read_dir(&self.dir)?
			.filter_map(|e| e.ok())
			.filter(|e| e.path().extension().map(|x| x == "share").unwrap_or(false))
			.count())
	}

	/// Loads or creates the 32-byte master secret file (Party B's commitment-seed root).
	pub fn load_or_create_master_secret(&self) -> io::Result<[u8; 32]> {
		let path = self.dir.join("master.secret");
		match fs::read(&path) {
			Ok(bytes) => {
				let bytes = self.unseal(bytes, "master secret")?;
				if bytes.len() != 32 {
					return Err(io::Error::new(
						io::ErrorKind::InvalidData,
						"master.secret must be 32 bytes",
					));
				}
				Ok(bytes.try_into().unwrap())
			},
			Err(e) if e.kind() == io::ErrorKind::NotFound => {
				use bitcoin::secp256k1::rand::RngCore;
				let mut secret = [0u8; 32];
				bitcoin::secp256k1::rand::thread_rng().fill_bytes(&mut secret);
				let tmp = self.dir.join("master.secret.tmp");
				{
					use std::io::Write;
					let mut f = fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
					#[cfg(unix)]
					{
						use std::os::unix::fs::PermissionsExt;
						f.set_permissions(fs::Permissions::from_mode(0o600))?;
					}
					f.write_all(&self.seal(&secret)?)?;
					f.sync_all()?;
				}
				fs::rename(&tmp, &path)?;
				Ok(secret)
			},
			Err(e) => Err(e),
		}
	}
}

impl KeyLookup for KeyStore {
	fn public_key(&self, key_id: &KeyId) -> Option<PublicKey> {
		let blob = self.get(key_id).ok()??;
		PublicKey::from_slice(&blob.public_key_compressed().ok()?).ok()
	}
}

pub struct PartyService {
	cfg: PartyConfig,
	store: KeyStore,
	policy: ChannelPolicy,
	key_locks: Mutex<HashMap<KeyId, Arc<Mutex<()>>>>,
	secp: Secp256k1<All>,
	shutdown: AtomicBool,
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
			ProtocolError::Transport(t) => {
				ServiceError::new(ErrorCode::PeerUnavailable, t.to_string())
			},
			ProtocolError::Cbmpc(c) => ServiceError::new(ErrorCode::ProtocolFailed, c.to_string()),
		}
	}
}

impl From<crate::cbmpc::CbmpcError> for ServiceError {
	fn from(e: crate::cbmpc::CbmpcError) -> Self {
		ServiceError::new(ErrorCode::ProtocolFailed, e.to_string())
	}
}

impl PartyService {
	pub fn new(cfg: PartyConfig) -> io::Result<Arc<Self>> {
		if cfg.party == Party::P1 && cfg.peer_addr.is_none() {
			return Err(io::Error::new(io::ErrorKind::InvalidInput, "P1 requires a peer address"));
		}
		let store = KeyStore::open_with_key(&cfg.keystore_dir, cfg.share_key)?;
		if cfg.share_key.is_none() {
			log::warn!("no share key configured: key shares are stored unencrypted");
		}
		if cfg.peer_psk.is_none() {
			log::warn!("no peer pre-shared key configured: the party link is plain TCP");
		}
		// Only Party B holds the commitment-seed master secret.
		let master =
			if cfg.party == Party::P2 { Some(store.load_or_create_master_secret()?) } else { None };
		let policy = ChannelPolicy::open(&cfg.keystore_dir, cfg.policy.clone(), master)?;
		Ok(Arc::new(PartyService {
			cfg,
			store,
			policy,
			key_locks: Mutex::new(HashMap::new()),
			secp: Secp256k1::new(),
			shutdown: AtomicBool::new(false),
		}))
	}

	pub fn config(&self) -> &PartyConfig {
		&self.cfg
	}

	pub fn store(&self) -> &KeyStore {
		&self.store
	}

	pub fn policy(&self) -> &ChannelPolicy {
		&self.policy
	}

	fn key_lock(&self, key_id: &KeyId) -> Arc<Mutex<()>> {
		let mut locks = self.key_locks.lock().unwrap();
		Arc::clone(locks.entry(*key_id).or_insert_with(|| Arc::new(Mutex::new(()))))
	}

	fn job<'a>(&self, transport: &'a dyn crate::cbmpc::Transport) -> Job<'a> {
		Job::new(self.cfg.party, &self.cfg.p1_name, &self.cfg.p2_name, transport)
	}

	pub fn request_shutdown(&self) {
		self.shutdown.store(true, Ordering::SeqCst);
	}

	/// Binds the listener and serves forever (or until `request_shutdown`).
	pub fn serve(self: &Arc<Self>) -> io::Result<()> {
		let listener = TcpListener::bind(self.cfg.listen_addr)?;
		self.serve_on(listener)
	}

	pub fn serve_on(self: &Arc<Self>, listener: TcpListener) -> io::Result<()> {
		log::info!(
			"mpc party {} listening on {} (keystore: {}, {} shares, payout allow-list: {})",
			self.cfg.party.as_str(),
			listener.local_addr()?,
			self.cfg.keystore_dir.display(),
			self.store.count().unwrap_or(0),
			self.cfg.policy.payout.as_ref().map(|p| p.len()).unwrap_or(0)
		);
		for conn in listener.incoming() {
			if self.shutdown.load(Ordering::SeqCst) {
				break;
			}
			match conn {
				Ok(stream) => {
					let svc = Arc::clone(self);
					thread::spawn(move || {
						if let Err(e) = svc.handle_connection(stream) {
							log::debug!("connection ended: {e}");
						}
					});
				},
				Err(e) => log::warn!("accept failed: {e}"),
			}
		}
		Ok(())
	}

	fn handle_connection(self: &Arc<Self>, stream: TcpStream) -> io::Result<()> {
		stream.set_nodelay(true)?;
		stream.set_read_timeout(Some(self.cfg.client_timeout))?;
		stream.set_write_timeout(Some(self.cfg.client_timeout))?;
		// Party A serves clients (client PSK); Party B serves Party A (peer PSK).
		let psk = match self.cfg.party {
			Party::P1 => self.cfg.client_psk,
			Party::P2 => self.cfg.peer_psk,
		};
		let mut conn = Conn::new(stream, psk.as_ref(), false)?;
		let first = conn.read_frame()?;
		match frame_kind(&first) {
			FrameKind::Request => {
				let resp = match Request::decode(&first) {
					Ok(req) => self.handle_request(req),
					Err(e) => {
						Response::Error { code: ErrorCode::BadRequest, message: e.to_string() }
					},
				};
				conn.write_frame(&resp.encode())
			},
			FrameKind::SessionStart => match SessionStart::decode(&first) {
				Ok(start) => self.handle_session(conn, start),
				Err(e) => {
					let ack =
						SessionAck::Error { code: ErrorCode::BadRequest, message: e.to_string() };
					conn.write_frame(&ack.encode())
				},
			},
			FrameKind::Other => Err(io::Error::new(io::ErrorKind::InvalidData, "unknown frame")),
		}
	}

	// -----------------------------------------------------------------------
	// Client requests (Party A)
	// -----------------------------------------------------------------------

	fn handle_request(self: &Arc<Self>, req: Request) -> Response {
		if self.cfg.party != Party::P1 {
			return Response::Error {
				code: ErrorCode::BadRequest,
				message: "only P1 serves client requests".into(),
			};
		}
		let res: Result<Response, ServiceError> = match req {
			Request::Ping => Ok(Response::Pong),
			Request::EnsureKey { key_id, channel } => self
				.ensure_key(&key_id, channel)
				.map(|pk| Response::PublicKey { pubkey: pk.serialize().to_vec() }),
			Request::GetPublicKey { key_id } => self
				.public_key(&key_id)
				.map(|pk| Response::PublicKey { pubkey: pk.serialize().to_vec() }),
			Request::GetPerCommitmentPoint { channel, idx } => self
				.forward(SessionOp::PerCommitmentPoint { channel, idx })
				.and_then(|payload| parse_pubkey(&payload))
				.map(|pk| Response::PublicKey { pubkey: pk.serialize().to_vec() }),
			Request::ReleaseCommitmentSecret { channel, idx } => {
				self.forward(SessionOp::ReleaseSecret { channel, idx }).and_then(|payload| {
					let secret: [u8; 32] = payload
						.try_into()
						.map_err(|_| ServiceError::new(ErrorCode::ProtocolFailed, "bad secret"))?;
					Ok(Response::Secret { secret })
				})
			},
			Request::HolderCommitmentValidated { channel, commitment_number } => {
				// Mirror the state on both parties.
				self.policy
					.holder_commitment_validated(&channel, commitment_number)
					.map_err(ServiceError::from)
					.and_then(|_| {
						self.forward(SessionOp::HolderCommitmentValidated {
							channel,
							commitment_number,
						})
					})
					.map(|_| Response::Ack)
			},
			Request::CounterpartyRevocationValidated { channel, idx, secret } => self
				.policy
				.counterparty_revocation_validated(&channel, idx, &secret)
				.map_err(ServiceError::from)
				.and_then(|_| {
					self.forward(SessionOp::CounterpartyRevocationValidated {
						channel,
						idx,
						secret,
					})
				})
				.map(|_| Response::Ack),
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

	fn pubkey_of(&self, blob: &KeyBlob) -> Result<PublicKey, ServiceError> {
		let bytes = blob.public_key_compressed()?;
		PublicKey::from_slice(&bytes)
			.map_err(|e| ServiceError::new(ErrorCode::Internal, format!("bad pubkey: {e}")))
	}

	pub fn public_key(&self, key_id: &KeyId) -> Result<PublicKey, ServiceError> {
		match self.store.get(key_id)? {
			Some(blob) => self.pubkey_of(&blob),
			None => Err(ServiceError::new(ErrorCode::KeyNotFound, "unknown key id")),
		}
	}

	fn connect_peer(&self) -> Result<Conn, ServiceError> {
		let addr = self
			.cfg
			.peer_addr
			.ok_or_else(|| ServiceError::new(ErrorCode::Internal, "no peer configured"))?;
		let stream = TcpStream::connect_timeout(&addr, self.cfg.protocol_timeout).map_err(|e| {
			ServiceError::new(ErrorCode::PeerUnavailable, format!("connect to {addr}: {e}"))
		})?;
		stream.set_nodelay(true)?;
		stream.set_read_timeout(Some(self.cfg.protocol_timeout))?;
		stream.set_write_timeout(Some(self.cfg.protocol_timeout))?;
		Conn::new(stream, self.cfg.peer_psk.as_ref(), true).map_err(|e| {
			ServiceError::new(ErrorCode::Unauthorized, format!("peer handshake with {addr}: {e}"))
		})
	}

	/// Opens a session with P2: sends the start header and returns the stream plus ack payload.
	fn open_session(&self, start: &SessionStart) -> Result<(Conn, Vec<u8>), ServiceError> {
		let mut conn = self.connect_peer()?;
		conn.write_frame(&start.encode())
			.map_err(|e| ServiceError::new(ErrorCode::PeerUnavailable, e.to_string()))?;
		let ack = conn
			.read_frame()
			.map_err(|e| ServiceError::new(ErrorCode::PeerUnavailable, e.to_string()))?;
		match SessionAck::decode(&ack) {
			Ok(SessionAck::Ok { payload }) => Ok((conn, payload)),
			Ok(SessionAck::Error { code, message }) => {
				Err(ServiceError::new(code, format!("peer refused session: {message}")))
			},
			Err(e) => Err(ServiceError::new(ErrorCode::ProtocolFailed, e.to_string())),
		}
	}

	/// Runs a non-interactive request on Party B and returns its payload.
	fn forward(&self, op: SessionOp) -> Result<Vec<u8>, ServiceError> {
		let (_stream, payload) = self.open_session(&SessionStart { op })?;
		Ok(payload)
	}

	fn read_done(&self, transport: TcpTransport) -> Result<PublicKey, ServiceError> {
		let mut conn = transport.into_inner();
		let frame = conn
			.read_frame()
			.map_err(|e| ServiceError::new(ErrorCode::PeerUnavailable, e.to_string()))?;
		let done = SessionDone::decode(&frame)
			.map_err(|e| ServiceError::new(ErrorCode::ProtocolFailed, e.to_string()))?;
		PublicKey::from_slice(&done.pubkey)
			.map_err(|e| ServiceError::new(ErrorCode::ProtocolFailed, format!("peer pubkey: {e}")))
	}

	/// Returns the key's public key, running DKG with P2 first if this party has no share.
	pub fn ensure_key(
		&self, key_id: &KeyId, channel: Option<(ChannelId, KeyKind)>,
	) -> Result<PublicKey, ServiceError> {
		let lock = self.key_lock(key_id);
		let _guard = lock.lock().unwrap();
		if let Some(blob) = self.store.get(key_id)? {
			if let Some((c, k)) = channel {
				self.policy.register_key(&c, k, key_id)?;
			}
			return self.pubkey_of(&blob);
		}
		log::info!("running DKG for key {} ({:?})", key_id.as_hex(), channel.map(|c| c.1));
		let start = SessionStart { op: SessionOp::Dkg { key_id: *key_id, channel } };
		let (conn, _) = self.open_session(&start)?;
		let transport = TcpTransport::new(conn, self.cfg.protocol_timeout)?;
		let blob = self.job(&transport).dkg()?;
		let peer_pk = self.read_done(transport)?;
		let pk = self.pubkey_of(&blob)?;
		if pk != peer_pk {
			return Err(ServiceError::new(
				ErrorCode::KeyMismatch,
				format!("aggregate public key mismatch: ours {pk}, peer {peer_pk}"),
			));
		}
		self.store.insert_new(key_id, blob)?;
		if let Some((c, k)) = channel {
			self.policy.register_key(&c, k, key_id)?;
		}
		log::info!("DKG complete for key {}: {}", key_id.as_hex(), pk);
		Ok(pk)
	}

	/// Derives the share to sign with and the expected derived public key.
	fn derive(
		&self, blob: &KeyBlob, derivation: &Derivation,
	) -> Result<(KeyBlob, PublicKey), ServiceError> {
		let base = self.pubkey_of(blob)?;
		match derivation {
			Derivation::None => Ok((KeyBlob(blob.0.clone()), base)),
			Derivation::Additive { tweak } => {
				let derived = blob.derive_additive_tweak(tweak)?;
				let scalar = Scalar::from_be_bytes(*tweak)
					.map_err(|_| ServiceError::new(ErrorCode::BadRequest, "bad tweak"))?;
				let pk = base
					.add_exp_tweak(&self.secp, &scalar)
					.map_err(|e| ServiceError::new(ErrorCode::BadRequest, e.to_string()))?;
				Ok((derived, pk))
			},
			Derivation::MulAdd { mul, add } => {
				let derived = blob.derive_mul_add(mul, add)?;
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

	/// Signs every item (Party A): policy, derivation, one parallel session per item to Party B,
	/// verification of each signature against the derived aggregate key.
	pub fn sign_batch(
		self: &Arc<Self>, channel: Option<ChannelId>, items: Vec<SignItem>,
	) -> Result<Vec<Signature>, ServiceError> {
		if items.is_empty() {
			return Err(ServiceError::new(ErrorCode::BadRequest, "empty sign request"));
		}
		// Authorize everything up front so a policy failure signs nothing.
		let mut auths = Vec::with_capacity(items.len());
		for item in &items {
			if self.store.get(&item.key_id)?.is_none() {
				return Err(ServiceError::new(ErrorCode::KeyNotFound, "unknown key id"));
			}
			auths.push(self.policy.authorize(channel.as_ref(), item, &self.store)?);
		}
		let mut handles = Vec::with_capacity(items.len());
		for item in items.into_iter() {
			let svc = Arc::clone(self);
			handles.push(thread::spawn(move || svc.sign_one(channel, item)));
		}
		let mut sigs = Vec::with_capacity(handles.len());
		for h in handles {
			sigs.push(h.join().map_err(|_| {
				ServiceError::new(ErrorCode::Internal, "signing thread panicked")
			})??);
		}
		for auth in auths {
			self.policy.commit(auth)?;
		}
		Ok(sigs)
	}

	fn sign_one(
		&self, channel: Option<ChannelId>, item: SignItem,
	) -> Result<Signature, ServiceError> {
		let blob = self
			.store
			.get(&item.key_id)?
			.ok_or_else(|| ServiceError::new(ErrorCode::KeyNotFound, "unknown key id"))?;
		let (share, expected_pk) = self.derive(&blob, &item.derivation)?;
		let digest = item.digest;
		let lock = self.key_lock(&item.key_id);
		let _guard = lock.lock().unwrap();
		let start = SessionStart { op: SessionOp::Sign { channel, item } };
		let (conn, _) = self.open_session(&start)?;
		let transport = TcpTransport::new(conn, self.cfg.protocol_timeout)?;
		let der = self.job(&transport).sign(&share, &digest)?.ok_or_else(|| {
			ServiceError::new(ErrorCode::ProtocolFailed, "P1 did not receive a signature")
		})?;
		let peer_pk = self.read_done(transport)?;
		if expected_pk != peer_pk {
			return Err(ServiceError::new(
				ErrorCode::KeyMismatch,
				"derived public key mismatch between parties",
			));
		}
		let mut sig = Signature::from_der(&der)
			.map_err(|e| ServiceError::new(ErrorCode::ProtocolFailed, format!("bad DER: {e}")))?;
		sig.normalize_s();
		self.secp.verify_ecdsa(&Message::from_digest(digest), &sig, &expected_pk).map_err(|e| {
			ServiceError::new(ErrorCode::ProtocolFailed, format!("signature failed to verify: {e}"))
		})?;
		Ok(sig)
	}

	// -----------------------------------------------------------------------
	// Peer sessions (Party B)
	// -----------------------------------------------------------------------

	fn handle_session(&self, mut conn: Conn, start: SessionStart) -> io::Result<()> {
		if self.cfg.party != Party::P2 {
			let ack = SessionAck::Error {
				code: ErrorCode::BadRequest,
				message: "only P2 accepts sessions".into(),
			};
			return conn.write_frame(&ack.encode());
		}
		conn.set_timeouts(self.cfg.protocol_timeout)?;

		match start.op {
			SessionOp::Dkg { key_id, channel } => self.session_dkg(conn, key_id, channel),
			SessionOp::Sign { channel, item } => self.session_sign(conn, channel, item),
			SessionOp::PerCommitmentPoint { channel, idx } => {
				let res = self
					.policy
					.per_commitment_point(&channel, idx)
					.map(|pk| pk.serialize().to_vec());
				Self::reply(conn, res)
			},
			SessionOp::ReleaseSecret { channel, idx } => {
				let res = self.policy.release_commitment_secret(&channel, idx).map(|s| s.to_vec());
				Self::reply(conn, res)
			},
			SessionOp::HolderCommitmentValidated { channel, commitment_number } => {
				let res = self
					.policy
					.holder_commitment_validated(&channel, commitment_number)
					.map(|_| Vec::new());
				Self::reply(conn, res)
			},
			SessionOp::CounterpartyRevocationValidated { channel, idx, secret } => {
				let res = self
					.policy
					.counterparty_revocation_validated(&channel, idx, &secret)
					.map(|_| Vec::new());
				Self::reply(conn, res)
			},
		}
	}

	fn reply(mut conn: Conn, res: Result<Vec<u8>, PolicyError>) -> io::Result<()> {
		let ack = match res {
			Ok(payload) => SessionAck::Ok { payload },
			Err(e) => {
				log::warn!("refusing request: {e}");
				SessionAck::Error { code: ErrorCode::PolicyDenied, message: e.to_string() }
			},
		};
		conn.write_frame(&ack.encode())
	}

	fn session_dkg(
		&self, mut conn: Conn, key_id: KeyId, channel: Option<(ChannelId, KeyKind)>,
	) -> io::Result<()> {
		if self.store.get(&key_id)?.is_some() {
			// P1 lost its share but we still have ours: refuse rather than silently generating
			// a different key under the same id.
			let ack = SessionAck::Error {
				code: ErrorCode::KeyMismatch,
				message: "P2 already holds a share for this key id".into(),
			};
			return conn.write_frame(&ack.encode());
		}
		let lock = self.key_lock(&key_id);
		let _guard = lock.lock().unwrap();
		conn.write_frame(&SessionAck::ok().encode())?;
		let transport = TcpTransport::new(conn, self.cfg.protocol_timeout)?;
		log::info!("running DKG (P2) for key {} ({:?})", key_id.as_hex(), channel.map(|c| c.1));
		let result: Result<PublicKey, ServiceError> =
			self.job(&transport).dkg().map_err(ServiceError::from).and_then(|blob| {
				let pk = self.pubkey_of(&blob)?;
				self.store.insert_new(&key_id, blob)?;
				if let Some((c, k)) = channel {
					self.policy.register_key(&c, k, &key_id)?;
				}
				log::info!("DKG complete for key {}: {}", key_id.as_hex(), pk);
				Ok(pk)
			});
		Self::finish(transport, result)
	}

	fn session_sign(
		&self, mut conn: Conn, channel: Option<ChannelId>, item: SignItem,
	) -> io::Result<()> {
		let prepared: Result<(Arc<KeyBlob>, crate::policy::Authorized), ServiceError> = (|| {
			let blob = self
				.store
				.get(&item.key_id)?
				.ok_or_else(|| ServiceError::new(ErrorCode::KeyNotFound, "unknown key id"))?;
			let auth = self.policy.authorize(channel.as_ref(), &item, &self.store)?;
			Ok((blob, auth))
		})();
		let (blob, auth) = match prepared {
			Ok(x) => x,
			Err(e) => {
				log::warn!("refusing sign for key {}: {}", item.key_id.as_hex(), e.message);
				let ack = SessionAck::Error { code: e.code, message: e.message };
				return conn.write_frame(&ack.encode());
			},
		};
		let lock = self.key_lock(&item.key_id);
		let _guard = lock.lock().unwrap();
		conn.write_frame(&SessionAck::ok().encode())?;
		let transport = TcpTransport::new(conn, self.cfg.protocol_timeout)?;
		let result: Result<PublicKey, ServiceError> = (|| {
			let (share, expected_pk) = self.derive(&blob, &item.derivation)?;
			self.job(&transport).sign(&share, &item.digest)?;
			self.policy.commit(auth)?;
			Ok(expected_pk)
		})();
		Self::finish(transport, result)
	}

	fn finish(transport: TcpTransport, result: Result<PublicKey, ServiceError>) -> io::Result<()> {
		let mut conn = transport.into_inner();
		match result {
			Ok(pk) => conn.write_frame(&SessionDone { pubkey: pk.serialize().to_vec() }.encode()),
			Err(e) => {
				log::warn!("session failed: {}", e.message);
				Err(io::Error::other(e.message))
			},
		}
	}
}

fn parse_pubkey(bytes: &[u8]) -> Result<PublicKey, ServiceError> {
	PublicKey::from_slice(bytes)
		.map_err(|e| ServiceError::new(ErrorCode::ProtocolFailed, format!("bad pubkey: {e}")))
}

// Keep the (unused here) protocol helpers referenced so they stay public API.
#[allow(dead_code)]
fn _protocol_helpers(_: &Writer, _: &Reader<'_>) {}
