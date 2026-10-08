//! The MPC party service.
//!
//! One process runs as P1 or P2. Each party holds only its own cb-mpc key-share blobs,
//! persisted under a keystore directory keyed by [`KeyId`]. No Lightning channel state is
//! stored or interpreted here.
//!
//! - **P1** accepts client [`Request`]s, and for `EnsureKey`/`Sign` opens a session to P2 and
//!   drives the cb-mpc protocol as the P1 role (the only role that obtains signatures).
//! - **P2** accepts sessions from P1 and plays the P2 role.
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
use bitcoin::secp256k1::{Message, PublicKey, Secp256k1};
use hex_conservative::DisplayHex;

use crate::cbmpc::{Job, KeyBlob, Party, ProtocolError};
use crate::policy::{AllowAllPolicy, MpcSignRequest, SigningPolicy};
use crate::protocol::{
	frame_kind, ErrorCode, FrameKind, KeyId, Request, Response, SessionAck, SessionDone, SessionOp,
	SessionStart, SigningContext,
};
use crate::transport::{read_frame, write_frame, TcpTransport};

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
}

/// On-disk key-share store: one file per key, `<hex key_id>.share`.
///
/// Blobs are stored unencrypted for this proof of concept. cb-mpc's guidance is to encrypt
/// them at rest (envelope encryption with an external KMS/HSM); see README "Remaining work".
pub struct KeyStore {
	dir: PathBuf,
	cache: Mutex<HashMap<KeyId, Arc<KeyBlob>>>,
}

impl KeyStore {
	pub fn open(dir: &Path) -> io::Result<Self> {
		fs::create_dir_all(dir)?;
		Ok(KeyStore { dir: dir.to_path_buf(), cache: Mutex::new(HashMap::new()) })
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
				let blob = Arc::new(KeyBlob(bytes));
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
			f.write_all(&blob.0)?;
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
}

pub struct PartyService {
	cfg: PartyConfig,
	store: KeyStore,
	key_locks: Mutex<HashMap<KeyId, Arc<Mutex<()>>>>,
	policy: Arc<dyn SigningPolicy>,
	secp: Secp256k1<bitcoin::secp256k1::All>,
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

impl PartyService {
	pub fn new(cfg: PartyConfig) -> io::Result<Arc<Self>> {
		Self::with_policy(cfg, Arc::new(AllowAllPolicy))
	}

	pub fn with_policy(cfg: PartyConfig, policy: Arc<dyn SigningPolicy>) -> io::Result<Arc<Self>> {
		if cfg.party == Party::P1 && cfg.peer_addr.is_none() {
			return Err(io::Error::new(io::ErrorKind::InvalidInput, "P1 requires a peer address"));
		}
		let store = KeyStore::open(&cfg.keystore_dir)?;
		Ok(Arc::new(PartyService {
			cfg,
			store,
			key_locks: Mutex::new(HashMap::new()),
			policy,
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

	/// Binds the listener and serves forever (or until `request_shutdown`). Each connection
	/// is handled on its own thread.
	pub fn serve(self: &Arc<Self>) -> io::Result<()> {
		let listener = TcpListener::bind(self.cfg.listen_addr)?;
		self.serve_on(listener)
	}

	pub fn serve_on(self: &Arc<Self>, listener: TcpListener) -> io::Result<()> {
		log::info!(
			"mpc party {} listening on {} (keystore: {}, {} shares)",
			self.cfg.party.as_str(),
			listener.local_addr()?,
			self.cfg.keystore_dir.display(),
			self.store.count().unwrap_or(0)
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

	fn handle_connection(&self, mut stream: TcpStream) -> io::Result<()> {
		stream.set_nodelay(true)?;
		stream.set_read_timeout(Some(self.cfg.client_timeout))?;
		stream.set_write_timeout(Some(self.cfg.client_timeout))?;
		let first = read_frame(&mut stream)?;
		match frame_kind(&first) {
			FrameKind::Request => {
				let resp = match Request::decode(&first) {
					Ok(req) => self.handle_request(req),
					Err(e) => {
						Response::Error { code: ErrorCode::BadRequest, message: e.to_string() }
					},
				};
				write_frame(&mut stream, &resp.encode())
			},
			FrameKind::SessionStart => match SessionStart::decode(&first) {
				Ok(start) => self.handle_session(stream, start),
				Err(e) => {
					let ack =
						SessionAck::Error { code: ErrorCode::BadRequest, message: e.to_string() };
					write_frame(&mut stream, &ack.encode())
				},
			},
			FrameKind::Other => Err(io::Error::new(io::ErrorKind::InvalidData, "unknown frame")),
		}
	}

	// -----------------------------------------------------------------------
	// Client requests (P1)
	// -----------------------------------------------------------------------

	fn handle_request(&self, req: Request) -> Response {
		let res = match req {
			Request::Ping => Ok(Response::Pong),
			Request::EnsureKey { key_id } => self
				.ensure_key(&key_id)
				.map(|pk| Response::PublicKey { pubkey: pk.serialize().to_vec() }),
			Request::GetPublicKey { key_id } => self
				.public_key(&key_id)
				.map(|pk| Response::PublicKey { pubkey: pk.serialize().to_vec() }),
			Request::Sign { request_id, key_id, digest, context } => self
				.sign(request_id, &key_id, &digest, context.as_ref())
				.map(|sig| Response::Signature {
					request_id,
					sig_compact: sig.serialize_compact().to_vec(),
				}),
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
		let bytes = blob
			.public_key_compressed()
			.map_err(|e| ServiceError::new(ErrorCode::Internal, e.to_string()))?;
		PublicKey::from_slice(&bytes)
			.map_err(|e| ServiceError::new(ErrorCode::Internal, format!("bad pubkey: {e}")))
	}

	pub fn public_key(&self, key_id: &KeyId) -> Result<PublicKey, ServiceError> {
		match self.store.get(key_id)? {
			Some(blob) => self.pubkey_of(&blob),
			None => Err(ServiceError::new(ErrorCode::KeyNotFound, "unknown key id")),
		}
	}

	fn connect_peer(&self) -> Result<TcpStream, ServiceError> {
		let addr = self
			.cfg
			.peer_addr
			.ok_or_else(|| ServiceError::new(ErrorCode::Internal, "no peer configured"))?;
		TcpStream::connect_timeout(&addr, self.cfg.protocol_timeout).map_err(|e| {
			ServiceError::new(ErrorCode::PeerUnavailable, format!("connect to {addr}: {e}"))
		})
	}

	/// Opens a session with P2: sends the start header and waits for the ack.
	fn open_session(&self, start: &SessionStart) -> Result<TcpTransport, ServiceError> {
		let mut stream = self.connect_peer()?;
		stream
			.set_read_timeout(Some(self.cfg.protocol_timeout))
			.and_then(|_| stream.set_write_timeout(Some(self.cfg.protocol_timeout)))?;
		write_frame(&mut stream, &start.encode())
			.map_err(|e| ServiceError::new(ErrorCode::PeerUnavailable, e.to_string()))?;
		let ack = read_frame(&mut stream)
			.map_err(|e| ServiceError::new(ErrorCode::PeerUnavailable, e.to_string()))?;
		match SessionAck::decode(&ack) {
			Ok(SessionAck::Ok) => {},
			Ok(SessionAck::Error { code, message }) => {
				return Err(ServiceError::new(code, format!("peer refused session: {message}")))
			},
			Err(e) => return Err(ServiceError::new(ErrorCode::ProtocolFailed, e.to_string())),
		}
		Ok(TcpTransport::new(stream, self.cfg.protocol_timeout)?)
	}

	fn read_done(&self, transport: TcpTransport) -> Result<PublicKey, ServiceError> {
		let mut stream = transport.into_inner();
		let frame = read_frame(&mut stream)
			.map_err(|e| ServiceError::new(ErrorCode::PeerUnavailable, e.to_string()))?;
		let done = SessionDone::decode(&frame)
			.map_err(|e| ServiceError::new(ErrorCode::ProtocolFailed, e.to_string()))?;
		PublicKey::from_slice(&done.pubkey)
			.map_err(|e| ServiceError::new(ErrorCode::ProtocolFailed, format!("peer pubkey: {e}")))
	}

	/// Returns the key's public key, running DKG with P2 first if this party has no share.
	pub fn ensure_key(&self, key_id: &KeyId) -> Result<PublicKey, ServiceError> {
		if self.cfg.party != Party::P1 {
			return Err(ServiceError::new(ErrorCode::BadRequest, "only P1 serves client requests"));
		}
		let lock = self.key_lock(key_id);
		let _guard = lock.lock().unwrap();
		if let Some(blob) = self.store.get(key_id)? {
			return self.pubkey_of(&blob);
		}
		log::info!("running DKG for key {}", key_id.as_hex());
		let start =
			SessionStart { op: SessionOp::Dkg, key_id: *key_id, digest: None, context: None };
		let transport = self.open_session(&start)?;
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
		log::info!("DKG complete for key {}: {}", key_id.as_hex(), pk);
		Ok(pk)
	}

	/// Produces a low-S ECDSA signature over `digest`, verified against the aggregate key.
	pub fn sign(
		&self, request_id: [u8; 16], key_id: &KeyId, digest: &[u8; 32],
		context: Option<&SigningContext>,
	) -> Result<Signature, ServiceError> {
		if self.cfg.party != Party::P1 {
			return Err(ServiceError::new(ErrorCode::BadRequest, "only P1 serves client requests"));
		}
		let blob = self
			.store
			.get(key_id)?
			.ok_or_else(|| ServiceError::new(ErrorCode::KeyNotFound, "unknown key id"))?;
		self.policy
			.authorize(&MpcSignRequest { request_id, key_id: *key_id, digest: *digest, context })
			.map_err(|e| ServiceError::new(ErrorCode::PolicyDenied, e.to_string()))?;

		let lock = self.key_lock(key_id);
		let _guard = lock.lock().unwrap();
		let start = SessionStart {
			op: SessionOp::Sign,
			key_id: *key_id,
			digest: Some(*digest),
			context: context.cloned(),
		};
		let transport = self.open_session(&start)?;
		let der = self.job(&transport).sign(&blob, digest)?.ok_or_else(|| {
			ServiceError::new(ErrorCode::ProtocolFailed, "P1 did not receive a signature")
		})?;
		let peer_pk = self.read_done(transport)?;
		let pk = self.pubkey_of(&blob)?;
		if pk != peer_pk {
			return Err(ServiceError::new(ErrorCode::KeyMismatch, "aggregate public key mismatch"));
		}
		let mut sig = Signature::from_der(&der)
			.map_err(|e| ServiceError::new(ErrorCode::ProtocolFailed, format!("bad DER: {e}")))?;
		sig.normalize_s();
		let msg = Message::from_digest(*digest);
		self.secp.verify_ecdsa(&msg, &sig, &pk).map_err(|e| {
			ServiceError::new(ErrorCode::ProtocolFailed, format!("signature failed to verify: {e}"))
		})?;
		log::debug!("signed request {} with key {}", request_id.as_hex(), key_id.as_hex());
		Ok(sig)
	}

	// -----------------------------------------------------------------------
	// Peer sessions (P2)
	// -----------------------------------------------------------------------

	fn handle_session(&self, mut stream: TcpStream, start: SessionStart) -> io::Result<()> {
		if self.cfg.party != Party::P2 {
			let ack = SessionAck::Error {
				code: ErrorCode::BadRequest,
				message: "only P2 accepts sessions".into(),
			};
			return write_frame(&mut stream, &ack.encode());
		}
		stream.set_read_timeout(Some(self.cfg.protocol_timeout))?;
		stream.set_write_timeout(Some(self.cfg.protocol_timeout))?;

		// Validate the request before acking so P1 gets a clear error.
		let prepared = self.prepare_session(&start);
		let blob = match prepared {
			Ok(blob) => blob,
			Err(e) => {
				log::warn!(
					"refusing session {:?} for key {}: {}",
					start.op,
					start.key_id.as_hex(),
					e.message
				);
				let ack = SessionAck::Error { code: e.code, message: e.message };
				return write_frame(&mut stream, &ack.encode());
			},
		};

		let lock = self.key_lock(&start.key_id);
		let _guard = lock.lock().unwrap();
		write_frame(&mut stream, &SessionAck::Ok.encode())?;
		let transport = TcpTransport::new(stream, self.cfg.protocol_timeout)?;

		let result: Result<PublicKey, ServiceError> = match start.op {
			SessionOp::Dkg => {
				log::info!("running DKG (P2) for key {}", start.key_id.as_hex());
				self.job(&transport).dkg().map_err(ServiceError::from).and_then(|blob| {
					let pk = self.pubkey_of(&blob)?;
					self.store.insert_new(&start.key_id, blob)?;
					log::info!("DKG complete for key {}: {}", start.key_id.as_hex(), pk);
					Ok(pk)
				})
			},
			SessionOp::Sign => {
				let blob = blob.expect("prepared");
				let digest = start.digest.expect("prepared");
				self.job(&transport)
					.sign(&blob, &digest)
					.map_err(ServiceError::from)
					.and_then(|_| self.pubkey_of(&blob))
			},
			SessionOp::Refresh => {
				Err(ServiceError::new(ErrorCode::BadRequest, "refresh not supported in this POC"))
			},
		};

		let mut stream = transport.into_inner();
		match result {
			Ok(pk) => {
				write_frame(&mut stream, &SessionDone { pubkey: pk.serialize().to_vec() }.encode())
			},
			Err(e) => {
				log::warn!(
					"session {:?} for key {} failed: {}",
					start.op,
					start.key_id.as_hex(),
					e.message
				);
				Err(io::Error::other(e.message))
			},
		}
	}

	fn prepare_session(&self, start: &SessionStart) -> Result<Option<Arc<KeyBlob>>, ServiceError> {
		match start.op {
			SessionOp::Dkg => {
				if self.store.get(&start.key_id)?.is_some() {
					// P1 lost its share but we still have ours: refuse rather than silently
					// generating a different key under the same id.
					return Err(ServiceError::new(
						ErrorCode::KeyMismatch,
						"P2 already holds a share for this key id",
					));
				}
				Ok(None)
			},
			SessionOp::Sign => {
				let blob = self
					.store
					.get(&start.key_id)?
					.ok_or_else(|| ServiceError::new(ErrorCode::KeyNotFound, "unknown key id"))?;
				let digest = start
					.digest
					.ok_or_else(|| ServiceError::new(ErrorCode::BadRequest, "missing digest"))?;
				self.policy
					.authorize(&MpcSignRequest {
						request_id: [0u8; 16],
						key_id: start.key_id,
						digest,
						context: start.context.as_ref(),
					})
					.map_err(|e| ServiceError::new(ErrorCode::PolicyDenied, e.to_string()))?;
				Ok(Some(blob))
			},
			SessionOp::Refresh => {
				Err(ServiceError::new(ErrorCode::BadRequest, "refresh not supported in this POC"))
			},
		}
	}
}
