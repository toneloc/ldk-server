//! Blocking client used by LDK Server's channel signer to talk to MPC Party A (P1).
//!
//! Each call opens a fresh TCP connection, sends one [`Request`] and reads one
//! [`Response`]. Calls are bounded by `timeout` so LDK's signer callbacks can never block
//! indefinitely.

use std::fmt;
use std::io;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{Message, PublicKey, Secp256k1, Verification};

use crate::protocol::{ErrorCode, KeyId, Request, Response, SigningContext};
use crate::transport::{read_frame, write_frame};

#[derive(Debug)]
pub enum ClientError {
	/// Could not connect or the connection failed / timed out.
	Io(io::Error),
	/// Malformed response.
	Protocol(String),
	/// The service returned an error.
	Remote { code: ErrorCode, message: String },
	/// The returned signature did not verify against the expected public key.
	InvalidSignature,
}

impl ClientError {
	pub fn is_timeout(&self) -> bool {
		matches!(self, ClientError::Io(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut)
	}
}

impl fmt::Display for ClientError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			ClientError::Io(e) => write!(f, "mpc client I/O error: {e}"),
			ClientError::Protocol(m) => write!(f, "mpc client protocol error: {m}"),
			ClientError::Remote { code, message } => {
				write!(f, "mpc service error {code:?}: {message}")
			},
			ClientError::InvalidSignature => write!(f, "mpc signature failed verification"),
		}
	}
}

impl std::error::Error for ClientError {}

impl From<io::Error> for ClientError {
	fn from(e: io::Error) -> Self {
		ClientError::Io(e)
	}
}

#[derive(Clone, Debug)]
pub struct MpcClient {
	addr: SocketAddr,
	connect_timeout: Duration,
	/// Read/write timeout for ordinary requests (sign, get key).
	request_timeout: Duration,
	/// Read timeout for `EnsureKey`, which may run a DKG.
	dkg_timeout: Duration,
}

impl MpcClient {
	pub fn new(addr: SocketAddr) -> Self {
		MpcClient {
			addr,
			connect_timeout: Duration::from_secs(5),
			request_timeout: Duration::from_secs(30),
			dkg_timeout: Duration::from_secs(120),
		}
	}

	pub fn with_timeouts(mut self, connect: Duration, request: Duration, dkg: Duration) -> Self {
		self.connect_timeout = connect;
		self.request_timeout = request;
		self.dkg_timeout = dkg;
		self
	}

	pub fn addr(&self) -> SocketAddr {
		self.addr
	}

	fn call(&self, req: &Request, read_timeout: Duration) -> Result<Response, ClientError> {
		let mut stream = TcpStream::connect_timeout(&self.addr, self.connect_timeout)?;
		stream.set_nodelay(true)?;
		stream.set_write_timeout(Some(self.request_timeout))?;
		stream.set_read_timeout(Some(read_timeout))?;
		write_frame(&mut stream, &req.encode())?;
		let frame = read_frame(&mut stream)?;
		let resp = Response::decode(&frame).map_err(|e| ClientError::Protocol(e.to_string()))?;
		if let Response::Error { code, message } = resp {
			return Err(ClientError::Remote { code, message });
		}
		Ok(resp)
	}

	pub fn ping(&self) -> Result<(), ClientError> {
		match self.call(&Request::Ping, self.request_timeout)? {
			Response::Pong => Ok(()),
			other => Err(ClientError::Protocol(format!("unexpected response {other:?}"))),
		}
	}

	fn parse_pubkey(resp: Response) -> Result<PublicKey, ClientError> {
		match resp {
			Response::PublicKey { pubkey } => PublicKey::from_slice(&pubkey)
				.map_err(|e| ClientError::Protocol(format!("invalid public key: {e}"))),
			other => Err(ClientError::Protocol(format!("unexpected response {other:?}"))),
		}
	}

	/// Returns the aggregate public key for `key_id`, running DKG if needed. Idempotent.
	pub fn ensure_key(&self, key_id: &KeyId) -> Result<PublicKey, ClientError> {
		Self::parse_pubkey(self.call(&Request::EnsureKey { key_id: *key_id }, self.dkg_timeout)?)
	}

	pub fn get_public_key(&self, key_id: &KeyId) -> Result<PublicKey, ClientError> {
		Self::parse_pubkey(
			self.call(&Request::GetPublicKey { key_id: *key_id }, self.request_timeout)?,
		)
	}

	/// Requests a 2-of-2 signature over `digest`. If `expected_pubkey` is given the
	/// signature is verified locally before being returned.
	pub fn sign<C: Verification>(
		&self, secp: &Secp256k1<C>, key_id: &KeyId, digest: &[u8; 32],
		context: Option<SigningContext>, expected_pubkey: Option<&PublicKey>,
	) -> Result<Signature, ClientError> {
		let request_id = new_request_id();
		let req = Request::Sign { request_id, key_id: *key_id, digest: *digest, context };
		let sig = match self.call(&req, self.request_timeout)? {
			Response::Signature { request_id: rid, sig_compact } => {
				if rid != request_id {
					return Err(ClientError::Protocol("request id mismatch".into()));
				}
				Signature::from_compact(&sig_compact)
					.map_err(|e| ClientError::Protocol(format!("invalid signature: {e}")))?
			},
			other => return Err(ClientError::Protocol(format!("unexpected response {other:?}"))),
		};
		if let Some(pk) = expected_pubkey {
			secp.verify_ecdsa(&Message::from_digest(*digest), &sig, pk)
				.map_err(|_| ClientError::InvalidSignature)?;
		}
		Ok(sig)
	}
}

fn new_request_id() -> [u8; 16] {
	use bitcoin::secp256k1::rand::RngCore;
	let mut id = [0u8; 16];
	bitcoin::secp256k1::rand::thread_rng().fill_bytes(&mut id);
	id
}
