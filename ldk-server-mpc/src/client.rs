//! Blocking client used by LDK Server's channel signer to talk to MPC Party A (P1).
//!
//! Each call opens a fresh TCP connection, sends one [`Request`] and reads one [`Response`].
//! Calls are bounded by `timeout` so LDK's signer callbacks can never block indefinitely.

use std::fmt;
use std::io;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{Message, PublicKey, Secp256k1, Verification};

use crate::protocol::{
	ChannelId, Derivation, ErrorCode, KeyId, KeyKind, Request, Response, SignItem, SigningContext,
	SigningOp,
};
use crate::secure::Conn;

#[derive(Debug)]
pub enum ClientError {
	/// Could not connect or the connection failed / timed out.
	Io(io::Error),
	/// Malformed response.
	Protocol(String),
	/// The service returned an error.
	Remote { code: ErrorCode, message: String },
	/// A returned signature did not verify against the expected public key.
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
	/// Read/write timeout for ordinary requests.
	request_timeout: Duration,
	/// Read timeout for `EnsureKey`, which may run a DKG.
	dkg_timeout: Duration,
	/// Pre-shared key for the authenticated, encrypted link to Party A.
	psk: Option<[u8; 32]>,
}

impl MpcClient {
	pub fn new(addr: SocketAddr) -> Self {
		MpcClient {
			addr,
			connect_timeout: Duration::from_secs(5),
			request_timeout: Duration::from_secs(30),
			dkg_timeout: Duration::from_secs(120),
			psk: None,
		}
	}

	/// Authenticates and encrypts the link with a 32-byte pre-shared key (see `secure`).
	pub fn with_psk(mut self, psk: [u8; 32]) -> Self {
		self.psk = Some(psk);
		self
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
		let stream = TcpStream::connect_timeout(&self.addr, self.connect_timeout)?;
		stream.set_nodelay(true)?;
		stream.set_write_timeout(Some(self.request_timeout))?;
		stream.set_read_timeout(Some(read_timeout))?;
		let mut conn = Conn::new(stream, self.psk.as_ref(), true)?;
		conn.write_frame(&req.encode())?;
		let frame = conn.read_frame()?;
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

	fn expect_ack(resp: Response) -> Result<(), ClientError> {
		match resp {
			Response::Ack => Ok(()),
			other => Err(ClientError::Protocol(format!("unexpected response {other:?}"))),
		}
	}

	/// Returns the aggregate public key for a standalone `key_id`, running DKG if needed.
	pub fn ensure_key(&self, key_id: &KeyId) -> Result<PublicKey, ClientError> {
		Self::parse_pubkey(
			self.call(&Request::EnsureKey { key_id: *key_id, channel: None }, self.dkg_timeout)?,
		)
	}

	/// Returns the aggregate public key for channel key `kind` of `channel`, running DKG if
	/// needed and binding the key to the channel for policy purposes.
	pub fn ensure_channel_key(
		&self, key_id: &KeyId, channel: &ChannelId, kind: KeyKind,
	) -> Result<PublicKey, ClientError> {
		Self::parse_pubkey(self.call(
			&Request::EnsureKey { key_id: *key_id, channel: Some((*channel, kind)) },
			self.dkg_timeout,
		)?)
	}

	pub fn get_public_key(&self, key_id: &KeyId) -> Result<PublicKey, ClientError> {
		Self::parse_pubkey(
			self.call(&Request::GetPublicKey { key_id: *key_id }, self.request_timeout)?,
		)
	}

	pub fn per_commitment_point(
		&self, channel: &ChannelId, idx: u64,
	) -> Result<PublicKey, ClientError> {
		Self::parse_pubkey(self.call(
			&Request::GetPerCommitmentPoint { channel: *channel, idx },
			self.request_timeout,
		)?)
	}

	pub fn release_commitment_secret(
		&self, channel: &ChannelId, idx: u64,
	) -> Result<[u8; 32], ClientError> {
		match self.call(
			&Request::ReleaseCommitmentSecret { channel: *channel, idx },
			self.request_timeout,
		)? {
			Response::Secret { secret } => Ok(secret),
			other => Err(ClientError::Protocol(format!("unexpected response {other:?}"))),
		}
	}

	pub fn holder_commitment_validated(
		&self, channel: &ChannelId, commitment_number: u64,
	) -> Result<(), ClientError> {
		Self::expect_ack(self.call(
			&Request::HolderCommitmentValidated { channel: *channel, commitment_number },
			self.request_timeout,
		)?)
	}

	pub fn counterparty_revocation_validated(
		&self, channel: &ChannelId, idx: u64, secret: [u8; 32],
	) -> Result<(), ClientError> {
		Self::expect_ack(self.call(
			&Request::CounterpartyRevocationValidated { channel: *channel, idx, secret },
			self.request_timeout,
		)?)
	}

	/// Requests one 2-of-2 signature per item. If `expected_pubkeys` is given (one per item),
	/// each signature is verified locally before being returned.
	pub fn sign_batch<C: Verification>(
		&self, secp: &Secp256k1<C>, channel: Option<ChannelId>, items: Vec<SignItem>,
		expected_pubkeys: Option<&[PublicKey]>,
	) -> Result<Vec<Signature>, ClientError> {
		let request_id = new_request_id();
		let n = items.len();
		let digests: Vec<[u8; 32]> = items.iter().map(|i| i.digest).collect();
		let req = Request::Sign { request_id, channel, items };
		let sigs = match self.call(&req, self.request_timeout)? {
			Response::Signatures { request_id: rid, sigs } => {
				if rid != request_id {
					return Err(ClientError::Protocol("request id mismatch".into()));
				}
				if sigs.len() != n {
					return Err(ClientError::Protocol("signature count mismatch".into()));
				}
				sigs.iter()
					.map(|s| {
						Signature::from_compact(s)
							.map_err(|e| ClientError::Protocol(format!("invalid signature: {e}")))
					})
					.collect::<Result<Vec<_>, _>>()?
			},
			other => return Err(ClientError::Protocol(format!("unexpected response {other:?}"))),
		};
		if let Some(pks) = expected_pubkeys {
			if pks.len() != n {
				return Err(ClientError::Protocol("expected pubkey count mismatch".into()));
			}
			for ((sig, pk), digest) in sigs.iter().zip(pks).zip(&digests) {
				secp.verify_ecdsa(&Message::from_digest(*digest), sig, pk)
					.map_err(|_| ClientError::InvalidSignature)?;
			}
		}
		Ok(sigs)
	}

	/// Convenience: a single signature over `digest` with a standalone key (tests, benchmarks).
	pub fn sign<C: Verification>(
		&self, secp: &Secp256k1<C>, key_id: &KeyId, digest: &[u8; 32],
		context: Option<SigningContext>, expected_pubkey: Option<&PublicKey>,
	) -> Result<Signature, ClientError> {
		let mut context = context.unwrap_or_default();
		if context.op.is_none() {
			context.op = Some(SigningOp::Test);
		}
		let item =
			SignItem { key_id: *key_id, derivation: Derivation::None, digest: *digest, context };
		let mut sigs =
			self.sign_batch(secp, None, vec![item], expected_pubkey.map(std::slice::from_ref))?;
		Ok(sigs.remove(0))
	}
}

fn new_request_id() -> [u8; 16] {
	use bitcoin::secp256k1::rand::RngCore;
	let mut id = [0u8; 16];
	bitcoin::secp256k1::rand::thread_rng().fill_bytes(&mut id);
	id
}
