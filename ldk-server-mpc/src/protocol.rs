//! Minimal binary wire protocol.
//!
//! Two message families share one framing (`transport::write_frame`):
//!
//! - **Client ⇄ P1**: [`Request`] / [`Response`]. One request per TCP connection.
//! - **P1 ⇄ P2**: a [`SessionStart`] header, a [`SessionAck`], the opaque cb-mpc protocol
//!   frames, and finally a [`SessionDone`] from P2 carrying the aggregate public key so P1
//!   can check both parties agree on it.
//!
//! The first byte of every frame is a tag so a listener can tell client requests from
//! peer sessions. Encoding is deliberately simple (big-endian integers, `u32`
//! length-prefixed byte strings) to avoid adding a serialization dependency.

use std::fmt;

/// Identifies a distributed key. For channel funding keys this is derived from LDK's
/// `channel_keys_id` (and the splice parent funding txid for spliced channels).
pub type KeyId = [u8; 32];

#[derive(Debug)]
pub struct DecodeError(pub &'static str);

impl fmt::Display for DecodeError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "decode error: {}", self.0)
	}
}

impl std::error::Error for DecodeError {}

pub struct Writer(pub Vec<u8>);

impl Writer {
	pub fn new() -> Self {
		Writer(Vec::new())
	}
	pub fn u8(&mut self, v: u8) {
		self.0.push(v);
	}
	pub fn u16(&mut self, v: u16) {
		self.0.extend_from_slice(&v.to_be_bytes());
	}
	pub fn u32(&mut self, v: u32) {
		self.0.extend_from_slice(&v.to_be_bytes());
	}
	pub fn u64(&mut self, v: u64) {
		self.0.extend_from_slice(&v.to_be_bytes());
	}
	pub fn fixed(&mut self, v: &[u8]) {
		self.0.extend_from_slice(v);
	}
	pub fn bytes(&mut self, v: &[u8]) {
		self.u32(v.len() as u32);
		self.0.extend_from_slice(v);
	}
	pub fn opt_fixed32(&mut self, v: Option<&[u8; 32]>) {
		match v {
			Some(v) => {
				self.u8(1);
				self.fixed(v);
			},
			None => self.u8(0),
		}
	}
	pub fn opt_u64(&mut self, v: Option<u64>) {
		match v {
			Some(v) => {
				self.u8(1);
				self.u64(v);
			},
			None => self.u8(0),
		}
	}
	pub fn opt_u32(&mut self, v: Option<u32>) {
		match v {
			Some(v) => {
				self.u8(1);
				self.u32(v);
			},
			None => self.u8(0),
		}
	}
}

impl Default for Writer {
	fn default() -> Self {
		Self::new()
	}
}

pub struct Reader<'a> {
	buf: &'a [u8],
	pos: usize,
}

impl<'a> Reader<'a> {
	pub fn new(buf: &'a [u8]) -> Self {
		Reader { buf, pos: 0 }
	}
	fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
		if self.pos + n > self.buf.len() {
			return Err(DecodeError("unexpected end of message"));
		}
		let s = &self.buf[self.pos..self.pos + n];
		self.pos += n;
		Ok(s)
	}
	pub fn u8(&mut self) -> Result<u8, DecodeError> {
		Ok(self.take(1)?[0])
	}
	pub fn u16(&mut self) -> Result<u16, DecodeError> {
		Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
	}
	pub fn u32(&mut self) -> Result<u32, DecodeError> {
		Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
	}
	pub fn u64(&mut self) -> Result<u64, DecodeError> {
		Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
	}
	pub fn fixed32(&mut self) -> Result<[u8; 32], DecodeError> {
		Ok(self.take(32)?.try_into().unwrap())
	}
	pub fn fixed16(&mut self) -> Result<[u8; 16], DecodeError> {
		Ok(self.take(16)?.try_into().unwrap())
	}
	pub fn bytes(&mut self) -> Result<Vec<u8>, DecodeError> {
		let n = self.u32()? as usize;
		if n > crate::transport::MAX_FRAME_LEN {
			return Err(DecodeError("byte string too large"));
		}
		Ok(self.take(n)?.to_vec())
	}
	pub fn string(&mut self) -> Result<String, DecodeError> {
		String::from_utf8(self.bytes()?).map_err(|_| DecodeError("invalid utf-8"))
	}
	pub fn opt_fixed32(&mut self) -> Result<Option<[u8; 32]>, DecodeError> {
		Ok(if self.u8()? == 1 { Some(self.fixed32()?) } else { None })
	}
	pub fn opt_u64(&mut self) -> Result<Option<u64>, DecodeError> {
		Ok(if self.u8()? == 1 { Some(self.u64()?) } else { None })
	}
	pub fn opt_u32(&mut self) -> Result<Option<u32>, DecodeError> {
		Ok(if self.u8()? == 1 { Some(self.u32()?) } else { None })
	}
	pub fn finish(self) -> Result<(), DecodeError> {
		if self.pos == self.buf.len() {
			Ok(())
		} else {
			Err(DecodeError("trailing bytes"))
		}
	}
}

// ---------------------------------------------------------------------------
// Signing context (optional metadata, informational only)
// ---------------------------------------------------------------------------

/// The Lightning operation a signature is requested for. Carried as metadata so a future
/// policy engine has something to look at. **Not verified** by the MPC services.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SigningOp {
	Unknown = 0,
	CounterpartyCommitment = 1,
	HolderCommitment = 2,
	ClosingTransaction = 3,
	HolderKeyedAnchorInput = 4,
	ChannelAnnouncement = 5,
	SpliceSharedInput = 6,
	Test = 255,
}

impl SigningOp {
	fn from_u8(v: u8) -> Self {
		match v {
			1 => SigningOp::CounterpartyCommitment,
			2 => SigningOp::HolderCommitment,
			3 => SigningOp::ClosingTransaction,
			4 => SigningOp::HolderKeyedAnchorInput,
			5 => SigningOp::ChannelAnnouncement,
			6 => SigningOp::SpliceSharedInput,
			255 => SigningOp::Test,
			_ => SigningOp::Unknown,
		}
	}
}

/// Optional Lightning context attached to a signing request.
///
/// This is supplied by LDK Server and is **not independently verified** by the MPC
/// parties. It must not be treated as proof that a transaction is safe to sign.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SigningContext {
	pub op: Option<SigningOp>,
	pub channel_keys_id: Option<[u8; 32]>,
	pub channel_value_satoshis: Option<u64>,
	pub commitment_number: Option<u64>,
	pub funding_txid: Option<[u8; 32]>,
	pub funding_vout: Option<u32>,
	pub splice_parent_funding_txid: Option<[u8; 32]>,
}

impl SigningContext {
	fn encode(&self, w: &mut Writer) {
		w.u8(self.op.map(|o| o as u8).unwrap_or(0));
		w.opt_fixed32(self.channel_keys_id.as_ref());
		w.opt_u64(self.channel_value_satoshis);
		w.opt_u64(self.commitment_number);
		w.opt_fixed32(self.funding_txid.as_ref());
		w.opt_u32(self.funding_vout);
		w.opt_fixed32(self.splice_parent_funding_txid.as_ref());
	}

	fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
		let op = r.u8()?;
		Ok(SigningContext {
			op: if op == 0 { None } else { Some(SigningOp::from_u8(op)) },
			channel_keys_id: r.opt_fixed32()?,
			channel_value_satoshis: r.opt_u64()?,
			commitment_number: r.opt_u64()?,
			funding_txid: r.opt_fixed32()?,
			funding_vout: r.opt_u32()?,
			splice_parent_funding_txid: r.opt_fixed32()?,
		})
	}
}

// ---------------------------------------------------------------------------
// Client ⇄ P1
// ---------------------------------------------------------------------------

const TAG_REQUEST: u8 = 0x01;
const TAG_RESPONSE: u8 = 0x02;
const TAG_SESSION_START: u8 = 0x10;
const TAG_SESSION_ACK: u8 = 0x11;
const TAG_SESSION_DONE: u8 = 0x12;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
	Ping,
	/// Returns the public key for `key_id`, running DKG with the other party if the key
	/// does not exist yet. Idempotent.
	EnsureKey {
		key_id: KeyId,
	},
	/// Returns the public key for an existing `key_id`; errors if unknown.
	GetPublicKey {
		key_id: KeyId,
	},
	/// Produces a 2-of-2 ECDSA signature over `digest` with key `key_id`.
	Sign {
		request_id: [u8; 16],
		key_id: KeyId,
		digest: [u8; 32],
		context: Option<SigningContext>,
	},
}

impl Request {
	pub fn encode(&self) -> Vec<u8> {
		let mut w = Writer::new();
		w.u8(TAG_REQUEST);
		match self {
			Request::Ping => w.u8(0),
			Request::EnsureKey { key_id } => {
				w.u8(1);
				w.fixed(key_id);
			},
			Request::GetPublicKey { key_id } => {
				w.u8(2);
				w.fixed(key_id);
			},
			Request::Sign { request_id, key_id, digest, context } => {
				w.u8(3);
				w.fixed(request_id);
				w.fixed(key_id);
				w.fixed(digest);
				match context {
					Some(c) => {
						w.u8(1);
						c.encode(&mut w);
					},
					None => w.u8(0),
				}
			},
		}
		w.0
	}

	pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
		let mut r = Reader::new(buf);
		if r.u8()? != TAG_REQUEST {
			return Err(DecodeError("not a request"));
		}
		let req = match r.u8()? {
			0 => Request::Ping,
			1 => Request::EnsureKey { key_id: r.fixed32()? },
			2 => Request::GetPublicKey { key_id: r.fixed32()? },
			3 => {
				let request_id = r.fixed16()?;
				let key_id = r.fixed32()?;
				let digest = r.fixed32()?;
				let context =
					if r.u8()? == 1 { Some(SigningContext::decode(&mut r)?) } else { None };
				Request::Sign { request_id, key_id, digest, context }
			},
			_ => return Err(DecodeError("unknown request kind")),
		};
		r.finish()?;
		Ok(req)
	}
}

/// Error codes returned to clients.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum ErrorCode {
	Unknown = 0,
	BadRequest = 1,
	KeyNotFound = 2,
	PeerUnavailable = 3,
	ProtocolFailed = 4,
	PolicyDenied = 5,
	Internal = 6,
	KeyMismatch = 7,
}

impl ErrorCode {
	pub fn from_u16(v: u16) -> Self {
		match v {
			1 => ErrorCode::BadRequest,
			2 => ErrorCode::KeyNotFound,
			3 => ErrorCode::PeerUnavailable,
			4 => ErrorCode::ProtocolFailed,
			5 => ErrorCode::PolicyDenied,
			6 => ErrorCode::Internal,
			7 => ErrorCode::KeyMismatch,
			_ => ErrorCode::Unknown,
		}
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Response {
	Pong,
	/// SEC1 compressed public key (33 bytes).
	PublicKey {
		pubkey: Vec<u8>,
	},
	/// 64-byte compact (r || s) low-S ECDSA signature.
	Signature {
		request_id: [u8; 16],
		sig_compact: Vec<u8>,
	},
	Error {
		code: ErrorCode,
		message: String,
	},
}

impl Response {
	pub fn encode(&self) -> Vec<u8> {
		let mut w = Writer::new();
		w.u8(TAG_RESPONSE);
		match self {
			Response::Pong => w.u8(0),
			Response::PublicKey { pubkey } => {
				w.u8(1);
				w.bytes(pubkey);
			},
			Response::Signature { request_id, sig_compact } => {
				w.u8(2);
				w.fixed(request_id);
				w.bytes(sig_compact);
			},
			Response::Error { code, message } => {
				w.u8(3);
				w.u16(*code as u16);
				w.bytes(message.as_bytes());
			},
		}
		w.0
	}

	pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
		let mut r = Reader::new(buf);
		if r.u8()? != TAG_RESPONSE {
			return Err(DecodeError("not a response"));
		}
		let resp = match r.u8()? {
			0 => Response::Pong,
			1 => Response::PublicKey { pubkey: r.bytes()? },
			2 => Response::Signature { request_id: r.fixed16()?, sig_compact: r.bytes()? },
			3 => Response::Error { code: ErrorCode::from_u16(r.u16()?), message: r.string()? },
			_ => return Err(DecodeError("unknown response kind")),
		};
		r.finish()?;
		Ok(resp)
	}
}

// ---------------------------------------------------------------------------
// P1 ⇄ P2 session framing
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionOp {
	Dkg,
	Sign,
	Refresh,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionStart {
	pub op: SessionOp,
	pub key_id: KeyId,
	pub digest: Option<[u8; 32]>,
	pub context: Option<SigningContext>,
}

impl SessionStart {
	pub fn encode(&self) -> Vec<u8> {
		let mut w = Writer::new();
		w.u8(TAG_SESSION_START);
		w.u8(match self.op {
			SessionOp::Dkg => 1,
			SessionOp::Sign => 2,
			SessionOp::Refresh => 3,
		});
		w.fixed(&self.key_id);
		w.opt_fixed32(self.digest.as_ref());
		match &self.context {
			Some(c) => {
				w.u8(1);
				c.encode(&mut w);
			},
			None => w.u8(0),
		}
		w.0
	}

	pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
		let mut r = Reader::new(buf);
		if r.u8()? != TAG_SESSION_START {
			return Err(DecodeError("not a session start"));
		}
		let op = match r.u8()? {
			1 => SessionOp::Dkg,
			2 => SessionOp::Sign,
			3 => SessionOp::Refresh,
			_ => return Err(DecodeError("unknown session op")),
		};
		let key_id = r.fixed32()?;
		let digest = r.opt_fixed32()?;
		let context = if r.u8()? == 1 { Some(SigningContext::decode(&mut r)?) } else { None };
		r.finish()?;
		Ok(SessionStart { op, key_id, digest, context })
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionAck {
	Ok,
	Error { code: ErrorCode, message: String },
}

impl SessionAck {
	pub fn encode(&self) -> Vec<u8> {
		let mut w = Writer::new();
		w.u8(TAG_SESSION_ACK);
		match self {
			SessionAck::Ok => w.u8(0),
			SessionAck::Error { code, message } => {
				w.u8(1);
				w.u16(*code as u16);
				w.bytes(message.as_bytes());
			},
		}
		w.0
	}

	pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
		let mut r = Reader::new(buf);
		if r.u8()? != TAG_SESSION_ACK {
			return Err(DecodeError("not a session ack"));
		}
		let ack = match r.u8()? {
			0 => SessionAck::Ok,
			1 => SessionAck::Error { code: ErrorCode::from_u16(r.u16()?), message: r.string()? },
			_ => return Err(DecodeError("unknown ack kind")),
		};
		r.finish()?;
		Ok(ack)
	}
}

/// Sent by P2 after the protocol completes so both sides can confirm they computed the same
/// aggregate public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionDone {
	pub pubkey: Vec<u8>,
}

impl SessionDone {
	pub fn encode(&self) -> Vec<u8> {
		let mut w = Writer::new();
		w.u8(TAG_SESSION_DONE);
		w.bytes(&self.pubkey);
		w.0
	}

	pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
		let mut r = Reader::new(buf);
		if r.u8()? != TAG_SESSION_DONE {
			return Err(DecodeError("not a session done"));
		}
		let pubkey = r.bytes()?;
		r.finish()?;
		Ok(SessionDone { pubkey })
	}
}

/// Peeks at the tag byte of an incoming frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameKind {
	Request,
	SessionStart,
	Other,
}

pub fn frame_kind(buf: &[u8]) -> FrameKind {
	match buf.first() {
		Some(&TAG_REQUEST) => FrameKind::Request,
		Some(&TAG_SESSION_START) => FrameKind::SessionStart,
		_ => FrameKind::Other,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn request_roundtrip() {
		let ctx = SigningContext {
			op: Some(SigningOp::CounterpartyCommitment),
			channel_keys_id: Some([7u8; 32]),
			channel_value_satoshis: Some(100_000),
			commitment_number: Some(281474976710655),
			funding_txid: Some([9u8; 32]),
			funding_vout: Some(1),
			splice_parent_funding_txid: None,
		};
		let reqs = vec![
			Request::Ping,
			Request::EnsureKey { key_id: [1u8; 32] },
			Request::GetPublicKey { key_id: [2u8; 32] },
			Request::Sign {
				request_id: [3u8; 16],
				key_id: [4u8; 32],
				digest: [5u8; 32],
				context: None,
			},
			Request::Sign {
				request_id: [3u8; 16],
				key_id: [4u8; 32],
				digest: [5u8; 32],
				context: Some(ctx),
			},
		];
		for req in reqs {
			assert_eq!(Request::decode(&req.encode()).unwrap(), req);
		}
	}

	#[test]
	fn response_roundtrip() {
		let resps = vec![
			Response::Pong,
			Response::PublicKey { pubkey: vec![2u8; 33] },
			Response::Signature { request_id: [1u8; 16], sig_compact: vec![9u8; 64] },
			Response::Error { code: ErrorCode::KeyNotFound, message: "nope".into() },
		];
		for r in resps {
			assert_eq!(Response::decode(&r.encode()).unwrap(), r);
		}
	}

	#[test]
	fn session_roundtrip() {
		let s = SessionStart {
			op: SessionOp::Sign,
			key_id: [1u8; 32],
			digest: Some([2u8; 32]),
			context: Some(SigningContext::default()),
		};
		assert_eq!(SessionStart::decode(&s.encode()).unwrap(), s);
		let a = SessionAck::Error { code: ErrorCode::PolicyDenied, message: "x".into() };
		assert_eq!(SessionAck::decode(&a.encode()).unwrap(), a);
		let d = SessionDone { pubkey: vec![3u8; 33] };
		assert_eq!(SessionDone::decode(&d.encode()).unwrap(), d);
		assert_eq!(frame_kind(&s.encode()), FrameKind::SessionStart);
		assert_eq!(frame_kind(&Request::Ping.encode()), FrameKind::Request);
	}

	#[test]
	fn rejects_trailing_bytes() {
		let mut buf = Request::Ping.encode();
		buf.push(0);
		assert!(Request::decode(&buf).is_err());
	}
}
