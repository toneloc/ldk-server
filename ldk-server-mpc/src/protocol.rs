//! Minimal binary wire protocol (v2).
//!
//! Two message families share one framing (`transport::write_frame`):
//!
//! - **Client ⇄ Party A (P1)**: [`Request`] / [`Response`]. One request per TCP connection.
//! - **Party A ⇄ Party B (P2)**: a [`SessionStart`] header, a [`SessionAck`], then, for
//!   interactive operations (DKG, sign), the opaque cb-mpc protocol frames and finally a
//!   [`SessionDone`] from P2 carrying the aggregate public key.
//!
//! Every signing request carries a [`SigningContext`] with the full transaction being signed,
//! so Party B can recompute the sighash and apply policy rather than trust a bare digest.
//! Encoding is deliberately simple (big-endian integers, `u32` length-prefixed byte strings).

use std::fmt;

/// Identifies a distributed key. For channel keys this is derived from LDK's
/// `channel_keys_id` and the key kind.
pub type KeyId = [u8; 32];
/// Identifies a channel for policy purposes (derived from LDK's `channel_keys_id`).
pub type ChannelId = [u8; 32];

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
	pub fn opt_fixed33(&mut self, v: Option<&[u8; 33]>) {
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
	pub fn opt_u16(&mut self, v: Option<u16>) {
		match v {
			Some(v) => {
				self.u8(1);
				self.u16(v);
			},
			None => self.u8(0),
		}
	}
	pub fn opt_bytes(&mut self, v: Option<&[u8]>) {
		match v {
			Some(v) => {
				self.u8(1);
				self.bytes(v);
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
	pub fn fixed33(&mut self) -> Result<[u8; 33], DecodeError> {
		Ok(self.take(33)?.try_into().unwrap())
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
	pub fn opt_fixed33(&mut self) -> Result<Option<[u8; 33]>, DecodeError> {
		Ok(if self.u8()? == 1 { Some(self.fixed33()?) } else { None })
	}
	pub fn opt_u64(&mut self) -> Result<Option<u64>, DecodeError> {
		Ok(if self.u8()? == 1 { Some(self.u64()?) } else { None })
	}
	pub fn opt_u32(&mut self) -> Result<Option<u32>, DecodeError> {
		Ok(if self.u8()? == 1 { Some(self.u32()?) } else { None })
	}
	pub fn opt_u16(&mut self) -> Result<Option<u16>, DecodeError> {
		Ok(if self.u8()? == 1 { Some(self.u16()?) } else { None })
	}
	pub fn opt_bytes(&mut self) -> Result<Option<Vec<u8>>, DecodeError> {
		Ok(if self.u8()? == 1 { Some(self.bytes()?) } else { None })
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
// Keys and derivations
// ---------------------------------------------------------------------------

/// The role of a distributed key within a channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum KeyKind {
	Funding = 1,
	/// A spliced funding key (fresh key per splice).
	SplicedFunding = 2,
	Payment = 3,
	DelayedPayment = 4,
	Htlc = 5,
	Revocation = 6,
	/// Not bound to a channel (tests / benchmarks).
	Standalone = 255,
}

impl KeyKind {
	pub fn from_u8(v: u8) -> Option<Self> {
		Some(match v {
			1 => KeyKind::Funding,
			2 => KeyKind::SplicedFunding,
			3 => KeyKind::Payment,
			4 => KeyKind::DelayedPayment,
			5 => KeyKind::Htlc,
			6 => KeyKind::Revocation,
			255 => KeyKind::Standalone,
			_ => return None,
		})
	}
}

/// How the signing key is derived from the stored basepoint share.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Derivation {
	/// Sign with the stored key as is.
	None,
	/// `basepoint + tweak` (BOLT 3 delayed-payment / HTLC keys).
	Additive { tweak: [u8; 32] },
	/// `basepoint * mul + add` (BOLT 3 revocation key).
	MulAdd { mul: [u8; 32], add: [u8; 32] },
}

impl Derivation {
	fn encode(&self, w: &mut Writer) {
		match self {
			Derivation::None => w.u8(0),
			Derivation::Additive { tweak } => {
				w.u8(1);
				w.fixed(tweak);
			},
			Derivation::MulAdd { mul, add } => {
				w.u8(2);
				w.fixed(mul);
				w.fixed(add);
			},
		}
	}
	fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
		Ok(match r.u8()? {
			0 => Derivation::None,
			1 => Derivation::Additive { tweak: r.fixed32()? },
			2 => Derivation::MulAdd { mul: r.fixed32()?, add: r.fixed32()? },
			_ => return Err(DecodeError("unknown derivation")),
		})
	}
}

// ---------------------------------------------------------------------------
// Signing context
// ---------------------------------------------------------------------------

/// The Lightning operation a signature is requested for.
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
	CounterpartyCommitmentHtlc = 7,
	JusticeRevokedOutput = 8,
	JusticeRevokedHtlc = 9,
	HolderHtlcTransaction = 10,
	CounterpartyHtlcTransaction = 11,
	SweepStaticPayment = 12,
	SweepDelayedPayment = 13,
	Test = 255,
}

impl SigningOp {
	pub fn from_u8(v: u8) -> Self {
		match v {
			1 => SigningOp::CounterpartyCommitment,
			2 => SigningOp::HolderCommitment,
			3 => SigningOp::ClosingTransaction,
			4 => SigningOp::HolderKeyedAnchorInput,
			5 => SigningOp::ChannelAnnouncement,
			6 => SigningOp::SpliceSharedInput,
			7 => SigningOp::CounterpartyCommitmentHtlc,
			8 => SigningOp::JusticeRevokedOutput,
			9 => SigningOp::JusticeRevokedHtlc,
			10 => SigningOp::HolderHtlcTransaction,
			11 => SigningOp::CounterpartyHtlcTransaction,
			12 => SigningOp::SweepStaticPayment,
			13 => SigningOp::SweepDelayedPayment,
			255 => SigningOp::Test,
			_ => SigningOp::Unknown,
		}
	}

	/// The key kind this operation must be signed with.
	pub fn expected_key_kind(self) -> Option<KeyKind> {
		Some(match self {
			SigningOp::CounterpartyCommitment
			| SigningOp::HolderCommitment
			| SigningOp::ClosingTransaction
			| SigningOp::HolderKeyedAnchorInput
			| SigningOp::ChannelAnnouncement
			| SigningOp::SpliceSharedInput => KeyKind::Funding,
			SigningOp::CounterpartyCommitmentHtlc
			| SigningOp::HolderHtlcTransaction
			| SigningOp::CounterpartyHtlcTransaction => KeyKind::Htlc,
			SigningOp::JusticeRevokedOutput | SigningOp::JusticeRevokedHtlc => KeyKind::Revocation,
			SigningOp::SweepStaticPayment => KeyKind::Payment,
			SigningOp::SweepDelayedPayment => KeyKind::DelayedPayment,
			SigningOp::Test | SigningOp::Unknown => return None,
		})
	}
}

/// Counterparty channel public keys (SEC1 compressed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CounterpartyKeys {
	pub funding_pubkey: [u8; 33],
	pub revocation_basepoint: [u8; 33],
	pub payment_point: [u8; 33],
	pub delayed_payment_basepoint: [u8; 33],
	pub htlc_basepoint: [u8; 33],
}

/// Context attached to a signing request. Supplied by LDK Server; Party B verifies the parts it
/// can (sighash, key derivation, balances) and applies policy. Fields it cannot verify are
/// informational only.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SigningContext {
	pub op: Option<SigningOp>,
	pub channel_keys_id: Option<[u8; 32]>,
	pub channel_value_satoshis: Option<u64>,
	pub commitment_number: Option<u64>,
	pub funding_txid: Option<[u8; 32]>,
	pub funding_vout: Option<u32>,
	pub splice_parent_funding_txid: Option<[u8; 32]>,
	/// Serialized `ChannelTypeFeatures`.
	pub channel_type_features: Option<Vec<u8>>,
	pub counterparty_keys: Option<CounterpartyKeys>,
	pub holder_selected_contest_delay: Option<u16>,
	pub counterparty_selected_contest_delay: Option<u16>,
	/// Consensus-serialized transaction being signed.
	pub transaction: Option<Vec<u8>>,
	pub input_index: u32,
	pub input_value_sat: u64,
	pub witness_script: Option<Vec<u8>>,
	/// BIP 143 sighash type byte (`0x01` ALL, `0x83` SINGLE|ANYONECANPAY).
	pub sighash_type: u8,
	pub per_commitment_point: Option<[u8; 33]>,
	/// Counterparty's revealed per-commitment secret, for revocation-key derivation checks.
	pub counterparty_per_commitment_secret: Option<[u8; 32]>,
	pub holder_balance_sat: Option<u64>,
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
		w.opt_bytes(self.channel_type_features.as_deref());
		match &self.counterparty_keys {
			Some(k) => {
				w.u8(1);
				w.fixed(&k.funding_pubkey);
				w.fixed(&k.revocation_basepoint);
				w.fixed(&k.payment_point);
				w.fixed(&k.delayed_payment_basepoint);
				w.fixed(&k.htlc_basepoint);
			},
			None => w.u8(0),
		}
		w.opt_u16(self.holder_selected_contest_delay);
		w.opt_u16(self.counterparty_selected_contest_delay);
		w.opt_bytes(self.transaction.as_deref());
		w.u32(self.input_index);
		w.u64(self.input_value_sat);
		w.opt_bytes(self.witness_script.as_deref());
		w.u8(self.sighash_type);
		w.opt_fixed33(self.per_commitment_point.as_ref());
		w.opt_fixed32(self.counterparty_per_commitment_secret.as_ref());
		w.opt_u64(self.holder_balance_sat);
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
			channel_type_features: r.opt_bytes()?,
			counterparty_keys: if r.u8()? == 1 {
				Some(CounterpartyKeys {
					funding_pubkey: r.fixed33()?,
					revocation_basepoint: r.fixed33()?,
					payment_point: r.fixed33()?,
					delayed_payment_basepoint: r.fixed33()?,
					htlc_basepoint: r.fixed33()?,
				})
			} else {
				None
			},
			holder_selected_contest_delay: r.opt_u16()?,
			counterparty_selected_contest_delay: r.opt_u16()?,
			transaction: r.opt_bytes()?,
			input_index: r.u32()?,
			input_value_sat: r.u64()?,
			witness_script: r.opt_bytes()?,
			sighash_type: r.u8()?,
			per_commitment_point: r.opt_fixed33()?,
			counterparty_per_commitment_secret: r.opt_fixed32()?,
			holder_balance_sat: r.opt_u64()?,
		})
	}
}

/// One signature within a batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignItem {
	pub key_id: KeyId,
	pub derivation: Derivation,
	pub digest: [u8; 32],
	pub context: SigningContext,
}

impl SignItem {
	fn encode(&self, w: &mut Writer) {
		w.fixed(&self.key_id);
		self.derivation.encode(w);
		w.fixed(&self.digest);
		self.context.encode(w);
	}
	fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
		Ok(SignItem {
			key_id: r.fixed32()?,
			derivation: Derivation::decode(r)?,
			digest: r.fixed32()?,
			context: SigningContext::decode(r)?,
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
	/// Returns the public key for `key_id`, running DKG with the other party if the key does
	/// not exist yet. Idempotent. `channel` binds the key to a channel for policy purposes.
	EnsureKey {
		key_id: KeyId,
		channel: Option<(ChannelId, KeyKind)>,
	},
	/// Returns the public key for an existing `key_id`; errors if unknown.
	GetPublicKey {
		key_id: KeyId,
	},
	/// Per-commitment point for commitment `idx` of `channel` (seed held by Party B).
	GetPerCommitmentPoint {
		channel: ChannelId,
		idx: u64,
	},
	/// Per-commitment secret for commitment `idx` of `channel`, subject to policy.
	ReleaseCommitmentSecret {
		channel: ChannelId,
		idx: u64,
	},
	/// LDK validated the counterparty's signatures on holder commitment `commitment_number`.
	HolderCommitmentValidated {
		channel: ChannelId,
		commitment_number: u64,
	},
	/// The counterparty revoked commitment `idx` with `secret`.
	CounterpartyRevocationValidated {
		channel: ChannelId,
		idx: u64,
		secret: [u8; 32],
	},
	/// Produces one 2-of-2 ECDSA signature per item.
	Sign {
		request_id: [u8; 16],
		channel: Option<ChannelId>,
		items: Vec<SignItem>,
	},
}

impl Request {
	pub fn encode(&self) -> Vec<u8> {
		let mut w = Writer::new();
		w.u8(TAG_REQUEST);
		match self {
			Request::Ping => w.u8(0),
			Request::EnsureKey { key_id, channel } => {
				w.u8(1);
				w.fixed(key_id);
				match channel {
					Some((c, k)) => {
						w.u8(1);
						w.fixed(c);
						w.u8(*k as u8);
					},
					None => w.u8(0),
				}
			},
			Request::GetPublicKey { key_id } => {
				w.u8(2);
				w.fixed(key_id);
			},
			Request::GetPerCommitmentPoint { channel, idx } => {
				w.u8(4);
				w.fixed(channel);
				w.u64(*idx);
			},
			Request::ReleaseCommitmentSecret { channel, idx } => {
				w.u8(5);
				w.fixed(channel);
				w.u64(*idx);
			},
			Request::HolderCommitmentValidated { channel, commitment_number } => {
				w.u8(6);
				w.fixed(channel);
				w.u64(*commitment_number);
			},
			Request::CounterpartyRevocationValidated { channel, idx, secret } => {
				w.u8(7);
				w.fixed(channel);
				w.u64(*idx);
				w.fixed(secret);
			},
			Request::Sign { request_id, channel, items } => {
				w.u8(8);
				w.fixed(request_id);
				w.opt_fixed32(channel.as_ref());
				w.u32(items.len() as u32);
				for item in items {
					item.encode(&mut w);
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
			1 => {
				let key_id = r.fixed32()?;
				let channel = if r.u8()? == 1 {
					let c = r.fixed32()?;
					let k = KeyKind::from_u8(r.u8()?).ok_or(DecodeError("unknown key kind"))?;
					Some((c, k))
				} else {
					None
				};
				Request::EnsureKey { key_id, channel }
			},
			2 => Request::GetPublicKey { key_id: r.fixed32()? },
			4 => Request::GetPerCommitmentPoint { channel: r.fixed32()?, idx: r.u64()? },
			5 => Request::ReleaseCommitmentSecret { channel: r.fixed32()?, idx: r.u64()? },
			6 => Request::HolderCommitmentValidated {
				channel: r.fixed32()?,
				commitment_number: r.u64()?,
			},
			7 => Request::CounterpartyRevocationValidated {
				channel: r.fixed32()?,
				idx: r.u64()?,
				secret: r.fixed32()?,
			},
			8 => {
				let request_id = r.fixed16()?;
				let channel = r.opt_fixed32()?;
				let n = r.u32()? as usize;
				if n > 1024 {
					return Err(DecodeError("too many sign items"));
				}
				let mut items = Vec::with_capacity(n);
				for _ in 0..n {
					items.push(SignItem::decode(&mut r)?);
				}
				Request::Sign { request_id, channel, items }
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
	Unauthorized = 8,
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
			8 => ErrorCode::Unauthorized,
			_ => ErrorCode::Unknown,
		}
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Response {
	Pong,
	Ack,
	/// SEC1 compressed public key (33 bytes).
	PublicKey {
		pubkey: Vec<u8>,
	},
	/// A 32-byte secret (per-commitment secret).
	Secret {
		secret: [u8; 32],
	},
	/// 64-byte compact (r || s) low-S ECDSA signatures, one per requested item, in order.
	Signatures {
		request_id: [u8; 16],
		sigs: Vec<[u8; 64]>,
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
			Response::Signatures { request_id, sigs } => {
				w.u8(2);
				w.fixed(request_id);
				w.u32(sigs.len() as u32);
				for s in sigs {
					w.fixed(s);
				}
			},
			Response::Error { code, message } => {
				w.u8(3);
				w.u16(*code as u16);
				w.bytes(message.as_bytes());
			},
			Response::Ack => w.u8(4),
			Response::Secret { secret } => {
				w.u8(5);
				w.fixed(secret);
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
			2 => {
				let request_id = r.fixed16()?;
				let n = r.u32()? as usize;
				if n > 1024 {
					return Err(DecodeError("too many signatures"));
				}
				let mut sigs = Vec::with_capacity(n);
				for _ in 0..n {
					let mut s = [0u8; 64];
					s.copy_from_slice(r.take(64)?);
					sigs.push(s);
				}
				Response::Signatures { request_id, sigs }
			},
			3 => Response::Error { code: ErrorCode::from_u16(r.u16()?), message: r.string()? },
			4 => Response::Ack,
			5 => Response::Secret { secret: r.fixed32()? },
			_ => return Err(DecodeError("unknown response kind")),
		};
		r.finish()?;
		Ok(resp)
	}
}

// ---------------------------------------------------------------------------
// P1 ⇄ P2 session framing
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum SessionOp {
	/// Interactive DKG for `key_id`.
	Dkg {
		key_id: KeyId,
		channel: Option<(ChannelId, KeyKind)>,
	},
	/// Interactive signing of one item.
	Sign {
		channel: Option<ChannelId>,
		item: SignItem,
	},
	/// Non-interactive requests served by Party B's policy / seed.
	PerCommitmentPoint {
		channel: ChannelId,
		idx: u64,
	},
	ReleaseSecret {
		channel: ChannelId,
		idx: u64,
	},
	HolderCommitmentValidated {
		channel: ChannelId,
		commitment_number: u64,
	},
	CounterpartyRevocationValidated {
		channel: ChannelId,
		idx: u64,
		secret: [u8; 32],
	},
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionStart {
	pub op: SessionOp,
}

impl SessionStart {
	pub fn encode(&self) -> Vec<u8> {
		let mut w = Writer::new();
		w.u8(TAG_SESSION_START);
		match &self.op {
			SessionOp::Dkg { key_id, channel } => {
				w.u8(1);
				w.fixed(key_id);
				match channel {
					Some((c, k)) => {
						w.u8(1);
						w.fixed(c);
						w.u8(*k as u8);
					},
					None => w.u8(0),
				}
			},
			SessionOp::Sign { channel, item } => {
				w.u8(2);
				w.opt_fixed32(channel.as_ref());
				item.encode(&mut w);
			},
			SessionOp::PerCommitmentPoint { channel, idx } => {
				w.u8(3);
				w.fixed(channel);
				w.u64(*idx);
			},
			SessionOp::ReleaseSecret { channel, idx } => {
				w.u8(4);
				w.fixed(channel);
				w.u64(*idx);
			},
			SessionOp::HolderCommitmentValidated { channel, commitment_number } => {
				w.u8(5);
				w.fixed(channel);
				w.u64(*commitment_number);
			},
			SessionOp::CounterpartyRevocationValidated { channel, idx, secret } => {
				w.u8(6);
				w.fixed(channel);
				w.u64(*idx);
				w.fixed(secret);
			},
		}
		w.0
	}

	pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
		let mut r = Reader::new(buf);
		if r.u8()? != TAG_SESSION_START {
			return Err(DecodeError("not a session start"));
		}
		let op = match r.u8()? {
			1 => {
				let key_id = r.fixed32()?;
				let channel = if r.u8()? == 1 {
					let c = r.fixed32()?;
					let k = KeyKind::from_u8(r.u8()?).ok_or(DecodeError("unknown key kind"))?;
					Some((c, k))
				} else {
					None
				};
				SessionOp::Dkg { key_id, channel }
			},
			2 => SessionOp::Sign { channel: r.opt_fixed32()?, item: SignItem::decode(&mut r)? },
			3 => SessionOp::PerCommitmentPoint { channel: r.fixed32()?, idx: r.u64()? },
			4 => SessionOp::ReleaseSecret { channel: r.fixed32()?, idx: r.u64()? },
			5 => SessionOp::HolderCommitmentValidated {
				channel: r.fixed32()?,
				commitment_number: r.u64()?,
			},
			6 => SessionOp::CounterpartyRevocationValidated {
				channel: r.fixed32()?,
				idx: r.u64()?,
				secret: r.fixed32()?,
			},
			_ => return Err(DecodeError("unknown session op")),
		};
		r.finish()?;
		Ok(SessionStart { op })
	}
}

/// Party B's answer to a [`SessionStart`]. For interactive ops `Ok` carries no payload and the
/// cb-mpc frames follow; for non-interactive ops `Ok` carries the result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionAck {
	Ok { payload: Vec<u8> },
	Error { code: ErrorCode, message: String },
}

impl SessionAck {
	pub fn ok() -> Self {
		SessionAck::Ok { payload: Vec::new() }
	}
	pub fn encode(&self) -> Vec<u8> {
		let mut w = Writer::new();
		w.u8(TAG_SESSION_ACK);
		match self {
			SessionAck::Ok { payload } => {
				w.u8(0);
				w.bytes(payload);
			},
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
			0 => SessionAck::Ok { payload: r.bytes()? },
			1 => SessionAck::Error { code: ErrorCode::from_u16(r.u16()?), message: r.string()? },
			_ => return Err(DecodeError("unknown ack kind")),
		};
		r.finish()?;
		Ok(ack)
	}
}

/// Sent by P2 after an interactive protocol completes so both sides can confirm they computed
/// the same aggregate public key.
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

	fn sample_context() -> SigningContext {
		SigningContext {
			op: Some(SigningOp::CounterpartyCommitment),
			channel_keys_id: Some([7u8; 32]),
			channel_value_satoshis: Some(100_000),
			commitment_number: Some(281474976710655),
			funding_txid: Some([9u8; 32]),
			funding_vout: Some(1),
			splice_parent_funding_txid: None,
			channel_type_features: Some(vec![1, 2, 3]),
			counterparty_keys: Some(CounterpartyKeys {
				funding_pubkey: [2u8; 33],
				revocation_basepoint: [3u8; 33],
				payment_point: [2u8; 33],
				delayed_payment_basepoint: [3u8; 33],
				htlc_basepoint: [2u8; 33],
			}),
			holder_selected_contest_delay: Some(144),
			counterparty_selected_contest_delay: Some(72),
			transaction: Some(vec![0u8; 100]),
			input_index: 0,
			input_value_sat: 100_000,
			witness_script: Some(vec![0x52; 71]),
			sighash_type: 1,
			per_commitment_point: Some([2u8; 33]),
			counterparty_per_commitment_secret: None,
			holder_balance_sat: Some(50_000),
		}
	}

	#[test]
	fn request_roundtrip() {
		let item = SignItem {
			key_id: [4u8; 32],
			derivation: Derivation::Additive { tweak: [5u8; 32] },
			digest: [6u8; 32],
			context: sample_context(),
		};
		let reqs = vec![
			Request::Ping,
			Request::EnsureKey { key_id: [1u8; 32], channel: Some(([8u8; 32], KeyKind::Funding)) },
			Request::EnsureKey { key_id: [1u8; 32], channel: None },
			Request::GetPublicKey { key_id: [2u8; 32] },
			Request::GetPerCommitmentPoint { channel: [1u8; 32], idx: 42 },
			Request::ReleaseCommitmentSecret { channel: [1u8; 32], idx: 42 },
			Request::HolderCommitmentValidated { channel: [1u8; 32], commitment_number: 41 },
			Request::CounterpartyRevocationValidated {
				channel: [1u8; 32],
				idx: 42,
				secret: [3u8; 32],
			},
			Request::Sign {
				request_id: [3u8; 16],
				channel: Some([8u8; 32]),
				items: vec![
					item.clone(),
					SignItem {
						derivation: Derivation::MulAdd { mul: [1u8; 32], add: [2u8; 32] },
						..item.clone()
					},
					SignItem {
						derivation: Derivation::None,
						context: SigningContext::default(),
						..item
					},
				],
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
			Response::Ack,
			Response::PublicKey { pubkey: vec![2u8; 33] },
			Response::Secret { secret: [9u8; 32] },
			Response::Signatures { request_id: [1u8; 16], sigs: vec![[9u8; 64], [8u8; 64]] },
			Response::Error { code: ErrorCode::KeyNotFound, message: "nope".into() },
		];
		for r in resps {
			assert_eq!(Response::decode(&r.encode()).unwrap(), r);
		}
	}

	#[test]
	fn session_roundtrip() {
		let ops = vec![
			SessionOp::Dkg { key_id: [1u8; 32], channel: Some(([2u8; 32], KeyKind::Htlc)) },
			SessionOp::Sign {
				channel: Some([2u8; 32]),
				item: SignItem {
					key_id: [1u8; 32],
					derivation: Derivation::None,
					digest: [2u8; 32],
					context: sample_context(),
				},
			},
			SessionOp::PerCommitmentPoint { channel: [2u8; 32], idx: 7 },
			SessionOp::ReleaseSecret { channel: [2u8; 32], idx: 7 },
			SessionOp::HolderCommitmentValidated { channel: [2u8; 32], commitment_number: 6 },
			SessionOp::CounterpartyRevocationValidated {
				channel: [2u8; 32],
				idx: 7,
				secret: [1u8; 32],
			},
		];
		for op in ops {
			let s = SessionStart { op };
			assert_eq!(SessionStart::decode(&s.encode()).unwrap(), s);
			assert_eq!(frame_kind(&s.encode()), FrameKind::SessionStart);
		}
		let a = SessionAck::Error { code: ErrorCode::PolicyDenied, message: "x".into() };
		assert_eq!(SessionAck::decode(&a.encode()).unwrap(), a);
		let a = SessionAck::Ok { payload: vec![1, 2, 3] };
		assert_eq!(SessionAck::decode(&a.encode()).unwrap(), a);
		let d = SessionDone { pubkey: vec![3u8; 33] };
		assert_eq!(SessionDone::decode(&d.encode()).unwrap(), d);
		assert_eq!(frame_kind(&Request::Ping.encode()), FrameKind::Request);
	}

	#[test]
	fn rejects_trailing_bytes() {
		let mut buf = Request::Ping.encode();
		buf.push(0);
		assert!(Request::decode(&buf).is_err());
	}
}
