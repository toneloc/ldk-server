//! Safe wrappers around the Coinbase `cb-mpc` ECDSA-2P C API.
//!
//! The library executes the interactive protocol synchronously on the calling thread and
//! calls back into a [`Transport`] to exchange messages with the other party.

use std::ffi::CString;
use std::fmt;
use std::os::raw::{c_int, c_void};
use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::ffi;

/// Which of the two ECDSA-2P roles this process plays.
///
/// In cb-mpc's ECDSA-2P protocol, P1 is the Paillier key owner / verifier and is the only
/// party that obtains the final signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Party {
	P1,
	P2,
}

impl Party {
	pub fn other(self) -> Party {
		match self {
			Party::P1 => Party::P2,
			Party::P2 => Party::P1,
		}
	}

	fn to_ffi(self) -> ffi::cbmpc_2pc_party_t {
		match self {
			Party::P1 => ffi::CBMPC_2PC_P1,
			Party::P2 => ffi::CBMPC_2PC_P2,
		}
	}

	pub fn as_str(self) -> &'static str {
		match self {
			Party::P1 => "p1",
			Party::P2 => "p2",
		}
	}
}

impl std::str::FromStr for Party {
	type Err = String;
	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s.to_ascii_lowercase().as_str() {
			"p1" | "1" | "a" => Ok(Party::P1),
			"p2" | "2" | "b" => Ok(Party::P2),
			other => Err(format!("unknown party '{other}', expected p1 or p2")),
		}
	}
}

/// Blocking message transport between the two parties of a single protocol session.
///
/// The library calls `send` and `recv` from the thread running the protocol. A `recv` must
/// block until a full message from the other party is available (or fail).
pub trait Transport {
	fn send(&self, msg: &[u8]) -> Result<(), TransportError>;
	fn recv(&self) -> Result<Vec<u8>, TransportError>;
}

#[derive(Debug)]
pub struct TransportError(pub String);

impl fmt::Display for TransportError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "transport error: {}", self.0)
	}
}

impl std::error::Error for TransportError {}

impl From<std::io::Error> for TransportError {
	fn from(e: std::io::Error) -> Self {
		TransportError(e.to_string())
	}
}

/// Error returned by cb-mpc, decoded from its integer error code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CbmpcError {
	pub code: i32,
}

impl CbmpcError {
	pub fn category(&self) -> u32 {
		((self.code as u32) >> 16) & 0xff
	}

	pub fn is_network(&self) -> bool {
		self.category() == ffi::CBMPC_ECATEGORY_NETWORK
	}

	pub fn is_bit_leak(&self) -> bool {
		self.code == ffi::CBMPC_E_ECDSA_2P_BIT_LEAK
	}
}

impl fmt::Display for CbmpcError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let name = match self.code {
			ffi::CBMPC_E_GENERAL => "E_GENERAL",
			ffi::CBMPC_E_BADARG => "E_BADARG",
			ffi::CBMPC_E_FORMAT => "E_FORMAT",
			ffi::CBMPC_E_NET_GENERAL => "E_NET_GENERAL",
			ffi::CBMPC_E_CRYPTO => "E_CRYPTO",
			ffi::CBMPC_E_ECDSA_2P_BIT_LEAK => "E_ECDSA_2P_BIT_LEAK",
			_ => "E_UNKNOWN",
		};
		write!(f, "cb-mpc error {name} (0x{:08x})", self.code as u32)
	}
}

impl std::error::Error for CbmpcError {}

fn check(code: ffi::cbmpc_error_t) -> Result<(), CbmpcError> {
	if code == ffi::CBMPC_SUCCESS {
		Ok(())
	} else {
		Err(CbmpcError { code })
	}
}

/// Takes ownership of a library-allocated `cmem_t`, copies it into a `Vec` and frees it
/// (the library zeroizes before freeing).
unsafe fn take_cmem(mem: ffi::cmem_t) -> Vec<u8> {
	if mem.data.is_null() || mem.size <= 0 {
		if !mem.data.is_null() {
			ffi::cbmpc_cmem_free(mem);
		}
		return Vec::new();
	}
	let out = std::slice::from_raw_parts(mem.data, mem.size as usize).to_vec();
	ffi::cbmpc_cmem_free(mem);
	out
}

fn view(bytes: &[u8]) -> ffi::cmem_t {
	ffi::cmem_t { data: bytes.as_ptr() as *mut u8, size: bytes.len() as c_int }
}

/// Context handed to the C transport callbacks.
struct CallbackCtx<'a> {
	transport: &'a dyn Transport,
	/// First transport failure, surfaced after the protocol returns.
	error: Option<TransportError>,
	/// Message that caused a panic inside a callback (should never happen).
	panicked: bool,
}

unsafe extern "C" fn cb_send(
	ctx: *mut c_void, _receiver: i32, data: *const u8, size: c_int,
) -> ffi::cbmpc_error_t {
	let ctx = &mut *(ctx as *mut CallbackCtx<'_>);
	let res = catch_unwind(AssertUnwindSafe(|| {
		let msg = if size > 0 { std::slice::from_raw_parts(data, size as usize) } else { &[][..] };
		ctx.transport.send(msg)
	}));
	match res {
		Ok(Ok(())) => ffi::CBMPC_SUCCESS,
		Ok(Err(e)) => {
			if ctx.error.is_none() {
				ctx.error = Some(e);
			}
			ffi::CBMPC_E_NET_GENERAL
		},
		Err(_) => {
			ctx.panicked = true;
			ffi::CBMPC_E_NET_GENERAL
		},
	}
}

unsafe extern "C" fn cb_receive(
	ctx: *mut c_void, _sender: i32, out_msg: *mut ffi::cmem_t,
) -> ffi::cbmpc_error_t {
	let ctx = &mut *(ctx as *mut CallbackCtx<'_>);
	*out_msg = ffi::cmem_t::null();
	let res = catch_unwind(AssertUnwindSafe(|| ctx.transport.recv()));
	match res {
		Ok(Ok(msg)) => {
			if msg.len() > c_int::MAX as usize {
				return ffi::CBMPC_E_FORMAT;
			}
			// The library frees this buffer with `cbmpc_free` (we do not supply a free fn).
			let buf = ffi::cbmpc_malloc(msg.len().max(1)) as *mut u8;
			if buf.is_null() {
				return ffi::CBMPC_E_GENERAL;
			}
			std::ptr::copy_nonoverlapping(msg.as_ptr(), buf, msg.len());
			*out_msg = ffi::cmem_t { data: buf, size: msg.len() as c_int };
			ffi::CBMPC_SUCCESS
		},
		Ok(Err(e)) => {
			if ctx.error.is_none() {
				ctx.error = Some(e);
			}
			ffi::CBMPC_E_NET_GENERAL
		},
		Err(_) => {
			ctx.panicked = true;
			ffi::CBMPC_E_NET_GENERAL
		},
	}
}

/// Error from running a protocol: either the library failed or the transport did.
#[derive(Debug)]
pub enum ProtocolError {
	Cbmpc(CbmpcError),
	Transport(TransportError),
}

impl fmt::Display for ProtocolError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			ProtocolError::Cbmpc(e) => write!(f, "{e}"),
			ProtocolError::Transport(e) => write!(f, "{e}"),
		}
	}
}

impl std::error::Error for ProtocolError {}

/// A 2-party protocol execution context.
///
/// `p1_name`/`p2_name` are the party identifiers (cb-mpc `pid`s) and must be stable,
/// unique identifiers of the two parties (see cb-mpc `SECURE_USAGE.md`, "Session
/// identifiers in commitments"). They are not just the roles.
pub struct Job<'a> {
	party: Party,
	p1_name: CString,
	p2_name: CString,
	transport: &'a dyn Transport,
}

impl<'a> Job<'a> {
	pub fn new(party: Party, p1_name: &str, p2_name: &str, transport: &'a dyn Transport) -> Self {
		Job {
			party,
			p1_name: CString::new(p1_name).expect("party name must not contain NUL"),
			p2_name: CString::new(p2_name).expect("party name must not contain NUL"),
			transport,
		}
	}

	pub fn party(&self) -> Party {
		self.party
	}

	fn run<R>(
		&self, f: impl FnOnce(*const ffi::cbmpc_2pc_job_t) -> Result<R, CbmpcError>,
	) -> Result<R, ProtocolError> {
		let mut ctx = CallbackCtx { transport: self.transport, error: None, panicked: false };
		let transport = ffi::cbmpc_transport_t {
			ctx: &mut ctx as *mut CallbackCtx<'_> as *mut c_void,
			send: Some(cb_send),
			receive: Some(cb_receive),
			receive_all: None,
			free: None,
		};
		let job = ffi::cbmpc_2pc_job_t {
			self_: self.party.to_ffi(),
			p1_name: self.p1_name.as_ptr(),
			p2_name: self.p2_name.as_ptr(),
			transport: &transport as *const ffi::cbmpc_transport_t,
		};
		let res = f(&job as *const ffi::cbmpc_2pc_job_t);
		if ctx.panicked {
			return Err(ProtocolError::Transport(TransportError(
				"transport callback panicked".to_string(),
			)));
		}
		match res {
			Ok(r) => Ok(r),
			Err(e) => match ctx.error.take() {
				Some(t) => Err(ProtocolError::Transport(t)),
				None => Err(ProtocolError::Cbmpc(e)),
			},
		}
	}

	/// Runs the interactive ECDSA-2P distributed key generation on secp256k1.
	///
	/// Returns this party's opaque key-share blob. Each party only ever holds its own
	/// share; the full private key is never assembled anywhere.
	pub fn dkg(&self) -> Result<KeyBlob, ProtocolError> {
		self.run(|job| unsafe {
			let mut out = ffi::cmem_t::null();
			check(ffi::cbmpc_ecdsa_2p_dkg(job, ffi::CBMPC_CURVE_SECP256K1, &mut out))?;
			Ok(KeyBlob(take_cmem(out)))
		})
	}

	/// Runs the interactive ECDSA-2P signing protocol over a 32-byte message digest.
	///
	/// The session id is left empty so the library derives it jointly with the other party
	/// (cb-mpc's recommended default). Only P1 receives the signature; P2 gets `None`.
	/// The returned signature is DER-encoded and **not** guaranteed to be low-S.
	pub fn sign(&self, key: &KeyBlob, digest: &[u8; 32]) -> Result<Option<Vec<u8>>, ProtocolError> {
		self.run(|job| unsafe {
			let mut sig = ffi::cmem_t::null();
			check(ffi::cbmpc_ecdsa_2p_sign(
				job,
				view(&key.0),
				view(digest),
				ffi::cmem_t::null(),
				std::ptr::null_mut(),
				&mut sig,
			))?;
			let sig = take_cmem(sig);
			Ok(if sig.is_empty() { None } else { Some(sig) })
		})
	}

	/// Runs the key refresh protocol, producing a new share for the same public key.
	pub fn refresh(&self, key: &KeyBlob) -> Result<KeyBlob, ProtocolError> {
		self.run(|job| unsafe {
			let mut out = ffi::cmem_t::null();
			check(ffi::cbmpc_ecdsa_2p_refresh(job, view(&key.0), &mut out))?;
			Ok(KeyBlob(take_cmem(out)))
		})
	}
}

/// An opaque, versioned cb-mpc key-share blob. Secret key material: treat accordingly.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyBlob(pub Vec<u8>);

impl fmt::Debug for KeyBlob {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "KeyBlob(<{} bytes>)", self.0.len())
	}
}

impl KeyBlob {
	/// Returns the aggregate (joint) public key in SEC1 compressed encoding (33 bytes).
	pub fn public_key_compressed(&self) -> Result<Vec<u8>, CbmpcError> {
		unsafe {
			let mut out = ffi::cmem_t::null();
			check(ffi::cbmpc_ecdsa_2p_get_public_key_compressed(view(&self.0), &mut out))?;
			Ok(take_cmem(out))
		}
	}
}

impl KeyBlob {
	/// Locally derives the share blob of `key + tweak` (BOLT 3 style additive derivation).
	///
	/// Both parties apply the same 32-byte tweak to their blobs of the same key and obtain
	/// shares of the derived key, whose public key is `Q + tweak*G`. No network round trip.
	pub fn derive_additive_tweak(&self, tweak: &[u8; 32]) -> Result<KeyBlob, CbmpcError> {
		unsafe {
			let mut out = ffi::cmem_t::null();
			check(ffi::cbmpc_ecdsa_2p_derive_additive_tweak(view(&self.0), view(tweak), &mut out))?;
			Ok(KeyBlob(take_cmem(out)))
		}
	}
}

impl Drop for KeyBlob {
	fn drop(&mut self) {
		// Best-effort zeroization of secret share material.
		for b in self.0.iter_mut() {
			unsafe { std::ptr::write_volatile(b, 0) };
		}
	}
}
