//! Safe wrappers around cb-mpc's multi-party threshold ECDSA (`include/cbmpc/c_api/ecdsa_mp.h`)
//! and the machinery its multi-party protocols share.
//!
//! Keys are shared under a [`Threshold`] access structure: `k` of the named parties can sign,
//! fewer learn nothing. Key generation and refresh need every party online; signing needs only
//! the `k` or more parties of the chosen quorum. The library runs each protocol synchronously
//! on the calling thread and exchanges messages through an [`MpTransport`].

use std::ffi::CString;
use std::fmt;
use std::os::raw::{c_char, c_int, c_void};
use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::cbmpc::{CbmpcError, ProtocolError, TransportError};
use crate::ffi;

pub(crate) fn check(code: ffi::cbmpc_error_t) -> Result<(), CbmpcError> {
	if code == ffi::CBMPC_SUCCESS {
		Ok(())
	} else {
		Err(CbmpcError { code })
	}
}

pub(crate) fn view(bytes: &[u8]) -> ffi::cmem_t {
	ffi::cmem_t { data: bytes.as_ptr() as *mut u8, size: bytes.len() as c_int }
}

pub(crate) unsafe fn take_cmem(mem: ffi::cmem_t) -> Vec<u8> {
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

pub(crate) unsafe fn take_cmems(mems: ffi::cmems_t) -> Vec<Vec<u8>> {
	let mut out = Vec::new();
	if mems.count > 0 && !mems.sizes.is_null() {
		let sizes = std::slice::from_raw_parts(mems.sizes, mems.count as usize);
		let mut offset = 0usize;
		for size in sizes {
			let size = (*size).max(0) as usize;
			if size == 0 || mems.data.is_null() {
				out.push(Vec::new());
			} else {
				out.push(std::slice::from_raw_parts(mems.data.add(offset), size).to_vec());
			}
			offset += size;
		}
	}
	ffi::cbmpc_cmems_free(mems);
	out
}

/// A list of byte slices in cb-mpc's flattened `cmems_t` layout, borrowed for one call.
pub(crate) struct Flat {
	data: Vec<u8>,
	sizes: Vec<c_int>,
}

impl Flat {
	pub(crate) fn new(items: &[Vec<u8>]) -> Self {
		let mut data = Vec::new();
		let mut sizes = Vec::with_capacity(items.len());
		for item in items {
			data.extend_from_slice(item);
			sizes.push(item.len() as c_int);
		}
		Flat { data, sizes }
	}

	pub(crate) fn view(&mut self) -> ffi::cmems_t {
		ffi::cmems_t {
			count: self.sizes.len() as c_int,
			data: self.data.as_mut_ptr(),
			sizes: self.sizes.as_mut_ptr(),
		}
	}
}

/// NUL-terminated copies of party names, with the pointer array cb-mpc expects.
pub(crate) struct Names {
	_owned: Vec<CString>,
	ptrs: Vec<*const c_char>,
}

impl Names {
	pub(crate) fn new<S: AsRef<str>>(names: &[S]) -> Self {
		let owned: Vec<CString> = names
			.iter()
			.map(|n| CString::new(n.as_ref()).expect("party name must not contain NUL"))
			.collect();
		let ptrs = owned.iter().map(|n| n.as_ptr()).collect();
		Names { _owned: owned, ptrs }
	}

	pub(crate) fn as_ptr(&self) -> *const *const c_char {
		self.ptrs.as_ptr()
	}

	pub(crate) fn len(&self) -> c_int {
		self.ptrs.len() as c_int
	}
}

/// Message transport of one party in a multi-party session. `peer` is the other party's index
/// in the session's party list.
pub trait MpTransport {
	fn send(&self, peer: usize, msg: &[u8]) -> Result<(), TransportError>;
	fn recv(&self, peer: usize) -> Result<Vec<u8>, TransportError>;
}

struct CallbackCtx<'a> {
	transport: &'a dyn MpTransport,
	error: Option<TransportError>,
	panicked: bool,
}

impl CallbackCtx<'_> {
	fn fail(&mut self, e: TransportError) -> ffi::cbmpc_error_t {
		if self.error.is_none() {
			self.error = Some(e);
		}
		ffi::CBMPC_E_NET_GENERAL
	}
}

unsafe fn alloc_copy(bytes: &[u8]) -> *mut u8 {
	let buf = ffi::cbmpc_malloc(bytes.len().max(1)) as *mut u8;
	if !buf.is_null() {
		std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, bytes.len());
	}
	buf
}

unsafe extern "C" fn cb_send(
	ctx: *mut c_void, receiver: i32, data: *const u8, size: c_int,
) -> ffi::cbmpc_error_t {
	let ctx = &mut *(ctx as *mut CallbackCtx<'_>);
	let res = catch_unwind(AssertUnwindSafe(|| {
		let msg = if size > 0 { std::slice::from_raw_parts(data, size as usize) } else { &[][..] };
		ctx.transport.send(receiver.max(0) as usize, msg)
	}));
	match res {
		Ok(Ok(())) => ffi::CBMPC_SUCCESS,
		Ok(Err(e)) => ctx.fail(e),
		Err(_) => {
			ctx.panicked = true;
			ffi::CBMPC_E_NET_GENERAL
		},
	}
}

unsafe extern "C" fn cb_receive(
	ctx: *mut c_void, sender: i32, out_msg: *mut ffi::cmem_t,
) -> ffi::cbmpc_error_t {
	let ctx = &mut *(ctx as *mut CallbackCtx<'_>);
	*out_msg = ffi::cmem_t::null();
	match catch_unwind(AssertUnwindSafe(|| ctx.transport.recv(sender.max(0) as usize))) {
		Ok(Ok(msg)) => {
			if msg.len() > c_int::MAX as usize {
				return ffi::CBMPC_E_FORMAT;
			}
			let buf = alloc_copy(&msg);
			if buf.is_null() {
				return ffi::CBMPC_E_GENERAL;
			}
			*out_msg = ffi::cmem_t { data: buf, size: msg.len() as c_int };
			ffi::CBMPC_SUCCESS
		},
		Ok(Err(e)) => ctx.fail(e),
		Err(_) => {
			ctx.panicked = true;
			ffi::CBMPC_E_NET_GENERAL
		},
	}
}

unsafe extern "C" fn cb_receive_all(
	ctx: *mut c_void, senders: *const i32, senders_count: c_int, out_msgs: *mut ffi::cmems_t,
) -> ffi::cbmpc_error_t {
	let ctx = &mut *(ctx as *mut CallbackCtx<'_>);
	*out_msgs = ffi::cmems_t { count: 0, data: std::ptr::null_mut(), sizes: std::ptr::null_mut() };
	let senders: &[i32] = if senders_count > 0 {
		std::slice::from_raw_parts(senders, senders_count as usize)
	} else {
		&[]
	};
	let res = catch_unwind(AssertUnwindSafe(|| {
		senders
			.iter()
			.map(|s| ctx.transport.recv((*s).max(0) as usize))
			.collect::<Result<Vec<_>, _>>()
	}));
	match res {
		Ok(Ok(msgs)) => {
			let total: usize = msgs.iter().map(|m| m.len()).sum();
			if total > c_int::MAX as usize {
				return ffi::CBMPC_E_FORMAT;
			}
			let flat: Vec<u8> = msgs.iter().flatten().copied().collect();
			let data = alloc_copy(&flat);
			let sizes =
				ffi::cbmpc_malloc(std::mem::size_of::<c_int>() * msgs.len().max(1)) as *mut c_int;
			if data.is_null() || sizes.is_null() {
				if !data.is_null() {
					ffi::cbmpc_free(data as *mut c_void);
				}
				if !sizes.is_null() {
					ffi::cbmpc_free(sizes as *mut c_void);
				}
				return ffi::CBMPC_E_GENERAL;
			}
			for (i, m) in msgs.iter().enumerate() {
				*sizes.add(i) = m.len() as c_int;
			}
			*out_msgs = ffi::cmems_t { count: msgs.len() as c_int, data, sizes };
			ffi::CBMPC_SUCCESS
		},
		Ok(Err(e)) => ctx.fail(e),
		Err(_) => {
			ctx.panicked = true;
			ffi::CBMPC_E_NET_GENERAL
		},
	}
}

/// Runs one multi-party protocol call as party `me` of `party_names`.
pub(crate) fn run_job<S: AsRef<str>, R>(
	party_names: &[S], me: usize, transport: &dyn MpTransport,
	f: impl FnOnce(*const ffi::cbmpc_mp_job_t) -> Result<R, CbmpcError>,
) -> Result<R, ProtocolError> {
	let names = Names::new(party_names);
	let mut ctx = CallbackCtx { transport, error: None, panicked: false };
	let c_transport = ffi::cbmpc_transport_t {
		ctx: &mut ctx as *mut CallbackCtx<'_> as *mut c_void,
		send: Some(cb_send),
		receive: Some(cb_receive),
		receive_all: Some(cb_receive_all),
		free: None,
	};
	let job = ffi::cbmpc_mp_job_t {
		self_: me as i32,
		party_names: names.as_ptr(),
		party_names_count: names.len(),
		transport: &c_transport,
	};
	let res = f(&job);
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

/// The access structure of every key: any `k` of `parties` together hold the key.
///
/// The party names are the cb-mpc party identifiers. They must be stable and unique, and every
/// party must use the same names (the order does not matter to the library, but this type keeps
/// one order so indices mean the same everywhere).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Threshold {
	pub parties: Vec<String>,
	pub k: usize,
}

impl Threshold {
	pub fn new(parties: Vec<String>, k: usize) -> Result<Self, String> {
		if parties.len() < 2 || k < 2 || k > parties.len() {
			return Err(format!("cannot require {k} of {} parties", parties.len()));
		}
		for (i, p) in parties.iter().enumerate() {
			if p.is_empty() || p.contains('\0') || parties[..i].contains(p) {
				return Err("party names must be distinct and non-empty".into());
			}
		}
		Ok(Threshold { parties, k })
	}

	pub fn index_of(&self, name: &str) -> Option<usize> {
		self.parties.iter().position(|p| p == name)
	}

	/// Whether `quorum` (party indices) is a set of at least `k` distinct parties.
	pub fn is_quorum(&self, quorum: &[usize]) -> bool {
		quorum.len() >= self.k
			&& quorum.iter().all(|i| *i < self.parties.len())
			&& quorum.iter().enumerate().all(|(n, i)| !quorum[..n].contains(i))
	}

	/// Calls `f` with the structure in cb-mpc's form: a THRESHOLD[k] root over one leaf each.
	pub(crate) fn with_c<R>(&self, f: impl FnOnce(*const ffi::cbmpc_access_structure_t) -> R) -> R {
		let names = Names::new(&self.parties);
		let n = self.parties.len();
		let mut nodes = Vec::with_capacity(n + 1);
		nodes.push(ffi::cbmpc_access_structure_node_t {
			type_: ffi::CBMPC_ACCESS_STRUCTURE_NODE_THRESHOLD,
			leaf_name: std::ptr::null(),
			threshold_k: self.k as i32,
			child_indices_offset: 0,
			child_indices_count: n as i32,
		});
		for i in 0..n {
			nodes.push(ffi::cbmpc_access_structure_node_t {
				type_: ffi::CBMPC_ACCESS_STRUCTURE_NODE_LEAF,
				leaf_name: unsafe { *names.as_ptr().add(i) },
				threshold_k: 0,
				child_indices_offset: 0,
				child_indices_count: 0,
			});
		}
		let children: Vec<i32> = (1..=n as i32).collect();
		let ac = ffi::cbmpc_access_structure_t {
			nodes: nodes.as_ptr(),
			nodes_count: nodes.len() as i32,
			child_indices: children.as_ptr(),
			child_indices_count: children.len() as i32,
			root_index: 0,
		};
		f(&ac)
	}
}

/// This party's share of a threshold ECDSA key: an opaque cb-mpc blob. Secret key material.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyShare(pub Vec<u8>);

impl fmt::Debug for KeyShare {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "KeyShare(<{} bytes>)", self.0.len())
	}
}

impl Drop for KeyShare {
	fn drop(&mut self) {
		for b in self.0.iter_mut() {
			unsafe { std::ptr::write_volatile(b, 0) };
		}
	}
}

impl KeyShare {
	/// The joint public key, SEC1 compressed (33 bytes).
	pub fn public_key_compressed(&self) -> Result<Vec<u8>, CbmpcError> {
		unsafe {
			let mut out = ffi::cmem_t::null();
			check(ffi::cbmpc_ecdsa_mp_get_public_key_compressed(view(&self.0), &mut out))?;
			Ok(take_cmem(out))
		}
	}

	/// Locally derives this party's share of `key * mul + add`, whose public key is
	/// `mul * Q + add * G`. Every party applies the same values to its share of the same key;
	/// no messages are exchanged. Used for BOLT 3 revocation keys.
	///
	/// Derived shares are for one signature and must never be refreshed or stored.
	pub fn derive_mul_add(&self, mul: &[u8; 32], add: &[u8; 32]) -> Result<KeyShare, CbmpcError> {
		unsafe {
			let mut out = ffi::cmem_t::null();
			check(ffi::cbmpc_ecdsa_mp_derive_mul_add_ac(
				view(&self.0),
				view(mul),
				view(add),
				&mut out,
			))?;
			Ok(KeyShare(take_cmem(out)))
		}
	}

	/// Locally derives this party's share of `key + tweak` (BOLT 3 per-commitment keys).
	pub fn derive_additive_tweak(&self, tweak: &[u8; 32]) -> Result<KeyShare, CbmpcError> {
		let mut one = [0u8; 32];
		one[31] = 1;
		self.derive_mul_add(&one, tweak)
	}
}

/// Generates a new key among all parties of `ac`. Every party must take part.
pub fn dkg(
	ac: &Threshold, me: usize, transport: &dyn MpTransport,
) -> Result<KeyShare, ProtocolError> {
	let quorum = Names::new(&ac.parties);
	run_job(&ac.parties, me, transport, |job| {
		ac.with_c(|c_ac| unsafe {
			let mut blob = ffi::cmem_t::null();
			let mut sid = ffi::cmem_t::null();
			check(ffi::cbmpc_ecdsa_mp_dkg_ac(
				job,
				ffi::CBMPC_CURVE_SECP256K1,
				ffi::cmem_t::null(),
				c_ac,
				quorum.as_ptr(),
				quorum.len(),
				&mut blob,
				&mut sid,
			))?;
			let _ = take_cmem(sid);
			Ok(KeyShare(take_cmem(blob)))
		})
	})
}

/// Replaces every party's share of `key` with a fresh one for the same public key. Every party
/// must take part; shares from before and after a refresh do not combine.
pub fn refresh(
	ac: &Threshold, me: usize, key: &KeyShare, transport: &dyn MpTransport,
) -> Result<KeyShare, ProtocolError> {
	let quorum = Names::new(&ac.parties);
	run_job(&ac.parties, me, transport, |job| {
		ac.with_c(|c_ac| unsafe {
			let mut blob = ffi::cmem_t::null();
			check(ffi::cbmpc_ecdsa_mp_refresh_ac(
				job,
				ffi::cmem_t::null(),
				view(&key.0),
				c_ac,
				quorum.as_ptr(),
				quorum.len(),
				std::ptr::null_mut(),
				&mut blob,
			))?;
			Ok(KeyShare(take_cmem(blob)))
		})
	})
}

/// Signs a 32-byte digest with the parties of `quorum` (indices into `ac.parties`), of which
/// this party is `quorum[me]`. Only `quorum[receiver]` obtains the DER signature (not
/// guaranteed low-S); the others get `None`.
pub fn sign(
	ac: &Threshold, quorum: &[usize], me: usize, key: &KeyShare, digest: &[u8; 32],
	receiver: usize, transport: &dyn MpTransport,
) -> Result<Option<Vec<u8>>, ProtocolError> {
	if !ac.is_quorum(quorum) || me >= quorum.len() || receiver >= quorum.len() {
		return Err(ProtocolError::Cbmpc(CbmpcError { code: ffi::CBMPC_E_BADARG }));
	}
	let names: Vec<&str> = quorum.iter().map(|i| ac.parties[*i].as_str()).collect();
	run_job(&names, me, transport, |job| {
		ac.with_c(|c_ac| unsafe {
			let mut sig = ffi::cmem_t::null();
			check(ffi::cbmpc_ecdsa_mp_sign_ac(
				job,
				view(&key.0),
				c_ac,
				view(digest),
				receiver as i32,
				&mut sig,
			))?;
			let sig = take_cmem(sig);
			Ok(if sig.is_empty() { None } else { Some(sig) })
		})
	})
}

#[cfg(test)]
pub(crate) mod test_util {
	use std::thread;
	use std::time::Duration;

	use super::*;
	use crate::transport::LocalMesh;

	pub fn threshold(n: usize, k: usize) -> Threshold {
		Threshold::new((0..n).map(|i| format!("party-{i}")).collect(), k).unwrap()
	}

	/// Runs `f(party index, transport)` for every party of an `n`-party session on its own
	/// thread and returns the results in party order.
	pub fn run_parties<R: Send + 'static>(
		n: usize, f: impl Fn(usize, &LocalMesh) -> R + Send + Sync + Clone + 'static,
	) -> Vec<R> {
		let handles: Vec<_> = LocalMesh::new(n, Duration::from_secs(60))
			.into_iter()
			.enumerate()
			.map(|(i, mesh)| {
				let f = f.clone();
				thread::spawn(move || f(i, &mesh))
			})
			.collect();
		handles.into_iter().map(|h| h.join().unwrap()).collect()
	}

	pub fn keygen(ac: &Threshold) -> Vec<KeyShare> {
		let ac = ac.clone();
		run_parties(ac.parties.len(), move |i, mesh| dkg(&ac, i, mesh).unwrap())
	}

	/// Signs `digest` with `quorum`; returns the receiver's DER signature.
	pub fn sign_with(
		ac: &Threshold, shares: &[KeyShare], quorum: &[usize], digest: [u8; 32],
	) -> Result<Vec<u8>, String> {
		let (ac, quorum) = (ac.clone(), quorum.to_vec());
		let shares: Vec<KeyShare> = quorum.iter().map(|i| shares[*i].clone()).collect();
		let out = run_parties(quorum.len(), move |pos, mesh| {
			sign(&ac, &quorum, pos, &shares[pos], &digest, 0, mesh).map_err(|e| e.to_string())
		});
		let mut out = out.into_iter();
		let first = out.next().unwrap()?;
		for other in out {
			other?;
		}
		first.ok_or_else(|| "receiver got no signature".to_string())
	}
}

#[cfg(test)]
mod tests {
	use bitcoin::secp256k1::ecdsa::Signature;
	use bitcoin::secp256k1::{Message, PublicKey, Scalar, Secp256k1};

	use super::test_util::*;
	use super::*;

	fn verify(pk: &PublicKey, digest: [u8; 32], der: &[u8]) -> bool {
		let secp = Secp256k1::new();
		let mut sig = Signature::from_der(der).unwrap();
		sig.normalize_s();
		secp.verify_ecdsa(&Message::from_digest(digest), &sig, pk).is_ok()
	}

	fn pubkey(share: &KeyShare) -> PublicKey {
		PublicKey::from_slice(&share.public_key_compressed().unwrap()).unwrap()
	}

	#[test]
	fn any_three_of_four_sign() {
		let ac = threshold(4, 3);
		let shares = keygen(&ac);
		let pk = pubkey(&shares[0]);
		assert!(shares.iter().all(|s| pubkey(s) == pk));
		for (n, quorum) in [
			vec![0, 1, 2],
			vec![0, 1, 3],
			vec![0, 2, 3],
			vec![1, 2, 3],
			vec![3, 1, 0],
			vec![0, 1, 2, 3],
		]
		.into_iter()
		.enumerate()
		{
			let digest = [n as u8 + 1; 32];
			let der = sign_with(&ac, &shares, &quorum, digest).unwrap();
			assert!(verify(&pk, digest, &der), "quorum {quorum:?}");
		}
	}

	#[test]
	fn two_of_four_cannot_sign() {
		let ac = threshold(4, 3);
		let shares = keygen(&ac);
		assert!(!ac.is_quorum(&[0, 1]));
		assert!(!ac.is_quorum(&[0, 1, 1]));
		assert!(sign_with(&ac, &shares, &[0, 1], [9u8; 32]).is_err());
	}

	#[test]
	fn derived_keys_sign_for_the_derived_public_key() {
		let secp = Secp256k1::new();
		let ac = threshold(4, 3);
		let shares = keygen(&ac);
		let base = pubkey(&shares[0]);

		// key + tweak (BOLT 3 per-commitment keys)
		let tweak = [0x21u8; 32];
		let expected = base.add_exp_tweak(&secp, &Scalar::from_be_bytes(tweak).unwrap()).unwrap();
		let derived: Vec<KeyShare> =
			shares.iter().map(|s| s.derive_additive_tweak(&tweak).unwrap()).collect();
		assert!(derived.iter().all(|s| pubkey(s) == expected));
		for quorum in [vec![0, 1, 2], vec![1, 2, 3], vec![0, 2, 3]] {
			let der = sign_with(&ac, &derived, &quorum, [0x31; 32]).unwrap();
			assert!(verify(&expected, [0x31; 32], &der), "additive, quorum {quorum:?}");
		}

		// key * mul + add (BOLT 3 revocation keys)
		let (mul, add) = ([0x45u8; 32], [0x67u8; 32]);
		let expected = base
			.mul_tweak(&secp, &Scalar::from_be_bytes(mul).unwrap())
			.unwrap()
			.add_exp_tweak(&secp, &Scalar::from_be_bytes(add).unwrap())
			.unwrap();
		let derived: Vec<KeyShare> =
			shares.iter().map(|s| s.derive_mul_add(&mul, &add).unwrap()).collect();
		assert!(derived.iter().all(|s| pubkey(s) == expected));
		for quorum in [vec![0, 1, 3], vec![3, 2, 1], vec![0, 1, 2, 3]] {
			let der = sign_with(&ac, &derived, &quorum, [0x32; 32]).unwrap();
			assert!(verify(&expected, [0x32; 32], &der), "mul-add, quorum {quorum:?}");
		}

		// A party that applies a different tweak breaks the signature, not the key.
		let mut mixed = derived.clone();
		mixed[1] = shares[1].derive_additive_tweak(&tweak).unwrap();
		assert!(sign_with(&ac, &mixed, &[0, 1, 2], [0x33; 32]).is_err());
		assert!(shares[0].derive_mul_add(&[0u8; 32], &add).is_err(), "zero multiplier");
	}

	#[test]
	fn refresh_keeps_the_key_and_retires_old_shares() {
		let ac = threshold(4, 3);
		let old = keygen(&ac);
		let pk = pubkey(&old[0]);
		let (ac2, old2) = (ac.clone(), old.clone());
		let new = run_parties(4, move |i, mesh| refresh(&ac2, i, &old2[i], mesh).unwrap());
		assert!(new.iter().all(|s| pubkey(s) == pk));
		assert!(new.iter().zip(&old).all(|(n, o)| n != o));
		let der = sign_with(&ac, &new, &[0, 2, 3], [0x41; 32]).unwrap();
		assert!(verify(&pk, [0x41; 32], &der));
		// Shares from different epochs do not combine: two old and one new fail to sign.
		let mixed = vec![old[0].clone(), old[1].clone(), new[2].clone(), new[3].clone()];
		assert!(sign_with(&ac, &mixed, &[0, 1, 2], [0x42; 32]).is_err());
	}

	#[test]
	fn two_of_two_also_works() {
		let ac = threshold(2, 2);
		let shares = keygen(&ac);
		let der = sign_with(&ac, &shares, &[0, 1], [0x51; 32]).unwrap();
		assert!(verify(&pubkey(&shares[0]), [0x51; 32], &der));
		assert!(Threshold::new(vec!["a".into(), "a".into()], 2).is_err());
		assert!(Threshold::new(vec!["a".into(), "b".into()], 3).is_err());
		assert!(Threshold::new(vec!["a".into(), "b".into()], 1).is_err());
	}
}
