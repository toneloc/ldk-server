//! Raw FFI declarations for the subset of the Coinbase `cb-mpc` public C API
//! (`include/cbmpc/c_api/{common,cmem,job,ecdsa_2p}.h`) used by this crate.
//!
//! Only ECDSA-2P (two-party ECDSA) entry points are declared. All functions are
//! synchronous: the library drives the interactive protocol on the calling thread and
//! invokes the supplied transport callbacks to exchange messages with the other party.

#![allow(non_camel_case_types)]

use std::os::raw::{c_char, c_int, c_void};

pub type cbmpc_error_t = c_int;
pub const CBMPC_SUCCESS: cbmpc_error_t = 0;

/// Error code encoding: `0xff000000 | (category << 16) | code`.
pub const fn cbmpc_errcode(category: u32, code: u32) -> cbmpc_error_t {
	(0xff00_0000u32 | (category << 16) | code) as cbmpc_error_t
}
pub const CBMPC_ECATEGORY_GENERIC: u32 = 0x01;
pub const CBMPC_ECATEGORY_NETWORK: u32 = 0x03;
pub const CBMPC_ECATEGORY_CRYPTO: u32 = 0x04;
pub const CBMPC_E_GENERAL: cbmpc_error_t = cbmpc_errcode(CBMPC_ECATEGORY_GENERIC, 0x0001);
pub const CBMPC_E_BADARG: cbmpc_error_t = cbmpc_errcode(CBMPC_ECATEGORY_GENERIC, 0x0002);
pub const CBMPC_E_FORMAT: cbmpc_error_t = cbmpc_errcode(CBMPC_ECATEGORY_GENERIC, 0x0003);
pub const CBMPC_E_NET_GENERAL: cbmpc_error_t = cbmpc_errcode(CBMPC_ECATEGORY_NETWORK, 0x0001);
pub const CBMPC_E_CRYPTO: cbmpc_error_t = cbmpc_errcode(CBMPC_ECATEGORY_CRYPTO, 0x0001);
/// Returned by the verifier (P1) if the counterparty cheated in a way that can leak a key
/// bit. See cb-mpc `SECURE_USAGE.md`. The public `sign()` API we use does not have the
/// global-abort property, but we still surface the code distinctly.
pub const CBMPC_E_ECDSA_2P_BIT_LEAK: cbmpc_error_t = cbmpc_errcode(CBMPC_ECATEGORY_CRYPTO, 0x0002);

pub const CBMPC_CURVE_SECP256K1: cbmpc_curve_id_t = 2;
pub type cbmpc_curve_id_t = c_int;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct cmem_t {
	pub data: *mut u8,
	pub size: c_int,
}

impl cmem_t {
	pub const fn null() -> Self {
		cmem_t { data: std::ptr::null_mut(), size: 0 }
	}
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct cmems_t {
	pub count: c_int,
	pub data: *mut u8,
	pub sizes: *mut c_int,
}

pub type cbmpc_transport_send_fn = Option<
	unsafe extern "C" fn(
		ctx: *mut c_void,
		receiver: i32,
		data: *const u8,
		size: c_int,
	) -> cbmpc_error_t,
>;
pub type cbmpc_transport_receive_fn = Option<
	unsafe extern "C" fn(ctx: *mut c_void, sender: i32, out_msg: *mut cmem_t) -> cbmpc_error_t,
>;
pub type cbmpc_transport_receive_all_fn = Option<
	unsafe extern "C" fn(
		ctx: *mut c_void,
		senders: *const i32,
		senders_count: c_int,
		out_msgs: *mut cmems_t,
	) -> cbmpc_error_t,
>;
pub type cbmpc_transport_free_fn = Option<unsafe extern "C" fn(ctx: *mut c_void, ptr: *mut c_void)>;

#[repr(C)]
pub struct cbmpc_transport_t {
	pub ctx: *mut c_void,
	pub send: cbmpc_transport_send_fn,
	pub receive: cbmpc_transport_receive_fn,
	pub receive_all: cbmpc_transport_receive_all_fn,
	pub free: cbmpc_transport_free_fn,
}

pub type cbmpc_2pc_party_t = c_int;
pub const CBMPC_2PC_P1: cbmpc_2pc_party_t = 0;
pub const CBMPC_2PC_P2: cbmpc_2pc_party_t = 1;

#[repr(C)]
pub struct cbmpc_2pc_job_t {
	pub self_: cbmpc_2pc_party_t,
	pub p1_name: *const c_char,
	pub p2_name: *const c_char,
	pub transport: *const cbmpc_transport_t,
}

extern "C" {
	pub fn cbmpc_malloc(size: usize) -> *mut c_void;
	pub fn cbmpc_free(ptr: *mut c_void);
	pub fn cbmpc_cmem_free(mem: cmem_t);

	pub fn cbmpc_ecdsa_2p_dkg(
		job: *const cbmpc_2pc_job_t, curve: cbmpc_curve_id_t, out_key_blob: *mut cmem_t,
	) -> cbmpc_error_t;
	pub fn cbmpc_ecdsa_2p_refresh(
		job: *const cbmpc_2pc_job_t, key_blob: cmem_t, out_new_key_blob: *mut cmem_t,
	) -> cbmpc_error_t;
	pub fn cbmpc_ecdsa_2p_sign(
		job: *const cbmpc_2pc_job_t, key_blob: cmem_t, msg_hash: cmem_t, sid_in: cmem_t,
		sid_out: *mut cmem_t, sig_der_out: *mut cmem_t,
	) -> cbmpc_error_t;
	pub fn cbmpc_ecdsa_2p_get_public_key_compressed(
		key_blob: cmem_t, out_pub_key: *mut cmem_t,
	) -> cbmpc_error_t;
}
