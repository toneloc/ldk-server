//! Raw FFI declarations for the subset of the Coinbase `cb-mpc` public C API
//! (`include/cbmpc/c_api/{common,cmem,job,access_structure,ecdsa_mp,tdh2}.h`) used by this
//! crate: threshold ECDSA (ECDSA-MP with an access structure) and TDH2 threshold decryption,
//! plus one local key-derivation function added by `contrib/patches`. Interactive functions are
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

/// Execution context for multi-party protocols (`include/cbmpc/c_api/job.h`).
#[repr(C)]
pub struct cbmpc_mp_job_t {
	pub self_: i32,
	pub party_names: *const *const c_char,
	pub party_names_count: c_int,
	pub transport: *const cbmpc_transport_t,
}

pub type cbmpc_access_structure_node_type_t = c_int;
pub const CBMPC_ACCESS_STRUCTURE_NODE_LEAF: cbmpc_access_structure_node_type_t = 1;
pub const CBMPC_ACCESS_STRUCTURE_NODE_THRESHOLD: cbmpc_access_structure_node_type_t = 4;

/// One node of an access structure (`include/cbmpc/c_api/access_structure.h`).
#[repr(C)]
pub struct cbmpc_access_structure_node_t {
	pub type_: cbmpc_access_structure_node_type_t,
	pub leaf_name: *const c_char,
	pub threshold_k: i32,
	pub child_indices_offset: i32,
	pub child_indices_count: i32,
}

#[repr(C)]
pub struct cbmpc_access_structure_t {
	pub nodes: *const cbmpc_access_structure_node_t,
	pub nodes_count: i32,
	pub child_indices: *const i32,
	pub child_indices_count: i32,
	pub root_index: i32,
}

extern "C" {
	pub fn cbmpc_malloc(size: usize) -> *mut c_void;
	pub fn cbmpc_free(ptr: *mut c_void);
	pub fn cbmpc_cmem_free(mem: cmem_t);
	pub fn cbmpc_cmems_free(mems: cmems_t);

	// ECDSA-MP with an access structure (`include/cbmpc/c_api/ecdsa_mp.h`).
	pub fn cbmpc_ecdsa_mp_dkg_ac(
		job: *const cbmpc_mp_job_t, curve: cbmpc_curve_id_t, sid_in: cmem_t,
		access_structure: *const cbmpc_access_structure_t,
		quorum_party_names: *const *const c_char, quorum_party_names_count: c_int,
		out_ac_key_blob: *mut cmem_t, out_sid: *mut cmem_t,
	) -> cbmpc_error_t;
	pub fn cbmpc_ecdsa_mp_refresh_ac(
		job: *const cbmpc_mp_job_t, sid_in: cmem_t, ac_key_blob: cmem_t,
		access_structure: *const cbmpc_access_structure_t,
		quorum_party_names: *const *const c_char, quorum_party_names_count: c_int,
		sid_out: *mut cmem_t, out_new_ac_key_blob: *mut cmem_t,
	) -> cbmpc_error_t;
	pub fn cbmpc_ecdsa_mp_sign_ac(
		job: *const cbmpc_mp_job_t, ac_key_blob: cmem_t,
		access_structure: *const cbmpc_access_structure_t, msg_hash: cmem_t, sig_receiver: i32,
		sig_der_out: *mut cmem_t,
	) -> cbmpc_error_t;
	pub fn cbmpc_ecdsa_mp_derive_mul_add_ac(
		ac_key_blob: cmem_t, mul: cmem_t, add: cmem_t, out_ac_key_blob: *mut cmem_t,
	) -> cbmpc_error_t;
	pub fn cbmpc_ecdsa_mp_get_public_key_compressed(
		key_blob: cmem_t, out_pub_key: *mut cmem_t,
	) -> cbmpc_error_t;

	// TDH2 with an access structure.
	pub fn cbmpc_tdh2_dkg_ac(
		job: *const cbmpc_mp_job_t, curve: cbmpc_curve_id_t, sid_in: cmem_t,
		access_structure: *const cbmpc_access_structure_t,
		quorum_party_names: *const *const c_char, quorum_party_names_count: c_int,
		out_public_key: *mut cmem_t, out_public_shares: *mut cmems_t,
		out_private_share: *mut cmem_t, out_sid: *mut cmem_t,
	) -> cbmpc_error_t;
	pub fn cbmpc_tdh2_combine_ac(
		access_structure: *const cbmpc_access_structure_t, public_key: cmem_t,
		party_names: *const *const c_char, party_names_count: c_int, public_shares: cmems_t,
		label: cmem_t, partial_decryption_party_names: *const *const c_char,
		partial_decryption_party_names_count: c_int, partial_decryptions: cmems_t,
		ciphertext: cmem_t, out_plaintext: *mut cmem_t,
	) -> cbmpc_error_t;

	// TDH2 threshold decryption (`include/cbmpc/c_api/tdh2.h`).
	pub fn cbmpc_tdh2_encrypt(
		public_key: cmem_t, plaintext: cmem_t, label: cmem_t, out_ciphertext: *mut cmem_t,
	) -> cbmpc_error_t;
	pub fn cbmpc_tdh2_verify(
		public_key: cmem_t, ciphertext: cmem_t, label: cmem_t,
	) -> cbmpc_error_t;
	pub fn cbmpc_tdh2_partial_decrypt(
		private_share: cmem_t, ciphertext: cmem_t, label: cmem_t,
		out_partial_decryption: *mut cmem_t,
	) -> cbmpc_error_t;

}
