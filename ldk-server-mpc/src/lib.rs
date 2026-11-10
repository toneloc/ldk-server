//! Coinbase `cb-mpc` threshold ECDSA signing for LDK Server channel keys.
//!
//! See `README.md` for the architecture. In short:
//!
//! ```text
//!   LDK Server ──(MpcClient, request/response)──▶ any party ◀──(sessions, cb-mpc protocols)──▶ a quorum of parties
//! ```
//!
//! - [`mp`]: safe wrappers over cb-mpc's threshold ECDSA (ECDSA-MP with an access structure).
//! - [`cbmpc`]: error types shared by the cb-mpc wrappers.
//! - [`mesh`]: identity keys, the roster, and the authenticated links sessions run over.
//! - [`transport`]: framing, and an in-memory transport for tests and benchmarks.
//! - [`protocol`]: the small wire format between the client and a party and between parties.
//! - [`party`]: the party service (key-share store, leading and joining sessions).
//! - [`client`]: the blocking client used by LDK Server's signer.
//! - [`policy`]: the signing and secret-release policy every party enforces.
//! - [`tdh2`]: safe wrappers over cb-mpc's TDH2 threshold decryption.
//! - [`kit`]: channel kits (threshold-encrypted per-commitment secrets) and the offline
//!   ceremony's building blocks.

pub mod cbmpc;
pub mod client;
pub mod ffi;
pub mod kit;
pub mod mesh;
pub mod mp;
pub mod party;
pub mod policy;
pub mod protocol;
pub mod secure;
pub mod tdh2;
pub mod transport;

pub use bitcoin;
