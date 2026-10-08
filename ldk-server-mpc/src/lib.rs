//! Coinbase `cb-mpc` 2-of-2 ECDSA signing for LDK Server channel funding keys.
//!
//! See `README.md` for the architecture. In short:
//!
//! ```text
//!   LDK Server ──(MpcClient, request/response)──▶ MPC Party A (P1) ◀──(cb-mpc protocol)──▶ MPC Party B (P2)
//! ```
//!
//! - [`cbmpc`]: safe wrappers over the cb-mpc ECDSA-2P C API.
//! - [`transport`]: framed TCP / in-memory transports used by the protocol.
//! - [`protocol`]: the small wire format between the client and P1 and between P1 and P2.
//! - [`party`]: the party service (key-share store, DKG/sign session handling).
//! - [`client`]: the blocking client used by LDK Server's signer.
//! - [`policy`]: the `SigningPolicy` extension point (only `AllowAllPolicy` is implemented).

pub mod cbmpc;
pub mod client;
pub mod ffi;
pub mod party;
pub mod policy;
pub mod protocol;
pub mod secure;
pub mod transport;

pub use bitcoin;
