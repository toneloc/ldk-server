//! Error types shared by the cb-mpc wrappers ([`crate::mp`], [`crate::tdh2`]).

use std::fmt;

use crate::ffi;

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
}

impl fmt::Display for CbmpcError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let name = match self.code {
			ffi::CBMPC_E_GENERAL => "E_GENERAL",
			ffi::CBMPC_E_BADARG => "E_BADARG",
			ffi::CBMPC_E_FORMAT => "E_FORMAT",
			ffi::CBMPC_E_NET_GENERAL => "E_NET_GENERAL",
			ffi::CBMPC_E_CRYPTO => "E_CRYPTO",
			_ => "E_UNKNOWN",
		};
		write!(f, "cb-mpc error {name} (0x{:08x})", self.code as u32)
	}
}

impl std::error::Error for CbmpcError {}

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
