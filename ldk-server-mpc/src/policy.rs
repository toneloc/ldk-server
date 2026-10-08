//! Signing policy extension point.
//!
//! The proof of concept ships only [`AllowAllPolicy`]. The hook exists so a future
//! validating policy can be plugged in without changing the service. Note that the
//! [`SigningContext`] attached to a request is supplied by LDK Server and is not
//! independently verified; a real policy must not trust it as proof of safety.

use std::fmt;

use crate::protocol::{KeyId, SigningContext};

/// A signing request as seen by the policy.
#[derive(Clone, Debug)]
pub struct MpcSignRequest<'a> {
	pub request_id: [u8; 16],
	pub key_id: KeyId,
	pub digest: [u8; 32],
	pub context: Option<&'a SigningContext>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyError(pub String);

impl fmt::Display for PolicyError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "policy denied: {}", self.0)
	}
}

impl std::error::Error for PolicyError {}

pub trait SigningPolicy: Send + Sync {
	fn authorize(&self, request: &MpcSignRequest<'_>) -> Result<(), PolicyError>;
}

/// Authorizes every request. The only policy implemented in this proof of concept.
#[derive(Clone, Copy, Debug, Default)]
pub struct AllowAllPolicy;

impl SigningPolicy for AllowAllPolicy {
	fn authorize(&self, _request: &MpcSignRequest<'_>) -> Result<(), PolicyError> {
		Ok(())
	}
}
