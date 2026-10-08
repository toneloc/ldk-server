//! [`ExternalFundingSigner`] implementation backed by the Coinbase cb-mpc 2-of-2 party
//! service (`ldk-server-mpc`).
//!
//! Only the channel **funding key** is MPC-backed. Every other channel key (revocation,
//! payment, delayed payment and HTLC basepoints, per-commitment secrets) stays in LDK's
//! `InMemorySigner`, derived from the node seed. See `ldk-server-mpc/README.md`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use ldk_node::bitcoin::hashes::{sha256, Hash, HashEngine};
use ldk_node::bitcoin::secp256k1::ecdsa::Signature;
use ldk_node::bitcoin::secp256k1::{All, Message, PublicKey, Secp256k1};
use ldk_node::bitcoin::Txid;
use ldk_node::signer::{ExternalFundingSigner, FundingSignContext, FundingSignOp};
use ldk_server_mpc::client::{ClientError, MpcClient};
use ldk_server_mpc::protocol::{KeyId, SigningContext, SigningOp};
use log::{debug, error, info};

use crate::util::config::MpcConfig;

/// Domain-separation tag for deriving MPC key ids from LDK channel key ids.
const KEY_ID_TAG: &[u8] = b"ldk-server/mpc-funding-key/v1";

pub(crate) struct MpcFundingSigner {
	client: MpcClient,
	secp: Secp256k1<All>,
	/// Public keys fetched from the MPC service, so signing operations never need a round
	/// trip for the key and `pubkeys()`-style callbacks stay cheap after first use.
	pubkeys: Mutex<HashMap<KeyId, PublicKey>>,
}

impl MpcFundingSigner {
	pub(crate) fn new(config: &MpcConfig) -> Self {
		let client = MpcClient::new(config.party_address).with_timeouts(
			Duration::from_secs(5),
			Duration::from_secs(config.request_timeout_secs),
			Duration::from_secs(config.dkg_timeout_secs),
		);
		MpcFundingSigner { client, secp: Secp256k1::new(), pubkeys: Mutex::new(HashMap::new()) }
	}

	/// Checks the MPC service is reachable.
	pub(crate) fn ping(&self) -> Result<(), ClientError> {
		self.client.ping()
	}

	/// Derives the MPC key id for a channel's funding key.
	///
	/// The original funding key is identified by `channel_keys_id` alone; each splice gets a
	/// fresh distributed key identified by the parent funding txid (cb-mpc exposes no
	/// additive tweak for 2P keys, so instead of tweaking we generate a new key).
	pub(crate) fn key_id(
		channel_keys_id: [u8; 32], splice_parent_funding_txid: Option<Txid>,
	) -> KeyId {
		let mut engine = sha256::Hash::engine();
		engine.input(KEY_ID_TAG);
		engine.input(&channel_keys_id);
		match splice_parent_funding_txid {
			Some(txid) => {
				engine.input(b"splice");
				engine.input(txid.as_ref());
			},
			None => engine.input(b"base"),
		}
		sha256::Hash::from_engine(engine).to_byte_array()
	}

	fn pubkey_for(&self, key_id: &KeyId) -> Result<PublicKey, ClientError> {
		if let Some(pk) = self.pubkeys.lock().unwrap().get(key_id) {
			return Ok(*pk);
		}
		let pk = self.client.ensure_key(key_id)?;
		self.pubkeys.lock().unwrap().insert(*key_id, pk);
		Ok(pk)
	}
}

fn to_signing_op(op: FundingSignOp) -> SigningOp {
	match op {
		FundingSignOp::CounterpartyCommitment => SigningOp::CounterpartyCommitment,
		FundingSignOp::HolderCommitment => SigningOp::HolderCommitment,
		FundingSignOp::ClosingTransaction => SigningOp::ClosingTransaction,
		FundingSignOp::HolderKeyedAnchorInput => SigningOp::HolderKeyedAnchorInput,
		FundingSignOp::ChannelAnnouncement => SigningOp::ChannelAnnouncement,
		FundingSignOp::SpliceSharedInput => SigningOp::SpliceSharedInput,
	}
}

impl ExternalFundingSigner for MpcFundingSigner {
	fn funding_pubkey(
		&self, channel_keys_id: [u8; 32], splice_parent_funding_txid: Option<Txid>,
	) -> Result<PublicKey, ()> {
		let key_id = Self::key_id(channel_keys_id, splice_parent_funding_txid);
		match self.pubkey_for(&key_id) {
			Ok(pk) => {
				info!(
					"MPC funding pubkey for channel keys id {} (splice parent: {:?}): {}",
					hex::DisplayHex::as_hex(&channel_keys_id[..]),
					splice_parent_funding_txid,
					pk
				);
				Ok(pk)
			},
			Err(e) => {
				error!("Failed to obtain MPC funding pubkey: {e}");
				Err(())
			},
		}
	}

	fn sign_with_funding_key(
		&self, channel_keys_id: [u8; 32], splice_parent_funding_txid: Option<Txid>, msg: &Message,
		context: &FundingSignContext,
	) -> Result<Signature, ()> {
		let key_id = Self::key_id(channel_keys_id, splice_parent_funding_txid);
		let pk = self.pubkey_for(&key_id).map_err(|e| {
			error!("Failed to obtain MPC funding pubkey for signing: {e}");
		})?;
		let signing_context = SigningContext {
			op: Some(to_signing_op(context.op)),
			channel_keys_id: Some(channel_keys_id),
			channel_value_satoshis: Some(context.channel_value_satoshis),
			commitment_number: context.commitment_number,
			funding_txid: context.funding_outpoint.map(|o| o.txid.to_byte_array()),
			funding_vout: context.funding_outpoint.map(|o| o.vout),
			splice_parent_funding_txid: splice_parent_funding_txid.map(|t| t.to_byte_array()),
		};
		let digest: [u8; 32] = *msg.as_ref();
		let started = std::time::Instant::now();
		match self.client.sign(&self.secp, &key_id, &digest, Some(signing_context), Some(&pk)) {
			Ok(sig) => {
				debug!(
					"MPC signed {:?} for channel keys id {} in {:?}",
					context.op,
					hex::DisplayHex::as_hex(&channel_keys_id[..]),
					started.elapsed()
				);
				Ok(sig)
			},
			Err(e) => {
				error!("MPC signing of {:?} failed: {e}", context.op);
				Err(())
			},
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn key_ids_are_domain_separated() {
		let id = [7u8; 32];
		let base = MpcFundingSigner::key_id(id, None);
		let txid = Txid::from_byte_array([9u8; 32]);
		let spliced = MpcFundingSigner::key_id(id, Some(txid));
		assert_ne!(base, id);
		assert_ne!(base, spliced);
		assert_eq!(base, MpcFundingSigner::key_id(id, None));
		assert_ne!(MpcFundingSigner::key_id([8u8; 32], None), base);
	}
}
