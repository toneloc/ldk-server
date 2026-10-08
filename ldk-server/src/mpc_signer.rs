//! [`ExternalChannelSigner`] implementation backed by the Coinbase cb-mpc 2-of-2 party service
//! (`ldk-server-mpc`).
//!
//! With `coverage = "all"` every channel key (funding, payment, delayed-payment, HTLC and
//! revocation basepoints) is a distributed key and the per-commitment secrets live on MPC
//! Party B. With `coverage = "funding"` only the funding key is distributed. See
//! `ldk-server-mpc/README.md`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use ldk_node::bitcoin::hashes::{sha256, Hash, HashEngine};
use ldk_node::bitcoin::secp256k1::ecdsa::Signature;
use ldk_node::bitcoin::secp256k1::{All, PublicKey, Scalar, Secp256k1, SecretKey};
use ldk_node::bitcoin::{EcdsaSighashType, Txid};
use ldk_node::lightning::ln::chan_utils::ChannelPublicKeys;
use ldk_node::lightning::util::ser::Writeable;
use ldk_node::signer::{
	ChannelKey, ChannelSignOp, ExternalChannelSigner, KeyCoverage, SignContext, SignRequest,
};
use ldk_server_mpc::client::{ClientError, MpcClient};
use ldk_server_mpc::policy::{bolt3_tweak, revocation_tweaks};
use ldk_server_mpc::protocol::{
	ChannelId, CounterpartyKeys, Derivation, KeyId, KeyKind, SignItem, SigningContext, SigningOp,
};
use log::{debug, error, info};

use crate::util::config::{MpcConfig, MpcCoverage};

/// Domain-separation tag for deriving MPC key ids from LDK channel key ids.
const KEY_ID_TAG: &[u8] = b"ldk-server/mpc-key/v1";

pub(crate) struct MpcChannelSigner {
	client: MpcClient,
	coverage: KeyCoverage,
	secp: Secp256k1<All>,
	/// Public keys fetched from the MPC service, keyed by MPC key id.
	pubkeys: Mutex<HashMap<KeyId, PublicKey>>,
}

impl MpcChannelSigner {
	pub(crate) fn new(config: &MpcConfig) -> Self {
		let client = MpcClient::new(config.party_address).with_timeouts(
			Duration::from_secs(5),
			Duration::from_secs(config.request_timeout_secs),
			Duration::from_secs(config.dkg_timeout_secs),
		);
		let coverage = match config.coverage {
			MpcCoverage::Funding => KeyCoverage::FundingOnly,
			MpcCoverage::All => KeyCoverage::AllChannelKeys,
		};
		MpcChannelSigner {
			client,
			coverage,
			secp: Secp256k1::new(),
			pubkeys: Mutex::new(HashMap::new()),
		}
	}

	/// Checks the MPC service is reachable.
	pub(crate) fn ping(&self) -> Result<(), ClientError> {
		self.client.ping()
	}

	fn tagged(channel_keys_id: [u8; 32], label: &[u8], extra: Option<&[u8]>) -> [u8; 32] {
		let mut engine = sha256::Hash::engine();
		engine.input(KEY_ID_TAG);
		engine.input(&channel_keys_id);
		engine.input(label);
		if let Some(extra) = extra {
			engine.input(extra);
		}
		sha256::Hash::from_engine(engine).to_byte_array()
	}

	/// The policy channel identifier for a channel.
	pub(crate) fn channel_id(channel_keys_id: [u8; 32]) -> ChannelId {
		Self::tagged(channel_keys_id, b"channel", None)
	}

	/// The MPC key id of a channel key.
	pub(crate) fn key_id(
		channel_keys_id: [u8; 32], kind: KeyKind, splice_parent: Option<Txid>,
	) -> KeyId {
		match kind {
			KeyKind::Funding => Self::tagged(channel_keys_id, b"funding", None),
			KeyKind::SplicedFunding => Self::tagged(
				channel_keys_id,
				b"splice",
				Some(splice_parent.expect("splice parent required").as_ref()),
			),
			KeyKind::Payment => Self::tagged(channel_keys_id, b"payment", None),
			KeyKind::DelayedPayment => Self::tagged(channel_keys_id, b"delayed", None),
			KeyKind::Htlc => Self::tagged(channel_keys_id, b"htlc", None),
			KeyKind::Revocation => Self::tagged(channel_keys_id, b"revocation", None),
			KeyKind::Standalone => Self::tagged(channel_keys_id, b"standalone", None),
		}
	}

	fn cached(&self, key_id: &KeyId) -> Option<PublicKey> {
		self.pubkeys.lock().unwrap().get(key_id).copied()
	}

	fn ensure(
		&self, channel_keys_id: [u8; 32], kind: KeyKind, splice_parent: Option<Txid>,
	) -> Result<PublicKey, ClientError> {
		let key_id = Self::key_id(channel_keys_id, kind, splice_parent);
		if let Some(pk) = self.cached(&key_id) {
			return Ok(pk);
		}
		let channel = Self::channel_id(channel_keys_id);
		let pk = self.client.ensure_channel_key(&key_id, &channel, kind)?;
		self.pubkeys.lock().unwrap().insert(key_id, pk);
		Ok(pk)
	}

	fn basepoint(&self, channel_keys_id: [u8; 32], kind: KeyKind) -> Result<PublicKey, ()> {
		self.ensure(channel_keys_id, kind, None).map_err(|e| {
			error!("Failed to obtain MPC {kind:?} key: {e}");
		})
	}

	fn to_signing_context(
		ctx: &SignContext, channel_keys_id: [u8; 32], secret: Option<&SecretKey>,
	) -> SigningContext {
		let op = match ctx.op {
			ChannelSignOp::CounterpartyCommitment => SigningOp::CounterpartyCommitment,
			ChannelSignOp::CounterpartyCommitmentHtlc => SigningOp::CounterpartyCommitmentHtlc,
			ChannelSignOp::HolderCommitment => SigningOp::HolderCommitment,
			ChannelSignOp::ClosingTransaction => SigningOp::ClosingTransaction,
			ChannelSignOp::HolderKeyedAnchorInput => SigningOp::HolderKeyedAnchorInput,
			ChannelSignOp::ChannelAnnouncement => SigningOp::ChannelAnnouncement,
			ChannelSignOp::SpliceSharedInput => SigningOp::SpliceSharedInput,
			ChannelSignOp::JusticeRevokedOutput => SigningOp::JusticeRevokedOutput,
			ChannelSignOp::JusticeRevokedHtlc => SigningOp::JusticeRevokedHtlc,
			ChannelSignOp::HolderHtlcTransaction => SigningOp::HolderHtlcTransaction,
			ChannelSignOp::CounterpartyHtlcTransaction => SigningOp::CounterpartyHtlcTransaction,
			ChannelSignOp::SweepStaticPayment => SigningOp::SweepStaticPayment,
			ChannelSignOp::SweepDelayedPayment => SigningOp::SweepDelayedPayment,
		};
		SigningContext {
			op: Some(op),
			channel_keys_id: Some(channel_keys_id),
			channel_value_satoshis: Some(ctx.channel_value_satoshis),
			commitment_number: ctx.commitment_number,
			funding_txid: ctx.funding_outpoint.map(|o| o.txid.to_byte_array()),
			funding_vout: ctx.funding_outpoint.map(|o| o.vout),
			splice_parent_funding_txid: ctx.splice_parent_funding_txid.map(|t| t.to_byte_array()),
			channel_type_features: ctx.channel_type_features.as_ref().map(|f| f.encode()),
			counterparty_keys: ctx.counterparty_pubkeys.as_ref().map(|k| CounterpartyKeys {
				funding_pubkey: k.funding_pubkey.serialize(),
				revocation_basepoint: k.revocation_basepoint.0.serialize(),
				payment_point: k.payment_point.serialize(),
				delayed_payment_basepoint: k.delayed_payment_basepoint.0.serialize(),
				htlc_basepoint: k.htlc_basepoint.0.serialize(),
			}),
			holder_selected_contest_delay: ctx.holder_selected_contest_delay,
			counterparty_selected_contest_delay: ctx.counterparty_selected_contest_delay,
			transaction: ctx.transaction.clone(),
			input_index: ctx.input_index,
			input_value_sat: ctx.input_value_sat,
			witness_script: ctx.witness_script.as_ref().map(|s| s.to_bytes()),
			sighash_type: match ctx.sighash_type {
				EcdsaSighashType::SinglePlusAnyoneCanPay => 0x83,
				_ => 0x01,
			},
			per_commitment_point: ctx.per_commitment_point.map(|p| p.serialize()),
			counterparty_per_commitment_secret: secret.map(|s| s.secret_bytes()),
			holder_balance_sat: ctx.holder_balance_sat,
		}
	}

	/// Resolves a request into a wire item plus the public key the signature must verify under.
	fn to_item(
		&self, channel_keys_id: [u8; 32], req: &SignRequest,
	) -> Result<(SignItem, PublicKey), ()> {
		let (key_id, derivation, expected, secret) = match &req.key {
			ChannelKey::Funding { splice_parent_funding_txid } => {
				let kind = if splice_parent_funding_txid.is_some() {
					KeyKind::SplicedFunding
				} else {
					KeyKind::Funding
				};
				let pk = self.ensure(channel_keys_id, kind, *splice_parent_funding_txid).map_err(
					|e| {
						error!("Failed to obtain MPC funding key: {e}");
					},
				)?;
				(
					Self::key_id(channel_keys_id, kind, *splice_parent_funding_txid),
					Derivation::None,
					pk,
					None,
				)
			},
			ChannelKey::Payment => {
				let pk = self.basepoint(channel_keys_id, KeyKind::Payment)?;
				(Self::key_id(channel_keys_id, KeyKind::Payment, None), Derivation::None, pk, None)
			},
			ChannelKey::DelayedPayment { per_commitment_point } => {
				let base = self.basepoint(channel_keys_id, KeyKind::DelayedPayment)?;
				let tweak = bolt3_tweak(&per_commitment_point.serialize(), &base.serialize());
				let pk = base
					.add_exp_tweak(&self.secp, &Scalar::from_be_bytes(tweak).map_err(|_| ())?)
					.map_err(|_| ())?;
				(
					Self::key_id(channel_keys_id, KeyKind::DelayedPayment, None),
					Derivation::Additive { tweak },
					pk,
					None,
				)
			},
			ChannelKey::Htlc { per_commitment_point } => {
				let base = self.basepoint(channel_keys_id, KeyKind::Htlc)?;
				let tweak = bolt3_tweak(&per_commitment_point.serialize(), &base.serialize());
				let pk = base
					.add_exp_tweak(&self.secp, &Scalar::from_be_bytes(tweak).map_err(|_| ())?)
					.map_err(|_| ())?;
				(
					Self::key_id(channel_keys_id, KeyKind::Htlc, None),
					Derivation::Additive { tweak },
					pk,
					None,
				)
			},
			ChannelKey::Revocation { per_commitment_secret } => {
				let base = self.basepoint(channel_keys_id, KeyKind::Revocation)?;
				let (mul, add) = revocation_tweaks(&self.secp, &base, per_commitment_secret);
				let mul_scalar = Scalar::from_be_bytes(mul).map_err(|_| ())?;
				let add_scalar = Scalar::from_be_bytes(add).map_err(|_| ())?;
				let pk = base
					.mul_tweak(&self.secp, &mul_scalar)
					.and_then(|p| p.add_exp_tweak(&self.secp, &add_scalar))
					.map_err(|_| ())?;
				(
					Self::key_id(channel_keys_id, KeyKind::Revocation, None),
					Derivation::MulAdd { mul, add },
					pk,
					Some(per_commitment_secret),
				)
			},
		};
		let context = Self::to_signing_context(&req.context, channel_keys_id, secret);
		Ok((SignItem { key_id, derivation, digest: *req.msg.as_ref(), context }, expected))
	}
}

impl ExternalChannelSigner for MpcChannelSigner {
	fn coverage(&self) -> KeyCoverage {
		self.coverage
	}

	fn funding_pubkey(
		&self, channel_keys_id: [u8; 32], splice_parent_funding_txid: Option<Txid>,
	) -> Result<PublicKey, ()> {
		let kind = if splice_parent_funding_txid.is_some() {
			KeyKind::SplicedFunding
		} else {
			KeyKind::Funding
		};
		match self.ensure(channel_keys_id, kind, splice_parent_funding_txid) {
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

	fn channel_pubkeys(&self, channel_keys_id: [u8; 32]) -> Result<ChannelPublicKeys, ()> {
		// Generate / fetch all five keys in parallel (each may be a DKG on first use).
		let kinds = [
			KeyKind::Funding,
			KeyKind::Revocation,
			KeyKind::Payment,
			KeyKind::DelayedPayment,
			KeyKind::Htlc,
		];
		let results: Vec<Result<PublicKey, ClientError>> = std::thread::scope(|s| {
			let handles: Vec<_> = kinds
				.iter()
				.map(|kind| s.spawn(move || self.ensure(channel_keys_id, *kind, None)))
				.collect();
			handles.into_iter().map(|h| h.join().expect("ensure thread panicked")).collect()
		});
		let mut keys = Vec::with_capacity(5);
		for (kind, res) in kinds.iter().zip(results) {
			match res {
				Ok(pk) => keys.push(pk),
				Err(e) => {
					error!(
						"Failed to obtain MPC {kind:?} key for channel keys id {}: {e}",
						hex::DisplayHex::as_hex(&channel_keys_id[..])
					);
					return Err(());
				},
			}
		}
		info!(
			"MPC channel keys for channel keys id {}: funding {}",
			hex::DisplayHex::as_hex(&channel_keys_id[..]),
			keys[0]
		);
		Ok(ChannelPublicKeys {
			funding_pubkey: keys[0],
			revocation_basepoint: keys[1].into(),
			payment_point: keys[2],
			delayed_payment_basepoint: keys[3].into(),
			htlc_basepoint: keys[4].into(),
		})
	}

	fn per_commitment_point(&self, channel_keys_id: [u8; 32], idx: u64) -> Result<PublicKey, ()> {
		self.client.per_commitment_point(&Self::channel_id(channel_keys_id), idx).map_err(|e| {
			error!("MPC per-commitment point {idx} failed: {e}");
		})
	}

	fn release_commitment_secret(
		&self, channel_keys_id: [u8; 32], idx: u64,
	) -> Result<[u8; 32], ()> {
		self.client.release_commitment_secret(&Self::channel_id(channel_keys_id), idx).map_err(
			|e| {
				error!("MPC release of commitment secret {idx} failed: {e}");
			},
		)
	}

	fn holder_commitment_validated(
		&self, channel_keys_id: [u8; 32], commitment_number: u64,
	) -> Result<(), ()> {
		self.client
			.holder_commitment_validated(&Self::channel_id(channel_keys_id), commitment_number)
			.map_err(|e| {
				error!("MPC holder commitment validation notice failed: {e}");
			})
	}

	fn counterparty_revocation_validated(
		&self, channel_keys_id: [u8; 32], idx: u64, secret: &SecretKey,
	) -> Result<(), ()> {
		self.client
			.counterparty_revocation_validated(
				&Self::channel_id(channel_keys_id),
				idx,
				secret.secret_bytes(),
			)
			.map_err(|e| {
				error!("MPC counterparty revocation notice failed: {e}");
			})
	}

	fn sign(
		&self, channel_keys_id: [u8; 32], requests: Vec<SignRequest>,
	) -> Result<Vec<Signature>, ()> {
		let started = std::time::Instant::now();
		let ops: Vec<ChannelSignOp> = requests.iter().map(|r| r.context.op).collect();
		let mut items = Vec::with_capacity(requests.len());
		let mut expected = Vec::with_capacity(requests.len());
		for req in &requests {
			let (item, pk) = self.to_item(channel_keys_id, req)?;
			items.push(item);
			expected.push(pk);
		}
		match self.client.sign_batch(
			&self.secp,
			Some(Self::channel_id(channel_keys_id)),
			items,
			Some(&expected),
		) {
			Ok(sigs) => {
				debug!(
					"MPC signed {:?} for channel keys id {} in {:?}",
					ops,
					hex::DisplayHex::as_hex(&channel_keys_id[..]),
					started.elapsed()
				);
				Ok(sigs)
			},
			Err(e) => {
				error!("MPC signing of {ops:?} failed: {e}");
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
		let funding = MpcChannelSigner::key_id(id, KeyKind::Funding, None);
		let payment = MpcChannelSigner::key_id(id, KeyKind::Payment, None);
		let txid = Txid::from_byte_array([9u8; 32]);
		let spliced = MpcChannelSigner::key_id(id, KeyKind::SplicedFunding, Some(txid));
		assert_ne!(funding, id);
		assert_ne!(funding, payment);
		assert_ne!(funding, spliced);
		assert_ne!(MpcChannelSigner::channel_id(id), funding);
		assert_eq!(funding, MpcChannelSigner::key_id(id, KeyKind::Funding, None));
		assert_ne!(MpcChannelSigner::key_id([8u8; 32], KeyKind::Funding, None), funding);
	}
}
