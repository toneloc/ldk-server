//! Signing policy enforced by Party B (and, redundantly, by Party A).
//!
//! The policy does not trust the metadata LDK Server attaches to a request. For every
//! signature it:
//!
//! 1. recomputes the BIP 143 sighash from the supplied transaction, input, value and witness
//!    script and requires it to equal the digest;
//! 2. requires the key kind (funding / payment / delayed / HTLC / revocation) registered for the
//!    key id at DKG time to match the operation;
//! 3. verifies per-commitment derivations: additive tweaks must equal
//!    `SHA256(per_commitment_point || basepoint)` for the basepoint it holds a share of, and
//!    revocation derivations must match the revealed counterparty secret;
//! 4. enforces monotonic commitment numbers (counterparty commitments only move forward; holder
//!    commitments may only be signed for the latest validated state);
//! 5. releases a per-commitment secret only once a newer holder commitment has been validated;
//! 6. tracks our balance in every commitment it signs (located by script, not by metadata) and
//!    optionally caps how much it may drop per update;
//! 7. requires cooperative-close and sweep outputs to pay an allow-listed script (an xpub's
//!    addresses or explicit scripts) and, for closes, to carry our last tracked balance minus a
//!    bounded fee.
//!
//! State is persisted per channel under the keystore directory.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Mutex;

use bitcoin::bip32::{ChildNumber, DerivationPath, Xpub};
use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::{All, PublicKey, Scalar, Secp256k1, SecretKey};
use bitcoin::{
	sighash, Address, Amount, CompressedPublicKey, EcdsaSighashType, Network, ScriptBuf,
	Transaction,
};
use hex_conservative::DisplayHex;
use lightning::ln::chan_utils;
use lightning::ln::channel_keys::{
	DelayedPaymentBasepoint, DelayedPaymentKey, RevocationBasepoint, RevocationKey,
};
use lightning::types::features::ChannelTypeFeatures;
use lightning::util::ser::Readable;

use crate::protocol::{ChannelId, Derivation, KeyId, KeyKind, Reader, SignItem, SigningOp, Writer};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyError(pub String);

impl fmt::Display for PolicyError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "policy denied: {}", self.0)
	}
}

impl std::error::Error for PolicyError {}

fn deny<T>(msg: impl Into<String>) -> Result<T, PolicyError> {
	Err(PolicyError(msg.into()))
}

/// Dust threshold below which a missing output is acceptable.
const DUST_SAT: u64 = 1_000;

// ---------------------------------------------------------------------------
// Payout allow-list
// ---------------------------------------------------------------------------

/// Scripts that cooperative-close and sweep outputs are allowed to pay to.
#[derive(Clone, Debug, Default)]
pub struct PayoutAllowlist {
	scripts: HashSet<ScriptBuf>,
}

impl PayoutAllowlist {
	/// Adds the P2WPKH scripts of `xpub/0/i` and `xpub/1/i` for `i < lookahead` (an account-level
	/// BIP 84 xpub, as `ldk-server` writes to `onchain_wallet_xpub`).
	pub fn add_bip84_xpub(&mut self, xpub: &Xpub, lookahead: u32) -> Result<(), String> {
		let secp = Secp256k1::verification_only();
		for change in 0..2u32 {
			let branch = xpub
				.derive_pub(
					&secp,
					&DerivationPath::from(vec![ChildNumber::from_normal_idx(change).unwrap()]),
				)
				.map_err(|e| e.to_string())?;
			for i in 0..lookahead {
				let child = branch
					.derive_pub(
						&secp,
						&DerivationPath::from(vec![ChildNumber::from_normal_idx(i).unwrap()]),
					)
					.map_err(|e| e.to_string())?;
				let pk = CompressedPublicKey(child.public_key);
				self.scripts.insert(Address::p2wpkh(&pk, Network::Bitcoin).script_pubkey());
			}
		}
		Ok(())
	}

	/// Adds an explicit address (any network).
	pub fn add_address(&mut self, address: &str) -> Result<(), String> {
		let addr = Address::from_str(address).map_err(|e| e.to_string())?.assume_checked();
		self.scripts.insert(addr.script_pubkey());
		Ok(())
	}

	pub fn add_script(&mut self, script: ScriptBuf) {
		self.scripts.insert(script);
	}

	pub fn contains(&self, script: &ScriptBuf) -> bool {
		self.scripts.contains(script)
	}

	pub fn len(&self) -> usize {
		self.scripts.len()
	}

	pub fn is_empty(&self) -> bool {
		self.scripts.is_empty()
	}
}

#[derive(Clone, Debug)]
pub struct PolicyConfig {
	/// Allowed payout scripts for closes and sweeps. `None` disables the check.
	pub payout: Option<PayoutAllowlist>,
	/// Maximum drop of our balance between two consecutive signed commitments. `None` disables.
	pub max_holder_balance_decrease_sat: Option<u64>,
	/// Maximum amount a cooperative close may pay us below our last tracked balance.
	pub max_closing_fee_sat: u64,
}

impl Default for PolicyConfig {
	fn default() -> Self {
		PolicyConfig {
			payout: None,
			max_holder_balance_decrease_sat: None,
			max_closing_fee_sat: 10_000,
		}
	}
}

// ---------------------------------------------------------------------------
// Per-channel state
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChannelState {
	pub keys: HashMap<u8, KeyId>,
	pub spliced_funding_keys: Vec<KeyId>,
	/// Lowest (newest) counterparty commitment number signed.
	pub last_counterparty_commitment: Option<u64>,
	/// Lowest (newest) holder commitment number LDK reported as validated.
	pub validated_holder_commitment: Option<u64>,
	/// Our balance in the last commitment we signed, in sats.
	pub last_holder_balance_sat: Option<u64>,
	/// Highest (oldest) per-commitment secret index not yet releasable; secrets with index
	/// greater than `validated_holder_commitment` may be released.
	pub released_secrets: u64,
}

impl ChannelState {
	fn encode(&self) -> Vec<u8> {
		let mut w = Writer::new();
		w.u8(1); // version
		w.u32(self.keys.len() as u32);
		let mut keys: Vec<_> = self.keys.iter().collect();
		keys.sort();
		for (k, id) in keys {
			w.u8(*k);
			w.fixed(id);
		}
		w.u32(self.spliced_funding_keys.len() as u32);
		for id in &self.spliced_funding_keys {
			w.fixed(id);
		}
		w.opt_u64(self.last_counterparty_commitment);
		w.opt_u64(self.validated_holder_commitment);
		w.opt_u64(self.last_holder_balance_sat);
		w.u64(self.released_secrets);
		w.0
	}

	fn decode(buf: &[u8]) -> Result<Self, String> {
		let mut r = Reader::new(buf);
		let mut st = ChannelState::default();
		(|| -> Result<(), crate::protocol::DecodeError> {
			if r.u8()? != 1 {
				return Err(crate::protocol::DecodeError("unknown policy state version"));
			}
			let n = r.u32()?;
			for _ in 0..n {
				let k = r.u8()?;
				st.keys.insert(k, r.fixed32()?);
			}
			let n = r.u32()?;
			for _ in 0..n {
				st.spliced_funding_keys.push(r.fixed32()?);
			}
			st.last_counterparty_commitment = r.opt_u64()?;
			st.validated_holder_commitment = r.opt_u64()?;
			st.last_holder_balance_sat = r.opt_u64()?;
			st.released_secrets = r.u64()?;
			Ok(())
		})()
		.map_err(|e| e.to_string())?;
		Ok(st)
	}

	pub fn kind_of(&self, key_id: &KeyId) -> Option<KeyKind> {
		for (k, id) in &self.keys {
			if id == key_id {
				return KeyKind::from_u8(*k);
			}
		}
		if self.spliced_funding_keys.contains(key_id) {
			return Some(KeyKind::SplicedFunding);
		}
		None
	}

	pub fn key(&self, kind: KeyKind) -> Option<&KeyId> {
		self.keys.get(&(kind as u8))
	}
}

/// The commitment-secret seed and policy state for all channels of one party.
pub struct ChannelPolicy {
	dir: PathBuf,
	config: PolicyConfig,
	/// 32-byte master secret from which per-channel commitment seeds are derived. Only Party
	/// B has one; Party A runs the policy without it (no secret / point service).
	master_secret: Option<[u8; 32]>,
	states: Mutex<HashMap<ChannelId, ChannelState>>,
	secp: Secp256k1<All>,
}

/// Public keys the policy needs from the key store to verify a request.
pub trait KeyLookup {
	/// Aggregate public key of a stored key, if present.
	fn public_key(&self, key_id: &KeyId) -> Option<PublicKey>;
}

/// Result of a successful authorization: state to persist once the operation succeeds.
pub struct Authorized {
	channel: Option<ChannelId>,
	state: Option<ChannelState>,
}

impl ChannelPolicy {
	pub fn open(
		dir: &Path, config: PolicyConfig, master_secret: Option<[u8; 32]>,
	) -> io::Result<Self> {
		fs::create_dir_all(dir)?;
		Ok(ChannelPolicy {
			dir: dir.to_path_buf(),
			config,
			master_secret,
			states: Mutex::new(HashMap::new()),
			secp: Secp256k1::new(),
		})
	}

	pub fn config(&self) -> &PolicyConfig {
		&self.config
	}

	pub fn has_seed(&self) -> bool {
		self.master_secret.is_some()
	}

	fn state_path(&self, channel: &ChannelId) -> PathBuf {
		self.dir.join(format!("{}.policy", channel.as_hex()))
	}

	fn load(&self, channel: &ChannelId) -> io::Result<ChannelState> {
		if let Some(s) = self.states.lock().unwrap().get(channel) {
			return Ok(s.clone());
		}
		let st = match fs::read(self.state_path(channel)) {
			Ok(bytes) => ChannelState::decode(&bytes)
				.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
			Err(e) if e.kind() == io::ErrorKind::NotFound => ChannelState::default(),
			Err(e) => return Err(e),
		};
		self.states.lock().unwrap().insert(*channel, st.clone());
		Ok(st)
	}

	fn store(&self, channel: &ChannelId, st: ChannelState) -> io::Result<()> {
		let path = self.state_path(channel);
		let tmp = self.dir.join(format!("{}.policy.tmp", channel.as_hex()));
		fs::write(&tmp, st.encode())?;
		fs::rename(&tmp, &path)?;
		self.states.lock().unwrap().insert(*channel, st);
		Ok(())
	}

	pub fn channel_state(&self, channel: &ChannelId) -> io::Result<ChannelState> {
		self.load(channel)
	}

	/// Records that `key_id` is channel `channel`'s key of kind `kind`. Refuses to rebind a kind
	/// to a different key.
	pub fn register_key(
		&self, channel: &ChannelId, kind: KeyKind, key_id: &KeyId,
	) -> Result<(), PolicyError> {
		let mut st = self.load(channel).map_err(|e| PolicyError(e.to_string()))?;
		match kind {
			KeyKind::SplicedFunding => {
				if !st.spliced_funding_keys.contains(key_id) {
					st.spliced_funding_keys.push(*key_id);
				}
			},
			KeyKind::Standalone => return deny("standalone keys cannot be bound to a channel"),
			_ => match st.keys.get(&(kind as u8)) {
				Some(existing) if existing != key_id => {
					return deny(format!("channel already has a {:?} key", kind));
				},
				Some(_) => return Ok(()),
				None => {
					st.keys.insert(kind as u8, *key_id);
				},
			},
		}
		self.store(channel, st).map_err(|e| PolicyError(e.to_string()))
	}

	// -----------------------------------------------------------------------
	// Commitment seed (Party B)
	// -----------------------------------------------------------------------

	fn commitment_seed(&self, channel: &ChannelId) -> Result<[u8; 32], PolicyError> {
		let master = self
			.master_secret
			.ok_or_else(|| PolicyError("this party holds no commitment seed".into()))?;
		let mut engine = sha256::Hash::engine();
		engine.input(b"ldk-server-mpc/commitment-seed/v1");
		engine.input(&master);
		engine.input(channel);
		Ok(sha256::Hash::from_engine(engine).to_byte_array())
	}

	fn per_commitment_secret(
		&self, channel: &ChannelId, idx: u64,
	) -> Result<SecretKey, PolicyError> {
		let seed = self.commitment_seed(channel)?;
		let secret = chan_utils::build_commitment_secret(&seed, idx);
		SecretKey::from_slice(&secret).map_err(|e| PolicyError(e.to_string()))
	}

	pub fn per_commitment_point(
		&self, channel: &ChannelId, idx: u64,
	) -> Result<PublicKey, PolicyError> {
		Ok(PublicKey::from_secret_key(&self.secp, &self.per_commitment_secret(channel, idx)?))
	}

	/// Releases the secret for `idx` only if a newer holder commitment has been validated.
	pub fn release_commitment_secret(
		&self, channel: &ChannelId, idx: u64,
	) -> Result<[u8; 32], PolicyError> {
		let mut st = self.load(channel).map_err(|e| PolicyError(e.to_string()))?;
		match st.validated_holder_commitment {
			Some(validated) if idx > validated => {},
			Some(validated) => {
				return deny(format!(
					"refusing to release secret {idx}: latest validated holder commitment is {validated}"
				))
			},
			None => {
				return deny(format!(
					"refusing to release secret {idx}: no holder commitment validated yet"
				))
			},
		}
		let secret = self.per_commitment_secret(channel, idx)?;
		st.released_secrets += 1;
		self.store(channel, st).map_err(|e| PolicyError(e.to_string()))?;
		Ok(secret.secret_bytes())
	}

	pub fn holder_commitment_validated(
		&self, channel: &ChannelId, number: u64,
	) -> Result<(), PolicyError> {
		let mut st = self.load(channel).map_err(|e| PolicyError(e.to_string()))?;
		if let Some(v) = st.validated_holder_commitment {
			if number > v {
				return deny(format!("holder commitment {number} is older than validated {v}"));
			}
		}
		st.validated_holder_commitment = Some(number);
		self.store(channel, st).map_err(|e| PolicyError(e.to_string()))
	}

	pub fn counterparty_revocation_validated(
		&self, _channel: &ChannelId, _idx: u64, _secret: &[u8; 32],
	) -> Result<(), PolicyError> {
		// Nothing to enforce yet; recorded for future HTLC accounting.
		Ok(())
	}

	// -----------------------------------------------------------------------
	// Signing authorization
	// -----------------------------------------------------------------------

	/// Verifies `item` against the policy. `keys` resolves key ids to aggregate public keys.
	/// On success the returned [`Authorized`] must be committed with [`Self::commit`] once the
	/// signature was produced (or before, to be conservative).
	pub fn authorize(
		&self, channel: Option<&ChannelId>, item: &SignItem, keys: &dyn KeyLookup,
	) -> Result<Authorized, PolicyError> {
		let ctx = &item.context;
		let op = ctx.op.unwrap_or(SigningOp::Unknown);
		let base_pubkey =
			keys.public_key(&item.key_id).ok_or_else(|| PolicyError("unknown key".into()))?;

		// Standalone keys (tests/benchmarks) are not channel-bound: only the digest is signed.
		let Some(channel) = channel else {
			if op != SigningOp::Test && op != SigningOp::Unknown {
				return deny("channel operation without a channel");
			}
			if item.derivation != Derivation::None {
				return deny("derivation requires a channel");
			}
			return Ok(Authorized { channel: None, state: None });
		};
		let mut st = self.load(channel).map_err(|e| PolicyError(e.to_string()))?;

		// 2. Key kind matches the operation.
		let kind = st
			.kind_of(&item.key_id)
			.ok_or_else(|| PolicyError("key is not bound to this channel".into()))?;
		let expected = op
			.expected_key_kind()
			.ok_or_else(|| PolicyError(format!("unsupported operation {op:?}")))?;
		let kind_ok =
			kind == expected || (expected == KeyKind::Funding && kind == KeyKind::SplicedFunding);
		if !kind_ok {
			return deny(format!("operation {op:?} requires a {expected:?} key, got {kind:?}"));
		}
		if ctx.channel_keys_id.is_none() {
			return deny("missing channel keys id");
		}

		// 3. Derivation matches the per-commitment point / revealed secret.
		self.check_derivation(kind, &item.derivation, &base_pubkey, item)?;

		// 1. Digest matches the recomputed sighash (announcements carry no transaction).
		let tx = match (&ctx.transaction, op) {
			(None, SigningOp::ChannelAnnouncement) => None,
			(None, _) => return deny("missing transaction"),
			(Some(bytes), _) => {
				let tx: Transaction =
					deserialize(bytes).map_err(|e| PolicyError(format!("bad transaction: {e}")))?;
				self.check_sighash(&tx, item)?;
				Some(tx)
			},
		};

		// 4–7. Operation-specific checks.
		match op {
			SigningOp::CounterpartyCommitment | SigningOp::CounterpartyCommitmentHtlc => {
				let number = ctx
					.commitment_number
					.ok_or_else(|| PolicyError("missing commitment number".into()))?;
				if let Some(last) = st.last_counterparty_commitment {
					if number > last {
						return deny(format!(
							"counterparty commitment {number} is older than last signed {last}"
						));
					}
				}
				if op == SigningOp::CounterpartyCommitment {
					let tx = tx.as_ref().unwrap();
					if let Some(balance) =
						self.holder_balance_in_counterparty_commitment(&st, keys, tx, item)?
					{
						self.check_balance_decrease(&st, balance)?;
						st.last_holder_balance_sat = Some(balance);
					}
					st.last_counterparty_commitment = Some(number);
				}
			},
			SigningOp::HolderCommitment => {
				let number = ctx
					.commitment_number
					.ok_or_else(|| PolicyError("missing commitment number".into()))?;
				if let Some(v) = st.validated_holder_commitment {
					if number > v {
						return deny(format!(
							"holder commitment {number} is older than validated {v}"
						));
					}
				}
				let tx = tx.as_ref().unwrap();
				if let Some(balance) =
					self.holder_balance_in_holder_commitment(channel, &st, keys, tx, item, number)?
				{
					self.check_balance_decrease(&st, balance)?;
					st.last_holder_balance_sat = Some(balance);
				}
			},
			SigningOp::ClosingTransaction => {
				let tx = tx.as_ref().unwrap();
				self.check_closing(&st, tx, ctx.holder_balance_sat)?;
			},
			SigningOp::SweepStaticPayment | SigningOp::SweepDelayedPayment => {
				let tx = tx.as_ref().unwrap();
				self.check_sweep_outputs(tx)?;
			},
			SigningOp::HolderKeyedAnchorInput
			| SigningOp::SpliceSharedInput
			| SigningOp::ChannelAnnouncement
			| SigningOp::JusticeRevokedOutput
			| SigningOp::JusticeRevokedHtlc
			| SigningOp::HolderHtlcTransaction
			| SigningOp::CounterpartyHtlcTransaction => {},
			SigningOp::Test | SigningOp::Unknown => return deny("unsupported operation"),
		}

		Ok(Authorized { channel: Some(*channel), state: Some(st) })
	}

	/// Persists the state changes of a successful authorization.
	pub fn commit(&self, auth: Authorized) -> Result<(), PolicyError> {
		if let (Some(channel), Some(st)) = (auth.channel, auth.state) {
			self.store(&channel, st).map_err(|e| PolicyError(e.to_string()))?;
		}
		Ok(())
	}

	fn check_sighash(&self, tx: &Transaction, item: &SignItem) -> Result<(), PolicyError> {
		let ctx = &item.context;
		let script = ctx
			.witness_script
			.as_ref()
			.ok_or_else(|| PolicyError("missing witness script".into()))?;
		let ty = match ctx.sighash_type {
			0x01 => EcdsaSighashType::All,
			0x83 => EcdsaSighashType::SinglePlusAnyoneCanPay,
			other => return deny(format!("unsupported sighash type 0x{other:02x}")),
		};
		let idx = ctx.input_index as usize;
		if idx >= tx.input.len() {
			return deny("input index out of range");
		}
		let sighash = sighash::SighashCache::new(tx)
			.p2wsh_signature_hash(
				idx,
				&ScriptBuf::from_bytes(script.clone()),
				Amount::from_sat(ctx.input_value_sat),
				ty,
			)
			.map_err(|e| PolicyError(format!("sighash: {e}")))?;
		if sighash.to_byte_array() != item.digest {
			return deny("digest does not match the transaction sighash");
		}
		Ok(())
	}

	fn check_derivation(
		&self, kind: KeyKind, derivation: &Derivation, base: &PublicKey, item: &SignItem,
	) -> Result<(), PolicyError> {
		let ctx = &item.context;
		match (kind, derivation) {
			(KeyKind::Funding | KeyKind::SplicedFunding | KeyKind::Payment, Derivation::None) => {
				Ok(())
			},
			(KeyKind::DelayedPayment | KeyKind::Htlc, Derivation::Additive { tweak }) => {
				let pcp = ctx
					.per_commitment_point
					.ok_or_else(|| PolicyError("missing per-commitment point".into()))?;
				let expected = bolt3_tweak(&pcp, &base.serialize());
				if *tweak != expected {
					return deny(
						"additive tweak does not match SHA256(per_commitment_point || basepoint)",
					);
				}
				Ok(())
			},
			(KeyKind::Revocation, Derivation::MulAdd { mul, add }) => {
				let secret = ctx.counterparty_per_commitment_secret.ok_or_else(|| {
					PolicyError("missing counterparty per-commitment secret".into())
				})?;
				let secret =
					SecretKey::from_slice(&secret).map_err(|e| PolicyError(e.to_string()))?;
				let pcp = PublicKey::from_secret_key(&self.secp, &secret);
				if let Some(claimed) = ctx.per_commitment_point {
					if claimed != pcp.serialize() {
						return deny("per-commitment point does not match the revealed secret");
					}
				}
				let (exp_mul, exp_add) = revocation_tweaks(&self.secp, base, &secret);
				if *mul != exp_mul || *add != exp_add {
					return deny("revocation derivation does not match BOLT 3");
				}
				Ok(())
			},
			_ => deny(format!("derivation {derivation:?} not allowed for {kind:?} key")),
		}
	}

	fn features(ctx: &crate::protocol::SigningContext) -> Result<ChannelTypeFeatures, PolicyError> {
		let bytes = ctx
			.channel_type_features
			.as_ref()
			.ok_or_else(|| PolicyError("missing channel type".into()))?;
		let mut cursor = io::Cursor::new(bytes);
		ChannelTypeFeatures::read(&mut cursor)
			.map_err(|_| PolicyError("bad channel type features".into()))
	}

	/// Our `to_remote` balance in a counterparty commitment, located by our payment point's
	/// script. `None` if this channel's payment key is not held here (funding-only coverage).
	fn holder_balance_in_counterparty_commitment(
		&self, st: &ChannelState, keys: &dyn KeyLookup, tx: &Transaction, item: &SignItem,
	) -> Result<Option<u64>, PolicyError> {
		let Some(payment_key) = st.key(KeyKind::Payment) else { return Ok(None) };
		let payment_point = keys
			.public_key(payment_key)
			.ok_or_else(|| PolicyError("payment key missing".into()))?;
		let features = Self::features(&item.context)?;
		let script = chan_utils::get_countersigner_payment_script(&features, &payment_point);
		Ok(Some(
			tx.output.iter().filter(|o| o.script_pubkey == script).map(|o| o.value.to_sat()).sum(),
		))
	}

	/// Our `to_local` balance in a holder commitment, located by the revokeable script built from
	/// our delayed-payment key and the counterparty's revocation basepoint.
	fn holder_balance_in_holder_commitment(
		&self, channel: &ChannelId, st: &ChannelState, keys: &dyn KeyLookup, tx: &Transaction,
		item: &SignItem, number: u64,
	) -> Result<Option<u64>, PolicyError> {
		let Some(delayed_key) = st.key(KeyKind::DelayedPayment) else { return Ok(None) };
		let ctx = &item.context;
		let delayed_base = keys
			.public_key(delayed_key)
			.ok_or_else(|| PolicyError("delayed key missing".into()))?;
		let pcp_claimed = ctx
			.per_commitment_point
			.ok_or_else(|| PolicyError("missing per-commitment point".into()))?;
		let pcp = PublicKey::from_slice(&pcp_claimed).map_err(|e| PolicyError(e.to_string()))?;
		if self.has_seed() && self.per_commitment_point(channel, number)? != pcp {
			return deny("per-commitment point does not match our seed for this commitment number");
		}
		let cp = ctx
			.counterparty_keys
			.as_ref()
			.ok_or_else(|| PolicyError("missing counterparty keys".into()))?;
		let cp_rev = PublicKey::from_slice(&cp.revocation_basepoint)
			.map_err(|e| PolicyError(e.to_string()))?;
		let delay = ctx
			.counterparty_selected_contest_delay
			.ok_or_else(|| PolicyError("missing contest delay".into()))?;
		let revocation_key =
			RevocationKey::from_basepoint(&self.secp, &RevocationBasepoint(cp_rev), &pcp);
		let delayed_pubkey = DelayedPaymentKey::from_basepoint(
			&self.secp,
			&DelayedPaymentBasepoint(delayed_base),
			&pcp,
		);
		let script =
			chan_utils::get_revokeable_redeemscript(&revocation_key, delay, &delayed_pubkey)
				.to_p2wsh();
		Ok(Some(
			tx.output.iter().filter(|o| o.script_pubkey == script).map(|o| o.value.to_sat()).sum(),
		))
	}

	fn check_balance_decrease(
		&self, st: &ChannelState, new_balance: u64,
	) -> Result<(), PolicyError> {
		if let (Some(max), Some(last)) =
			(self.config.max_holder_balance_decrease_sat, st.last_holder_balance_sat)
		{
			if new_balance + max < last {
				return deny(format!("holder balance would drop from {last} to {new_balance} sat (max decrease {max})"));
			}
		}
		Ok(())
	}

	fn check_closing(
		&self, st: &ChannelState, tx: &Transaction, claimed: Option<u64>,
	) -> Result<(), PolicyError> {
		let Some(allow) = &self.config.payout else { return Ok(()) };
		let expected = st.last_holder_balance_sat.or(claimed).unwrap_or(0);
		if expected <= DUST_SAT {
			return Ok(());
		}
		let min = expected.saturating_sub(self.config.max_closing_fee_sat);
		let ok =
			tx.output.iter().any(|o| allow.contains(&o.script_pubkey) && o.value.to_sat() >= min);
		if !ok {
			return deny(format!(
				"closing transaction does not pay at least {min} sat to an allow-listed script"
			));
		}
		Ok(())
	}

	fn check_sweep_outputs(&self, tx: &Transaction) -> Result<(), PolicyError> {
		let Some(allow) = &self.config.payout else { return Ok(()) };
		if tx.output.iter().any(|o| !allow.contains(&o.script_pubkey)) {
			return deny("sweep transaction pays a non-allow-listed script");
		}
		Ok(())
	}
}

/// `SHA256(per_commitment_point || basepoint)` as a 32-byte scalar (BOLT 3).
pub fn bolt3_tweak(per_commitment_point: &[u8; 33], basepoint: &[u8; 33]) -> [u8; 32] {
	let mut engine = sha256::Hash::engine();
	engine.input(per_commitment_point);
	engine.input(basepoint);
	sha256::Hash::from_engine(engine).to_byte_array()
}

/// The `(mul, add)` tweaks turning our revocation basepoint into the revocation key for a
/// counterparty commitment whose per-commitment secret was revealed (BOLT 3):
/// `key = basepoint * SHA256(basepoint || pcp) + secret * SHA256(pcp || basepoint)`.
pub fn revocation_tweaks(
	secp: &Secp256k1<All>, basepoint: &PublicKey, per_commitment_secret: &SecretKey,
) -> ([u8; 32], [u8; 32]) {
	let pcp = PublicKey::from_secret_key(secp, per_commitment_secret);
	let mut e = sha256::Hash::engine();
	e.input(&basepoint.serialize());
	e.input(&pcp.serialize());
	let mul = sha256::Hash::from_engine(e).to_byte_array();
	let mut e = sha256::Hash::engine();
	e.input(&pcp.serialize());
	e.input(&basepoint.serialize());
	let h2 = sha256::Hash::from_engine(e).to_byte_array();
	let add = per_commitment_secret
		.mul_tweak(&Scalar::from_be_bytes(h2).expect("hash < n"))
		.expect("non-zero")
		.secret_bytes();
	(mul, add)
}
