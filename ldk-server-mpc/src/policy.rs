//! Signing and secret-release policy, enforced by every party from its own record.
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
//! 5. treats a holder commitment as validated only after checking the counterparty's signature
//!    on it itself, against a funding script and counterparty keys it pinned when it first
//!    signed for the channel, and checking that the transaction encodes the claimed commitment
//!    number (the host's word is not enough);
//! 6. contributes to releasing a per-commitment secret only once a newer holder commitment has
//!    been validated, and only for the channel's own kit (see [`crate::kit`]); no party holds the
//!    secrets or their seed;
//! 7. tracks our balance in every commitment it signs (located by script, not by metadata) and
//!    optionally caps how much it may drop per update;
//! 8. requires cooperative-close and sweep outputs to pay an allow-listed script (an xpub's
//!    addresses or explicit scripts) and, for closes, to carry our last tracked balance minus a
//!    bounded fee;
//! 9. follows a channel to a new funding output only through a splice transaction it saw being
//!    signed (or that carries the parties' own signature), and refuses the splice's first
//!    commitment if it leaves us with less than the counterparty last signed for, other than
//!    what the splice pays to allow-listed scripts and a bounded fee.
//!
//! State is persisted per channel under the keystore directory.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use bitcoin::bip32::{ChildNumber, DerivationPath, Xpub};
use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{All, Message, PublicKey, Scalar, Secp256k1, SecretKey};
use bitcoin::{
	sighash, Address, Amount, CompressedPublicKey, EcdsaSighashType, Network, ScriptBuf,
	Transaction, TxOut,
};
use hex_conservative::DisplayHex;
use lightning::ln::chan_utils;
use lightning::ln::channel_keys::{
	DelayedPaymentBasepoint, DelayedPaymentKey, RevocationBasepoint, RevocationKey,
};
use lightning::types::features::ChannelTypeFeatures;
use lightning::util::ser::Readable;

use crate::kit::{KitId, KitRecord, KitStore};
use crate::protocol::{
	ChannelId, CounterpartyKeys, Derivation, HolderProof, KeyId, KeyKind, Reader, SignItem,
	SigningOp, SpliceProof, Writer,
};

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

/// Dust threshold below which a missing output is acceptable. Also the slack allowed when two
/// commitments of the same state are compared (rounding, and fees that differ with the dust
/// limits of the two sides).
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
	/// Our balance in the last commitment we signed, in sats, and that commitment's number.
	pub last_holder_balance_sat: Option<u64>,
	pub last_holder_balance_commitment: Option<u64>,
	/// Highest (oldest) per-commitment secret index not yet releasable; secrets with index
	/// greater than `validated_holder_commitment` may be released.
	pub released_secrets: u64,
	/// The kit holding this channel's encrypted per-commitment secrets. Set once.
	pub kit_id: Option<KitId>,
	/// Funding outputs (2-of-2 witness script and value) this party has signed counterparty
	/// commitments for. A holder commitment counts as validated only with the counterparty's
	/// signature under one of them.
	pub fundings: Vec<Funding>,
	/// The counterparty's basepoints and the delay on our own outputs, pinned the first time
	/// this party signed a counterparty commitment. They never change during a channel's life
	/// (only the funding key does, on a splice).
	pub counterparty_keys: Option<CounterpartyKeys>,
	pub counterparty_selected_contest_delay: Option<u16>,
	/// Splice transactions this party saw signed (or was shown the parties' signature on).
	/// A new funding output is accepted only if one of them creates it.
	pub splices: Vec<Splice>,
}

/// A funding output of a channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Funding {
	pub witness_script: Vec<u8>,
	pub value_sat: u64,
	/// Our balance in the last commitment seen for this funding. While a splice is pending
	/// there are commitments for both fundings, with different balances.
	pub balance_sat: Option<u64>,
	/// Our balance in the newest holder commitment for this funding that carried the
	/// counterparty's signature. Unlike the balances taken from transactions LDK Server asks
	/// us to sign, the host cannot make this one up. It is what a splice of this funding must
	/// preserve.
	pub validated_balance_sat: Option<u64>,
	/// For a funding created by a splice: the least our balance may be in commitments with
	/// the commitment number the splice was signed at.
	pub floor: Option<SpliceFloor>,
}

impl Funding {
	fn new(witness_script: Vec<u8>, value_sat: u64) -> Self {
		Funding {
			witness_script,
			value_sat,
			balance_sat: None,
			validated_balance_sat: None,
			floor: None,
		}
	}

	fn is(&self, witness_script: &[u8], value_sat: u64) -> bool {
		self.witness_script == witness_script && self.value_sat == value_sat
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpliceFloor {
	pub commitment_number: u64,
	pub min_balance_sat: u64,
}

/// A splice transaction of this channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Splice {
	pub txid: [u8; 32],
	/// Consensus-serialized, without witnesses.
	pub transaction: Vec<u8>,
	/// The input spending the funding output the splice replaces.
	pub input_index: u32,
	/// The parties' signature on that input, once known. With it another party can be shown
	/// that a quorum agreed to this splice.
	pub signature: Option<[u8; 64]>,
	/// The newest counterparty commitment number when the splice was signed, and the least our
	/// balance may be in the new funding's commitments with that number. `None` where this
	/// party could not tell (it learned of the splice from the signature, or does not hold the
	/// keys that locate our balance).
	pub commitment_number: u64,
	pub min_balance_sat: Option<u64>,
}

/// How many funding outputs to remember per channel (the original plus splices).
const MAX_FUNDINGS: usize = 16;

/// How many splice transactions to remember per channel (a splice and its fee bumps).
const MAX_SPLICES: usize = 8;

/// The two keys of a `2 <key> <key> 2 OP_CHECKMULTISIG` funding script.
fn funding_script_keys(script: &[u8]) -> Option<(PublicKey, PublicKey)> {
	if script.len() != 71
		|| script[0] != 0x52
		|| script[1] != 0x21
		|| script[35] != 0x21
		|| script[69] != 0x52
		|| script[70] != 0xae
	{
		return None;
	}
	Some((
		PublicKey::from_slice(&script[2..35]).ok()?,
		PublicKey::from_slice(&script[36..69]).ok()?,
	))
}

/// Whether two sets of counterparty keys agree on everything but the funding key.
fn same_basepoints(a: &CounterpartyKeys, b: &CounterpartyKeys) -> bool {
	a.revocation_basepoint == b.revocation_basepoint
		&& a.payment_point == b.payment_point
		&& a.delayed_payment_basepoint == b.delayed_payment_basepoint
		&& a.htlc_basepoint == b.htlc_basepoint
}

impl ChannelState {
	fn encode(&self) -> Vec<u8> {
		let mut w = Writer::new();
		w.u8(4); // version
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
		w.opt_u64(self.last_holder_balance_commitment);
		w.u64(self.released_secrets);
		w.opt_fixed32(self.kit_id.as_ref());
		w.u32(self.fundings.len() as u32);
		for f in &self.fundings {
			w.bytes(&f.witness_script);
			w.u64(f.value_sat);
			w.opt_u64(f.balance_sat);
			w.opt_u64(f.validated_balance_sat);
			w.opt_u64(f.floor.map(|f| f.commitment_number));
			w.opt_u64(f.floor.map(|f| f.min_balance_sat));
		}
		match &self.counterparty_keys {
			Some(k) => {
				w.u8(1);
				w.fixed(&k.funding_pubkey);
				w.fixed(&k.revocation_basepoint);
				w.fixed(&k.payment_point);
				w.fixed(&k.delayed_payment_basepoint);
				w.fixed(&k.htlc_basepoint);
			},
			None => w.u8(0),
		}
		w.opt_u16(self.counterparty_selected_contest_delay);
		w.u32(self.splices.len() as u32);
		for splice in &self.splices {
			w.fixed(&splice.txid);
			w.bytes(&splice.transaction);
			w.u32(splice.input_index);
			match &splice.signature {
				Some(sig) => {
					w.u8(1);
					w.fixed(sig);
				},
				None => w.u8(0),
			}
			w.u64(splice.commitment_number);
			w.opt_u64(splice.min_balance_sat);
		}
		w.0
	}

	fn decode(buf: &[u8]) -> Result<Self, String> {
		let mut r = Reader::new(buf);
		let mut st = ChannelState::default();
		(|| -> Result<(), crate::protocol::DecodeError> {
			let version = r.u8()?;
			if !(1..=4).contains(&version) {
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
			st.last_holder_balance_commitment = r.opt_u64()?;
			st.released_secrets = r.u64()?;
			if version >= 2 {
				st.kit_id = r.opt_fixed32()?;
			}
			if version >= 3 {
				let n = r.u32()?;
				for _ in 0..n {
					let mut funding = Funding::new(r.bytes()?, r.u64()?);
					if version >= 4 {
						funding.balance_sat = r.opt_u64()?;
						funding.validated_balance_sat = r.opt_u64()?;
						funding.floor = match (r.opt_u64()?, r.opt_u64()?) {
							(Some(commitment_number), Some(min_balance_sat)) => {
								Some(SpliceFloor { commitment_number, min_balance_sat })
							},
							_ => None,
						};
					}
					st.fundings.push(funding);
				}
				if r.u8()? == 1 {
					st.counterparty_keys = Some(CounterpartyKeys {
						funding_pubkey: r.fixed33()?,
						revocation_basepoint: r.fixed33()?,
						payment_point: r.fixed33()?,
						delayed_payment_basepoint: r.fixed33()?,
						htlc_basepoint: r.fixed33()?,
					});
				}
				st.counterparty_selected_contest_delay = r.opt_u16()?;
			}
			if version >= 4 {
				let n = r.u32()?;
				for _ in 0..n {
					let txid = r.fixed32()?;
					let transaction = r.bytes()?;
					let input_index = r.u32()?;
					let signature = if r.u8()? == 1 {
						let mut sig = [0u8; 64];
						sig[..32].copy_from_slice(&r.fixed32()?);
						sig[32..].copy_from_slice(&r.fixed32()?);
						Some(sig)
					} else {
						None
					};
					st.splices.push(Splice {
						txid,
						transaction,
						input_index,
						signature,
						commitment_number: r.u64()?,
						min_balance_sat: r.opt_u64()?,
					});
				}
			}
			Ok(())
		})()
		.map_err(|e| e.to_string())?;
		Ok(st)
	}

	/// Merges `newer` into `self`, keeping the most advanced value of every monotonic field.
	/// Used so that concurrent authorizations (e.g. the HTLC signatures of one commitment)
	/// cannot lose each other's updates.
	fn merge(&mut self, newer: &ChannelState) {
		for (k, id) in &newer.keys {
			self.keys.entry(*k).or_insert(*id);
		}
		for id in &newer.spliced_funding_keys {
			if !self.spliced_funding_keys.contains(id) {
				self.spliced_funding_keys.push(*id);
			}
		}
		self.last_counterparty_commitment =
			min_opt(self.last_counterparty_commitment, newer.last_counterparty_commitment);
		self.validated_holder_commitment =
			min_opt(self.validated_holder_commitment, newer.validated_holder_commitment);
		match (self.last_holder_balance_commitment, newer.last_holder_balance_commitment) {
			(Some(mine), Some(theirs)) if theirs > mine => {},
			(_, Some(_)) => {
				self.last_holder_balance_sat = newer.last_holder_balance_sat;
				self.last_holder_balance_commitment = newer.last_holder_balance_commitment;
			},
			(None, None) if newer.last_holder_balance_sat.is_some() => {
				self.last_holder_balance_sat = newer.last_holder_balance_sat;
			},
			_ => {},
		}
		self.released_secrets = self.released_secrets.max(newer.released_secrets);
		if self.kit_id.is_none() {
			self.kit_id = newer.kit_id;
		}
		// Balances of known fundings are not merged here: `newer` may be a copy that predates
		// the latest one. Whoever changed a balance applies it itself (see `Authorized`).
		for f in &newer.fundings {
			self.pin_funding(f.clone());
		}
		for splice in &newer.splices {
			self.add_splice(splice.clone());
		}
		if self.counterparty_keys.is_none() {
			self.counterparty_keys = newer.counterparty_keys.clone();
		}
		if self.counterparty_selected_contest_delay.is_none() {
			self.counterparty_selected_contest_delay = newer.counterparty_selected_contest_delay;
		}
	}

	/// Remembers `funding` unless it is known already. Returns its position.
	fn pin_funding(&mut self, funding: Funding) -> usize {
		if let Some(i) = self.funding_position(&funding.witness_script, funding.value_sat) {
			return i;
		}
		if self.fundings.len() == MAX_FUNDINGS {
			self.fundings.remove(0);
		}
		self.fundings.push(funding);
		self.fundings.len() - 1
	}

	fn funding_position(&self, witness_script: &[u8], value_sat: u64) -> Option<usize> {
		self.fundings.iter().position(|f| f.is(witness_script, value_sat))
	}

	/// Remembers `splice`, or completes what is known of it with the signature.
	fn add_splice(&mut self, splice: Splice) {
		match self.splices.iter_mut().find(|s| s.txid == splice.txid) {
			Some(known) => {
				if known.signature.is_none() {
					known.signature = splice.signature;
				}
			},
			None => {
				if self.splices.len() == MAX_SPLICES {
					self.splices.remove(0);
				}
				self.splices.push(splice);
			},
		}
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

fn min_opt(a: Option<u64>, b: Option<u64>) -> Option<u64> {
	match (a, b) {
		(Some(a), Some(b)) => Some(a.min(b)),
		(a, None) => a,
		(None, b) => b,
	}
}

/// The policy state for all channels of one party.
pub struct ChannelPolicy {
	dir: PathBuf,
	config: PolicyConfig,
	/// This party's channel kits: per-commitment points and encrypted secrets. Without kits the
	/// party serves no points and takes no part in releasing secrets.
	kits: Option<Arc<KitStore>>,
	states: Mutex<HashMap<ChannelId, ChannelState>>,
	locks: Mutex<HashMap<ChannelId, Arc<Mutex<()>>>>,
	tmp_counter: AtomicU64,
	secp: Secp256k1<All>,
}

/// Public keys the policy needs from the key store to verify a request.
pub trait KeyLookup {
	/// Aggregate public key of a stored key, if present.
	fn public_key(&self, key_id: &KeyId) -> Option<PublicKey>;
}

/// Result of a successful authorization: state to persist once the operation succeeds.
#[derive(Debug)]
pub struct Authorized {
	channel: Option<ChannelId>,
	state: Option<ChannelState>,
	/// The funding (witness script and value) whose balance this authorization moved, and
	/// the new balance.
	balance: Option<(Vec<u8>, u64, u64)>,
}

impl ChannelPolicy {
	pub fn open(dir: &Path, config: PolicyConfig, kits: Option<Arc<KitStore>>) -> io::Result<Self> {
		fs::create_dir_all(dir)?;
		Ok(ChannelPolicy {
			dir: dir.to_path_buf(),
			config,
			kits,
			states: Mutex::new(HashMap::new()),
			locks: Mutex::new(HashMap::new()),
			tmp_counter: AtomicU64::new(0),
			secp: Secp256k1::new(),
		})
	}

	fn lock(&self, channel: &ChannelId) -> Arc<Mutex<()>> {
		let mut locks = self.locks.lock().unwrap();
		Arc::clone(locks.entry(*channel).or_insert_with(|| Arc::new(Mutex::new(()))))
	}

	pub fn config(&self) -> &PolicyConfig {
		&self.config
	}

	pub fn has_kits(&self) -> bool {
		self.kits.is_some()
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
		let n = self.tmp_counter.fetch_add(1, Ordering::Relaxed);
		let tmp =
			self.dir.join(format!("{}.policy.{}.{}.tmp", channel.as_hex(), std::process::id(), n));
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
		let lock = self.lock(channel);
		let _guard = lock.lock().unwrap();
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
	// Per-commitment points and secret release (channel kits)
	// -----------------------------------------------------------------------

	fn kits(&self) -> Result<&KitStore, PolicyError> {
		self.kits.as_deref().ok_or_else(|| PolicyError("this party has no channel kits".into()))
	}

	/// Records `kit_id` as the kit of `channel`. A channel keeps its kit for life and a kit
	/// serves one channel, so neither side of the binding can be changed afterwards.
	pub fn bind_kit(&self, channel: &ChannelId, kit_id: &KitId) -> Result<(), PolicyError> {
		let lock = self.lock(channel);
		let _guard = lock.lock().unwrap();
		let mut st = self.load(channel).map_err(|e| PolicyError(e.to_string()))?;
		match st.kit_id {
			Some(existing) if &existing == kit_id => return Ok(()),
			Some(_) => return deny("channel already has a different kit"),
			None => {},
		}
		self.kits()?
			.bind(kit_id, channel)
			.map_err(|e| PolicyError(format!("cannot bind kit: {e}")))?;
		st.kit_id = Some(*kit_id);
		self.store(channel, st).map_err(|e| PolicyError(e.to_string()))
	}

	/// The kit bound to `channel`, if any.
	pub fn kit_of(&self, channel: &ChannelId) -> Result<Option<KitId>, PolicyError> {
		Ok(self.load(channel).map_err(|e| PolicyError(e.to_string()))?.kit_id)
	}

	/// The kit entry for commitment `idx` of `channel`. Reading it authorizes nothing.
	pub fn kit_entry(
		&self, channel: &ChannelId, idx: u64,
	) -> Result<(KitId, KitRecord), PolicyError> {
		let kit_id =
			self.kit_of(channel)?.ok_or_else(|| PolicyError("channel has no kit bound".into()))?;
		let record = self
			.kits()?
			.record(&kit_id, idx)
			.map_err(|e| PolicyError(format!("kit read failed: {e}")))?
			.ok_or_else(|| {
				PolicyError(format!(
					"kit has no entry for commitment {idx}: run the refill ceremony"
				))
			})?;
		Ok((kit_id, record))
	}

	pub fn per_commitment_point(
		&self, channel: &ChannelId, idx: u64,
	) -> Result<PublicKey, PolicyError> {
		Ok(self.kit_entry(channel, idx)?.1.point)
	}

	/// Allows this party's contribution to releasing the secret for `idx`, which is given only
	/// if a newer holder commitment has been validated. Returns the kit entry to decrypt.
	///
	/// Together with the rule that holder commitments are only signed for the latest validated
	/// state, this keeps a released state from ever being signed for broadcast, and a state
	/// that may still be broadcast from ever being revoked.
	pub fn authorize_release(
		&self, channel: &ChannelId, idx: u64,
	) -> Result<(KitId, KitRecord), PolicyError> {
		let lock = self.lock(channel);
		let _guard = lock.lock().unwrap();
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
		let entry = self.kit_entry(channel, idx)?;
		st.released_secrets += 1;
		self.store(channel, st).map_err(|e| PolicyError(e.to_string()))?;
		Ok(entry)
	}

	/// Records holder commitment `number` as validated, which makes older states releasable.
	///
	/// The first commitment of a channel is accepted as is: nothing can be released on its
	/// strength. Every later one needs `proof`, the commitment transaction with the
	/// counterparty's signature, which is checked here against what this party pinned when it
	/// signed for the channel. A host that only claims a commitment was validated gets nowhere.
	pub fn holder_commitment_validated(
		&self, channel: &ChannelId, number: u64, proof: Option<&HolderProof>, keys: &dyn KeyLookup,
	) -> Result<(), PolicyError> {
		let lock = self.lock(channel);
		let _guard = lock.lock().unwrap();
		let mut st = self.load(channel).map_err(|e| PolicyError(e.to_string()))?;
		if let Some(v) = st.validated_holder_commitment {
			if number > v {
				return deny(format!("holder commitment {number} is older than validated {v}"));
			}
		}
		// The first commitment arrives before this party has signed anything for an inbound
		// channel, so there may be nothing to check it against yet.
		let first = number == crate::kit::INITIAL_COMMITMENT_NUMBER;
		if !first || (proof.is_some() && !st.fundings.is_empty()) {
			let proof = proof.ok_or_else(|| {
				PolicyError(format!(
					"holder commitment {number} needs the counterparty's signature"
				))
			})?;
			let (tx, funding) = self.verify_holder_proof(&st, keys, number, proof)?;
			if let Some(balance) =
				self.holder_balance_in_validated_commitment(channel, &st, keys, &tx, number)?
			{
				self.check_balance_decrease(st.fundings[funding].balance_sat, balance)?;
				st.fundings[funding].balance_sat = Some(balance);
				st.fundings[funding].validated_balance_sat = Some(balance);
				st.last_holder_balance_sat = Some(balance);
				st.last_holder_balance_commitment = Some(number);
			}
		}
		st.validated_holder_commitment = Some(number);
		self.store(channel, st).map_err(|e| PolicyError(e.to_string()))
	}

	/// Checks that `proof` is holder commitment `number` of this channel, signed by the
	/// counterparty: its funding input must verify under a pinned funding script that contains
	/// one of our funding keys, and its locktime and sequence must encode `number`.
	fn verify_holder_proof(
		&self, st: &ChannelState, keys: &dyn KeyLookup, number: u64, proof: &HolderProof,
	) -> Result<(Transaction, usize), PolicyError> {
		let tx: Transaction = deserialize(&proof.transaction)
			.map_err(|e| PolicyError(format!("bad holder commitment transaction: {e}")))?;
		if tx.input.len() != 1 {
			return deny("a commitment transaction has exactly one input");
		}
		let sig = Signature::from_compact(&proof.counterparty_sig)
			.map_err(|e| PolicyError(format!("bad counterparty signature: {e}")))?;
		let ours = Self::our_funding_keys(st, keys);
		let signed = st.fundings.iter().position(|funding| {
			let Some((a, b)) = funding_script_keys(&funding.witness_script) else { return false };
			let theirs = match (ours.contains(&a), ours.contains(&b)) {
				(true, false) => b,
				(false, true) => a,
				_ => return false,
			};
			sighash::SighashCache::new(&tx)
				.p2wsh_signature_hash(
					0,
					&ScriptBuf::from_bytes(funding.witness_script.clone()),
					Amount::from_sat(funding.value_sat),
					EcdsaSighashType::All,
				)
				.map(|h| {
					let msg = Message::from_digest(h.to_byte_array());
					self.secp.verify_ecdsa(&msg, &sig, &theirs).is_ok()
				})
				.unwrap_or(false)
		});
		let Some(funding) = signed else {
			return deny("holder commitment is not signed by the counterparty for a known funding");
		};

		// BOLT 3 hides the commitment number in the locktime and sequence, XORed with a value
		// derived from both payment basepoints. Check it against both possible channel openers.
		let cp = st
			.counterparty_keys
			.as_ref()
			.ok_or_else(|| PolicyError("counterparty keys are not pinned yet".into()))?;
		let cp_payment =
			PublicKey::from_slice(&cp.payment_point).map_err(|e| PolicyError(e.to_string()))?;
		let our_payment = st
			.key(KeyKind::Payment)
			.and_then(|id| keys.public_key(id))
			.ok_or_else(|| PolicyError("payment key missing".into()))?;
		let obscured = ((tx.input[0].sequence.0 as u64 & 0xff_ffff) << 24)
			| (tx.lock_time.to_consensus_u32() as u64 & 0xff_ffff);
		let matches = [true, false].iter().any(|outbound| {
			let factor = chan_utils::get_commitment_transaction_number_obscure_factor(
				&our_payment,
				&cp_payment,
				*outbound,
			);
			obscured ^ factor == crate::kit::INITIAL_COMMITMENT_NUMBER - number
		});
		if !matches {
			return deny(format!("transaction is not holder commitment {number}"));
		}
		Ok((tx, funding))
	}

	/// Our `to_local` balance in a validated holder commitment, from pinned parameters.
	fn holder_balance_in_validated_commitment(
		&self, channel: &ChannelId, st: &ChannelState, keys: &dyn KeyLookup, tx: &Transaction,
		number: u64,
	) -> Result<Option<u64>, PolicyError> {
		let (Some(delayed_key), Some(cp), Some(delay)) = (
			st.key(KeyKind::DelayedPayment),
			st.counterparty_keys.as_ref(),
			st.counterparty_selected_contest_delay,
		) else {
			return Ok(None);
		};
		if !self.has_kits() {
			return Ok(None);
		}
		let delayed_base = keys
			.public_key(delayed_key)
			.ok_or_else(|| PolicyError("delayed key missing".into()))?;
		let pcp = self.per_commitment_point(channel, number)?;
		let cp_rev = PublicKey::from_slice(&cp.revocation_basepoint)
			.map_err(|e| PolicyError(e.to_string()))?;
		Ok(Some(self.to_local_value(tx, &cp_rev, delay, &delayed_base, &pcp)))
	}

	fn to_local_value(
		&self, tx: &Transaction, cp_revocation_basepoint: &PublicKey, delay: u16,
		delayed_basepoint: &PublicKey, pcp: &PublicKey,
	) -> u64 {
		let revocation_key = RevocationKey::from_basepoint(
			&self.secp,
			&RevocationBasepoint(*cp_revocation_basepoint),
			pcp,
		);
		let delayed_pubkey = DelayedPaymentKey::from_basepoint(
			&self.secp,
			&DelayedPaymentBasepoint(*delayed_basepoint),
			pcp,
		);
		let script =
			chan_utils::get_revokeable_redeemscript(&revocation_key, delay, &delayed_pubkey)
				.to_p2wsh();
		tx.output.iter().filter(|o| o.script_pubkey == script).map(|o| o.value.to_sat()).sum()
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
			return Ok(Authorized { channel: None, state: None, balance: None });
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

		// 4–9. Operation-specific checks.
		let mut balance_moved = None;
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
					let funding = self.pin_channel_parameters(&mut st, &base_pubkey, item, tx)?;
					if let Some(balance) =
						self.holder_balance_in_counterparty_commitment(&st, keys, tx, item)?
					{
						Self::check_splice_floor(&st.fundings[funding], number, balance)?;
						self.check_balance_decrease(st.fundings[funding].balance_sat, balance)?;
						balance_moved = Some(Self::set_balance(&mut st, funding, balance));
						st.last_holder_balance_sat = Some(balance);
						st.last_holder_balance_commitment = Some(number);
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
				let funding = Self::spent_funding(&st, ctx)?;
				let tx = tx.as_ref().unwrap();
				if let Some(balance) =
					self.holder_balance_in_holder_commitment(channel, &st, keys, tx, item, number)?
				{
					let last = match funding {
						Some(funding) => st.fundings[funding].balance_sat,
						None => st.last_holder_balance_sat,
					};
					self.check_balance_decrease(last, balance)?;
					if let Some(funding) = funding {
						balance_moved = Some(Self::set_balance(&mut st, funding, balance));
					}
					st.last_holder_balance_sat = Some(balance);
					st.last_holder_balance_commitment = Some(number);
				}
			},
			SigningOp::ClosingTransaction => {
				let funding = Self::spent_funding(&st, ctx)?;
				let tx = tx.as_ref().unwrap();
				let tracked = funding
					.and_then(|funding| st.fundings[funding].balance_sat)
					.or(st.last_holder_balance_sat);
				self.check_closing(tracked, tx, ctx.holder_balance_sat)?;
			},
			SigningOp::SweepStaticPayment | SigningOp::SweepDelayedPayment => {
				let tx = tx.as_ref().unwrap();
				self.check_sweep_outputs(tx)?;
			},
			SigningOp::SpliceSharedInput => {
				let tx = tx.as_ref().unwrap();
				self.check_splice(&mut st, tx, ctx)?;
			},
			SigningOp::HolderKeyedAnchorInput
			| SigningOp::ChannelAnnouncement
			| SigningOp::JusticeRevokedOutput
			| SigningOp::JusticeRevokedHtlc
			| SigningOp::HolderHtlcTransaction
			| SigningOp::CounterpartyHtlcTransaction => {},
			SigningOp::Test | SigningOp::Unknown => return deny("unsupported operation"),
		}

		Ok(Authorized { channel: Some(*channel), state: Some(st), balance: balance_moved })
	}

	fn set_balance(st: &mut ChannelState, funding: usize, balance: u64) -> (Vec<u8>, u64, u64) {
		let funding = &mut st.fundings[funding];
		funding.balance_sat = Some(balance);
		(funding.witness_script.clone(), funding.value_sat, balance)
	}

	/// The funding output a commitment, closing or splice transaction spends, which must be
	/// one this party knows. `None` only for a channel with no funding recorded yet (state
	/// written by an earlier version).
	fn spent_funding(
		st: &ChannelState, ctx: &crate::protocol::SigningContext,
	) -> Result<Option<usize>, PolicyError> {
		if st.fundings.is_empty() {
			return Ok(None);
		}
		let script = ctx
			.witness_script
			.as_ref()
			.ok_or_else(|| PolicyError("missing witness script".into()))?;
		match st.funding_position(script, ctx.input_value_sat) {
			Some(funding) => Ok(Some(funding)),
			None => deny("transaction does not spend a funding output of this channel"),
		}
	}

	// -----------------------------------------------------------------------
	// Splices
	// -----------------------------------------------------------------------

	/// Checks a splice transaction before our signature on the funding output it spends, and
	/// remembers it: its outputs are the only new funding outputs this party will follow the
	/// channel to.
	///
	/// What the splice does to our balance is not visible here. The transaction does not say
	/// which of its outputs and other inputs are ours and which the counterparty's, and the
	/// new funding script is not known yet. So this records the least our balance may be
	/// afterwards, and the check itself happens when the first commitment for the new funding
	/// is signed ([`Self::check_splice_floor`]). The counterparty does not sign the splice
	/// before it has that commitment signature, so refusing it there stops the splice.
	fn check_splice(
		&self, st: &mut ChannelState, tx: &Transaction, ctx: &crate::protocol::SigningContext,
	) -> Result<(), PolicyError> {
		let Some(spent) = Self::spent_funding(st, ctx)? else {
			return deny("no funding output recorded for this channel yet");
		};
		let spent = &st.fundings[spent];
		if !tx.output.iter().any(|o| o.script_pubkey.is_p2wsh()) {
			return deny("splice transaction has no output that could fund the channel");
		}
		// Without the keys that locate our balance in a commitment (funding-only coverage)
		// there is nothing to compare.
		let tracks_balance =
			st.key(KeyKind::Payment).is_some() && st.key(KeyKind::DelayedPayment).is_some();
		let min_balance_sat = if tracks_balance {
			let before = spent.validated_balance_sat.ok_or_else(|| {
				PolicyError(
					"cannot splice yet: no commitment with the counterparty's signature seen"
						.into(),
				)
			})?;
			let outputs: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
			let paid_out: u64 = match &self.config.payout {
				Some(allow) => tx
					.output
					.iter()
					.filter(|o| allow.contains(&o.script_pubkey))
					.map(|o| o.value.to_sat())
					.sum(),
				None => 0,
			};
			// What the funding output loses to the miners. With no other inputs this is the
			// whole fee; with other inputs it is the least the fee can be, and whoever added
			// them pays the rest.
			let fee = spent.value_sat.saturating_sub(outputs);
			Some(before.saturating_sub(paid_out).saturating_sub(fee).saturating_sub(DUST_SAT))
		} else {
			None
		};
		let mut unsigned = tx.clone();
		for input in &mut unsigned.input {
			input.witness.clear();
		}
		st.add_splice(Splice {
			txid: tx.compute_txid().to_byte_array(),
			transaction: bitcoin::consensus::encode::serialize(&unsigned),
			input_index: ctx.input_index,
			signature: None,
			commitment_number: st
				.last_counterparty_commitment
				.unwrap_or(crate::kit::INITIAL_COMMITMENT_NUMBER),
			min_balance_sat,
		});
		Ok(())
	}

	/// The splice's first commitment must leave us at least what [`Self::check_splice`] worked
	/// out. Later commitments are ordinary channel updates.
	fn check_splice_floor(funding: &Funding, number: u64, balance: u64) -> Result<(), PolicyError> {
		match funding.floor {
			Some(floor) if number >= floor.commitment_number && balance < floor.min_balance_sat => {
				deny(format!(
					"splice would leave us {balance} sat, less than the {} sat it must: it pays \
					 our balance to a script that is not allow-listed (or a fee out of proportion)",
					floor.min_balance_sat
				))
			},
			_ => Ok(()),
		}
	}

	/// Records the parties' signature on a splice transaction this party authorized, so it can
	/// later show other parties that the splice was agreed.
	pub fn splice_signed(
		&self, channel: &ChannelId, item: &SignItem, signature: &Signature,
	) -> Result<(), PolicyError> {
		let Some(bytes) = &item.context.transaction else { return Ok(()) };
		let tx: Transaction =
			deserialize(bytes).map_err(|e| PolicyError(format!("bad transaction: {e}")))?;
		let txid = tx.compute_txid().to_byte_array();
		let lock = self.lock(channel);
		let _guard = lock.lock().unwrap();
		let mut st = self.load(channel).map_err(|e| PolicyError(e.to_string()))?;
		match st.splices.iter_mut().find(|s| s.txid == txid) {
			Some(splice) if splice.signature.is_none() => {
				splice.signature = Some(signature.serialize_compact());
			},
			_ => return Ok(()),
		}
		self.store(channel, st).map_err(|e| PolicyError(e.to_string()))
	}

	/// The proof to send along with a commitment for a funding output created by a splice.
	pub fn splice_proof_for(&self, channel: &ChannelId, item: &SignItem) -> Option<SpliceProof> {
		if item.context.op != Some(SigningOp::CounterpartyCommitment) {
			return None;
		}
		let tx: Transaction = deserialize(item.context.transaction.as_ref()?).ok()?;
		let parent = tx.input.first()?.previous_output.txid.to_byte_array();
		let st = self.load(channel).ok()?;
		let splice = st.splices.iter().find(|s| s.txid == parent)?;
		Some(SpliceProof {
			transaction: splice.transaction.clone(),
			input_index: splice.input_index,
			signature: splice.signature?,
		})
	}

	/// Takes note of a splice this party did not see being signed (it was down, or outside the
	/// quorum and the notice got lost). The proof is the splice transaction with the parties'
	/// own signature on the funding output it spends: that signature exists only if a quorum
	/// agreed to the splice, each party by its own policy.
	pub fn learn_splice(
		&self, channel: &ChannelId, proof: &SpliceProof, keys: &dyn KeyLookup,
	) -> Result<(), PolicyError> {
		let tx: Transaction = deserialize(&proof.transaction)
			.map_err(|e| PolicyError(format!("bad splice transaction: {e}")))?;
		let txid = tx.compute_txid().to_byte_array();
		let lock = self.lock(channel);
		let _guard = lock.lock().unwrap();
		let mut st = self.load(channel).map_err(|e| PolicyError(e.to_string()))?;
		if st.splices.iter().any(|s| s.txid == txid && s.signature.is_some()) {
			return Ok(());
		}
		let sig = Signature::from_compact(&proof.signature)
			.map_err(|e| PolicyError(format!("bad splice signature: {e}")))?;
		let ours = Self::our_funding_keys(&st, keys);
		let signed = st.fundings.iter().any(|funding| {
			let Some((a, b)) = funding_script_keys(&funding.witness_script) else { return false };
			let key = match (ours.contains(&a), ours.contains(&b)) {
				(true, false) => a,
				(false, true) => b,
				_ => return false,
			};
			sighash::SighashCache::new(&tx)
				.p2wsh_signature_hash(
					proof.input_index as usize,
					&ScriptBuf::from_bytes(funding.witness_script.clone()),
					Amount::from_sat(funding.value_sat),
					EcdsaSighashType::All,
				)
				.map(|h| {
					let msg = Message::from_digest(h.to_byte_array());
					self.secp.verify_ecdsa(&msg, &sig, &key).is_ok()
				})
				.unwrap_or(false)
		});
		if !signed {
			return deny("splice transaction is not signed by the parties for a known funding");
		}
		let commitment_number =
			st.last_counterparty_commitment.unwrap_or(crate::kit::INITIAL_COMMITMENT_NUMBER);
		st.add_splice(Splice {
			txid,
			transaction: proof.transaction.clone(),
			input_index: proof.input_index,
			signature: Some(proof.signature),
			commitment_number,
			min_balance_sat: None,
		});
		self.store(channel, st).map_err(|e| PolicyError(e.to_string()))
	}

	fn our_funding_keys(st: &ChannelState, keys: &dyn KeyLookup) -> Vec<PublicKey> {
		st.key(KeyKind::Funding)
			.into_iter()
			.chain(st.spliced_funding_keys.iter())
			.filter_map(|id| keys.public_key(id))
			.collect()
	}

	/// Pins what a counterparty commitment signature tells us about the channel: the funding
	/// script and value it spends, the counterparty's basepoints and the delay on our outputs.
	/// The first signature for a channel sets them; later ones must agree on the basepoints,
	/// and may only move to a funding output that a known splice transaction creates. Returns
	/// the position of the funding the commitment spends.
	fn pin_channel_parameters(
		&self, st: &mut ChannelState, our_funding_key: &PublicKey, item: &SignItem,
		tx: &Transaction,
	) -> Result<usize, PolicyError> {
		let ctx = &item.context;
		let script = ctx
			.witness_script
			.as_ref()
			.ok_or_else(|| PolicyError("missing witness script".into()))?;
		match funding_script_keys(script) {
			Some((a, b)) if (&a == our_funding_key) != (&b == our_funding_key) => {},
			_ => return deny("funding script is not a 2-of-2 with our funding key"),
		}
		if let Some(cp) = &ctx.counterparty_keys {
			match &st.counterparty_keys {
				Some(pinned) if !same_basepoints(pinned, cp) => {
					return deny(
						"counterparty basepoints differ from the ones pinned for this channel",
					);
				},
				Some(_) => {},
				None => st.counterparty_keys = Some(cp.clone()),
			}
		}
		if let Some(delay) = ctx.counterparty_selected_contest_delay {
			match st.counterparty_selected_contest_delay {
				Some(pinned) if pinned != delay => {
					return deny("contest delay differs from the one pinned for this channel");
				},
				Some(_) => {},
				None => st.counterparty_selected_contest_delay = Some(delay),
			}
		}
		if let Some(funding) = st.funding_position(script, ctx.input_value_sat) {
			return Ok(funding);
		}
		let mut funding = Funding::new(script.clone(), ctx.input_value_sat);
		if !st.fundings.is_empty() {
			// Not the channel's first funding: a splice must have created it.
			let spent = match tx.input.as_slice() {
				[input] => input.previous_output,
				_ => return deny("a commitment transaction has exactly one input"),
			};
			let output = TxOut {
				value: Amount::from_sat(ctx.input_value_sat),
				script_pubkey: ScriptBuf::from_bytes(script.clone()).to_p2wsh(),
			};
			let splice = st
				.splices
				.iter()
				.find(|splice| {
					splice.txid == spent.txid.to_byte_array()
						&& deserialize::<Transaction>(&splice.transaction)
							.map(|tx| tx.output.get(spent.vout as usize) == Some(&output))
							.unwrap_or(false)
				})
				.ok_or_else(|| {
					PolicyError(
						"commitment spends a funding output this party has seen no splice into"
							.into(),
					)
				})?;
			funding.floor = splice.min_balance_sat.map(|min_balance_sat| SpliceFloor {
				commitment_number: splice.commitment_number,
				min_balance_sat,
			});
		}
		Ok(st.pin_funding(funding))
	}

	/// Persists the state changes of a successful authorization.
	pub fn commit(&self, auth: Authorized) -> Result<(), PolicyError> {
		if let (Some(channel), Some(st)) = (auth.channel, auth.state) {
			let lock = self.lock(&channel);
			let _guard = lock.lock().unwrap();
			let mut current = self.load(&channel).map_err(|e| PolicyError(e.to_string()))?;
			current.merge(&st);
			if let Some((script, value, balance)) = auth.balance {
				if let Some(funding) = current.funding_position(&script, value) {
					current.fundings[funding].balance_sat = Some(balance);
				}
			}
			self.store(&channel, current).map_err(|e| PolicyError(e.to_string()))?;
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
		if self.has_kits() && self.per_commitment_point(channel, number)? != pcp {
			return deny("per-commitment point does not match our kit for this commitment number");
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
		Ok(Some(self.to_local_value(tx, &cp_rev, delay, &delayed_base, &pcp)))
	}

	fn check_balance_decrease(
		&self, last_balance: Option<u64>, new_balance: u64,
	) -> Result<(), PolicyError> {
		if let (Some(max), Some(last)) = (self.config.max_holder_balance_decrease_sat, last_balance)
		{
			if new_balance + max < last {
				return deny(format!("holder balance would drop from {last} to {new_balance} sat (max decrease {max})"));
			}
		}
		Ok(())
	}

	fn check_closing(
		&self, tracked: Option<u64>, tx: &Transaction, claimed: Option<u64>,
	) -> Result<(), PolicyError> {
		let Some(allow) = &self.config.payout else { return Ok(()) };
		let expected = tracked.or(claimed).unwrap_or(0);
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

#[cfg(test)]
mod tests {
	use std::collections::HashMap;

	use bitcoin::absolute::LockTime;
	use bitcoin::consensus::encode::serialize;
	use bitcoin::hashes::Hash as _;
	use bitcoin::secp256k1::rand::{thread_rng, RngCore};
	use bitcoin::transaction::Version;
	use bitcoin::{OutPoint, Sequence, TxIn, TxOut, Txid, Witness};
	use lightning::util::ser::Writeable;

	use super::*;
	use crate::kit::INITIAL_COMMITMENT_NUMBER as START;
	use crate::protocol::SigningContext;

	struct Keys {
		secrets: HashMap<KeyId, SecretKey>,
		pubkeys: HashMap<KeyId, PublicKey>,
	}

	impl Keys {
		fn new() -> Self {
			Keys { secrets: HashMap::new(), pubkeys: HashMap::new() }
		}
		fn add(&mut self, id: u8) -> KeyId {
			let secp = Secp256k1::new();
			let mut sk = [0u8; 32];
			thread_rng().fill_bytes(&mut sk);
			let sk = SecretKey::from_slice(&sk).unwrap();
			let key_id = [id; 32];
			self.pubkeys.insert(key_id, PublicKey::from_secret_key(&secp, &sk));
			self.secrets.insert(key_id, sk);
			key_id
		}
	}

	impl KeyLookup for Keys {
		fn public_key(&self, key_id: &KeyId) -> Option<PublicKey> {
			self.pubkeys.get(key_id).copied()
		}
	}

	struct Fixture {
		policy: ChannelPolicy,
		keys: Keys,
		channel: ChannelId,
		funding: KeyId,
		payment: KeyId,
		delayed: KeyId,
		htlc: KeyId,
		revocation: KeyId,
		cp_rev: SecretKey,
		cp_funding: SecretKey,
		_dir: PathBuf,
	}

	const KIT: KitId = [0x4bu8; 32];

	fn fixture(config: PolicyConfig) -> Fixture {
		let mut dir = std::env::temp_dir();
		let nanos =
			std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
		dir.push(format!("ldk-mpc-policy-test-{nanos}"));
		let (kits, _, _) = crate::kit::test_util::store_with_kit(&KIT, 3);
		let policy = ChannelPolicy::open(&dir, config, Some(Arc::new(kits))).unwrap();
		let mut keys = Keys::new();
		let channel = [0xccu8; 32];
		policy.bind_kit(&channel, &KIT).unwrap();
		let funding = keys.add(1);
		let payment = keys.add(2);
		let delayed = keys.add(3);
		let htlc = keys.add(4);
		let revocation = keys.add(5);
		policy.register_key(&channel, KeyKind::Funding, &funding).unwrap();
		policy.register_key(&channel, KeyKind::Payment, &payment).unwrap();
		policy.register_key(&channel, KeyKind::DelayedPayment, &delayed).unwrap();
		policy.register_key(&channel, KeyKind::Htlc, &htlc).unwrap();
		policy.register_key(&channel, KeyKind::Revocation, &revocation).unwrap();
		let cp_rev = SecretKey::from_slice(&[0x77u8; 32]).unwrap();
		Fixture {
			policy,
			keys,
			channel,
			funding,
			payment,
			delayed,
			htlc,
			revocation,
			cp_rev,
			cp_funding: SecretKey::from_slice(&[0x66u8; 32]).unwrap(),
			_dir: dir,
		}
	}

	fn features() -> ChannelTypeFeatures {
		ChannelTypeFeatures::only_static_remote_key()
	}

	fn tx_with_outputs(outputs: Vec<TxOut>) -> Transaction {
		Transaction {
			version: Version::TWO,
			lock_time: LockTime::ZERO,
			input: vec![TxIn {
				previous_output: OutPoint { txid: Txid::all_zeros(), vout: 0 },
				script_sig: ScriptBuf::new(),
				sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
				witness: Witness::new(),
			}],
			output: outputs,
		}
	}

	fn digest(tx: &Transaction, script: &ScriptBuf, value: u64, ty: EcdsaSighashType) -> [u8; 32] {
		sighash::SighashCache::new(tx)
			.p2wsh_signature_hash(0, script, Amount::from_sat(value), ty)
			.unwrap()
			.to_byte_array()
	}

	fn counterparty_keys(f: &Fixture) -> CounterpartyKeys {
		let secp = Secp256k1::new();
		let cp_rev_pk = PublicKey::from_secret_key(&secp, &f.cp_rev);
		CounterpartyKeys {
			funding_pubkey: cp_funding_pk(f).serialize(),
			revocation_basepoint: cp_rev_pk.serialize(),
			payment_point: cp_payment_pk().serialize(),
			delayed_payment_basepoint: [3u8; 33],
			htlc_basepoint: [2u8; 33],
		}
	}

	fn base_context(
		f: &Fixture, op: SigningOp, tx: &Transaction, script: &ScriptBuf, value: u64,
	) -> SigningContext {
		SigningContext {
			op: Some(op),
			channel_keys_id: Some([1u8; 32]),
			channel_value_satoshis: Some(100_000),
			commitment_number: None,
			funding_txid: None,
			funding_vout: None,
			splice_parent_funding_txid: None,
			channel_type_features: Some(features().encode()),
			counterparty_keys: Some(counterparty_keys(f)),
			holder_selected_contest_delay: Some(144),
			counterparty_selected_contest_delay: Some(144),
			transaction: Some(serialize(tx)),
			input_index: 0,
			input_value_sat: value,
			witness_script: Some(script.to_bytes()),
			sighash_type: 0x01,
			per_commitment_point: None,
			counterparty_per_commitment_secret: None,
			holder_balance_sat: None,
		}
	}

	/// A counterparty commitment paying `ours` sats to our payment point.
	fn cp_funding_pk(f: &Fixture) -> PublicKey {
		PublicKey::from_secret_key(&Secp256k1::new(), &f.cp_funding)
	}

	fn cp_payment_pk() -> PublicKey {
		PublicKey::from_secret_key(
			&Secp256k1::new(),
			&SecretKey::from_slice(&[0x55u8; 32]).unwrap(),
		)
	}

	fn funding_script(f: &Fixture) -> ScriptBuf {
		chan_utils::make_funding_redeemscript(
			&f.keys.public_key(&f.funding).unwrap(),
			&cp_funding_pk(f),
		)
	}

	/// Our holder commitment `number` with `ours` sats to us, signed by `signer` as the
	/// counterparty's funding key.
	fn holder_proof(f: &Fixture, number: u64, ours: u64, signer: &SecretKey) -> HolderProof {
		let secp = Secp256k1::new();
		let factor = chan_utils::get_commitment_transaction_number_obscure_factor(
			&f.keys.public_key(&f.payment).unwrap(),
			&cp_payment_pk(),
			true,
		);
		let obscured = factor ^ (START - number);
		let pcp = f.policy.per_commitment_point(&f.channel, number).unwrap();
		let cp_rev = PublicKey::from_secret_key(&secp, &f.cp_rev);
		let revocation_key =
			RevocationKey::from_basepoint(&secp, &RevocationBasepoint(cp_rev), &pcp);
		let delayed = DelayedPaymentKey::from_basepoint(
			&secp,
			&DelayedPaymentBasepoint(f.keys.public_key(&f.delayed).unwrap()),
			&pcp,
		);
		let to_local =
			chan_utils::get_revokeable_redeemscript(&revocation_key, 144, &delayed).to_p2wsh();
		let mut tx =
			tx_with_outputs(vec![TxOut { value: Amount::from_sat(ours), script_pubkey: to_local }]);
		tx.input[0].sequence = Sequence((0x80 << 24) | (obscured >> 24) as u32);
		tx.lock_time = LockTime::from_consensus((0x20 << 24) | (obscured & 0xff_ffff) as u32);
		let msg =
			Message::from_digest(digest(&tx, &funding_script(f), 100_000, EcdsaSighashType::All));
		HolderProof {
			transaction: serialize(&tx),
			counterparty_sig: secp.sign_ecdsa(&msg, signer).serialize_compact(),
		}
	}

	/// Signs a counterparty commitment (which pins the channel) and validates holder
	/// commitment `number` with a genuine proof.
	fn validate(f: &Fixture, number: u64) -> Result<(), PolicyError> {
		let item = counterparty_commitment(f, 100, 60_000);
		f.policy.commit(f.policy.authorize(Some(&f.channel), &item, &f.keys)?)?;
		let proof = holder_proof(f, number, 60_000, &f.cp_funding);
		f.policy.holder_commitment_validated(&f.channel, number, Some(&proof), &f.keys)
	}

	fn counterparty_commitment(f: &Fixture, number: u64, ours: u64) -> SignItem {
		let payment_point = f.keys.public_key(&f.payment).unwrap();
		let script = chan_utils::get_countersigner_payment_script(&features(), &payment_point);
		let tx = tx_with_outputs(vec![
			TxOut { value: Amount::from_sat(ours), script_pubkey: script },
			TxOut {
				value: Amount::from_sat(100_000 - ours - 1_000),
				script_pubkey: ScriptBuf::new_op_return([1u8]),
			},
		]);
		let redeem = funding_script(f);
		let mut ctx = base_context(f, SigningOp::CounterpartyCommitment, &tx, &redeem, 100_000);
		ctx.commitment_number = Some(number);
		ctx.per_commitment_point = Some([2u8; 33]);
		SignItem {
			key_id: f.funding,
			derivation: Derivation::None,
			digest: digest(&tx, &redeem, 100_000, EcdsaSighashType::All),
			context: ctx,
			splice: None,
		}
	}

	#[test]
	fn standalone_keys_only_sign_test_ops() {
		let f = fixture(PolicyConfig::default());
		let item = SignItem {
			key_id: f.funding,
			derivation: Derivation::None,
			digest: [1u8; 32],
			context: SigningContext { op: Some(SigningOp::Test), ..Default::default() },
			splice: None,
		};
		assert!(f.policy.authorize(None, &item, &f.keys).is_ok());
		let bad = SignItem {
			context: SigningContext {
				op: Some(SigningOp::ClosingTransaction),
				..Default::default()
			},
			..item
		};
		assert!(f.policy.authorize(None, &bad, &f.keys).is_err());
	}

	#[test]
	fn digest_must_match_sighash() {
		let f = fixture(PolicyConfig::default());
		let mut item = counterparty_commitment(&f, 100, 60_000);
		assert!(f.policy.authorize(Some(&f.channel), &item, &f.keys).is_ok());
		item.digest[0] ^= 1;
		let err = f.policy.authorize(Some(&f.channel), &item, &f.keys).unwrap_err();
		assert!(err.0.contains("sighash"), "{err}");
		// A different input value changes the sighash too.
		let mut item = counterparty_commitment(&f, 100, 60_000);
		item.context.input_value_sat = 99_999;
		assert!(f.policy.authorize(Some(&f.channel), &item, &f.keys).is_err());
	}

	#[test]
	fn key_kind_must_match_operation() {
		let f = fixture(PolicyConfig::default());
		let mut item = counterparty_commitment(&f, 100, 60_000);
		item.key_id = f.payment;
		let err = f.policy.authorize(Some(&f.channel), &item, &f.keys).unwrap_err();
		assert!(err.0.contains("requires a Funding key"), "{err}");
		// Keys of another channel are rejected.
		let other = [0xddu8; 32];
		let err = f
			.policy
			.authorize(Some(&other), &counterparty_commitment(&f, 100, 60_000), &f.keys)
			.unwrap_err();
		assert!(err.0.contains("not bound"), "{err}");
		// A kind cannot be rebound to a different key.
		assert!(f.policy.register_key(&f.channel, KeyKind::Funding, &f.htlc).is_err());
	}

	#[test]
	fn commitment_numbers_are_monotonic_and_balance_tracked() {
		let f = fixture(PolicyConfig {
			max_holder_balance_decrease_sat: Some(10_000),
			..Default::default()
		});
		let sign = |number: u64, ours: u64| {
			let item = counterparty_commitment(&f, number, ours);
			f.policy
				.authorize(Some(&f.channel), &item, &f.keys)
				.map(|a| f.policy.commit(a).unwrap())
		};
		sign(100, 60_000).unwrap();
		assert_eq!(
			f.policy.channel_state(&f.channel).unwrap().last_holder_balance_sat,
			Some(60_000)
		);
		sign(100, 60_000).unwrap(); // re-signing the same state is allowed
		assert!(sign(101, 60_000).unwrap_err().0.contains("older"));
		sign(99, 55_000).unwrap(); // within the 10k cap
		let err = sign(98, 40_000).unwrap_err(); // 15k drop exceeds the cap
		assert!(err.0.contains("drop"), "{err}");
		assert_eq!(
			f.policy.channel_state(&f.channel).unwrap().last_holder_balance_sat,
			Some(55_000)
		);
		sign(98, 70_000).unwrap(); // increases are fine
	}

	#[test]
	fn htlc_derivation_must_match_bolt3() {
		let f = fixture(PolicyConfig::default());
		let base = f.keys.public_key(&f.htlc).unwrap();
		let pcp = PublicKey::from_secret_key(
			&Secp256k1::new(),
			&SecretKey::from_slice(&[9u8; 32]).unwrap(),
		);
		let tx = tx_with_outputs(vec![TxOut {
			value: Amount::from_sat(900),
			script_pubkey: ScriptBuf::new_op_return([1u8]),
		}]);
		let script = ScriptBuf::from_bytes(vec![0x63; 10]);
		let mut ctx = base_context(&f, SigningOp::HolderHtlcTransaction, &tx, &script, 1_000);
		ctx.per_commitment_point = Some(pcp.serialize());
		let tweak = bolt3_tweak(&pcp.serialize(), &base.serialize());
		let item = SignItem {
			key_id: f.htlc,
			derivation: Derivation::Additive { tweak },
			digest: digest(&tx, &script, 1_000, EcdsaSighashType::All),
			context: ctx,
			splice: None,
		};
		assert!(f.policy.authorize(Some(&f.channel), &item, &f.keys).is_ok());
		let mut wrong = tweak;
		wrong[5] ^= 0xff;
		let bad = SignItem { derivation: Derivation::Additive { tweak: wrong }, ..item.clone() };
		assert!(f
			.policy
			.authorize(Some(&f.channel), &bad, &f.keys)
			.unwrap_err()
			.0
			.contains("tweak"));
		// An HTLC key cannot be used untweaked, and a funding key cannot be tweaked.
		let bad = SignItem { derivation: Derivation::None, ..item.clone() };
		assert!(f.policy.authorize(Some(&f.channel), &bad, &f.keys).is_err());
		let _ = f.delayed;
	}

	#[test]
	fn revocation_derivation_must_match_revealed_secret() {
		let f = fixture(PolicyConfig::default());
		let secp = Secp256k1::new();
		let base = f.keys.public_key(&f.revocation).unwrap();
		let cp_secret = SecretKey::from_slice(&[0x33u8; 32]).unwrap();
		let (mul, add) = revocation_tweaks(&secp, &base, &cp_secret);
		let tx = tx_with_outputs(vec![TxOut {
			value: Amount::from_sat(900),
			script_pubkey: ScriptBuf::new_op_return([1u8]),
		}]);
		let script = ScriptBuf::from_bytes(vec![0x63; 10]);
		let mut ctx = base_context(&f, SigningOp::JusticeRevokedOutput, &tx, &script, 1_000);
		ctx.counterparty_per_commitment_secret = Some(cp_secret.secret_bytes());
		ctx.per_commitment_point = Some(PublicKey::from_secret_key(&secp, &cp_secret).serialize());
		let item = SignItem {
			key_id: f.revocation,
			derivation: Derivation::MulAdd { mul, add },
			digest: digest(&tx, &script, 1_000, EcdsaSighashType::All),
			context: ctx,
			splice: None,
		};
		assert!(f.policy.authorize(Some(&f.channel), &item, &f.keys).is_ok());
		let mut bad_add = add;
		bad_add[0] ^= 1;
		let bad = SignItem { derivation: Derivation::MulAdd { mul, add: bad_add }, ..item.clone() };
		assert!(f.policy.authorize(Some(&f.channel), &bad, &f.keys).is_err());
		let mut ctx = item.context.clone();
		ctx.counterparty_per_commitment_secret = Some([0x34u8; 32]);
		let bad = SignItem { context: ctx, ..item };
		assert!(f.policy.authorize(Some(&f.channel), &bad, &f.keys).is_err());
	}

	#[test]
	fn secrets_release_only_after_newer_holder_commitment_validated() {
		let f = fixture(PolicyConfig::default());
		let start = 281474976710655u64;
		assert!(f.policy.authorize_release(&f.channel, start).is_err());
		validate(&f, start - 1).unwrap();
		let (kit, entry) = f.policy.authorize_release(&f.channel, start).unwrap();
		assert_eq!(kit, KIT);
		assert_eq!(
			entry,
			f.policy.authorize_release(&f.channel, start).unwrap().1,
			"re-release is stable"
		);
		assert!(
			f.policy.authorize_release(&f.channel, start - 1).is_err(),
			"current state not releasable"
		);
		assert!(f.policy.authorize_release(&f.channel, start - 2).is_err());
		// The point served for a commitment is the one stored beside its encrypted secret.
		assert_eq!(f.policy.per_commitment_point(&f.channel, start).unwrap(), entry.point);
		// Holder commitments only sign for the latest validated state or newer.
		let mut st = f.policy.channel_state(&f.channel).unwrap();
		assert_eq!(st.validated_holder_commitment, Some(start - 1));
		st.released_secrets = 0;
		assert!(
			f.policy.holder_commitment_validated(&f.channel, start, None, &f.keys).is_err(),
			"cannot go backwards"
		);
	}

	#[test]
	fn validation_needs_the_counterpartys_signature() {
		let f = fixture(PolicyConfig::default());
		let claim = |number: u64, proof: Option<&HolderProof>| {
			f.policy.holder_commitment_validated(&f.channel, number, proof, &f.keys)
		};
		// The first commitment needs no proof, and makes nothing releasable.
		claim(START, None).unwrap();
		assert!(f.policy.authorize_release(&f.channel, START).is_err());

		// A host that only says "validated" is refused, so the current state stays unreleasable.
		let err = claim(START - 1, None).unwrap_err();
		assert!(err.0.contains("signature"), "{err}");
		assert!(f.policy.authorize_release(&f.channel, START).is_err());

		// Before this party has signed for the channel there is no funding to check against.
		let genuine = holder_proof(&f, START - 1, 60_000, &f.cp_funding);
		assert!(claim(START - 1, Some(&genuine)).is_err());
		let item = counterparty_commitment(&f, 100, 60_000);
		f.policy.commit(f.policy.authorize(Some(&f.channel), &item, &f.keys).unwrap()).unwrap();

		// Signed by someone other than the counterparty.
		let forged =
			holder_proof(&f, START - 1, 60_000, &SecretKey::from_slice(&[0x99u8; 32]).unwrap());
		let err = claim(START - 1, Some(&forged)).unwrap_err();
		assert!(err.0.contains("not signed by the counterparty"), "{err}");

		// A genuine signature on commitment START - 1 passed off as START - 2.
		let err = claim(START - 2, Some(&genuine)).unwrap_err();
		assert!(err.0.contains("is not holder commitment"), "{err}");
		assert!(f.policy.authorize_release(&f.channel, START).is_err());

		// The real thing.
		claim(START - 1, Some(&genuine)).unwrap();
		assert!(f.policy.authorize_release(&f.channel, START).is_ok());
		assert!(f.policy.authorize_release(&f.channel, START - 1).is_err());
	}

	#[test]
	fn validated_commitments_respect_the_balance_cap() {
		let f = fixture(PolicyConfig {
			max_holder_balance_decrease_sat: Some(10_000),
			..Default::default()
		});
		let item = counterparty_commitment(&f, 100, 60_000);
		f.policy.commit(f.policy.authorize(Some(&f.channel), &item, &f.keys).unwrap()).unwrap();
		// The counterparty signs a state that takes 40k from us: not accepted as validated, so
		// the state before it cannot be revoked.
		let drained = holder_proof(&f, START - 1, 20_000, &f.cp_funding);
		let err = f
			.policy
			.holder_commitment_validated(&f.channel, START - 1, Some(&drained), &f.keys)
			.unwrap_err();
		assert!(err.0.contains("drop"), "{err}");
		assert!(f.policy.authorize_release(&f.channel, START).is_err());
		let fair = holder_proof(&f, START - 1, 55_000, &f.cp_funding);
		f.policy.holder_commitment_validated(&f.channel, START - 1, Some(&fair), &f.keys).unwrap();
	}

	#[test]
	fn pinned_channel_parameters_cannot_change() {
		let f = fixture(PolicyConfig::default());
		let item = counterparty_commitment(&f, 100, 60_000);
		f.policy.commit(f.policy.authorize(Some(&f.channel), &item, &f.keys).unwrap()).unwrap();
		let st = f.policy.channel_state(&f.channel).unwrap();
		assert_eq!(st.fundings.len(), 1);
		assert_eq!(ChannelState::decode(&st.encode()).unwrap(), st);

		let mut other = counterparty_commitment(&f, 99, 60_000);
		other.context.counterparty_keys.as_mut().unwrap().payment_point = [3u8; 33];
		let err = f.policy.authorize(Some(&f.channel), &other, &f.keys).unwrap_err();
		assert!(err.0.contains("basepoints differ"), "{err}");

		// A funding script without our key is not a funding of this channel.
		let mut foreign = counterparty_commitment(&f, 99, 60_000);
		let script = chan_utils::make_funding_redeemscript(&cp_payment_pk(), &cp_funding_pk(&f));
		let tx: Transaction = deserialize(foreign.context.transaction.as_ref().unwrap()).unwrap();
		foreign.context.witness_script = Some(script.to_bytes());
		foreign.digest = digest(&tx, &script, 100_000, EcdsaSighashType::All);
		let err = f.policy.authorize(Some(&f.channel), &foreign, &f.keys).unwrap_err();
		assert!(err.0.contains("2-of-2"), "{err}");
	}

	#[test]
	fn a_channel_keeps_its_kit() {
		let f = fixture(PolicyConfig::default());
		f.policy.bind_kit(&f.channel, &KIT).unwrap();
		assert!(f.policy.bind_kit(&f.channel, &[1u8; 32]).is_err(), "kit cannot be swapped");
		assert!(f.policy.bind_kit(&[0xddu8; 32], &KIT).is_err(), "kit serves one channel");
		assert!(f.policy.bind_kit(&[0xddu8; 32], &[1u8; 32]).is_err(), "unknown kit");
		assert_eq!(f.policy.kit_of(&f.channel).unwrap(), Some(KIT));
		assert_eq!(f.policy.kit_of(&[0xddu8; 32]).unwrap(), None);
		assert!(f.policy.per_commitment_point(&[0xddu8; 32], 5).is_err());
	}

	#[test]
	fn release_stops_where_the_kit_ends() {
		let f = fixture(PolicyConfig::default());
		let start = 281474976710655u64;
		// The fixture kit covers three commitment numbers.
		assert!(f.policy.per_commitment_point(&f.channel, start - 2).is_ok());
		let err = f.policy.per_commitment_point(&f.channel, start - 3).unwrap_err();
		assert!(err.0.contains("refill"), "{err}");
		validate(&f, start - 2).unwrap();
		assert!(f.policy.authorize_release(&f.channel, start - 1).is_ok());
		// The newest covered state is still current, so it stays unreleasable.
		assert!(f.policy.authorize_release(&f.channel, start - 2).is_err());
	}

	#[test]
	fn state_written_before_kits_still_loads() {
		let mut st = ChannelState { validated_holder_commitment: Some(7), ..Default::default() };
		let mut v1 = st.encode();
		v1[0] = 1;
		// Version 1 had no kit field (1 byte), no pinned parameters (4 + 1 + 1 bytes) and no
		// splices (4 bytes).
		v1.truncate(v1.len() - 11);
		assert_eq!(ChannelState::decode(&v1).unwrap(), st);
		st.kit_id = Some(KIT);
		assert_eq!(ChannelState::decode(&st.encode()).unwrap(), st);
	}

	#[test]
	fn closing_must_pay_allowlisted_script_with_balance() {
		let mut allow = PayoutAllowlist::default();
		allow.add_address("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080").unwrap();
		let ok_script = Address::from_str("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080")
			.unwrap()
			.assume_checked()
			.script_pubkey();
		let f = fixture(PolicyConfig {
			payout: Some(allow),
			max_closing_fee_sat: 2_000,
			..Default::default()
		});
		// Establish a balance of 60k via a signed counterparty commitment.
		let item = counterparty_commitment(&f, 100, 60_000);
		f.policy.commit(f.policy.authorize(Some(&f.channel), &item, &f.keys).unwrap()).unwrap();

		let closing = |script: ScriptBuf, value: u64| {
			let tx = tx_with_outputs(vec![
				TxOut { value: Amount::from_sat(value), script_pubkey: script },
				TxOut {
					value: Amount::from_sat(39_000),
					script_pubkey: ScriptBuf::new_op_return([2u8]),
				},
			]);
			let redeem = funding_script(&f);
			let ctx = base_context(&f, SigningOp::ClosingTransaction, &tx, &redeem, 100_000);
			SignItem {
				key_id: f.funding,
				derivation: Derivation::None,
				digest: digest(&tx, &redeem, 100_000, EcdsaSighashType::All),
				context: ctx,
				splice: None,
			}
		};
		assert!(f
			.policy
			.authorize(Some(&f.channel), &closing(ok_script.clone(), 59_000), &f.keys)
			.is_ok());
		let err = f
			.policy
			.authorize(Some(&f.channel), &closing(ok_script.clone(), 50_000), &f.keys)
			.unwrap_err();
		assert!(err.0.contains("allow-listed"), "{err}");
		let elsewhere = ScriptBuf::new_op_return([9u8]);
		assert!(f
			.policy
			.authorize(Some(&f.channel), &closing(elsewhere, 60_000), &f.keys)
			.is_err());
		// The funding key signs closes of this channel's funding output only.
		let mut other = closing(ok_script, 59_000);
		other.context.input_value_sat = 90_000;
		let tx: Transaction = deserialize(other.context.transaction.as_ref().unwrap()).unwrap();
		other.digest = digest(&tx, &funding_script(&f), 90_000, EcdsaSighashType::All);
		let err = f.policy.authorize(Some(&f.channel), &other, &f.keys).unwrap_err();
		assert!(err.0.contains("does not spend a funding output"), "{err}");
	}

	#[test]
	fn sweeps_must_pay_allowlisted_scripts() {
		let mut allow = PayoutAllowlist::default();
		let xpub: Xpub = "tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba".parse().unwrap();
		allow.add_bip84_xpub(&xpub, 5).unwrap();
		assert_eq!(allow.len(), 10);
		let secp = Secp256k1::new();
		let child = xpub
			.derive_pub(
				&secp,
				&DerivationPath::from(vec![
					ChildNumber::from_normal_idx(0).unwrap(),
					ChildNumber::from_normal_idx(3).unwrap(),
				]),
			)
			.unwrap();
		let ok_script = Address::p2wpkh(&CompressedPublicKey(child.public_key), Network::Bitcoin)
			.script_pubkey();
		let f = fixture(PolicyConfig { payout: Some(allow), ..Default::default() });
		let payment_point = f.keys.public_key(&f.payment).unwrap();
		let witness_script =
			chan_utils::get_countersigner_payment_script(&features(), &payment_point);
		let sweep = |script: ScriptBuf| {
			let tx = tx_with_outputs(vec![TxOut {
				value: Amount::from_sat(9_000),
				script_pubkey: script,
			}]);
			let ctx = base_context(&f, SigningOp::SweepStaticPayment, &tx, &witness_script, 10_000);
			SignItem {
				key_id: f.payment,
				derivation: Derivation::None,
				digest: digest(&tx, &witness_script, 10_000, EcdsaSighashType::All),
				context: ctx,
				splice: None,
			}
		};
		assert!(f.policy.authorize(Some(&f.channel), &sweep(ok_script), &f.keys).is_ok());
		assert!(f
			.policy
			.authorize(Some(&f.channel), &sweep(ScriptBuf::new_op_return([1u8])), &f.keys)
			.is_err());
	}

	// --- splices ---

	const SPLICE_KEY: u8 = 6;

	/// Registers a spliced funding key and returns the new 2-of-2 funding script.
	fn spliced_funding(f: &mut Fixture) -> (KeyId, ScriptBuf) {
		let key = f.keys.add(SPLICE_KEY);
		f.policy.register_key(&f.channel, KeyKind::SplicedFunding, &key).unwrap();
		let script = chan_utils::make_funding_redeemscript(
			&f.keys.public_key(&key).unwrap(),
			&cp_payment_pk(), // the counterparty's funding key changes with a splice too
		);
		(key, script)
	}

	/// A splice of the fixture's 100k funding into `new_value`, with `extra` outputs.
	fn splice_tx(new_script: &ScriptBuf, new_value: u64, extra: Vec<TxOut>) -> Transaction {
		let mut outputs = vec![TxOut {
			value: Amount::from_sat(new_value),
			script_pubkey: new_script.to_p2wsh(),
		}];
		outputs.extend(extra);
		tx_with_outputs(outputs)
	}

	fn splice_item(f: &Fixture, tx: &Transaction) -> SignItem {
		let redeem = funding_script(f);
		let ctx = base_context(f, SigningOp::SpliceSharedInput, tx, &redeem, 100_000);
		SignItem {
			key_id: f.funding,
			derivation: Derivation::None,
			digest: digest(tx, &redeem, 100_000, EcdsaSighashType::All),
			context: ctx,
			splice: None,
		}
	}

	/// The counterparty's commitment `number` on the funding output `vout` of `parent`.
	#[allow(clippy::too_many_arguments)]
	fn spliced_commitment(
		f: &Fixture, key: KeyId, script: &ScriptBuf, value: u64, parent: &Transaction, vout: u32,
		number: u64, ours: u64,
	) -> SignItem {
		let payment_point = f.keys.public_key(&f.payment).unwrap();
		let to_us = chan_utils::get_countersigner_payment_script(&features(), &payment_point);
		let mut tx =
			tx_with_outputs(vec![TxOut { value: Amount::from_sat(ours), script_pubkey: to_us }]);
		tx.input[0].previous_output = OutPoint { txid: parent.compute_txid(), vout };
		let mut ctx = base_context(f, SigningOp::CounterpartyCommitment, &tx, script, value);
		ctx.commitment_number = Some(number);
		ctx.per_commitment_point = Some([2u8; 33]);
		ctx.counterparty_keys.as_mut().unwrap().funding_pubkey = cp_payment_pk().serialize();
		SignItem {
			key_id: key,
			derivation: Derivation::None,
			digest: digest(&tx, script, value, EcdsaSighashType::All),
			context: ctx,
			splice: None,
		}
	}

	fn allow(f: &Fixture, item: &SignItem) -> Result<(), PolicyError> {
		f.policy.authorize(Some(&f.channel), item, &f.keys).and_then(|a| f.policy.commit(a))
	}

	fn elsewhere() -> TxOut {
		TxOut { value: Amount::from_sat(30_000), script_pubkey: ScriptBuf::new_op_return([9u8]) }
	}

	#[test]
	fn a_channel_moves_only_to_a_funding_output_a_signed_splice_creates() {
		let mut f = fixture(PolicyConfig::default());
		validate(&f, START - 1).unwrap(); // counterparty commitment 100, our balance 60k
		let (key, script) = spliced_funding(&mut f);
		let splice = splice_tx(&script, 150_000, vec![]);
		let first = spliced_commitment(&f, key, &script, 150_000, &splice, 0, 100, 60_000);

		// The host cannot simply declare a new funding output.
		let err = allow(&f, &first).unwrap_err();
		assert!(err.0.contains("no splice"), "{err}");

		allow(&f, &splice_item(&f, &splice)).unwrap();
		// Not another output of the splice, nor the right one with another value.
		let wrong = spliced_commitment(&f, key, &script, 150_000, &splice, 1, 100, 60_000);
		assert!(allow(&f, &wrong).is_err());
		let wrong = spliced_commitment(&f, key, &script, 140_000, &splice, 0, 100, 60_000);
		assert!(allow(&f, &wrong).is_err());
		allow(&f, &first).unwrap();

		let st = f.policy.channel_state(&f.channel).unwrap();
		assert_eq!(st.fundings.len(), 2);
		assert_eq!(st.splices.len(), 1);
		assert_eq!(ChannelState::decode(&st.encode()).unwrap(), st);

		// A splice must spend a funding output of this channel.
		let mut foreign = splice_item(&f, &splice);
		foreign.context.input_value_sat = 90_000;
		foreign.digest = digest(&splice, &funding_script(&f), 90_000, EcdsaSighashType::All);
		let err = allow(&f, &foreign).unwrap_err();
		assert!(err.0.contains("does not spend a funding output"), "{err}");
	}

	#[test]
	fn a_splice_cannot_pay_our_balance_to_a_script_that_is_not_allow_listed() {
		let mut list = PayoutAllowlist::default();
		let ours = Address::from_str("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080")
			.unwrap()
			.assume_checked()
			.script_pubkey();
		list.add_script(ours.clone());
		let mut f = fixture(PolicyConfig { payout: Some(list), ..Default::default() });
		validate(&f, START - 1).unwrap(); // the counterparty signed for 60k to us
		let (key, script) = spliced_funding(&mut f);

		// 30k leaves the channel for somewhere else. Nothing in the transaction says whose
		// 30k it is; the first commitment on the new funding does.
		let theft = splice_tx(&script, 69_000, vec![elsewhere()]);
		allow(&f, &splice_item(&f, &theft)).unwrap();
		let ours_gone = spliced_commitment(&f, key, &script, 69_000, &theft, 0, 100, 30_000);
		let err = allow(&f, &ours_gone).unwrap_err();
		assert!(err.0.contains("not allow-listed"), "{err}");
		// Had it been the counterparty's 30k, our balance would be untouched.
		let theirs_gone = spliced_commitment(&f, key, &script, 69_000, &theft, 0, 100, 59_500);
		allow(&f, &theirs_gone).unwrap();
		// Once the splice's first commitment is signed, signing it again for less is refused
		// too; a later commitment is an ordinary update.
		assert!(allow(&f, &ours_gone).is_err());
		let later = spliced_commitment(&f, key, &script, 69_000, &theft, 0, 99, 30_000);
		allow(&f, &later).unwrap();

		// The same amount to our own wallet is a splice-out.
		let out = splice_tx(
			&script,
			69_500,
			vec![TxOut { value: Amount::from_sat(30_000), script_pubkey: ours }],
		);
		allow(&f, &splice_item(&f, &out)).unwrap();
		let after = spliced_commitment(&f, key, &script, 69_500, &out, 0, 99, 29_500);
		allow(&f, &after).unwrap();
	}

	#[test]
	fn a_splice_needs_a_balance_the_counterparty_signed_for() {
		let mut f = fixture(PolicyConfig::default());
		// A counterparty commitment the host had us sign says 60k, but that is the host's word.
		allow(&f, &counterparty_commitment(&f, 100, 60_000)).unwrap();
		let (_, script) = spliced_funding(&mut f);
		let splice = splice_tx(&script, 150_000, vec![]);
		let err = allow(&f, &splice_item(&f, &splice)).unwrap_err();
		assert!(err.0.contains("cannot splice yet"), "{err}");
		// The channel's first holder commitment counts once there is a funding to check its
		// signature against.
		let proof = holder_proof(&f, START, 60_000, &f.cp_funding);
		f.policy.holder_commitment_validated(&f.channel, START, Some(&proof), &f.keys).unwrap();
		allow(&f, &splice_item(&f, &splice)).unwrap();
	}

	#[test]
	fn a_party_that_missed_a_splice_follows_the_parties_signature() {
		let mut f = fixture(PolicyConfig::default());
		validate(&f, START - 1).unwrap();
		let (key, script) = spliced_funding(&mut f);
		let splice = splice_tx(&script, 150_000, vec![]);
		let first = spliced_commitment(&f, key, &script, 150_000, &splice, 0, 100, 60_000);
		assert!(allow(&f, &first).is_err());

		let secp = Secp256k1::new();
		let msg = Message::from_digest(digest(
			&splice,
			&funding_script(&f),
			100_000,
			EcdsaSighashType::All,
		));
		let proof = |signer: &SecretKey| SpliceProof {
			transaction: serialize(&splice),
			input_index: 0,
			signature: secp.sign_ecdsa(&msg, signer).serialize_compact(),
		};
		// Signed by the counterparty alone, or by anyone else: not the parties' agreement.
		let err = f.policy.learn_splice(&f.channel, &proof(&f.cp_funding), &f.keys).unwrap_err();
		assert!(err.0.contains("not signed by the parties"), "{err}");
		assert!(allow(&f, &first).is_err());

		let genuine = proof(&f.keys.secrets[&f.funding]);
		f.policy.learn_splice(&f.channel, &genuine, &f.keys).unwrap();
		allow(&f, &first).unwrap();
		// It can now pass the proof on.
		assert_eq!(f.policy.splice_proof_for(&f.channel, &first), Some(genuine));
		assert_eq!(
			f.policy.splice_proof_for(&f.channel, &counterparty_commitment(&f, 99, 60_000)),
			None
		);
	}

	#[test]
	fn the_signature_on_a_splice_is_kept_as_its_proof() {
		let mut f = fixture(PolicyConfig::default());
		validate(&f, START - 1).unwrap();
		let (key, script) = spliced_funding(&mut f);
		let splice = splice_tx(&script, 150_000, vec![]);
		let item = splice_item(&f, &splice);
		allow(&f, &item).unwrap();
		let first = spliced_commitment(&f, key, &script, 150_000, &splice, 0, 100, 60_000);
		assert_eq!(f.policy.splice_proof_for(&f.channel, &first), None, "not signed yet");
		let sig = Secp256k1::new()
			.sign_ecdsa(&Message::from_digest(item.digest), &f.keys.secrets[&f.funding]);
		f.policy.splice_signed(&f.channel, &item, &sig).unwrap();
		let proof = f.policy.splice_proof_for(&f.channel, &first).unwrap();
		assert_eq!(proof.signature, sig.serialize_compact());
		// And it is a proof another party accepts.
		let g = {
			let mut g = fixture(PolicyConfig::default());
			g.keys = Keys { secrets: f.keys.secrets.clone(), pubkeys: f.keys.pubkeys.clone() };
			g
		};
		allow(&g, &counterparty_commitment(&g, 100, 60_000)).unwrap();
		g.policy.register_key(&g.channel, KeyKind::SplicedFunding, &key).unwrap();
		g.policy.learn_splice(&g.channel, &proof, &g.keys).unwrap();
		allow(&g, &first).unwrap();
	}

	#[test]
	fn balances_are_tracked_per_funding_while_a_splice_is_pending() {
		let mut f = fixture(PolicyConfig {
			max_holder_balance_decrease_sat: Some(10_000),
			..Default::default()
		});
		validate(&f, START - 1).unwrap();
		let (key, script) = spliced_funding(&mut f);
		// We add 50k to the channel. Until the splice confirms, every update is signed for
		// both funding outputs, and our balance differs between them by those 50k.
		let splice = splice_tx(&script, 150_000, vec![]);
		allow(&f, &splice_item(&f, &splice)).unwrap();
		let new =
			|number, ours| spliced_commitment(&f, key, &script, 150_000, &splice, 0, number, ours);
		allow(&f, &new(100, 110_000)).unwrap();
		allow(&f, &counterparty_commitment(&f, 99, 58_000)).unwrap();
		allow(&f, &new(99, 108_000)).unwrap();
		// The cap still holds on each of them.
		assert!(allow(&f, &counterparty_commitment(&f, 98, 40_000))
			.unwrap_err()
			.0
			.contains("drop"));
		assert!(allow(&f, &new(98, 90_000)).unwrap_err().0.contains("drop"));
	}
}
