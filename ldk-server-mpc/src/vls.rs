//! The Validating Lightning Signer's policy engine, embedded in every party.
//!
//! VLS is a signer that holds the keys itself. Here the keys are shared among the parties, so
//! only its validation is used: each party keeps VLS's record of every channel
//! ([`EnforcementState`]) and of the payments in flight across channels ([`NodeState`]), and
//! runs VLS's validator on every commitment before it takes part in signing it.
//!
//! What that adds to [`crate::policy`]:
//!
//! - VLS's per-commitment rules: contest delays, feerate and fee bounds, HTLC count and value
//!   limits, no HTLCs in the first commitment, a re-signed commitment must be identical;
//! - VLS's routing rule: an HTLC we offer must be matched by one offered to us for the same
//!   payment hash (a forward), or be a payment of our own that was approved;
//! - an outflow limit. A party approves payments of our own by itself, against a budget per
//!   hour or day (VLS's velocity control). Anything else that lowers what a counterparty
//!   commitment leaves us (dust HTLCs, fees, a plain shift of balance) is charged to the same
//!   budget. With a limit set, that is the most a compromised LDK Server can move out of our
//!   channel balances in that time, by any route.
//!
//! The parties do not follow the chain, so VLS's rules that need the block height are off, and
//! a party that missed updates (it was down) picks the sequence up where it finds it instead of
//! refusing: at least two of any three signers saw every step.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::{Network, OutPoint};
use lightning_signer::channel::{ChannelId, ChannelSetup, CommitmentType};
use lightning_signer::lightning::ln::chan_utils::ChannelPublicKeys;
use lightning_signer::lightning::ln::channel_keys::{
	DelayedPaymentBasepoint, HtlcBasepoint, RevocationBasepoint,
};
use lightning_signer::lightning::types::payment::PaymentHash;
use lightning_signer::node::{NodeState, PaymentState, PaymentType, RoutedPayment};
use lightning_signer::policy::filter::{FilterRule, PolicyFilter};
use lightning_signer::policy::simple_validator::{
	make_default_simple_policy, SimplePolicy, SimpleValidatorFactory,
};
use lightning_signer::policy::validator::{
	BalanceDelta, ChainState, CommitmentSignatures, EnforcementState, Validator, ValidatorFactory,
};
use lightning_signer::tx::tx::{CommitmentInfo2, HTLCInfo2};
use lightning_signer::util::velocity::{
	VelocityControl, VelocityControlIntervalType, VelocityControlSpec,
};

use crate::kit::INITIAL_COMMITMENT_NUMBER;

/// How much may leave our channel balances, and over what time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutflowLimit {
	Unlimited,
	PerHour { sat: u64 },
	PerDay { sat: u64 },
}

#[derive(Clone, Debug)]
pub struct GuardConfig {
	/// Selects VLS's policy defaults (stricter on mainnet).
	pub network: Network,
	pub outflow: OutflowLimit,
}

impl Default for GuardConfig {
	fn default() -> Self {
		GuardConfig { network: Network::Bitcoin, outflow: OutflowLimit::Unlimited }
	}
}

/// An HTLC output of a commitment.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Htlc {
	pub payment_hash: [u8; 32],
	pub value_sat: u64,
	pub cltv_expiry: u32,
}

/// What a commitment transaction says, from our point of view, whoever broadcasts it.
#[derive(Clone, Debug)]
pub struct Commitment {
	/// Counting down from [`INITIAL_COMMITMENT_NUMBER`], as LDK does.
	pub number: u64,
	pub per_commitment_point: PublicKey,
	pub ours_sat: u64,
	pub theirs_sat: u64,
	pub feerate_per_kw: u32,
	/// HTLCs offered to us.
	pub incoming: Vec<Htlc>,
	/// HTLCs we offer.
	pub outgoing: Vec<Htlc>,
}

/// The fixed facts of a channel on one of its funding outputs.
#[derive(Clone, Debug)]
pub struct Setup {
	pub is_outbound: bool,
	pub value_sat: u64,
	pub funding_outpoint: OutPoint,
	pub holder_selected_contest_delay: u16,
	pub counterparty_selected_contest_delay: u16,
	/// Funding key, revocation, payment, delayed-payment and HTLC basepoints.
	pub counterparty_keys: [PublicKey; 5],
	pub anchors_zero_fee_htlc: bool,
}

impl Setup {
	fn to_vls(&self) -> ChannelSetup {
		let k = &self.counterparty_keys;
		ChannelSetup {
			is_outbound: self.is_outbound,
			channel_value_sat: self.value_sat,
			push_value_msat: 0,
			funding_outpoint: self.funding_outpoint,
			holder_selected_contest_delay: self.holder_selected_contest_delay,
			holder_shutdown_script: None,
			counterparty_points: ChannelPublicKeys {
				funding_pubkey: k[0],
				revocation_basepoint: RevocationBasepoint(k[1]),
				payment_point: k[2],
				delayed_payment_basepoint: DelayedPaymentBasepoint(k[3]),
				htlc_basepoint: HtlcBasepoint(k[4]),
			},
			counterparty_selected_contest_delay: self.counterparty_selected_contest_delay,
			counterparty_shutdown_script: None,
			commitment_type: if self.anchors_zero_fee_htlc {
				CommitmentType::AnchorsZeroFeeHtlc
			} else {
				CommitmentType::StaticRemoteKey
			},
		}
	}
}

/// A channel on one of its funding outputs. Both sides of a pending splice are signed for,
/// with different balances, so each funding output has a record of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Key {
	pub channel: [u8; 32],
	/// Identifies the funding output (a hash of its script and value).
	pub funding: [u8; 32],
}

/// What a counterparty commitment left us, for comparison with the next one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Baseline {
	number: u64,
	/// Our output, plus the fees if we pay them, plus the HTLCs we offer.
	total_sat: u64,
	outgoing: Vec<Htlc>,
	/// The commitment's content, to recognize the same commitment being signed again.
	digest: String,
}

struct Chan {
	estate: EnforcementState,
	baseline: Option<Baseline>,
	/// Copied from the channel's previous funding output and not signed for yet, per side.
	fresh_counterparty: bool,
	fresh_holder: bool,
}

struct Inner {
	node: NodeState,
	chans: HashMap<Key, Chan>,
	/// Payments of our own that this party approved, by payment hash, in sat.
	approved: HashMap<[u8; 32], u64>,
}

/// The state changes of a counterparty commitment that passed, applied once it is signed.
pub struct Pending {
	key: Key,
	estate: Option<EnforcementState>,
	baseline: Baseline,
	incoming: lightning_signer::prelude::Map<PaymentHash, u64>,
	outgoing: lightning_signer::prelude::Map<PaymentHash, u64>,
	delta: BalanceDelta,
	approvals: Vec<([u8; 32], u64)>,
	charge_sat: u64,
}

impl std::fmt::Debug for Pending {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Pending")
			.field("key", &self.key)
			.field("charge_sat", &self.charge_sat)
			.finish()
	}
}

pub struct Guard {
	dir: PathBuf,
	network: Network,
	policy: SimplePolicy,
	inner: Mutex<Inner>,
}

/// One of the generator points, where VLS wants a public key that is only a label.
fn label_key() -> PublicKey {
	PublicKey::from_slice(&[
		0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
		0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
		0xf8, 0x17, 0x98,
	])
	.expect("valid point")
}

/// VLS guards some of its arithmetic with panics. A request that trips one is refused; it must
/// not take the party down with it.
fn no_panic<T>(f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
	std::panic::catch_unwind(std::panic::AssertUnwindSafe(f))
		.unwrap_or_else(|_| Err("the validator could not process this commitment".to_string()))
}

fn now_secs() -> u64 {
	SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn vls_number(ldk_number: u64) -> u64 {
	INITIAL_COMMITMENT_NUMBER - ldk_number
}

fn htlcs(list: &[Htlc]) -> Vec<HTLCInfo2> {
	list.iter()
		.map(|h| HTLCInfo2 {
			value_sat: h.value_sat,
			payment_hash: PaymentHash(h.payment_hash),
			cltv_expiry: h.cltv_expiry,
		})
		.collect()
}

fn hex(bytes: &[u8]) -> String {
	bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The parties do not follow the chain; VLS's validator only looks at this when told to.
const NO_CHAIN: ChainState = ChainState {
	current_height: 0,
	funding_depth: 1,
	funding_double_spent_depth: 0,
	closing_depth: 0,
};

impl Guard {
	pub fn open(dir: &Path, config: &GuardConfig) -> io::Result<Self> {
		fs::create_dir_all(dir)?;
		let mut policy = make_default_simple_policy(config.network);
		policy.use_chain_state = false;
		// A channel opened with a push to the counterparty is not told apart here.
		policy.filter = PolicyFilter {
			rules: vec![FilterRule::new_warn("policy-commitment-initial-funding-value")],
		};
		let spec = match config.outflow {
			OutflowLimit::Unlimited => VelocityControlSpec::UNLIMITED,
			OutflowLimit::PerHour { sat } => VelocityControlSpec {
				limit_msat: sat.saturating_mul(1000),
				interval_type: VelocityControlIntervalType::Hourly,
			},
			OutflowLimit::PerDay { sat } => VelocityControlSpec {
				limit_msat: sat.saturating_mul(1000),
				interval_type: VelocityControlIntervalType::Daily,
			},
		};
		let mut velocity = VelocityControl::new(spec);
		if let Ok(saved) = fs::read_to_string(dir.join("outflow.velocity")) {
			let mut numbers = saved.split_whitespace().filter_map(|n| n.parse::<u64>().ok());
			if let Some(start) = numbers.next() {
				let buckets: Vec<u64> = numbers.collect();
				if buckets.len() == velocity.buckets.len() {
					velocity = VelocityControl::load_from_state(spec, (start, buckets));
				}
			}
		}
		let fee_velocity = VelocityControl::new(VelocityControlSpec::UNLIMITED);
		let mut inner = Inner {
			node: NodeState::new(velocity, fee_velocity, Vec::new()),
			chans: HashMap::new(),
			approved: HashMap::new(),
		};
		// Every channel's record is loaded up front: the routing rule looks across channels.
		for entry in fs::read_dir(dir)?.filter_map(|e| e.ok()) {
			let path = entry.path();
			if path.extension().map(|x| x != "vls").unwrap_or(true) {
				continue;
			}
			let Some(key) = Self::key_of(&path) else { continue };
			let text = fs::read_to_string(&path)?;
			let (first, rest) = text.split_once('\n').unwrap_or(("", &text));
			let estate: EnforcementState = serde_json::from_str(rest).map_err(|e| {
				io::Error::new(io::ErrorKind::InvalidData, format!("{path:?}: {e}"))
			})?;
			Self::restore_payments(&mut inner.node, &key, &estate);
			let baseline = Self::parse_baseline(first);
			inner.chans.insert(
				key,
				Chan { estate, baseline, fresh_counterparty: false, fresh_holder: false },
			);
		}
		Ok(Guard {
			dir: dir.to_path_buf(),
			network: config.network,
			policy,
			inner: Mutex::new(inner),
		})
	}

	/// VLS's validator with this party's policy. (It is not a type that can be shared between
	/// threads, so each call makes its own.)
	fn validator(&self) -> Arc<dyn Validator> {
		SimpleValidatorFactory::new_with_policy(self.policy.clone()).make_validator(
			self.network,
			label_key(),
			None,
		)
	}

	fn path(&self, key: &Key) -> PathBuf {
		self.dir.join(format!("{}.{}.vls", hex(&key.channel), hex(&key.funding)))
	}

	fn key_of(path: &Path) -> Option<Key> {
		let name = path.file_stem()?.to_str()?;
		let (channel, funding) = name.split_once('.')?;
		let parse = |s: &str| -> Option<[u8; 32]> {
			if s.len() != 64 {
				return None;
			}
			let mut out = [0u8; 32];
			for (i, byte) in out.iter_mut().enumerate() {
				*byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
			}
			Some(out)
		};
		Some(Key { channel: parse(channel)?, funding: parse(funding)? })
	}

	fn parse_baseline(line: &str) -> Option<Baseline> {
		// number total digest hash:value:cltv ...
		let mut parts = line.split_whitespace();
		let number = parts.next()?.parse().ok()?;
		let total_sat = parts.next()?.parse().ok()?;
		let digest = parts.next()?.to_string();
		let mut outgoing = Vec::new();
		for part in parts {
			let mut f = part.split(':');
			let hash = f.next()?;
			let mut payment_hash = [0u8; 32];
			if hash.len() != 64 {
				return None;
			}
			for (i, byte) in payment_hash.iter_mut().enumerate() {
				*byte = u8::from_str_radix(&hash[2 * i..2 * i + 2], 16).ok()?;
			}
			outgoing.push(Htlc {
				payment_hash,
				value_sat: f.next()?.parse().ok()?,
				cltv_expiry: f.next()?.parse().ok()?,
			});
		}
		Some(Baseline { number, total_sat, outgoing, digest })
	}

	fn persist(&self, key: &Key, chan: &Chan) -> io::Result<()> {
		let mut text = String::new();
		if let Some(b) = &chan.baseline {
			text.push_str(&format!("{} {} {}", b.number, b.total_sat, b.digest));
			for h in &b.outgoing {
				text.push_str(&format!(
					" {}:{}:{}",
					hex(&h.payment_hash),
					h.value_sat,
					h.cltv_expiry
				));
			}
		}
		text.push('\n');
		text.push_str(
			&serde_json::to_string(&chan.estate)
				.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?,
		);
		let path = self.path(key);
		let tmp = path.with_extension("vls.tmp");
		fs::write(&tmp, text)?;
		fs::rename(&tmp, &path)
	}

	fn persist_velocity(&self, node: &NodeState) {
		let (start, buckets) = node.velocity_control.get_state();
		let mut text = start.to_string();
		for b in buckets {
			text.push_str(&format!(" {b}"));
		}
		if let Err(e) = fs::write(self.dir.join("outflow.velocity"), text) {
			log::warn!("could not save the outflow record: {e}");
		}
	}

	fn restore_payments(node: &mut NodeState, key: &Key, estate: &EnforcementState) {
		let id = ChannelId::new(&key.channel);
		let incoming = estate.incoming_payments_summary(None, None);
		let outgoing = estate.payments_summary(None, None);
		for hash in incoming.keys().chain(outgoing.keys()) {
			let payment = node.payments.entry(*hash).or_insert_with(RoutedPayment::new);
			payment.apply(
				&id,
				incoming.get(hash).copied().unwrap_or(0),
				outgoing.get(hash).copied().unwrap_or(0),
			);
		}
	}

	/// The record for `key`, starting a new funding output of a known channel from the
	/// channel's latest record: the HTLCs in flight are the same on both.
	fn chan<'a>(inner: &'a mut Inner, key: &Key) -> &'a mut Chan {
		if !inner.chans.contains_key(key) {
			let sibling = inner
				.chans
				.iter()
				.filter(|(k, _)| k.channel == key.channel)
				.max_by_key(|(_, c)| c.estate.next_counterparty_commit_num)
				.map(|(_, c)| c.estate.clone());
			let chan = match sibling {
				Some(estate) => {
					Chan { estate, baseline: None, fresh_counterparty: true, fresh_holder: true }
				},
				None => Chan {
					estate: EnforcementState::new(0),
					baseline: None,
					fresh_counterparty: false,
					fresh_holder: false,
				},
			};
			inner.chans.insert(*key, chan);
		}
		inner.chans.get_mut(key).expect("just inserted")
	}

	/// Drops the records of payments that are no longer in flight on any channel, and the
	/// approvals that went with them.
	fn forget_settled(inner: &mut Inner) {
		inner.node.payments.retain(|_, p| !(p.is_no_incoming() && p.is_no_outgoing()));
		let payments = &inner.node.payments;
		inner.node.invoices.retain(|hash, _| payments.contains_key(hash));
		inner.approved.retain(|hash, _| {
			payments.get(&PaymentHash(*hash)).map(|p| !p.is_no_outgoing()).unwrap_or(false)
		});
	}

	fn approval(hash: &[u8; 32], sat: u64) -> PaymentState {
		PaymentState {
			invoice_hash: *hash,
			amount_msat: sat.saturating_mul(1000),
			payee: label_key(),
			duration_since_epoch: std::time::Duration::from_secs(now_secs()),
			expiry_duration: std::time::Duration::from_secs(3600),
			is_fulfilled: false,
			payment_type: PaymentType::Keysend,
		}
	}

	/// Checks a counterparty commitment we are asked to sign. Nothing is recorded until
	/// [`Self::apply`].
	pub fn check_counterparty_commitment(
		&self, key: &Key, setup: &Setup, c: &Commitment,
	) -> Result<Pending, String> {
		no_panic(|| self.check_counterparty_commitment_inner(key, setup, c))
	}

	fn check_counterparty_commitment_inner(
		&self, key: &Key, setup: &Setup, c: &Commitment,
	) -> Result<Pending, String> {
		let validator = self.validator();
		let mut guard = self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
		let inner = &mut *guard;
		let setup_vls = setup.to_vls();
		let n = vls_number(c.number);
		let info = CommitmentInfo2::new(
			true,
			c.ours_sat,
			c.theirs_sat,
			htlcs(&c.incoming),
			htlcs(&c.outgoing),
			c.feerate_per_kw,
		);
		let digest = format!("{:?}", info)
			.bytes()
			.fold(0xcbf29ce484222325u64, |h, b| (h ^ b as u64).wrapping_mul(0x100000001b3));
		let digest = format!("{digest:016x}");

		// What the commitment leaves us: our output, the fees if we pay them (they come back
		// when they fall), and the HTLCs we offer (they come back if they fail).
		let outputs: u64 = c.ours_sat
			+ c.theirs_sat
			+ c.incoming.iter().chain(c.outgoing.iter()).map(|h| h.value_sat).sum::<u64>();
		let fees = if setup.is_outbound { setup.value_sat.saturating_sub(outputs) } else { 0 };
		let total_sat = c.ours_sat + fees + c.outgoing.iter().map(|h| h.value_sat).sum::<u64>();
		let mut outgoing_sorted = c.outgoing.clone();
		outgoing_sorted.sort();
		let baseline = Baseline { number: c.number, total_sat, outgoing: outgoing_sorted, digest };

		let id = ChannelId::new(&key.channel);
		let (mut estate, before, fresh) = {
			let chan = Self::chan(inner, key);
			(chan.estate.clone(), chan.baseline.clone(), chan.fresh_counterparty)
		};
		if before.as_ref() == Some(&baseline) {
			// The same commitment again (a retransmission): nothing new to judge.
			return Ok(Pending {
				key: *key,
				estate: None,
				baseline,
				incoming: Default::default(),
				outgoing: Default::default(),
				delta: BalanceDelta(0, 0),
				approvals: Vec::new(),
				charge_sat: 0,
			});
		}
		// A party that was away, or a funding output that was just spliced in, takes the
		// sequence up where the request is.
		let next = estate.next_counterparty_commit_num;
		if n > next || (fresh && n + 1 == next) {
			estate.next_counterparty_commit_num = n;
			if n > next {
				// The point on record belongs to a commitment further back than n - 1.
				estate.current_counterparty_point = None;
			}
		}
		// VLS expects commitment n to be signed while n - 1 is the newest revoked one at most.
		// A party that missed revocations is behind that; one that is told of a revocation
		// before the signature it follows, or that signs the same state again for a new
		// funding output, is ahead. Neither is a reason to refuse: line the count up for the
		// check and put the real one back after.
		let revoked = estate.next_counterparty_revoke_num;
		estate.next_counterparty_revoke_num = n.saturating_sub(1);

		validator.validate_channel_value(&setup_vls).map_err(|e| e.to_string())?;
		// VLS's balance enforcement is off (its default), so the balance delta it would use
		// is not computed: with a splice the channel value changes under it.
		let delta = BalanceDelta(0, 0);
		let incoming = estate.incoming_payments_summary(None, Some(&info));
		let outgoing = estate.payments_summary(None, Some(&info));
		validator
			.validate_counterparty_commitment_tx(
				&estate,
				n,
				&c.per_commitment_point,
				&setup_vls,
				&NO_CHAIN,
				&info,
			)
			.map_err(|e| e.to_string())?;

		// Payments of our own: HTLCs we offer beyond what is offered to us for the same hash.
		let mut approvals = Vec::new();
		let mut charge_sat = 0u64;
		for (hash, out_here) in outgoing.iter() {
			let in_here = incoming.get(hash).copied().unwrap_or(0);
			let (inc, out) = match inner.node.payments.get(hash) {
				Some(p) => p.updated_incoming_outgoing(&id, in_here, *out_here),
				None => (in_here, *out_here),
			};
			let needed = out.saturating_sub(inc);
			let have = inner.approved.get(&hash.0).copied().unwrap_or(0);
			if needed > have {
				approvals.push((hash.0, needed));
				charge_sat += needed - have;
			}
		}
		// Anything else that lowers what we are left with, compared with the last commitment
		// on this funding output. An HTLC of ours that is gone explains its own amount: it
		// either came back or was paid for when it was offered.
		if let Some(before) = &before {
			let mut gone = before.outgoing.clone();
			for h in &baseline.outgoing {
				if let Some(i) = gone.iter().position(|g| g == h) {
					gone.remove(i);
				}
			}
			let settled: u64 = gone.iter().map(|h| h.value_sat).sum();
			charge_sat +=
				before.total_sat.saturating_sub(baseline.total_sat).saturating_sub(settled);
		}
		if charge_sat > 0 {
			let mut budget = inner.node.velocity_control.clone();
			if !budget.insert(now_secs(), charge_sat.saturating_mul(1000)) {
				return Err(format!(
					"outflow limit: this commitment moves {charge_sat} sat out of our balance, \
					 more than the limit leaves room for"
				));
			}
		}

		// VLS's routing rule, with those approvals in place for the length of the check.
		let saved: Vec<_> = approvals
			.iter()
			.map(|(hash, sat)| {
				(*hash, inner.node.invoices.insert(PaymentHash(*hash), Self::approval(hash, *sat)))
			})
			.collect();
		let routed =
			inner.node.validate_payments(&id, &incoming, &outgoing, &delta, Arc::clone(&validator));
		for (hash, previous) in saved {
			match previous {
				Some(p) => inner.node.invoices.insert(PaymentHash(hash), p),
				None => inner.node.invoices.remove(&PaymentHash(hash)),
			};
		}
		routed.map_err(|e| e.to_string())?;

		validator
			.set_next_counterparty_commit_num(&mut estate, n + 1, c.per_commitment_point, info)
			.map_err(|e| e.to_string())?;
		estate.next_counterparty_revoke_num = revoked.max(estate.next_counterparty_revoke_num);
		Ok(Pending {
			key: *key,
			estate: Some(estate),
			baseline,
			incoming,
			outgoing,
			delta,
			approvals,
			charge_sat,
		})
	}

	/// Records a counterparty commitment that was signed.
	pub fn apply(&self, pending: Pending) {
		let Some(estate) = pending.estate else { return };
		let validator = self.validator();
		let mut guard = self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
		let inner = &mut *guard;
		let id = ChannelId::new(&pending.key.channel);
		for (hash, sat) in &pending.approvals {
			inner.node.invoices.insert(PaymentHash(*hash), Self::approval(hash, *sat));
			inner.node.payments.entry(PaymentHash(*hash)).or_insert_with(RoutedPayment::new);
			inner.approved.insert(*hash, *sat);
		}
		if pending.charge_sat > 0 {
			// Checked when the commitment was; if the budget has since been used by another
			// channel, this one is still counted, and the next request finds it spent.
			let msat = pending.charge_sat.saturating_mul(1000);
			if !inner.node.velocity_control.insert(now_secs(), msat) {
				let bucket = &mut inner.node.velocity_control.buckets[0];
				*bucket = bucket.saturating_add(msat);
			}
			self.persist_velocity(&inner.node);
		}
		inner.node.apply_payments(
			&id,
			&pending.incoming,
			&pending.outgoing,
			&pending.delta,
			Arc::clone(&validator),
		);
		Self::forget_settled(inner);
		let chan = Self::chan(inner, &pending.key);
		chan.estate = estate;
		chan.baseline = Some(pending.baseline);
		chan.fresh_counterparty = false;
		if let Err(e) = self.persist(&pending.key, chan) {
			log::error!("could not save the channel record: {e}");
		}
	}

	/// Checks and records a holder commitment the counterparty signed.
	pub fn holder_commitment_validated(
		&self, key: &Key, setup: &Setup, c: &Commitment, counterparty_sig: &Signature,
	) -> Result<(), String> {
		no_panic(|| self.holder_commitment_validated_inner(key, setup, c, counterparty_sig))
	}

	fn holder_commitment_validated_inner(
		&self, key: &Key, setup: &Setup, c: &Commitment, counterparty_sig: &Signature,
	) -> Result<(), String> {
		let validator = self.validator();
		let mut guard = self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
		let inner = &mut *guard;
		let setup_vls = setup.to_vls();
		let n = vls_number(c.number);
		let info = CommitmentInfo2::new(
			false,
			c.theirs_sat,
			c.ours_sat,
			htlcs(&c.outgoing),
			htlcs(&c.incoming),
			c.feerate_per_kw,
		);
		let id = ChannelId::new(&key.channel);
		let (mut estate, fresh) = {
			let chan = Self::chan(inner, key);
			(chan.estate.clone(), chan.fresh_holder)
		};
		let next = estate.next_holder_commit_num;
		if n + 1 == next && !fresh && estate.current_holder_commit_info.as_ref() == Some(&info) {
			return Ok(()); // the same commitment again
		}
		if n > next || (fresh && n + 1 == next) {
			estate.next_holder_commit_num = n;
		}
		let delta = BalanceDelta(0, 0);
		let incoming = estate.incoming_payments_summary(Some(&info), None);
		let outgoing = estate.payments_summary(Some(&info), None);
		validator
			.validate_holder_commitment_tx(
				&estate,
				n,
				&c.per_commitment_point,
				&setup_vls,
				&NO_CHAIN,
				&info,
			)
			.map_err(|e| e.to_string())?;
		inner
			.node
			.validate_payments(&id, &incoming, &outgoing, &delta, Arc::clone(&validator))
			.map_err(|e| e.to_string())?;
		validator
			.set_next_holder_commit_num(
				&mut estate,
				n + 1,
				info,
				CommitmentSignatures(*counterparty_sig, Vec::new()),
			)
			.map_err(|e| e.to_string())?;
		inner.node.apply_payments(&id, &incoming, &outgoing, &delta, Arc::clone(&validator));
		Self::forget_settled(inner);
		let chan = Self::chan(inner, key);
		chan.estate = estate;
		chan.fresh_holder = false;
		if let Err(e) = self.persist(key, chan) {
			log::error!("could not save the channel record: {e}");
		}
		Ok(())
	}

	/// Records that the counterparty revoked its commitment `number` (LDK numbering), after
	/// checking the secret against the point that commitment was signed for.
	pub fn counterparty_revoked(&self, channel: &[u8; 32], number: u64, secret: &SecretKey) {
		let validator = self.validator();
		let mut guard = self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
		let n = vls_number(number);
		let keys: Vec<Key> =
			guard.chans.keys().filter(|k| &k.channel == channel).copied().collect();
		for key in keys {
			let chan = guard.chans.get_mut(&key).expect("listed");
			let estate = &mut chan.estate;
			// The revocation of n follows our signature on n + 1. A record that has not seen
			// that signature (a party that was away, a funding output no longer in use) has
			// nothing to check the secret against.
			if estate.next_counterparty_commit_num < n + 2
				|| n < estate.next_counterparty_revoke_num
			{
				continue;
			}
			let in_sequence = n == estate.next_counterparty_revoke_num
				&& estate.get_previous_counterparty_point(n).is_some();
			if in_sequence {
				let checked = no_panic(|| {
					validator
						.validate_counterparty_revocation(estate, n, secret)
						.map_err(|e| e.to_string())
				});
				if let Err(e) = checked {
					log::warn!("counterparty revocation {number} does not check out: {e}");
					continue;
				}
			}
			estate.set_next_counterparty_revoke_num(n + 1);
			if let Err(e) = self.persist(&key, chan) {
				log::error!("could not save the channel record: {e}");
			}
		}
	}

	/// How much of the outflow budget is used, in sat (for logs and tests).
	pub fn outflow_used_sat(&self) -> u64 {
		self.inner
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner())
			.node
			.velocity_control
			.velocity()
			/ 1000
	}
}
