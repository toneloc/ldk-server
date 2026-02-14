use std::path::Path;
use std::sync::{Arc, Mutex};

use ldk_node::lightning::ln::types::ChannelId;
use ldk_node::Node;
use log::{error, info, warn};
use serde::Deserialize;

use stable_channels::audit::audit_event;
use stable_channels::constants::*;
use stable_channels::db::Database;
use stable_channels::price_feeds::get_cached_price;
use stable_channels::stable;
use stable_channels::types::{Bitcoin, StableChannel, USD};

use serde_json::json;

// ============================================================================
// Trade message types (signed TLV payloads from user)
// ============================================================================

#[derive(Deserialize, Debug)]
struct TradeSignedMessage {
	payload: String,
	#[allow(dead_code)]
	signature: String,
}

#[derive(Deserialize, Debug)]
struct TradePayload {
	#[serde(rename = "type")]
	kind: String,
	channel_id: String,
	expected_usd: f64,
}

// ============================================================================
// StableChannelManager
// ============================================================================

pub struct StableChannelManager {
	pub stable_channels: Vec<StableChannel>,
	pub db: Database,
	pub btc_price: f64,
	data_dir: String,
}

impl StableChannelManager {
	pub fn new(data_dir: &Path) -> Self {
		let db =
			Database::open(data_dir).expect("Failed to open stable channels database");

		let data_dir_str = data_dir.to_string_lossy().to_string();

		// Set audit log path
		let audit_path = format!("{}/audit_log.txt", data_dir_str);
		stable_channels::audit::set_audit_log_path(&audit_path);

		let btc_price = get_cached_price();

		Self { stable_channels: Vec::new(), db, btc_price, data_dir: data_dir_str }
	}

	// ---- Persistence --------------------------------------------------------

	pub fn save_stable_channels(&self) {
		for sc in &self.stable_channels {
			let ch_id = sc.channel_id.to_string();
			info!(
				"[stable] saving channel={} expected_usd={} backing_sats={}",
				ch_id, sc.expected_usd.0, sc.backing_sats
			);
			if let Err(e) = self.db.save_channel(
				&ch_id,
				sc.expected_usd.0,
				sc.backing_sats,
				sc.note.as_deref(),
			) {
				error!("[stable] ERROR saving channel {} to DB: {}", ch_id, e);
			}
		}
	}

	pub fn load_stable_channels(&mut self, node: &Node) {
		let entries = match self.db.load_all_channels() {
			Ok(e) => e,
			Err(e) => {
				error!("Error loading channels from DB: {}", e);
				return;
			},
		};

		let ldk_channels = node.list_channels();
		info!(
			"[stable] DB has {} entries, LDK has {} channels",
			entries.len(),
			ldk_channels.len()
		);

		self.stable_channels.clear();

		for entry in entries {
			info!(
				"[stable] DB entry: channel_id={}, expected_usd={}",
				entry.channel_id, entry.expected_usd
			);
			let mut matched = false;
			for channel in &ldk_channels {
				if channel.channel_id.to_string() == entry.channel_id {
					matched = true;
					let unspendable = channel.unspendable_punishment_reserve.unwrap_or(0);
					let our_balance_sats =
						(channel.outbound_capacity_msat / 1000) + unspendable;
					let their_balance_sats =
						channel.channel_value_sats.saturating_sub(our_balance_sats);

					let stable_provider_btc = Bitcoin::from_sats(our_balance_sats);
					let stable_receiver_btc = Bitcoin::from_sats(their_balance_sats);
					let stable_provider_usd =
						USD::from_bitcoin(stable_provider_btc, self.btc_price);
					let stable_receiver_usd =
						USD::from_bitcoin(stable_receiver_btc, self.btc_price);

					let stable_channel = StableChannel {
						channel_id: channel.channel_id,
						counterparty: channel.counterparty_node_id,
						is_stable_receiver: false,
						expected_usd: USD::from_f64(entry.expected_usd),
						expected_btc: Bitcoin::from_btc(0.0),
						stable_receiver_btc,
						stable_receiver_usd,
						stable_provider_btc,
						stable_provider_usd,
						latest_price: self.btc_price,
						risk_level: 0,
						payment_made: false,
						timestamp: 0,
						formatted_datetime: String::new(),
						sc_dir: self.data_dir.clone(),
						prices: String::new(),
						onchain_btc: Bitcoin::from_sats(0),
						onchain_usd: USD(0.0),
						note: entry.note.clone(),
						native_channel_btc: Bitcoin::from_sats(0),
						backing_sats: entry.backing_sats,
					};

					self.stable_channels.push(stable_channel);
					break;
				}
			}
			if !matched {
				warn!(
					"[stable] no LDK channel matched DB entry {}",
					entry.channel_id
				);
			}
		}

		info!("Loaded {} stable channels from DB", self.stable_channels.len());
	}

	// ---- Stability checking -------------------------------------------------

	pub fn check_and_update_stable_channels(&mut self, node: &Node) -> bool {
		let current_price = get_cached_price();
		if current_price > 0.0 {
			self.btc_price = current_price;
		}

		let mut channels_updated = false;
		let mut payment_sent = false;

		for sc in &mut self.stable_channels {
			if !stable::channel_exists(node, &sc.channel_id) {
				continue;
			}

			sc.latest_price = current_price;
			if stable::check_stability(node, sc, current_price).is_some() {
				payment_sent = true;
			}

			if sc.payment_made {
				channels_updated = true;
			}
		}

		if channels_updated {
			self.save_stable_channels();
		}

		payment_sent
	}

	// ---- Event handlers -----------------------------------------------------

	pub fn handle_channel_ready(&mut self, channel_id: ChannelId, node: &Node) {
		if let Some(chan) =
			node.list_channels().into_iter().find(|c| c.channel_id == channel_id)
		{
			let funded_usd = chan.channel_value_sats as f64 / 2.0
				/ SATS_IN_BTC as f64
				* self.btc_price;

			// Create channel with $0 stabilized (user opts in via trade message)
			let unspendable = chan.unspendable_punishment_reserve.unwrap_or(0);
			let our_balance_sats =
				(chan.outbound_capacity_msat / 1000) + unspendable;
			let their_balance_sats =
				chan.channel_value_sats.saturating_sub(our_balance_sats);

			let stable_channel = StableChannel {
				channel_id: chan.channel_id,
				counterparty: chan.counterparty_node_id,
				is_stable_receiver: false,
				expected_usd: USD::from_f64(0.0),
				expected_btc: Bitcoin::from_btc(0.0),
				stable_receiver_btc: Bitcoin::from_sats(their_balance_sats),
				stable_receiver_usd: USD::from_bitcoin(
					Bitcoin::from_sats(their_balance_sats),
					self.btc_price,
				),
				stable_provider_btc: Bitcoin::from_sats(our_balance_sats),
				stable_provider_usd: USD::from_bitcoin(
					Bitcoin::from_sats(our_balance_sats),
					self.btc_price,
				),
				latest_price: self.btc_price,
				risk_level: 0,
				payment_made: false,
				timestamp: 0,
				formatted_datetime: String::new(),
				sc_dir: self.data_dir.clone(),
				prices: String::new(),
				onchain_btc: Bitcoin::from_sats(0),
				onchain_usd: USD(0.0),
				note: None,
				native_channel_btc: Bitcoin::from_sats(0),
				backing_sats: 0,
			};

			// Update or insert
			let mut found = false;
			for sc in &mut self.stable_channels {
				if sc.channel_id == chan.channel_id {
					*sc = stable_channel.clone();
					found = true;
					break;
				}
			}
			if !found {
				self.stable_channels.push(stable_channel);
			}

			self.save_stable_channels();

			audit_event(
				"CHANNEL_READY",
				json!({
					"channel_id": channel_id.to_string(),
					"funded_usd": funded_usd,
					"stabilized_usd": 0.0
				}),
			);

			info!(
				"Channel {} ready (funded ${:.2}, awaiting stabilization opt-in)",
				channel_id, funded_usd
			);
		}
	}

	pub fn handle_channel_closed(&mut self, channel_id: ChannelId) {
		// Remove from in-memory list
		self.stable_channels.retain(|sc| sc.channel_id != channel_id);

		// Remove from DB
		if let Err(e) = self.db.delete_channel(&channel_id.to_string()) {
			error!("[stable] failed to delete channel {} from DB: {}", channel_id, e);
		}
	}

	pub fn handle_payment_received(
		&mut self, amount_msat: u64, custom_records: Vec<ldk_node::CustomTlvRecord>,
		node: &Node,
	) {
		let mut decoded_payload: Option<String> = None;

		for tlv in &custom_records {
			if tlv.type_num == STABLE_CHANNEL_TLV_TYPE {
				if let Ok(s) = String::from_utf8(tlv.value.clone()) {
					decoded_payload = Some(s);
				}
			}
		}

		match &decoded_payload {
			Some(raw) => {
				audit_event(
					"MESSAGE_RECEIVED",
					json!({
						"amount_msat": amount_msat,
						"raw": raw,
					}),
				);
				self.handle_trade_message(raw, node);
			},
			None => {
				audit_event(
					"PAYMENT_RECEIVED",
					json!({
						"amount_msat": amount_msat,
					}),
				);

				// Non-TLV payment is likely a stability payment from the user.
				// Reset backing_sats to equilibrium so the next check_stability
				// uses the correct baseline.
				let current_price = get_cached_price();
				for sc in &mut self.stable_channels {
					if current_price > 0.0 {
						sc.latest_price = current_price;
					}
					stable::reconcile_incoming(sc);
				}
				self.save_stable_channels();
			},
		}
	}

	pub fn handle_payment_forwarded(
		&mut self, prev_channel_id: ChannelId, next_channel_id: ChannelId,
		outbound_amount_forwarded_msat: Option<u64>, total_fee_earned_msat: Option<u64>,
		node: &Node,
	) {
		let forwarded_msat = outbound_amount_forwarded_msat.unwrap_or(0);
		let fee_msat = total_fee_earned_msat.unwrap_or(0);
		let total_msat = forwarded_msat + fee_msat;
		let total_sats = total_msat / 1000;

		audit_event(
			"PAYMENT_FORWARDED",
			json!({
				"prev_channel_id": prev_channel_id.to_string(),
				"next_channel_id": next_channel_id.to_string(),
				"forwarded_msat": forwarded_msat,
				"fee_msat": fee_msat,
				"total_sats": total_sats,
			}),
		);

		// Check if the payment came FROM a stable channel (user sent payment out)
		if let Some(sc) = self
			.stable_channels
			.iter_mut()
			.find(|sc| sc.channel_id == prev_channel_id)
		{
			if sc.expected_usd.0 <= 0.0 || self.btc_price <= 0.0 {
				return;
			}

			// Get the user's current channel balance (remote side from LSP perspective)
			let user_total_sats = node
				.list_channels()
				.iter()
				.find(|c| c.channel_id == prev_channel_id)
				.map(|c| {
					let unspendable = c.unspendable_punishment_reserve.unwrap_or(0);
					let lsp_sats = (c.outbound_capacity_msat / 1000) + unspendable;
					c.channel_value_sats.saturating_sub(lsp_sats)
				})
				.unwrap_or(0);

			let old_expected = sc.expected_usd.0;
			let native_sats = user_total_sats.saturating_sub(sc.backing_sats);

			if let Some(usd_deducted) =
				stable::reconcile_forwarded(sc, user_total_sats, total_sats, self.btc_price)
			{
				let overflow_sats = total_sats.saturating_sub(native_sats);
				info!(
					"[forwarded] channel {} spent {} sats ({} native, {} from stable), expected_usd: ${:.2} -> ${:.2}",
					prev_channel_id, total_sats, native_sats, overflow_sats, old_expected, sc.expected_usd.0
				);

				audit_event(
					"STABLE_SPEND_DEDUCTED",
					json!({
						"channel_id": prev_channel_id.to_string(),
						"total_sats_spent": total_sats,
						"native_sats_spent": native_sats,
						"stable_sats_spent": overflow_sats,
						"usd_deducted": usd_deducted,
						"old_expected_usd": old_expected,
						"new_expected_usd": sc.expected_usd.0,
						"btc_price": self.btc_price,
					}),
				);

				self.save_stable_channels();
			} else {
				info!(
					"[forwarded] channel {} spent {} sats from native BTC ({} native available), stable ${:.2} unchanged",
					prev_channel_id, total_sats, native_sats, sc.expected_usd.0
				);
			}
		}
	}

	// ---- Trade message handling ----------------------------------------------

	fn handle_trade_message(&mut self, raw_msg: &str, node: &Node) {
		// 1) Parse outer envelope
		let signed: TradeSignedMessage = match serde_json::from_str(raw_msg) {
			Ok(v) => v,
			Err(e) => {
				audit_event(
					"TRADE_PARSE_SIGNED_FAILED",
					json!({ "error": format!("{e}"), "raw": raw_msg }),
				);
				return;
			},
		};

		// 2) Parse inner payload
		let payload: TradePayload = match serde_json::from_str(&signed.payload) {
			Ok(v) => v,
			Err(e) => {
				audit_event(
					"TRADE_PARSE_PAYLOAD_FAILED",
					json!({ "error": format!("{e}"), "payload": signed.payload }),
				);
				return;
			},
		};

		audit_event(
			"TRADE_PARSED_PAYLOAD_OK",
			json!({
				"channel_id": &payload.channel_id,
				"type": &payload.kind,
				"expected_usd": payload.expected_usd,
			}),
		);

		if payload.kind != TRADE_MESSAGE_TYPE {
			audit_event("TRADE_UNHANDLED_TYPE", json!({ "kind": payload.kind }));
			return;
		}

		// 3) Validate expected_usd
		let new_expected_usd = payload.expected_usd;
		if new_expected_usd < 0.0 {
			audit_event(
				"TRADE_INVALID_AMOUNT",
				json!({ "expected_usd": new_expected_usd, "reason": "negative amount" }),
			);
			return;
		}

		let chan_id_str = payload.channel_id.clone();

		// 4) Find the channel to verify signature
		let channel_opt =
			node.list_channels().into_iter().find(|c| c.channel_id.to_string() == chan_id_str);

		let channel = match channel_opt {
			Some(ch) => ch,
			None => {
				audit_event(
					"TRADE_CHANNEL_NOT_FOUND",
					json!({ "channel_id": chan_id_str, "expected_usd": new_expected_usd }),
				);
				return;
			},
		};

		// 5) Verify signature using counterparty's pubkey
		let pkey = channel.counterparty_node_id;
		let sig_ok =
			node.verify_signature(signed.payload.as_bytes(), &signed.signature, &pkey);

		if !sig_ok {
			audit_event(
				"TRADE_SIGNATURE_INVALID",
				json!({ "channel_id": chan_id_str, "expected_usd": new_expected_usd }),
			);
			info!("Trade message signature NOT verified for channel {}", chan_id_str);
			return;
		}

		audit_event(
			"TRADE_SIGNATURE_VALID",
			json!({ "channel_id": chan_id_str, "expected_usd": new_expected_usd }),
		);

		// 6) Apply new expected_usd to StableChannel
		if let Some(sc) = self
			.stable_channels
			.iter_mut()
			.find(|sc| sc.channel_id == channel.channel_id)
		{
			// Refresh balances
			let (ok, _) = stable::update_balances(node, sc);
			if !ok {
				audit_event(
					"TRADE_BALANCE_UPDATE_FAILED",
					json!({ "channel_id": chan_id_str }),
				);
				return;
			}

			// Validate: can't stabilize more than the user's channel balance
			let receiver_usd = sc.stable_receiver_usd.0;
			if new_expected_usd > receiver_usd {
				audit_event(
					"TRADE_EXCEEDS_BALANCE",
					json!({
						"channel_id": chan_id_str,
						"expected_usd": new_expected_usd,
						"receiver_usd": receiver_usd,
					}),
				);
				return;
			}

			let old = sc.expected_usd.0;
			info!(
				"[trade] updating expected_usd: {} -> {} for channel {}",
				old, new_expected_usd, sc.channel_id
			);

			stable::apply_trade(sc, new_expected_usd, sc.latest_price);

			self.save_stable_channels();

			audit_event(
				"TRADE_APPLIED",
				json!({
					"channel_id": chan_id_str,
					"old_expected_usd": old,
					"new_expected_usd": new_expected_usd,
				}),
			);

			info!(
				"Trade applied: ${:.2} -> ${:.2} for channel {}",
				old, new_expected_usd, chan_id_str
			);
		} else {
			audit_event(
				"TRADE_STABLE_ENTRY_NOT_FOUND",
				json!({ "channel_id": chan_id_str, "expected_usd": new_expected_usd }),
			);
		}
	}

	// ---- API handlers -------------------------------------------------------

	pub fn edit_stable_channel(
		&mut self, channel_id_str: &str, target_usd: f64, note: Option<String>, node: &Node,
	) -> Result<String, String> {
		let channel = node
			.list_channels()
			.into_iter()
			.find(|c| c.channel_id.to_string() == channel_id_str)
			.ok_or_else(|| format!("No channel found matching: {}", channel_id_str))?;

		let expected_usd = USD::from_f64(target_usd);
		let expected_btc = Bitcoin::from_usd(expected_usd, self.btc_price);

		let unspendable = channel.unspendable_punishment_reserve.unwrap_or(0);
		let our_balance_sats = (channel.outbound_capacity_msat / 1000) + unspendable;
		let their_balance_sats = channel.channel_value_sats.saturating_sub(our_balance_sats);

		let stable_provider_btc = Bitcoin::from_sats(our_balance_sats);
		let stable_receiver_btc = Bitcoin::from_sats(their_balance_sats);
		let stable_provider_usd = USD::from_bitcoin(stable_provider_btc, self.btc_price);
		let stable_receiver_usd = USD::from_bitcoin(stable_receiver_btc, self.btc_price);

		// Preserve existing note if none provided
		let note = note.or_else(|| {
			self.stable_channels
				.iter()
				.find(|sc| sc.channel_id == channel.channel_id)
				.and_then(|sc| sc.note.clone())
		});

		let backing_sats = if self.btc_price > 0.0 {
			let btc_amount = target_usd / self.btc_price;
			(btc_amount * 100_000_000.0) as u64
		} else {
			0
		};

		let stable_channel = StableChannel {
			channel_id: channel.channel_id,
			counterparty: channel.counterparty_node_id,
			is_stable_receiver: false,
			expected_usd,
			expected_btc,
			stable_receiver_btc,
			stable_receiver_usd,
			stable_provider_btc,
			stable_provider_usd,
			latest_price: self.btc_price,
			risk_level: 0,
			payment_made: false,
			timestamp: 0,
			formatted_datetime: String::new(),
			sc_dir: self.data_dir.clone(),
			prices: String::new(),
			onchain_btc: Bitcoin::from_sats(0),
			onchain_usd: USD(0.0),
			note,
			native_channel_btc: Bitcoin::from_sats(0),
			backing_sats,
		};

		let mut found = false;
		for sc in &mut self.stable_channels {
			if sc.channel_id == channel.channel_id {
				*sc = stable_channel.clone();
				found = true;
				break;
			}
		}
		if !found {
			self.stable_channels.push(stable_channel);
		}

		self.save_stable_channels();

		audit_event(
			"STABLE_EDITED",
			json!({ "channel_id": channel_id_str, "target_usd": target_usd }),
		);

		Ok(format!("Channel {} edited as stable with target ${}", channel_id_str, target_usd))
	}
}

// Thread-safe wrapper
pub type SharedStableManager = Arc<Mutex<StableChannelManager>>;
