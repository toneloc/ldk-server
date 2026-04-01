use std::path::Path;
use std::sync::{Arc, Mutex};

use ldk_node::bitcoin::secp256k1::PublicKey;
use ldk_node::lightning::ln::types::ChannelId;
use ldk_node::{CustomTlvRecord, Node};
use log::{error, info, warn};
use serde::Deserialize;

use stable_channels::audit::audit_event;
use stable_channels::constants::*;
use stable_channels::db::Database;
use stable_channels::price_feeds::get_cached_price;
use stable_channels::stable;
use stable_channels::types::{Bitcoin, StableChannel, USD};

use serde_json::json;

/// A stability payment that needs a push notification to wake the peer.
pub struct StabilityPushTarget {
	pub node_id: String,    // Lightning pubkey hex
	pub direction: String,  // "lsp_to_user" or "user_to_lsp"
}

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
	#[serde(default)]
	channel_id: Option<String>,
	#[serde(default)]
	user_channel_id: Option<String>,
	expected_usd: f64,
}

// ============================================================================
// Bitcoind RPC helper
// ============================================================================

/// Look up the value (in sats) of a specific transaction output via bitcoind RPC.
///
/// Uses `getrawtransaction` with verbose=true to get the decoded transaction,
/// then extracts the output value at the given vout index.
///
/// Returns None if the lookup fails (tx not found, RPC error, etc.)
fn get_output_sats(txid: &str, vout: u32) -> Option<u64> {
	let rpc_url = "http://127.0.0.1:8332";
	let rpc_user = std::env::var("BITCOIND_RPC_USER").unwrap_or_default();
	let rpc_pass = std::env::var("BITCOIND_RPC_PASS").unwrap_or_default();

	let body = json!({
		"jsonrpc": "1.0",
		"id": "sc_splice",
		"method": "getrawtransaction",
		"params": [txid, true]
	});

	let credentials = format!("{}:{}", rpc_user, rpc_pass);
	let auth_value = format!(
		"Basic {}",
		openssl::base64::encode_block(credentials.as_bytes())
	);

	let client = reqwest::blocking::Client::new();
	let response = client
		.post(rpc_url)
		.header("Authorization", &auth_value)
		.header("Content-Type", "application/json")
		.json(&body)
		.send()
		.ok()?;

	let json: serde_json::Value = response.json().ok()?;
	let vouts = json["result"]["vout"].as_array()?;
	let output = vouts.get(vout as usize)?;
	let value_btc = output["value"].as_f64()?;
	let value_sats = (value_btc * 100_000_000.0).round() as u64;

	Some(value_sats)
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
		let db = Database::open(data_dir).expect("Failed to open stable channels database");

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
			let uch_id = format!("{}", sc.user_channel_id);
			info!(
				"[stable] saving channel={} user_channel_id={} expected_usd={} backing_sats={} native_sats={}",
				ch_id, uch_id, sc.expected_usd.0, sc.backing_sats, sc.native_sats
			);
			if let Err(e) =
				self.db.save_channel(&ch_id, &uch_id, sc.expected_usd.0, sc.backing_sats, sc.native_sats, sc.note.as_deref())
			{
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
		info!("[stable] DB has {} entries, LDK has {} channels", entries.len(), ldk_channels.len());
		for ch in &ldk_channels {
			info!(
				"[stable]   LDK channel: {} (user_channel_id={})",
				ch.channel_id, ch.user_channel_id.0
			);
		}

		self.stable_channels.clear();

		for entry in entries {
			info!(
				"[stable] DB entry: channel_id={}, user_channel_id={}, expected_usd={}",
				entry.channel_id, entry.user_channel_id, entry.expected_usd
			);
			let mut matched = false;
			for channel in &ldk_channels {
				// Match by user_channel_id (stable across splices), fall back to channel_id for legacy entries
				let matches = if !entry.user_channel_id.is_empty() {
					format!("{}", channel.user_channel_id.0) == entry.user_channel_id
				} else {
					channel.channel_id.to_string() == entry.channel_id
				};
				if matches {
					matched = true;
					let unspendable = channel.unspendable_punishment_reserve.unwrap_or(0);
					let our_balance_sats = (channel.outbound_capacity_msat / 1000) + unspendable;
					let their_balance_sats =
						channel.channel_value_sats.saturating_sub(our_balance_sats);

					let stable_provider_btc = Bitcoin::from_sats(our_balance_sats);
					let stable_receiver_btc = Bitcoin::from_sats(their_balance_sats);
					let stable_provider_usd =
						USD::from_bitcoin(stable_provider_btc, self.btc_price);
					let stable_receiver_usd =
						USD::from_bitcoin(stable_receiver_btc, self.btc_price);

					let mut stable_channel = StableChannel {
						channel_id: channel.channel_id,
						user_channel_id: channel.user_channel_id.0,
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
						native_sats: entry.native_sats,
						last_stability_payment: 0,
					};

					// Migrate: if native_sats not set yet, derive from balance
					if stable_channel.native_sats == 0 && stable_channel.backing_sats > 0 {
						stable_channel.native_sats =
							their_balance_sats.saturating_sub(stable_channel.backing_sats);
						info!(
							"[stable] Migrated native_sats={} for channel {}",
							stable_channel.native_sats, stable_channel.channel_id
						);
					}

					self.stable_channels.push(stable_channel);
					break;
				}
			}
			if !matched {
				warn!(
					"[stable] no LDK channel matched DB entry channel_id={} user_channel_id={}",
					entry.channel_id, entry.user_channel_id
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
			if !stable::channel_exists(node, sc.user_channel_id) {
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

	// ---- Peer connectivity --------------------------------------------------

	/// Check if a peer is connected by looking for a usable channel with them.
	pub fn is_peer_connected(&self, node: &Node, user_channel_id: u128) -> bool {
		node.list_channels()
			.iter()
			.any(|c| c.user_channel_id.0 == user_channel_id && c.is_usable)
	}

	// ---- Push targets -------------------------------------------------------

	/// Returns a list of offline peers that need stability payments, with direction.
	/// The caller should send a push notification to each and retry after a delay.
	pub fn get_stability_push_targets(&self, node: &Node) -> Vec<StabilityPushTarget> {
		let current_price = get_cached_price();
		if current_price <= 0.0 {
			return Vec::new();
		}

		let mut targets = Vec::new();
		for sc in &self.stable_channels {
			if !stable::channel_exists(node, sc.user_channel_id) {
				continue;
			}
			if sc.expected_usd.0 < 0.01 {
				continue;
			}

			// Quick drift check -- does this channel need a stability payment?
			// Use backing_sats directly (set at trade time, reset after payments)
			let stable_usd_value = if sc.backing_sats > 0 {
				(sc.backing_sats as f64 / 100_000_000.0) * current_price
			} else {
				sc.stable_receiver_usd.0
			};
			let target_usd = sc.expected_usd.0;
			let percent_from_par = if target_usd > 0.0 {
				(((stable_usd_value - target_usd) / target_usd) * 100.0).abs()
			} else {
				0.0
			};

			let is_receiver_below_expected = stable_usd_value < target_usd;

			let dollars_from_par_abs = (stable_usd_value - target_usd).abs();

			if percent_from_par >= STABILITY_THRESHOLD_PERCENT
				&& dollars_from_par_abs >= STABILITY_THRESHOLD_USD
				&& !self.is_peer_connected(node, sc.user_channel_id)
			{
				// Determine direction from LSP perspective:
				// LSP is_stable_receiver=false, so:
				//   - Price dropped -> user below expected -> LSP pays user -> lsp_to_user
				//   - Price rose -> user above expected -> user pays LSP -> user_to_lsp
				let direction = if is_receiver_below_expected {
					"lsp_to_user"
				} else {
					"user_to_lsp"
				};

				targets.push(StabilityPushTarget {
					node_id: sc.counterparty.to_string(),
					direction: direction.to_string(),
				});
			}
		}
		targets
	}

	// ---- SYNC_V1 message sending --------------------------------------------

	/// Send authoritative expected_usd to the user after a stable deduction.
	/// Ensures both sides agree on the stable position value.
	fn send_sync_message(&self, node: &Node, user_channel_id: u128, expected_usd: f64, counterparty: PublicKey) {
		let payload = json!({
			"type": SYNC_MESSAGE_TYPE,
			"user_channel_id": format!("{}", user_channel_id),
			"expected_usd": expected_usd,
		});
		let payload_str = payload.to_string();
		let signature = node.sign_message(payload_str.as_bytes());

		let signed_msg = json!({
			"payload": payload_str,
			"signature": signature,
		});
		let signed_str = signed_msg.to_string();

		let custom_tlv = CustomTlvRecord {
			type_num: STABLE_CHANNEL_TLV_TYPE,
			value: signed_str.as_bytes().to_vec(),
		};

		match node.spontaneous_payment().send_with_custom_tlvs(
			1, // 1 msat
			counterparty,
			None,
			vec![custom_tlv],
		) {
			Ok(payment_id) => {
				audit_event(
					"SYNC_MESSAGE_SENT",
					json!({
						"user_channel_id": format!("{}", user_channel_id),
						"expected_usd": expected_usd,
						"payment_id": format!("{}", payment_id),
					}),
				);
			}
			Err(e) => {
				audit_event(
					"SYNC_MESSAGE_FAILED",
					json!({
						"user_channel_id": format!("{}", user_channel_id),
						"expected_usd": expected_usd,
						"error": format!("{e}"),
					}),
				);
			}
		}
	}

	// ---- Event handlers -----------------------------------------------------

	pub fn handle_channel_ready(&mut self, channel_id: ChannelId, user_channel_id: u128, node: &Node) {
		if let Some(chan) = node.list_channels().into_iter().find(|c| c.channel_id == channel_id) {
			let funded_usd =
				chan.channel_value_sats as f64 / 2.0 / SATS_IN_BTC as f64 * self.btc_price;

			// Check if a stable channel already exists for this user_channel_id (splice case)
			let existing = self
				.stable_channels
				.iter_mut()
				.find(|sc| sc.user_channel_id == user_channel_id);

			if let Some(sc) = existing {
				// Splice: update channel_id but preserve expected_usd and other state
				let old_channel_id = sc.channel_id.to_string();
				sc.channel_id = channel_id;
				let old_expected_usd = sc.expected_usd.0;

				// Update balances from LDK so stable_receiver_btc reflects post-splice state
				stable::update_balances(node, sc);

				// If splice-out exceeded native BTC, reconcile the stable portion
				let price = sc.latest_price;
				let usd_deducted = stable::reconcile_outgoing(sc, price);
				if let Some(deducted) = usd_deducted {
					audit_event(
						"SPLICE_OUT_STABLE_DEDUCTED",
						json!({
							"channel_id": channel_id.to_string(),
							"user_channel_id": format!("{}", user_channel_id),
							"usd_deducted": deducted,
							"old_expected_usd": old_expected_usd,
							"new_expected_usd": sc.expected_usd.0,
							"btc_price": price,
						}),
					);
				}

				let new_expected_usd = sc.expected_usd.0;
				let sync_counterparty = sc.counterparty;

				audit_event(
					"CHANNEL_READY_SPLICE",
					json!({
						"channel_id": channel_id.to_string(),
						"old_channel_id": old_channel_id,
						"user_channel_id": format!("{}", user_channel_id),
						"funded_usd": funded_usd,
						"expected_usd": new_expected_usd,
					}),
				);
				self.save_stable_channels();

				// Send SYNC_V1 if stable balance was deducted during splice
				if usd_deducted.is_some() {
					self.send_sync_message(node, user_channel_id, new_expected_usd, sync_counterparty);
				}

				info!(
					"Channel {} ready after splice (${:.2} stabilized)",
					channel_id, new_expected_usd
				);
			} else {
				// New channel: create entry with $0 stabilized (user opts in via trade message)
				let unspendable = chan.unspendable_punishment_reserve.unwrap_or(0);
				let our_balance_sats = (chan.outbound_capacity_msat / 1000) + unspendable;
				let their_balance_sats = chan.channel_value_sats.saturating_sub(our_balance_sats);

				let stable_channel = StableChannel {
					channel_id: chan.channel_id,
					user_channel_id: chan.user_channel_id.0,
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
					native_sats: 0,
					last_stability_payment: 0,
				};

				// Update or insert by user_channel_id
				let mut found = false;
				for sc in &mut self.stable_channels {
					if sc.user_channel_id == chan.user_channel_id.0 {
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
						"user_channel_id": format!("{}", chan.user_channel_id.0),
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
	}

	pub fn handle_channel_closed(&mut self, channel_id: ChannelId, user_channel_id: u128) {
		// Remove from in-memory list by user_channel_id
		self.stable_channels.retain(|sc| sc.user_channel_id != user_channel_id);

		// Remove from DB
		if let Err(e) = self.db.delete_channel(&format!("{}", user_channel_id)) {
			error!("[stable] failed to delete channel {} from DB: {}", channel_id, e);
		}

		audit_event(
			"CHANNEL_CLOSED",
			json!({
				"channel_id": channel_id.to_string(),
				"user_channel_id": format!("{}", user_channel_id),
			}),
		);
	}

	pub fn handle_splice_pending(
		&mut self, channel_id: ChannelId, user_channel_id: u128,
		new_funding_txid: &str, new_funding_vout: u32, node: &Node,
	) {
		audit_event(
			"SPLICE_PENDING",
			json!({
				"channel_id": channel_id.to_string(),
				"user_channel_id": format!("{}", user_channel_id),
				"funding_txo": format!("{}:{}", new_funding_txid, new_funding_vout),
			}),
		);

		// Get old channel value (list_channels still shows pre-splice value)
		let old_channel_value_sats = node
			.list_channels()
			.iter()
			.find(|c| c.user_channel_id.0 == user_channel_id)
			.map(|c| c.channel_value_sats);

		// Look up new funding output value from bitcoind
		if let Some(old_value) = old_channel_value_sats {
			match get_output_sats(new_funding_txid, new_funding_vout) {
				Some(new_value) => {
					audit_event(
						"SPLICE_PENDING_LOOKUP",
						json!({
							"old_channel_sats": old_value,
							"new_channel_sats": new_value,
							"delta_sats": (new_value as i64) - (old_value as i64),
						}),
					);

					if new_value < old_value {
						// Splice-out: channel got smaller
						let splice_out_sats = old_value - new_value;

						let mut sync_info: Option<(u128, f64, PublicKey)> = None;
						if let Some(sc) = self
							.stable_channels
							.iter_mut()
							.find(|sc| sc.user_channel_id == user_channel_id)
						{
							// Update channel_id to the new one
							sc.channel_id = channel_id;

							let price = sc.latest_price;
							if let Some(usd_deducted) =
								stable::deduct_outgoing(sc, splice_out_sats, price)
							{
								audit_event(
									"SPLICE_PENDING_STABLE_DEDUCTED",
									json!({
										"channel_id": channel_id.to_string(),
										"user_channel_id": format!("{}", user_channel_id),
										"splice_out_sats": splice_out_sats,
										"usd_deducted": usd_deducted,
										"new_expected_usd": sc.expected_usd.0,
										"btc_price": price,
									}),
								);
								sync_info = Some((
									sc.user_channel_id,
									sc.expected_usd.0,
									sc.counterparty,
								));
							}
						}
						if let Some((ucid, eusd, cp)) = sync_info {
							self.send_sync_message(node, ucid, eusd, cp);
						}
						self.save_stable_channels();
					} else {
						// Splice-in: just update channel_id
						if let Some(sc) = self
							.stable_channels
							.iter_mut()
							.find(|sc| sc.user_channel_id == user_channel_id)
						{
							sc.channel_id = channel_id;
						}
						self.save_stable_channels();
					}
				}
				None => {
					// Tx not yet in mempool or RPC error -- trade message + ChannelReady will handle it
					info!(
						"[SplicePending] Could not look up funding output {}:{}",
						new_funding_txid, new_funding_vout
					);
					audit_event(
						"SPLICE_PENDING_LOOKUP_FAILED",
						json!({
							"txid": new_funding_txid,
							"vout": new_funding_vout,
						}),
					);
				}
			}
		}
	}

	pub fn handle_payment_received(
		&mut self, amount_msat: u64, custom_records: Vec<ldk_node::CustomTlvRecord>, node: &Node,
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
					// Update balances after receiving stability payment
					stable::update_balances(node, sc);
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
		// Look up user_channel_id from LDK (channel_id changes on splice, user_channel_id doesn't)
		let prev_user_ch_id = node
			.list_channels()
			.iter()
			.find(|c| c.channel_id == prev_channel_id)
			.map(|c| c.user_channel_id.0);

		if let Some(sc) = prev_user_ch_id.and_then(|uid| {
			self.stable_channels
				.iter_mut()
				.find(|sc| sc.user_channel_id == uid)
		}) {
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
			let native_sats = sc.native_sats;

			if let Some(usd_deducted) =
				stable::reconcile_forwarded(sc, user_total_sats, total_sats, self.btc_price)
			{
				let overflow_sats = total_sats.saturating_sub(native_sats);
				let new_expected_usd = sc.expected_usd.0;
				let sc_user_channel_id = sc.user_channel_id;
				let sc_counterparty = sc.counterparty;

				info!(
					"[forwarded] channel {} spent {} sats ({} native, {} from stable), expected_usd: ${:.2} -> ${:.2}",
					prev_channel_id, total_sats, native_sats, overflow_sats, old_expected, new_expected_usd
				);

				audit_event(
					"STABLE_SPEND_DEDUCTED",
					json!({
						"user_channel_id": format!("{}", sc_user_channel_id),
						"total_sats_spent": total_sats,
						"native_sats_spent": native_sats,
						"stable_sats_spent": overflow_sats,
						"usd_deducted": usd_deducted,
						"old_expected_usd": old_expected,
						"new_expected_usd": new_expected_usd,
						"btc_price": self.btc_price,
					}),
				);

				self.save_stable_channels();

				// Send SYNC_V1 to sync the user after stable deduction
				self.send_sync_message(node, sc_user_channel_id, new_expected_usd, sc_counterparty);
			} else {
				// Payment fully covered by native — update native_sats to reflect the spend
				sc.native_sats = native_sats.saturating_sub(total_sats);
				stable::recompute_native(sc);
				// Set cooldown — stability check can see intermediate states during HTLC forwarding
				sc.last_stability_payment = std::time::SystemTime::now()
					.duration_since(std::time::UNIX_EPOCH)
					.unwrap_or_default()
					.as_secs() as i64;
				info!(
					"[forwarded] channel {} spent {} sats from native BTC ({} -> {} native), stable ${:.2} unchanged",
					prev_channel_id, total_sats, native_sats, sc.native_sats, sc.expected_usd.0
				);
				self.save_stable_channels();
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
				"user_channel_id": &payload.user_channel_id,
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

		let user_ch_id_str = payload.user_channel_id.clone().unwrap_or_default();

		// 4) Find the channel -- prefer channel_id (shared between both nodes),
		//    fall back to user_channel_id for backward compat
		let channels = node.list_channels();
		let channel_opt = if let Some(ref cid) = payload.channel_id {
			channels.iter().find(|c| c.channel_id.to_string() == *cid)
		} else {
			channels
				.iter()
				.find(|c| format!("{}", c.user_channel_id.0) == user_ch_id_str)
		};

		let channel = match channel_opt {
			Some(ch) => ch.clone(),
			None => {
				audit_event(
					"TRADE_CHANNEL_NOT_FOUND",
					json!({
						"channel_id": payload.channel_id,
						"user_channel_id": user_ch_id_str,
						"expected_usd": new_expected_usd,
					}),
				);
				return;
			},
		};

		let chan_id_str = channel.channel_id.to_string();

		// 5) Verify signature using counterparty's pubkey
		let pkey = channel.counterparty_node_id;
		let sig_ok = node.verify_signature(signed.payload.as_bytes(), &signed.signature, &pkey);

		if !sig_ok {
			audit_event(
				"TRADE_SIGNATURE_INVALID",
				json!({
					"channel_id": chan_id_str,
					"user_channel_id": user_ch_id_str,
					"expected_usd": new_expected_usd,
				}),
			);
			info!("Trade message signature NOT verified for channel {}", chan_id_str);
			return;
		}

		audit_event(
			"TRADE_SIGNATURE_VALID",
			json!({
				"channel_id": chan_id_str,
				"user_channel_id": user_ch_id_str,
				"expected_usd": new_expected_usd,
			}),
		);

		// 6) Apply new expected_usd to StableChannel (match by user_channel_id)
		if let Some(sc) =
			self.stable_channels.iter_mut().find(|sc| sc.user_channel_id == channel.user_channel_id.0)
		{
			// Refresh balances
			let (ok, _) = stable::update_balances(node, sc);
			if !ok {
				audit_event(
					"TRADE_BALANCE_UPDATE_FAILED",
					json!({ "user_channel_id": user_ch_id_str }),
				);
				return;
			}

			// Validate: can't stabilize more than the user's channel balance
			let receiver_usd = sc.stable_receiver_usd.0;
			if new_expected_usd > receiver_usd {
				audit_event(
					"TRADE_EXCEEDS_BALANCE",
					json!({
						"user_channel_id": user_ch_id_str,
						"expected_usd": new_expected_usd,
						"receiver_usd": receiver_usd,
					}),
				);
				return;
			}

			let old = sc.expected_usd.0;
			info!(
				"[trade] updating expected_usd: {} -> {} for user_channel_id={}",
				old, new_expected_usd, sc.user_channel_id
			);

			stable::apply_trade(sc, new_expected_usd, sc.latest_price);

			self.save_stable_channels();

			audit_event(
				"TRADE_APPLIED",
				json!({
					"user_channel_id": user_ch_id_str,
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
				json!({
					"channel_id": chan_id_str,
					"user_channel_id": user_ch_id_str,
					"expected_usd": new_expected_usd,
				}),
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
				.find(|sc| sc.user_channel_id == channel.user_channel_id.0)
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
			user_channel_id: channel.user_channel_id.0,
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
			native_sats: stable_receiver_btc.sats.saturating_sub(backing_sats),
			last_stability_payment: 0,
		};

		let mut found = false;
		for sc in &mut self.stable_channels {
			if sc.user_channel_id == channel.user_channel_id.0 {
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
			json!({
				"user_channel_id": format!("{}", channel.user_channel_id.0),
				"target_usd": target_usd,
			}),
		);

		Ok(format!("Channel {} edited as stable with target ${}", channel_id_str, target_usd))
	}

	// ---- Log reading --------------------------------------------------------

	pub fn read_audit_log(&self, max_lines: usize) -> String {
		let path = format!("{}/audit_log.txt", self.data_dir);
		read_tail_lines(&path, max_lines)
	}

	pub fn read_ldk_log(&self, max_lines: usize) -> String {
		let path = format!("{}/ldk_node.log", self.data_dir);
		read_tail_lines(&path, max_lines)
	}
}

/// Read the last `max_lines` lines from a file.
fn read_tail_lines(path: &str, max_lines: usize) -> String {
	match std::fs::read_to_string(path) {
		Ok(content) => {
			let all: Vec<&str> = content.lines().collect();
			let start = all.len().saturating_sub(max_lines);
			all[start..].join("\n")
		}
		Err(e) => format!("Error reading {}: {}", path, e),
	}
}

// Thread-safe wrapper
pub type SharedStableManager = Arc<Mutex<StableChannelManager>>;
