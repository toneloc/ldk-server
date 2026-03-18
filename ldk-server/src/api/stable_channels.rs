use ldk_server_protos::stable::{
	EditStableChannelRequest, EditStableChannelResponse, GetPriceRequest, GetPriceResponse,
	ListStableChannelsRequest, ListStableChannelsResponse, LogRequest, LogResponse,
	StableChannelInfo,
};

use crate::api::error::LdkServerError;
use crate::service::Context;

pub(crate) fn handle_get_price_request(
	context: Context, _request: GetPriceRequest,
) -> Result<GetPriceResponse, LdkServerError> {
	let mgr = context.stable_manager.lock().unwrap();
	Ok(GetPriceResponse { price: mgr.btc_price })
}

pub(crate) fn handle_list_stable_channels_request(
	context: Context, _request: ListStableChannelsRequest,
) -> Result<ListStableChannelsResponse, LdkServerError> {
	let mgr = context.stable_manager.lock().unwrap();
	let channels: Vec<StableChannelInfo> = mgr
		.stable_channels
		.iter()
		.map(|sc| StableChannelInfo {
			channel_id: sc.channel_id.to_string(),
			counterparty: sc.counterparty.to_string(),
			expected_usd: sc.expected_usd.0,
			expected_msats: sc.backing_sats * 1000,
			latest_price: sc.latest_price,
			note: sc.note.clone().unwrap_or_default(),
			is_stable_receiver: sc.is_stable_receiver,
		})
		.collect();
	Ok(ListStableChannelsResponse { channels })
}

pub(crate) fn handle_edit_stable_channel_request(
	context: Context, request: EditStableChannelRequest,
) -> Result<EditStableChannelResponse, LdkServerError> {
	let mut mgr = context.stable_manager.lock().unwrap();
	let target_usd = request.expected_usd.unwrap_or(0.0);
	let note = request.note;
	match mgr.edit_stable_channel(&request.channel_id, target_usd, note, &context.node) {
		Ok(msg) => Ok(EditStableChannelResponse { ok: true, status: msg }),
		Err(msg) => Ok(EditStableChannelResponse { ok: false, status: msg }),
	}
}

pub(crate) fn handle_audit_log_request(
	context: Context, request: LogRequest,
) -> Result<LogResponse, LdkServerError> {
	let max_lines = if request.max_lines == 0 { 200 } else { request.max_lines as usize };
	let mgr = context.stable_manager.lock().unwrap();
	let content = mgr.read_audit_log(max_lines);
	Ok(LogResponse { content })
}

pub(crate) fn handle_ldk_log_request(
	context: Context, request: LogRequest,
) -> Result<LogResponse, LdkServerError> {
	let max_lines = if request.max_lines == 0 { 200 } else { request.max_lines as usize };
	let mgr = context.stable_manager.lock().unwrap();
	let content = mgr.read_ldk_log(max_lines);
	Ok(LogResponse { content })
}
