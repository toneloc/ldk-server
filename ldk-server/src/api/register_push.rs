use ldk_server_protos::stable::{RegisterPushRequest, RegisterPushResponse};
use log::info;

use crate::api::error::LdkServerError;
use crate::service::Context;

pub(crate) fn handle_register_push_request(
	context: Context, request: RegisterPushRequest,
) -> Result<RegisterPushResponse, LdkServerError> {
	let ps = context.push_service.lock().unwrap();
	ps.register_token(&request.token, &request.platform, &request.node_id, &request.environment);

	info!(
		"[push] Registered {} device for node {}",
		request.platform,
		if request.node_id.len() > 16 { &request.node_id[..16] } else { &request.node_id }
	);

	Ok(RegisterPushResponse { ok: true })
}
