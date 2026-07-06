use a2::{
	Client as ApnsClient, ClientConfig as ApnsClientConfig, DefaultNotificationBuilder,
	NotificationBuilder, NotificationOptions, Priority,
};
use log::{error, info, warn};
use std::io::Cursor;
use std::path::Path;

const APNS_KEY_ID: &str = "Y58XTJ3N4C";
const APNS_TEAM_ID: &str = "VJF3VBKXV9";
const APNS_TOPIC: &str = "com.stablechannels.app";

#[derive(Clone)]
pub struct ApnsService {
	sandbox_client: Option<ApnsClient>,
	production_client: Option<ApnsClient>,
}

impl ApnsService {
	pub fn new(data_dir: &Path) -> Self {
		let key_path = data_dir.join("AuthKey.p8");

		let key_data = if key_path.exists() {
			match std::fs::read(&key_path) {
				Ok(data) => Some(data),
				Err(e) => {
					warn!("[apns] Failed to read AuthKey.p8: {}", e);
					None
				},
			}
		} else {
			warn!("[apns] AuthKey.p8 not found at {}", key_path.display());
			None
		};

		let sandbox_client = key_data.as_ref().and_then(|data| {
			match ApnsClient::token(
				&mut Cursor::new(data),
				APNS_KEY_ID,
				APNS_TEAM_ID,
				ApnsClientConfig::new(a2::Endpoint::Sandbox),
			) {
				Ok(c) => Some(c),
				Err(e) => {
					warn!("[apns] Failed to create sandbox client: {}", e);
					None
				},
			}
		});

		let production_client = key_data.as_ref().and_then(|data| {
			match ApnsClient::token(
				&mut Cursor::new(data),
				APNS_KEY_ID,
				APNS_TEAM_ID,
				ApnsClientConfig::new(a2::Endpoint::Production),
			) {
				Ok(c) => Some(c),
				Err(e) => {
					warn!("[apns] Failed to create production client: {}", e);
					None
				},
			}
		});

		Self { sandbox_client, production_client }
	}

	pub async fn send(&self, token: &str, direction: &str, environment: &str) {
		let client = if environment == "production" {
			&self.production_client
		} else {
			&self.sandbox_client
		};

		let client = match client {
			Some(c) => c,
			None => {
				warn!("[apns] No {} client available", environment);
				return;
			},
		};

		let title = "Stability Update";
		let body = match direction {
			"lsp_to_user" => "Receiving stability payment...",
			"user_to_lsp" => "Sending stability payment...",
			_ => "Processing payment...",
		};

		let mut payload = DefaultNotificationBuilder::new()
			.set_title(title)
			.set_body(body)
			.set_mutable_content()
			.set_sound("default")
			.build(
				token,
				NotificationOptions {
					apns_topic: Some(APNS_TOPIC),
					apns_priority: Some(Priority::High),
					..Default::default()
				},
			);

		// Add custom data so the NSE can read the payment direction
		let mut stability_data = std::collections::HashMap::new();
		stability_data.insert("direction", direction);
		let _ = payload.add_custom_data("stability", &stability_data);

		match client.send(payload).await {
			Ok(response) => info!("[apns] Push sent to {}: {:?}", &token[..8], response),
			Err(e) => error!("[apns] Push failed: {}", e),
		}
	}
}
