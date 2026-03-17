pub mod apns;
pub mod fcm;
pub mod tokens;

use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;
use log::{info, warn};

pub struct PushService {
    apns: apns::ApnsService,
    fcm: fcm::FcmService,
    data_dir: String,
    last_push_sent: HashMap<String, Instant>,
}

const PUSH_COOLDOWN_SECS: u64 = 600; // 10 minutes

impl PushService {
    pub fn new(data_dir: &Path) -> Self {
        tokens::init_db(data_dir);
        Self {
            apns: apns::ApnsService::new(data_dir),
            fcm: fcm::FcmService::new(data_dir),
            data_dir: data_dir.to_string_lossy().to_string(),
            last_push_sent: HashMap::new(),
        }
    }

    pub fn register_token(&self, token: &str, platform: &str, node_id: &str, environment: &str) {
        tokens::save_token(&self.data_dir, token, platform, node_id, environment);
    }

    pub fn should_notify(&self, node_id: &str) -> bool {
        match self.last_push_sent.get(node_id) {
            Some(last) => last.elapsed().as_secs() >= PUSH_COOLDOWN_SECS,
            None => true,
        }
    }

    pub fn mark_notified(&mut self, node_id: &str) {
        self.last_push_sent.insert(node_id.to_string(), Instant::now());
    }

    pub fn notify(&mut self, node_id: &str, direction: &str) {
        if !self.should_notify(node_id) {
            info!("[push] Skipping notification for {} (cooldown)", node_id);
            return;
        }

        let token_info = match tokens::load_token_for_node(&self.data_dir, node_id) {
            Some(t) => t,
            None => {
                warn!("[push] No push token registered for node {}", node_id);
                return;
            }
        };

        self.mark_notified(node_id);

        let token = token_info.token.clone();
        let platform = token_info.platform.clone();
        let environment = token_info.environment.clone();
        let node_id_owned = node_id.to_string();
        let direction_owned = direction.to_string();

        if platform == "android" {
            let fcm = self.fcm.clone();
            tokio::spawn(async move {
                fcm.send(&token, &direction_owned, &node_id_owned).await;
            });
        } else {
            let apns = self.apns.clone();
            tokio::spawn(async move {
                apns.send(&token, &direction_owned, &environment).await;
            });
        }

        info!("[push] Sent {} notification to {} ({})", direction, node_id, platform);
    }
}
