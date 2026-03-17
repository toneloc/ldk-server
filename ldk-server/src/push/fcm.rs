use log::{error, info, warn};
use serde::Deserialize;
use std::path::Path;

#[derive(Clone)]
pub struct FcmService {
    credentials: Option<FcmCredentials>,
}

#[derive(Clone, Deserialize)]
struct FcmCredentials {
    private_key: String,
    client_email: String,
    project_id: String,
}

impl FcmService {
    pub fn new(data_dir: &Path) -> Self {
        let cred_path = data_dir.join("firebase-service-account.json");
        let credentials = if cred_path.exists() {
            match std::fs::read_to_string(&cred_path) {
                Ok(contents) => match serde_json::from_str::<FcmCredentials>(&contents) {
                    Ok(creds) => {
                        info!("[fcm] Loaded service account for {}", creds.project_id);
                        Some(creds)
                    }
                    Err(e) => { warn!("[fcm] Failed to parse service account: {}", e); None }
                },
                Err(e) => { warn!("[fcm] Failed to read {}: {}", cred_path.display(), e); None }
            }
        } else {
            warn!("[fcm] firebase-service-account.json not found");
            None
        };

        Self { credentials }
    }

    pub async fn send(&self, token: &str, direction: &str, node_id: &str) {
        let creds = match &self.credentials {
            Some(c) => c,
            None => { warn!("[fcm] No credentials available"); return; }
        };

        let access_token = match generate_access_token(creds).await {
            Some(t) => t,
            None => { error!("[fcm] Failed to generate access token"); return; }
        };

        let url = format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            creds.project_id
        );

        let body = serde_json::json!({
            "message": {
                "token": token,
                "data": {
                    "stability": serde_json::json!({
                        "direction": direction,
                        "node_id": node_id,
                    }).to_string()
                },
                "android": {
                    "priority": "high"
                }
            }
        });

        match reqwest::Client::new()
            .post(&url)
            .bearer_auth(&access_token)
            .json(&body)
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    info!("[fcm] Push sent to {}...", &token[..8.min(token.len())]);
                } else {
                    let text = resp.text().await.unwrap_or_default();
                    error!("[fcm] Push failed ({}): {}", status, text);
                }
            }
            Err(e) => error!("[fcm] Request failed: {}", e),
        }
    }
}

async fn generate_access_token(creds: &FcmCredentials) -> Option<String> {
    use openssl::base64;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::sign::Signer;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();

    let header = serde_json::json!({"alg": "RS256", "typ": "JWT"});
    let claims = serde_json::json!({
        "iss": creds.client_email,
        "scope": "https://www.googleapis.com/auth/firebase.messaging",
        "aud": "https://oauth2.googleapis.com/token",
        "iat": now,
        "exp": now + 3600,
    });

    let b64_encode = |data: &[u8]| -> String {
        base64::encode_block(data)
            .replace('+', "-")
            .replace('/', "_")
            .replace('=', "")
    };

    let header_b64 = b64_encode(header.to_string().as_bytes());
    let claims_b64 = b64_encode(claims.to_string().as_bytes());
    let signing_input = format!("{}.{}", header_b64, claims_b64);

    let pkey = PKey::private_key_from_pem(creds.private_key.as_bytes()).ok()?;
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey).ok()?;
    signer.update(signing_input.as_bytes()).ok()?;
    let signature = signer.sign_to_vec().ok()?;
    let sig_b64 = b64_encode(&signature);

    let jwt = format!("{}.{}", signing_input, sig_b64);

    let client = reqwest::Client::new();
    let resp = client
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", &jwt),
        ])
        .send()
        .await
        .ok()?;

    let json: serde_json::Value = resp.json().await.ok()?;
    json.get("access_token")?.as_str().map(|s| s.to_string())
}
