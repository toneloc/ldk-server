use log::{error, info};
use rusqlite::Connection;
use std::path::Path;

pub struct TokenInfo {
	pub token: String,
	pub platform: String,
	pub environment: String,
}

fn db_path(data_dir: &str) -> String {
	format!("{}/push_tokens.db", data_dir)
}

pub fn init_db(data_dir: &Path) {
	let path = db_path(&data_dir.to_string_lossy());
	let conn = match Connection::open(&path) {
		Ok(c) => c,
		Err(e) => {
			error!("[push-tokens] Failed to open DB: {}", e);
			return;
		},
	};

	conn.execute_batch(
		"CREATE TABLE IF NOT EXISTS push_tokens (
            device_token TEXT PRIMARY KEY,
            platform TEXT NOT NULL,
            registered_at INTEGER,
            node_id TEXT,
            environment TEXT,
            last_seen INTEGER
        )",
	)
	.unwrap_or_else(|e| error!("[push-tokens] Failed to create table: {}", e));
}

pub fn save_token(data_dir: &str, token: &str, platform: &str, node_id: &str, environment: &str) {
	let path = db_path(data_dir);
	let conn = match Connection::open(&path) {
		Ok(c) => c,
		Err(e) => {
			error!("[push-tokens] Failed to open DB: {}", e);
			return;
		},
	};

	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap_or_default()
		.as_secs() as i64;

	match conn.execute(
        "INSERT OR REPLACE INTO push_tokens (device_token, platform, registered_at, node_id, environment, last_seen)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![token, platform, now, node_id, environment, now],
    ) {
        Ok(_) => info!("[push-tokens] Saved token for node {} ({})", node_id, platform),
        Err(e) => error!("[push-tokens] Failed to save token: {}", e),
    }
}

pub fn load_token_for_node(data_dir: &str, node_id: &str) -> Option<TokenInfo> {
	let path = db_path(data_dir);
	let conn = Connection::open(&path).ok()?;

	let cutoff = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap_or_default()
		.as_secs() as i64
		- (30 * 86400); // 30 days

	conn.query_row(
		"SELECT device_token, platform, environment FROM push_tokens
         WHERE node_id = ?1 AND last_seen > ?2
         ORDER BY last_seen DESC LIMIT 1",
		rusqlite::params![node_id, cutoff],
		|row| {
			Ok(TokenInfo {
				token: row.get(0)?,
				platform: row.get(1)?,
				environment: row
					.get::<_, Option<String>>(2)?
					.unwrap_or_else(|| "sandbox".to_string()),
			})
		},
	)
	.ok()
}
