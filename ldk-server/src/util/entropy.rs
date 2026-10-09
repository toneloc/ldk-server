// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use std::io;
use std::path::Path;
use std::str::FromStr;

use ldk_node::bip39::{Mnemonic, WordCount};
use ldk_node::entropy::NodeEntropy;
use log::info;

use crate::util::{create_dir_all_private, read_to_string_with_limit, write_new};

const DEFAULT_MNEMONIC_FILE: &str = "keys_mnemonic";
const MNEMONIC_FILE_SIZE_LIMIT: usize = 1024;

pub(crate) fn load_or_generate_node_entropy(storage_dir: &Path) -> io::Result<NodeEntropy> {
	let mnemonic_path = storage_dir.join(DEFAULT_MNEMONIC_FILE);
	load_or_generate_entropy_at(&mnemonic_path, "on-chain funds and Lightning channels")
}

/// Loads or generates the BIP39 mnemonic backing the on-chain wallet when it is configured
/// to use entropy separate from the node seed (`node.onchain_wallet_mnemonic_path`).
pub(crate) fn load_or_generate_onchain_wallet_entropy(
	mnemonic_path: &Path,
) -> io::Result<NodeEntropy> {
	load_or_generate_entropy_at(mnemonic_path, "on-chain funds")
}

fn load_or_generate_entropy_at(mnemonic_path: &Path, protects: &str) -> io::Result<NodeEntropy> {
	let mnemonic = match read_to_string_with_limit(&mnemonic_path, MNEMONIC_FILE_SIZE_LIMIT) {
		Ok(raw) => Mnemonic::from_str(raw.trim()).map_err(|e| {
			io::Error::new(
				io::ErrorKind::InvalidData,
				format!("Invalid BIP39 mnemonic in {}: {}", mnemonic_path.display(), e),
			)
		})?,
		Err(e) if e.kind() == io::ErrorKind::NotFound => {
			if let Some(parent) = mnemonic_path.parent() {
				create_dir_all_private(parent)?;
			}
			let mnemonic = Mnemonic::generate(WordCount::Words24).map_err(io::Error::other)?;
			write_new(&mnemonic_path, format!("{}\n", mnemonic).as_bytes(), 0o600)?;
			info!(
				"Generated new BIP39 mnemonic at {}. Back up this file securely — it is required to recover {}.",
				mnemonic_path.display(),
				protects
			);
			mnemonic
		},
		Err(e) => return Err(e),
	};

	Ok(NodeEntropy::from_bip39_mnemonic(mnemonic, None))
}

/// Derives the BIP 84 account xpub (`m/84'/coin'/0'`) of the on-chain wallet backed by the
/// mnemonic at `mnemonic_path` and writes it to `out_path`. Returns the xpub string.
pub(crate) fn write_onchain_wallet_xpub(
	mnemonic_path: &Path, out_path: &Path, network: ldk_node::bitcoin::Network,
) -> io::Result<String> {
	use ldk_node::bitcoin::bip32::{ChildNumber, Xpriv, Xpub};
	use ldk_node::bitcoin::secp256k1::Secp256k1;

	let raw = read_to_string_with_limit(mnemonic_path, MNEMONIC_FILE_SIZE_LIMIT)?;
	let mnemonic = Mnemonic::from_str(raw.trim())
		.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
	let seed = mnemonic.to_seed("");
	let secp = Secp256k1::new();
	let master = Xpriv::new_master(network, &seed).map_err(io::Error::other)?;
	let coin = if network == ldk_node::bitcoin::Network::Bitcoin { 0 } else { 1 };
	let path = [
		ChildNumber::from_hardened_idx(84).unwrap(),
		ChildNumber::from_hardened_idx(coin).unwrap(),
		ChildNumber::from_hardened_idx(0).unwrap(),
	];
	let account = master.derive_priv(&secp, &path).map_err(io::Error::other)?;
	let xpub = Xpub::from_priv(&secp, &account).to_string();
	std::fs::write(out_path, format!("{xpub}\n"))?;
	Ok(xpub)
}

#[cfg(test)]
mod tests {
	use std::fs;
	use std::os::unix::fs::{MetadataExt, PermissionsExt};
	use std::path::PathBuf;

	use super::*;

	const STALE_SEED_FILE: &str = "keys_seed";
	const KNOWN_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

	fn tempdir(tag: &str) -> PathBuf {
		let dir = std::env::temp_dir().join(format!(
			"ldk-server-entropy-test-{}-{}",
			tag,
			std::process::id()
		));
		let _ = fs::remove_dir_all(&dir);
		fs::create_dir_all(&dir).unwrap();
		dir
	}

	#[test]
	fn onchain_wallet_entropy_is_independent_of_node_entropy() {
		let dir = tempdir("wallet");
		load_or_generate_node_entropy(&dir).unwrap();
		let wallet_path = dir.join("onchain_wallet_mnemonic");
		load_or_generate_onchain_wallet_entropy(&wallet_path).unwrap();
		assert!(wallet_path.exists(), "wallet mnemonic was not created");
		let perms = fs::metadata(&wallet_path).unwrap().permissions();
		assert_eq!(perms.mode() & 0o777, 0o600, "expected 0600 permissions");

		let node_mnemonic = fs::read_to_string(dir.join(DEFAULT_MNEMONIC_FILE)).unwrap();
		let wallet_mnemonic = fs::read_to_string(&wallet_path).unwrap();
		assert_eq!(wallet_mnemonic.trim().split_whitespace().count(), 24);
		assert_ne!(node_mnemonic, wallet_mnemonic, "wallet mnemonic must not equal node mnemonic");

		// Reloading keeps the same wallet mnemonic.
		load_or_generate_onchain_wallet_entropy(&wallet_path).unwrap();
		assert_eq!(fs::read_to_string(&wallet_path).unwrap(), wallet_mnemonic);
	}

	#[test]
	fn generates_mnemonic_on_fresh_start() {
		let dir = tempdir("fresh");

		load_or_generate_node_entropy(&dir).unwrap();

		let mnemonic_path = dir.join(DEFAULT_MNEMONIC_FILE);
		assert!(mnemonic_path.exists(), "keys_mnemonic was not created");

		let perms = fs::metadata(&mnemonic_path).unwrap().permissions();
		assert_eq!(perms.mode() & 0o777, 0o600, "expected 0600 permissions");

		let content = fs::read_to_string(&mnemonic_path).unwrap();
		let word_count = content.trim().split_whitespace().count();
		assert_eq!(word_count, 24, "expected 24-word mnemonic, got {}", word_count);

		let mtime_before = fs::metadata(&mnemonic_path).unwrap().mtime();
		load_or_generate_node_entropy(&dir).unwrap();
		let mtime_after = fs::metadata(&mnemonic_path).unwrap().mtime();
		assert_eq!(mtime_before, mtime_after, "mnemonic file was rewritten on second call");
	}

	#[test]
	fn rereads_existing_mnemonic_without_mutation() {
		let dir = tempdir("reread");
		let mnemonic_path = dir.join(DEFAULT_MNEMONIC_FILE);
		fs::write(&mnemonic_path, format!("{}\n", KNOWN_MNEMONIC)).unwrap();
		let bytes_before = fs::read(&mnemonic_path).unwrap();

		load_or_generate_node_entropy(&dir).unwrap();

		let bytes_after = fs::read(&mnemonic_path).unwrap();
		assert_eq!(bytes_before, bytes_after, "mnemonic file content changed");
	}

	#[test]
	fn default_entropy_ignores_stale_keys_seed() {
		let dir = tempdir("stale-seed");
		let stale_seed_path = dir.join(STALE_SEED_FILE);
		fs::write(&stale_seed_path, vec![0x42u8; 64]).unwrap();

		load_or_generate_node_entropy(&dir).unwrap();

		assert!(dir.join(DEFAULT_MNEMONIC_FILE).exists(), "keys_mnemonic was not created");
		assert!(stale_seed_path.exists(), "stale keys_seed was removed");
	}

	#[test]
	fn rejects_invalid_mnemonic_file() {
		let dir = tempdir("invalid");
		fs::write(
			dir.join(DEFAULT_MNEMONIC_FILE),
			"these words are definitely not a valid bip39 phrase at all nope",
		)
		.unwrap();

		let err = load_or_generate_node_entropy(&dir).unwrap_err();
		assert_eq!(err.kind(), io::ErrorKind::InvalidData);
	}

	#[test]
	fn rejects_oversized_mnemonic_file() {
		let dir = tempdir("oversized");
		fs::write(dir.join(DEFAULT_MNEMONIC_FILE), vec![b'a'; MNEMONIC_FILE_SIZE_LIMIT + 1])
			.unwrap();

		let err = load_or_generate_node_entropy(&dir).unwrap_err();
		assert_eq!(err.kind(), io::ErrorKind::InvalidData);
	}
}
