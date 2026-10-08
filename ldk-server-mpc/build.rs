//! Links the statically built Coinbase `cb-mpc` library and its custom OpenSSL `libcrypto`.
//!
//! Configuration (environment variables, all optional):
//! - `CBMPC_DIR`: cb-mpc checkout root. Defaults to `<workspace>/../cb-mpc`.
//! - `CBMPC_LIB_DIR`: directory containing `libcbmpc.a`. Defaults to `$CBMPC_DIR/lib/Release`.
//! - `CBMPC_OPENSSL_ROOT`: custom OpenSSL install root. Defaults to
//!   `$CBMPC_DIR/openssl-3.6.4-install`.
//!
//! See `ldk-server-mpc/README.md` for how to build cb-mpc.

use std::env;
use std::path::PathBuf;

fn main() {
	println!("cargo:rerun-if-env-changed=CBMPC_DIR");
	println!("cargo:rerun-if-env-changed=CBMPC_LIB_DIR");
	println!("cargo:rerun-if-env-changed=CBMPC_OPENSSL_ROOT");

	let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
	let cbmpc_dir = env::var("CBMPC_DIR")
		.map(PathBuf::from)
		.unwrap_or_else(|_| manifest_dir.join("..").join("..").join("cb-mpc"));
	let lib_dir = env::var("CBMPC_LIB_DIR")
		.map(PathBuf::from)
		.unwrap_or_else(|_| cbmpc_dir.join("lib").join("Release"));
	let openssl_root = env::var("CBMPC_OPENSSL_ROOT")
		.map(PathBuf::from)
		.unwrap_or_else(|_| cbmpc_dir.join("openssl-3.6.4-install"));

	let libcbmpc = lib_dir.join("libcbmpc.a");
	if !libcbmpc.exists() {
		panic!(
			"libcbmpc.a not found at {}. Build cb-mpc first (see ldk-server-mpc/README.md) or set CBMPC_LIB_DIR.",
			libcbmpc.display()
		);
	}
	let openssl_lib_dir = ["lib", "lib64"]
		.iter()
		.map(|d| openssl_root.join(d))
		.find(|d| d.join("libcrypto.a").exists())
		.unwrap_or_else(|| {
			panic!(
				"libcrypto.a not found under {}. Build cb-mpc's custom OpenSSL first or set CBMPC_OPENSSL_ROOT.",
				openssl_root.display()
			)
		});

	println!("cargo:rustc-link-search=native={}", lib_dir.display());
	println!("cargo:rustc-link-search=native={}", openssl_lib_dir.display());
	println!("cargo:rustc-link-lib=static=cbmpc");
	println!("cargo:rustc-link-lib=static=crypto");

	let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
	if target_os == "macos" {
		println!("cargo:rustc-link-lib=dylib=c++");
	} else {
		println!("cargo:rustc-link-lib=dylib=stdc++");
	}
}
