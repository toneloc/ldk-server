// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use std::str::FromStr;

use ldk_node::bitcoin::secp256k1::PublicKey;
use ldk_node::bitcoin::Address;
use ldk_node::UserChannelId;
use ldk_server_protos::api::{
	SpliceInRequest, SpliceInResponse, SpliceOutRequest, SpliceOutResponse,
};

use crate::api::error::LdkServerError;
use crate::api::error::LdkServerErrorCode::InvalidRequestError;
use crate::service::Context;

pub(crate) fn handle_splice_in_request(
	context: Context, request: SpliceInRequest,
) -> Result<SpliceInResponse, LdkServerError> {
	let user_channel_id = parse_user_channel_id(&request.user_channel_id)?;
	let counterparty_node_id = parse_counterparty_node_id(&request.counterparty_node_id)?;

	context.node.splice_in(&user_channel_id, counterparty_node_id, request.splice_amount_sats)?;

	Ok(SpliceInResponse {})
}

pub(crate) fn handle_splice_out_request(
	context: Context, request: SpliceOutRequest,
) -> Result<SpliceOutResponse, LdkServerError> {
	let user_channel_id = parse_user_channel_id(&request.user_channel_id)?;
	let counterparty_node_id = parse_counterparty_node_id(&request.counterparty_node_id)?;

	let address = request
		.address
		.map(|address| {
			Address::from_str(&address)
				.and_then(|address| address.require_network(context.node.config().network))
				.map_err(|_| ldk_node::NodeError::InvalidAddress)
		})
		.unwrap_or_else(|| context.node.onchain_payment().new_address())
		.map_err(|_| {
			LdkServerError::new(
				InvalidRequestError,
				"Address is not valid for the configured network.".to_string(),
			)
		})?;

	context.node.splice_out(
		&user_channel_id,
		counterparty_node_id,
		&address,
		request.splice_amount_sats,
	)?;

	Ok(SpliceOutResponse { address: address.to_string() })
}

fn parse_user_channel_id(id: &str) -> Result<UserChannelId, LdkServerError> {
	let parsed = id.parse::<u128>().map_err(|_| {
		LdkServerError::new(InvalidRequestError, "Invalid UserChannelId.".to_string())
	})?;
	Ok(UserChannelId(parsed))
}

fn parse_counterparty_node_id(id: &str) -> Result<PublicKey, LdkServerError> {
	PublicKey::from_str(id).map_err(|e| {
		LdkServerError::new(
			InvalidRequestError,
			format!("Invalid counterparty node ID, error: {}", e),
		)
	})
}

#[cfg(test)]
mod tests {
	use super::*;

	// Helper function to create a valid test public key
	fn valid_public_key_str() -> &'static str {
		"02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
	}

	// Tests for parse_user_channel_id

	#[test]
	fn test_parse_user_channel_id_valid_small() {
		let result = parse_user_channel_id("123456789");
		assert!(result.is_ok());
		let channel_id = result.unwrap();
		assert_eq!(channel_id.0, 123456789);
	}

	#[test]
	fn test_parse_user_channel_id_valid_large() {
		let result = parse_user_channel_id("340282366920938463463374607431768211455");
		assert!(result.is_ok());
		let channel_id = result.unwrap();
		assert_eq!(channel_id.0, 340282366920938463463374607431768211455);
	}

	#[test]
	fn test_parse_user_channel_id_valid_zero() {
		let result = parse_user_channel_id("0");
		assert!(result.is_ok());
		let channel_id = result.unwrap();
		assert_eq!(channel_id.0, 0);
	}

	#[test]
	fn test_parse_user_channel_id_invalid_empty() {
		let result = parse_user_channel_id("");
		assert!(result.is_err());
		let error = result.unwrap_err();
		assert_eq!(error.error_code, InvalidRequestError);
		assert!(error.message.contains("Invalid UserChannelId"));
	}

	#[test]
	fn test_parse_user_channel_id_invalid_non_numeric() {
		let result = parse_user_channel_id("not_a_number");
		assert!(result.is_err());
		let error = result.unwrap_err();
		assert_eq!(error.error_code, InvalidRequestError);
		assert!(error.message.contains("Invalid UserChannelId"));
	}

	#[test]
	fn test_parse_user_channel_id_invalid_alphanumeric() {
		let result = parse_user_channel_id("123abc456");
		assert!(result.is_err());
		let error = result.unwrap_err();
		assert_eq!(error.error_code, InvalidRequestError);
	}

	#[test]
	fn test_parse_user_channel_id_invalid_negative() {
		let result = parse_user_channel_id("-123");
		assert!(result.is_err());
		let error = result.unwrap_err();
		assert_eq!(error.error_code, InvalidRequestError);
	}

	#[test]
	fn test_parse_user_channel_id_invalid_overflow() {
		let result = parse_user_channel_id("340282366920938463463374607431768211456");
		assert!(result.is_err());
		let error = result.unwrap_err();
		assert_eq!(error.error_code, InvalidRequestError);
	}

	#[test]
	fn test_parse_user_channel_id_with_spaces() {
		let result = parse_user_channel_id("123 456");
		assert!(result.is_err());
		let error = result.unwrap_err();
		assert_eq!(error.error_code, InvalidRequestError);
	}

	// Tests for parse_counterparty_node_id

	#[test]
	fn test_parse_counterparty_node_id_valid_compressed() {
		let result = parse_counterparty_node_id(valid_public_key_str());
		assert!(result.is_ok());
		let pubkey = result.unwrap();
		assert_eq!(pubkey.to_string(), valid_public_key_str());
	}

	#[test]
	fn test_parse_counterparty_node_id_valid_another() {
		// Test with the same valid key to ensure consistency
		let result = parse_counterparty_node_id(valid_public_key_str());
		assert!(result.is_ok());
		let pubkey = result.unwrap();
		assert_eq!(pubkey.to_string(), valid_public_key_str());
	}

	#[test]
	fn test_parse_counterparty_node_id_invalid_empty() {
		let result = parse_counterparty_node_id("");
		assert!(result.is_err());
		let error = result.unwrap_err();
		assert_eq!(error.error_code, InvalidRequestError);
		assert!(error.message.contains("Invalid counterparty node ID"));
	}

	#[test]
	fn test_parse_counterparty_node_id_invalid_too_short() {
		let result = parse_counterparty_node_id("02f9308a019258c31049344f85f89d5229b531c8");
		assert!(result.is_err());
		let error = result.unwrap_err();
		assert_eq!(error.error_code, InvalidRequestError);
		assert!(error.message.contains("Invalid counterparty node ID"));
	}

	#[test]
	fn test_parse_counterparty_node_id_invalid_non_hex() {
		let result = parse_counterparty_node_id(
			"02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036fX",
		);
		assert!(result.is_err());
		let error = result.unwrap_err();
		assert_eq!(error.error_code, InvalidRequestError);
	}

	#[test]
	fn test_parse_counterparty_node_id_invalid_wrong_prefix() {
		let result = parse_counterparty_node_id(
			"01f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
		);
		assert!(result.is_err());
		let error = result.unwrap_err();
		assert_eq!(error.error_code, InvalidRequestError);
	}

	#[test]
	fn test_parse_counterparty_node_id_invalid_odd_length() {
		let result = parse_counterparty_node_id(
			"02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f",
		);
		assert!(result.is_err());
		let error = result.unwrap_err();
		assert_eq!(error.error_code, InvalidRequestError);
	}

	#[test]
	fn test_parse_counterparty_node_id_error_message_includes_details() {
		let result = parse_counterparty_node_id("invalid");
		assert!(result.is_err());
		let error = result.unwrap_err();
		assert!(error.message.contains("Invalid counterparty node ID"));
		assert!(error.message.contains("error:"));
	}

	// Integration tests for parsing both IDs

	#[test]
	fn test_both_parsing_functions_work_together() {
		let channel_id_str = "42";
		let node_id_str = valid_public_key_str();

		let channel_id = parse_user_channel_id(channel_id_str);
		let node_id = parse_counterparty_node_id(node_id_str);

		assert!(channel_id.is_ok());
		assert!(node_id.is_ok());

		assert_eq!(channel_id.unwrap().0, 42);
		assert_eq!(node_id.unwrap().to_string(), node_id_str);
	}

	#[test]
	fn test_parsing_fails_gracefully_with_bad_channel_id() {
		let channel_id_str = "not_a_number";
		let node_id_str = valid_public_key_str();

		let channel_id = parse_user_channel_id(channel_id_str);
		let node_id = parse_counterparty_node_id(node_id_str);

		assert!(channel_id.is_err());
		assert!(node_id.is_ok());
	}

	#[test]
	fn test_parsing_fails_gracefully_with_bad_node_id() {
		let channel_id_str = "42";
		let node_id_str = "invalid_pubkey";

		let channel_id = parse_user_channel_id(channel_id_str);
		let node_id = parse_counterparty_node_id(node_id_str);

		assert!(channel_id.is_ok());
		assert!(node_id.is_err());
	}
}
