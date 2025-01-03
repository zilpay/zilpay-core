use crate::Result;
use proto::address::Address;
use rpc::{
    methods::{EvmMethods, ZilMethods},
    network_config::NetworkConfig,
    provider::RpcProvider,
    zil_interfaces::ResultRes,
};
use serde_json::{json, Value};
use zil_errors::network::NetworkErrors;

pub fn build_nonce_request(address: &Address) -> Value {
    match address {
        Address::Secp256k1Sha256Zilliqa(_) => {
            let base16_address = address
                .get_zil_check_sum_addr()
                .unwrap_or_default() // TODO: maybe never call.
                .to_lowercase();

            RpcProvider::<NetworkConfig>::build_payload(
                json!([base16_address]),
                ZilMethods::GetBalance,
            )
        }
        Address::Secp256k1Keccak256Ethereum(_) => {
            let eth_address = address.to_eth_checksummed().unwrap_or_default();

            RpcProvider::<NetworkConfig>::build_payload(
                json!([eth_address, "latest"]),
                EvmMethods::GetTransactionCount,
            )
        }
    }
}

pub fn process_nonce_response(response: &ResultRes<Value>, address_type: &Address) -> Result<u64> {
    if let Some(error) = &response.error {
        let error_msg = format!(
            "JSON-RPC error (code: {}): {}{}",
            error.code,
            error.message,
            error
                .data
                .as_ref()
                .map(|d| format!(", data: {}", d))
                .unwrap_or_default()
        );
        return Err(NetworkErrors::RPCError(error_msg));
    }

    match address_type {
        Address::Secp256k1Sha256Zilliqa(_) => Ok(0u64),
        // response
        //     .result
        //     .as_ref()
        //     .and_then(|v| v.get("nonce"))
        //     .and_then(|v| v.as_str())
        //     .ok_or_else(|| TokenError::ABIError("Invalid nonce format".to_string()))?
        //     .parse()
        //     .map_err(|_| TokenError::ABIError("Invalid nonce value".to_string())),
        Address::Secp256k1Keccak256Ethereum(_) => Ok(response
            .result
            .as_ref()
            .and_then(|v| v.as_str())
            .and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok())
            .unwrap()),
    }
}
