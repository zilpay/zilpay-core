use proto::address::Address;
use rpc::{
    methods::{EvmMethods, ZilMethods},
    network_config::ChainConfig,
    provider::RpcProvider,
    zil_interfaces::ResultRes,
};
use serde_json::{json, Value};

pub fn build_last_block_header_request(address: &Address, block_number: Option<u128>) -> Value {
    match address {
        Address::Secp256k1Sha256(_) => {
            if let Some(number) = block_number {
                RpcProvider::<ChainConfig>::build_payload(
                    json!([number.to_string()]),
                    ZilMethods::GetTxBlock,
                )
            } else {
                RpcProvider::<ChainConfig>::build_payload(json!([]), ZilMethods::GetLatestTxBlock)
            }
        }
        Address::Secp256k1Keccak256(_) => {
            let block_number = if let Some(number) = block_number {
                &format!("0x{:x}", number)
            } else {
                "latest"
            };
            RpcProvider::<ChainConfig>::build_payload(
                json!([block_number, false]),
                EvmMethods::GetBlockByNumber,
            )
        }
    }
}

pub fn process_get_timestampt_block_response(
    response: &ResultRes<Value>,
    address_type: &Address,
) -> (u128, u64) {
    let timestamp = match address_type {
        Address::Secp256k1Sha256(_) => response
            .result
            .as_ref()
            .and_then(|v| v.get("header"))
            .and_then(|h| h.get("Timestamp"))
            .and_then(|t| t.as_str())
            .and_then(|t| t.parse::<u64>().ok())
            .and_then(|t| Some(t / 1000000)) // Zilliqa shit time
            .unwrap_or_default(),
        Address::Secp256k1Keccak256(_) => response
            .result
            .as_ref()
            .and_then(|v| v.get("timestamp"))
            .and_then(|v| v.as_str())
            .and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok())
            .unwrap_or_default(),
    };
    let blocknumber = match address_type {
        Address::Secp256k1Sha256(_) => response
            .result
            .as_ref()
            .and_then(|v| v.get("header"))
            .and_then(|h| h.get("BlockNum"))
            .and_then(|t| t.as_str())
            .and_then(|t| t.parse::<u128>().ok())
            .unwrap_or_default(),
        Address::Secp256k1Keccak256(_) => response
            .result
            .as_ref()
            .and_then(|v| v.get("number"))
            .and_then(|v| v.as_str())
            .and_then(|v| u128::from_str_radix(v.trim_start_matches("0x"), 16).ok())
            .unwrap_or_default(),
    };

    (blocknumber, timestamp)
}
