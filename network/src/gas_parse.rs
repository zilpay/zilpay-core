use alloy::primitives::U256;
use errors::{network::NetworkErrors, tx::TransactionErrors};
use proto::tx::TransactionRequest;
use rpc::{
    methods::EvmMethods, network_config::ChainConfig, provider::RpcProvider,
    zil_interfaces::ErrorRes,
};
use serde_json::{json, Value};

pub const SCILLA_EIP: u16 = 666;
pub const REQUIRED_EIP: u16 = 1559;

pub fn json_rpc_error(error: &ErrorRes) -> Result<(), NetworkErrors> {
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

pub fn build_fee_history_request(block_count: u64, percentiles: &[f64]) -> Value {
    RpcProvider::<ChainConfig>::build_payload(
        json!([block_count, "latest", percentiles]),
        EvmMethods::FeeHistory,
    )
}

pub fn build_evm_estimate_gas_request(tx: &TransactionRequest) -> Result<Value, NetworkErrors> {
    match tx {
        TransactionRequest::Ethereum((tx, _)) => {
            let tx_object = serde_json::to_value(&tx)
                .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;

            let request = RpcProvider::<ChainConfig>::build_payload(
                json!([tx_object]),
                EvmMethods::EstimateGas,
            );

            Ok(request)
        }
        TransactionRequest::Zilliqa(_) => Err(NetworkErrors::RPCError(
            "Zilliqa network doesn't support gas estimation".to_string(),
        )),
    }
}

pub fn process_parse_fee_history_request(value: &Value) -> Result<(U256, U256), NetworkErrors> {
    let fee_history = value;
    let base_fee = fee_history
        .get("baseFeePerGas")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.last())
        .and_then(|v| v.as_str())
        .ok_or(NetworkErrors::ResponseParseError)?;
    let base_fee = U256::from_str_radix(base_fee.trim_start_matches("0x"), 16)
        .map_err(|_| NetworkErrors::ResponseParseError)?;
    let rewards = fee_history
        .get("reward")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.last())
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.get(1))
        .and_then(|v| v.as_str())
        .ok_or(NetworkErrors::ResponseParseError)?;
    let priority_fee = U256::from_str_radix(rewards.trim_start_matches("0x"), 16)
        .map_err(|_| NetworkErrors::ResponseParseError)?;
    let max_fee = base_fee
        .saturating_mul(U256::from(2))
        .saturating_add(priority_fee);

    Ok((max_fee, priority_fee))
}
