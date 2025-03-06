use alloy::primitives::U256;
use errors::{network::NetworkErrors, tx::TransactionErrors};
use proto::{address::Address, tx::TransactionRequest};
use rpc::{
    methods::{EvmMethods, ZilMethods},
    network_config::ChainConfig,
    provider::RpcProvider,
    zil_interfaces::ErrorRes,
};
use serde_json::{json, Value};

use crate::nonce_parser::build_nonce_request;

#[derive(Debug, Default)]
pub struct GasFeeHistory {
    pub max_fee: U256,
    pub priority_fee: U256,
    pub base_fee: U256,
}

#[derive(Debug)]
pub struct RequiredTxParams {
    pub gas_price: U256,
    pub max_priority_fee: U256,
    pub fee_history: GasFeeHistory,
    pub tx_estimate_gas: U256,
    pub blob_base_fee: U256,
    pub nonce: u64,
}

pub const EIP1559: u16 = 1559;
pub const EIP4844: u16 = 4844;

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

pub fn build_batch_gas_request(
    tx: &TransactionRequest,
    block_count: u64,
    percentiles: &[f64],
    features: &[u16],
    sender: &Address,
) -> Result<Vec<Value>, NetworkErrors> {
    let mut requests = Vec::with_capacity(4);

    requests.push(build_nonce_request(sender));

    match tx {
        TransactionRequest::Zilliqa(_) => {
            requests.push(RpcProvider::<ChainConfig>::build_payload(
                json!([]),
                ZilMethods::GetMinimumGasPrice,
            ));
            return Ok(requests);
        }
        TransactionRequest::Ethereum(_) => {
            requests.push(RpcProvider::<ChainConfig>::build_payload(
                json!([]),
                EvmMethods::GasPrice,
            ));
        }
    }

    let tx_object = match tx {
        TransactionRequest::Zilliqa(_) => {
            return Err(TransactionErrors::InvalidTransaction)?;
        }
        TransactionRequest::Ethereum((tx, _)) => serde_json::to_value(&tx)
            .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?,
    };
    let request_estimate_gas =
        RpcProvider::<ChainConfig>::build_payload(json!([tx_object]), EvmMethods::EstimateGas);

    requests.push(request_estimate_gas);

    if features.contains(&EIP1559) {
        requests.push(RpcProvider::<ChainConfig>::build_payload(
            json!([]),
            EvmMethods::MaxPriorityFeePerGas,
        ));
        requests.push(build_fee_history_request(block_count, percentiles));
    }

    if features.contains(&EIP4844) {
        requests.push(RpcProvider::<ChainConfig>::build_payload(
            json!([]),
            EvmMethods::BlobBaseFee,
        ));
    }

    Ok(requests)
}

pub fn process_parse_fee_history_request(value: &Value) -> Result<GasFeeHistory, NetworkErrors> {
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

    Ok(GasFeeHistory {
        max_fee,
        priority_fee,
        base_fee,
    })
}
