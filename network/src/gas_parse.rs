use errors::network::NetworkErrors;
use proto::tx::TransactionRequest;
use rpc::{
    methods::{EvmMethods, ZilMethods},
    network_config::ChainConfig,
    provider::RpcProvider,
};
use serde_json::{json, Value};

pub fn build_fee_history_request(block_count: u64, percentiles: &[f64]) -> Value {
    RpcProvider::<ChainConfig>::build_payload(
        json!([block_count, "latest", percentiles]),
        EvmMethods::FeeHistory,
    )
}

pub fn build_emv_eip1559_gas_price_request() -> Value {
    RpcProvider::<ChainConfig>::build_payload(json!([]), EvmMethods::MaxPriorityFeePerGas)
}

pub fn build_evm_gas_price_request() -> Value {
    RpcProvider::<ChainConfig>::build_payload(json!([]), EvmMethods::GasPrice)
}

pub fn build_scilla_gas_price_request() -> Value {
    RpcProvider::<ChainConfig>::build_payload(json!([]), ZilMethods::GetMinimumGasPrice)
}

pub fn build_estimate_gas_request(tx: &TransactionRequest) -> Result<Value, NetworkErrors> {
    match tx {
        TransactionRequest::Ethereum((tx, _)) => {
            // let params: String = tx.into();

            Ok(json!([]))
        }
        TransactionRequest::Zilliqa(_) => Err(NetworkErrors::RPCError(
            "Zilliqa network doesn't support gas estimation".to_string(),
        )),
    }
}
