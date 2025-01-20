use crate::Result;
use alloy::{eips::eip2718::Encodable2718, hex};
use errors::{network::NetworkErrors, tx::TransactionErrors};
use proto::tx::TransactionReceipt;
use rpc::{
    methods::{EvmMethods, ZilMethods},
    network_config::ChainConfig,
    provider::RpcProvider,
    zil_interfaces::ResultRes,
};
use serde_json::{json, Value};

pub fn build_tx_request(tx: &TransactionReceipt) -> Value {
    match tx {
        TransactionReceipt::Zilliqa((zil, _)) => {
            RpcProvider::<ChainConfig>::build_payload(json!([zil]), ZilMethods::CreateTransaction)
        }
        TransactionReceipt::Ethereum((eth, _)) => {
            let mut encoded = Vec::with_capacity(eth.eip2718_encoded_length());
            eth.encode_2718(&mut encoded);
            let hex_tx = format!("0x{}", hex::encode(encoded));

            RpcProvider::<ChainConfig>::build_payload(
                json!([hex_tx]),
                EvmMethods::SendRawTransaction,
            )
        }
    }
}

pub fn process_tx_response(response: &ResultRes<Value>, tx: &mut TransactionReceipt) -> Result<()> {
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

    match tx {
        TransactionReceipt::Zilliqa((_zil, metadata)) => {
            if let Some(result) = &response.result {
                let info = result
                    .get("Info")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let tx_id = result
                    .get("TranID")
                    .and_then(|v| v.as_str())
                    .ok_or(TransactionErrors::InvalidTxHash)?;

                metadata.hash = Some(tx_id.to_string());
                metadata.info = Some(info.to_string());

                Ok(())
            } else {
                Err(NetworkErrors::RPCError("Invlid response".to_string()))
            }
        }
        TransactionReceipt::Ethereum((_eth, metadata)) => {
            if let Some(result) = &response.result {
                let hash = result
                    .as_str()
                    .map(|v| v.trim_start_matches("0x").to_string())
                    .ok_or(TransactionErrors::InvalidTxHash)?;

                metadata.hash = Some(hash);

                Ok(())
            } else {
                Err(NetworkErrors::RPCError("Invlid response".to_string()))
            }
        }
    }
}
