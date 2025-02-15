use crate::Result;
use alloy::eips::eip2718::Encodable2718;
use errors::{network::NetworkErrors, tx::TransactionErrors};
use history::{
    status::TransactionStatus,
    transaction::{ChainType, HistoricalTransaction},
};
use proto::tx::TransactionReceipt;
use rpc::{
    methods::{EvmMethods, ZilMethods},
    network_config::ChainConfig,
    provider::RpcProvider,
    zil_interfaces::ResultRes,
};
use serde_json::{json, Value};

pub fn build_send_signed_tx_request(tx: &TransactionReceipt) -> Value {
    match tx {
        TransactionReceipt::Zilliqa((zil, _)) => {
            RpcProvider::<ChainConfig>::build_payload(json!([zil]), ZilMethods::CreateTransaction)
        }
        TransactionReceipt::Ethereum((eth, _)) => {
            let mut encoded = Vec::with_capacity(eth.eip2718_encoded_length());
            eth.encode_2718(&mut encoded);
            let hex_tx = alloy::hex::encode_prefixed(encoded);

            RpcProvider::<ChainConfig>::build_payload(
                json!([hex_tx]),
                EvmMethods::SendRawTransaction,
            )
        }
    }
}

pub fn build_payload_tx_receipt(tx: &HistoricalTransaction) -> Value {
    match tx.chain_type {
        ChainType::Scilla => {
            todo!()
        }
        ChainType::EVM => RpcProvider::<ChainConfig>::build_payload(
            json!([tx.transaction_hash]),
            EvmMethods::GetTransactionReceipt,
        ),
    }
}

pub fn process_tx_receipt_response(
    response: ResultRes<Value>,
    tx: &mut HistoricalTransaction,
) -> Result<()> {
    if let Some(err) = response.error {
        return Err(NetworkErrors::RPCError(err.to_string()));
    } else if let Some(result) = response.result {
        match tx.chain_type {
            ChainType::Scilla => {
                todo!()
            }
            ChainType::EVM => {
                let receipt: alloy::rpc::types::TransactionReceipt = serde_json::from_value(result)
                    .map_err(|e| NetworkErrors::ParseHttpError(e.to_string()))?;

                tx.block_number = receipt.block_number;
                tx.gas_used = Some(receipt.gas_used);
                tx.blob_gas_used = receipt.blob_gas_used;
                tx.blob_gas_price = receipt.blob_gas_price;
                tx.effective_gas_price = Some(receipt.effective_gas_price);

                if receipt.status() {
                    tx.status = TransactionStatus::Confirmed;
                } else {
                    tx.status = TransactionStatus::Rejected;
                }

                dbg!(&receipt);
                // TODO: calc fee
                // tx.effective_gas_price = Some(receipt.effective_gas_price);

                return Ok(());
            }
        };
    } else {
        return Err(TransactionErrors::NoTxWithHash(tx.transaction_hash.clone()).into());
    }
}

pub fn process_tx_send_response(
    response: &ResultRes<Value>,
    tx: &mut TransactionReceipt,
) -> Result<()> {
    if let Some(error) = &response.error {
        return Err(NetworkErrors::RPCError(error.to_string()));
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
