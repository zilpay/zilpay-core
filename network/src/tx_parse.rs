use std::time::{SystemTime, UNIX_EPOCH};

use crate::Result;
use alloy::eips::eip2718::Encodable2718;
use errors::{network::NetworkErrors, tx::TransactionErrors};
use history::{
    status::TransactionStatus,
    transaction::{ChainType, HistoricalTransaction},
};
use proto::{address::Address, tx::TransactionReceipt, U256};
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
        ChainType::Scilla => RpcProvider::<ChainConfig>::build_payload(
            json!([tx.transaction_hash]),
            ZilMethods::GetTransactionStatus,
        ),
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
                let amount = result
                    .get("amount")
                    .and_then(|a| a.as_str())
                    .and_then(|a| a.parse::<U256>().ok())
                    .unwrap_or(tx.amount);
                let gas_limit = result
                    .get("gasLimit")
                    .and_then(|a| a.as_str())
                    .and_then(|a| a.parse::<u128>().ok())
                    .unwrap_or(tx.gas_limit.unwrap_or_default());
                let gas_price = result
                    .get("gasPrice")
                    .and_then(|a| a.as_str())
                    .and_then(|a| a.parse::<u128>().ok())
                    .unwrap_or(tx.gas_price.unwrap_or_default());
                let nonce = result
                    .get("nonce")
                    .and_then(|a| a.as_str())
                    .and_then(|a| a.parse::<u128>().ok())
                    .unwrap_or(tx.nonce);
                let mb_status = result
                    .get("status")
                    .and_then(|a| a.as_number())
                    .and_then(|a| a.as_u64())
                    .and_then(|status| Some(status as u8));
                let mb_sender = result
                    .get("senderAddr")
                    .and_then(|a| a.as_str())
                    .and_then(|a| Address::from_zil_base16(a).ok());

                tx.amount = amount;
                tx.gas_limit = Some(gas_limit);
                tx.gas_price = Some(gas_price);
                tx.nonce = nonce;
                tx.fee = gas_price * gas_limit;

                if let Some(status) = mb_status {
                    match status {
                        1 | 2 | 4 | 5 | 6 => tx.status = TransactionStatus::Pending,
                        3 => tx.status = TransactionStatus::Confirmed,
                        _ => tx.status = TransactionStatus::Rejected,
                    }
                    tx.status_code = mb_status;
                }

                if tx.status == TransactionStatus::Pending {
                    const MINUTES_IN_SECONDS: u64 = 10 * 60; // 10 minutes in seconds

                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

                    let cutoff = now - MINUTES_IN_SECONDS;

                    if tx.timestamp < cutoff {
                        tx.status = TransactionStatus::Rejected;
                        tx.error = Some("timeout".to_string());
                    }
                }

                if let Some(sender) = mb_sender {
                    tx.sender = sender.auto_format();
                }

                return Ok(());
            }
            ChainType::EVM => {
                let receipt: alloy::rpc::types::TransactionReceipt = serde_json::from_value(result)
                    .map_err(|e| NetworkErrors::ParseHttpError(e.to_string()))?;

                tx.sender = receipt.from.to_string();
                tx.contract_address = receipt.contract_address.map(|a| a.to_string());

                if let Some(to) = receipt.to {
                    tx.recipient = to.to_string();
                }

                tx.block_number = receipt.block_number.map(|b| b as u128);
                tx.gas_used = Some(receipt.gas_used as u128);
                tx.blob_gas_used = receipt.blob_gas_used.map(|b| b as u128);
                tx.blob_gas_price = receipt.blob_gas_price;
                tx.effective_gas_price = Some(receipt.effective_gas_price);

                if receipt.status() {
                    tx.status = TransactionStatus::Confirmed;
                } else {
                    tx.status = TransactionStatus::Rejected;
                }

                let mut total_cost = receipt.gas_used as u128 * receipt.effective_gas_price;

                if let Some(blob_gas_used) = receipt.blob_gas_used {
                    if let Some(blob_gas_price) = receipt.blob_gas_price {
                        total_cost += blob_gas_used as u128 * blob_gas_price;
                    }
                }

                tx.fee = total_cost;

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
                let hash = result.as_str().ok_or(TransactionErrors::InvalidTxHash)?;

                metadata.hash = Some(hash.to_string());

                Ok(())
            } else {
                Err(NetworkErrors::RPCError("Invlid response".to_string()))
            }
        }
    }
}
