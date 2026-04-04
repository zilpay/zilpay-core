use std::time::{SystemTime, UNIX_EPOCH};

use crate::Result;
use alloy::eips::Encodable2718;
use errors::{network::NetworkErrors, tx::TransactionErrors};
use history::{status::TransactionStatus, transaction::HistoricalTransaction};
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
        TransactionReceipt::Zilliqa((zil, metadata)) => {
            dbg!(
                "[build_send_signed_tx_request] variant=Zilliqa",
                &metadata.hash,
                &metadata.chain_hash
            );
            RpcProvider::<ChainConfig>::build_payload(json!([zil]), ZilMethods::CreateTransaction)
        }
        TransactionReceipt::Ethereum((eth, metadata)) => {
            let mut encoded = Vec::with_capacity(eth.eip2718_encoded_length());
            eth.encode_2718(&mut encoded);
            let hex_tx = alloy::hex::encode_prefixed(encoded);

            dbg!(
                "[build_send_signed_tx_request] variant=Ethereum",
                &metadata.hash,
                &metadata.chain_hash,
                &hex_tx
            );

            RpcProvider::<ChainConfig>::build_payload(
                json!([hex_tx]),
                EvmMethods::SendRawTransaction,
            )
        }
        _ => {
            dbg!("[build_send_signed_tx_request] variant=unsupported");
            json!({"error": "transactions not supported in EVM operations"})
        }
    }
}

pub fn build_payload_tx_receipt(tx: &HistoricalTransaction) -> Value {
    if tx.scilla.is_some() {
        let hash = tx
            .get_scilla()
            .and_then(|s| {
                s.get("hash")
                    .and_then(|h| h.as_str())
                    .map(|s| s.to_string())
            })
            .unwrap_or_default();
        RpcProvider::<ChainConfig>::build_payload(json!([hash]), ZilMethods::GetTransactionStatus)
    } else if tx.tron.is_some() {
        RpcProvider::<ChainConfig>::build_payload(
            json!([tx.metadata.hash.clone().unwrap_or_default()]),
            EvmMethods::GetTransactionReceipt,
        )
    } else {
        let hash = tx
            .get_evm()
            .and_then(|e| {
                e.get("transactionHash")
                    .and_then(|h| h.as_str())
                    .map(|s| s.to_string())
            })
            .unwrap_or_default();
        RpcProvider::<ChainConfig>::build_payload(json!([hash]), EvmMethods::GetTransactionReceipt)
    }
}

pub fn process_tx_receipt_response(
    response: ResultRes<Value>,
    tx: &mut HistoricalTransaction,
) -> Result<()> {
    const MINUTES_IN_SECONDS: u64 = 10 * 60;

    if response.error.is_some() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let cutoff = now - MINUTES_IN_SECONDS;
        let tx_timestamp_secs = tx.timestamp / 1000;

        if tx_timestamp_secs < cutoff {
            tx.status = TransactionStatus::Failed;
        }

        return Ok(());
    }

    if let Some(result) = response.result {
        if tx.scilla.is_some() {
            tx.update_from_scilla_result(result);

            if tx.status == TransactionStatus::Pending {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                let cutoff = now - MINUTES_IN_SECONDS;
                let tx_timestamp_secs = tx.timestamp / 1000;

                if tx_timestamp_secs < cutoff {
                    tx.status = TransactionStatus::Failed;
                }
            }
        } else {
            tx.update_from_evm_receipt(result);
        }

        return Ok(());
    }

    let hash = tx
        .metadata
        .hash
        .clone()
        .unwrap_or_else(|| "unknown".to_string());
    Err(TransactionErrors::NoTxWithHash(hash).into())
}

pub fn process_tx_send_response(
    response: &ResultRes<Value>,
    tx: &mut TransactionReceipt,
) -> Result<()> {
    dbg!("[process_tx_send_response] response =", &response);
    dbg!(
        "[process_tx_send_response] tx variant hash before =",
        tx.hash()
    );

    if let Some(error) = &response.error {
        dbg!("[process_tx_send_response] error =", error);
        return Err(NetworkErrors::RPCError(error.to_string()));
    }

    match tx {
        TransactionReceipt::Zilliqa((_zil, metadata)) => {
            dbg!(
                "[process_tx_send_response] matching Zilliqa variant",
                &metadata.hash
            );
            if let Some(result) = &response.result {
                dbg!("[process_tx_send_response] Zilliqa result =", result);
                let info = result
                    .get("Info")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let tx_id = result
                    .get("TranID")
                    .and_then(|v| v.as_str())
                    .ok_or(TransactionErrors::InvalidTxHash)?;

                dbg!(
                    "[process_tx_send_response] Zilliqa TranID =",
                    tx_id,
                    "Info =",
                    info
                );
                metadata.hash = Some(tx_id.to_string());
                metadata.info = Some(info.to_string());

                dbg!(
                    "[process_tx_send_response] Zilliqa hash after =",
                    &metadata.hash
                );
                Ok(())
            } else {
                dbg!("[process_tx_send_response] Zilliqa no result in response");
                Err(NetworkErrors::RPCError("Invalid response".to_string()))
            }
        }
        TransactionReceipt::Ethereum((_eth, metadata)) => {
            dbg!(
                "[process_tx_send_response] matching Ethereum variant",
                &metadata.hash
            );
            if let Some(result) = &response.result {
                dbg!("[process_tx_send_response] Ethereum result =", result);
                let hash = result.as_str().ok_or(TransactionErrors::InvalidTxHash)?;

                dbg!("[process_tx_send_response] Ethereum parsed hash =", hash);
                metadata.hash = Some(hash.to_string());

                dbg!(
                    "[process_tx_send_response] Ethereum hash after =",
                    &metadata.hash
                );
                Ok(())
            } else {
                dbg!("[process_tx_send_response] Ethereum no result in response");
                Err(NetworkErrors::RPCError("Invalid response".to_string()))
            }
        }
        _ => {
            dbg!("[process_tx_send_response] unmatched variant");
            Err(NetworkErrors::RPCError(
                "transactions not supported in EVM operations".to_string(),
            ))
        }
    }
}
