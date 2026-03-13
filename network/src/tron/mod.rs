use crate::evm::{GasFeeHistory, RequiredTxParams};
use crate::provider::NetworkProvider;
use crate::Result;
use alloy::primitives::U256;
use async_trait::async_trait;
use errors::crypto::SignatureError;
use errors::network::NetworkErrors;
use errors::tx::TransactionErrors;
use history::status::TransactionStatus;
use history::transaction::HistoricalTransaction;
use prost::Message;
use proto::address::Address;
use proto::tron_generated::protocol;
use proto::tron_generated::protocol::wallet_client::WalletClient;
use proto::tron_tx::{TronContractCall, TronTransactionRequest};
use proto::tx::{TransactionReceipt, TransactionRequest};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tonic::transport::Channel;

const TRON_REQUEST_TIMEOUT_SECS: u64 = 8;
const TRON_ATTEMPT_TIMEOUT_SECS: u64 = 25;
const TRON_TOTAL_TIMEOUT_SECS: u64 = 60;
const TRON_MAX_RETRIES: usize = 3;
const TRON_BLOCK_TIME_SECS: u64 = 3;
const TRON_DEFAULT_ENERGY_FEE: u64 = 420;
const TRON_BANDWIDTH_PER_TRANSFER: u64 = 280;
const TRON_BANDWIDTH_PRICE: u64 = 1000;
const BLOCK_SAMPLE_SIZE: u64 = 10;

type TronClient = Arc<WalletClient<Channel>>;

macro_rules! tron_retry {
    ($self:expr, $method:expr, |$client:ident| $body:expr) => {{
        let retry_start = std::time::Instant::now();
        let total_deadline = Duration::from_secs(TRON_TOTAL_TIMEOUT_SECS);
        let mut last_error = None;
        let endpoints = $self.tron_endpoints();
        for (_i, endpoint) in endpoints.iter().take(TRON_MAX_RETRIES).enumerate() {
            let elapsed = retry_start.elapsed();
            if elapsed >= total_deadline {
                break;
            }
            let remaining = total_deadline - elapsed;
            let per_attempt = Duration::from_secs(TRON_ATTEMPT_TIMEOUT_SECS).min(remaining);
            match tokio::time::timeout(per_attempt, async {
                let $client = NetworkProvider::tron_connect(&endpoint).await?;
                $body
            })
            .await
            {
                Ok(Ok(val)) => {
                    return Ok(val);
                }
                Ok(Err(e)) => {
                    last_error = Some(e);
                }
                Err(_) => {
                    last_error = Some(NetworkErrors::RPCError(format!(
                        "Timeout {}s: {}",
                        TRON_REQUEST_TIMEOUT_SECS, endpoint
                    )));
                }
            }
        }
        Err(last_error
            .unwrap_or_else(|| NetworkErrors::RPCError("No Tron nodes configured".into())))
    }};
}

fn grpc_err(e: tonic::Status) -> NetworkErrors {
    NetworkErrors::RPCError(format!("gRPC: {}", e))
}

impl NetworkProvider {
    fn tron_endpoints(&self) -> Vec<String> {
        self.config
            .rpc
            .iter()
            .filter_map(|url| {
                if url.starts_with("http://") || url.starts_with("https://") {
                    None
                } else if let Some(stripped) = url.strip_prefix("grpc://") {
                    Some(format!("http://{}", stripped))
                } else {
                    Some(format!("http://{}", url))
                }
            })
            .collect()
    }

    async fn tron_connect(endpoint: &str) -> std::result::Result<TronClient, NetworkErrors> {
        let ch = Channel::from_shared(endpoint.to_string())
            .map_err(|e| NetworkErrors::RPCError(format!("{}: {}", endpoint, e)))?
            .connect_timeout(Duration::from_secs(TRON_REQUEST_TIMEOUT_SECS))
            .timeout(Duration::from_secs(TRON_REQUEST_TIMEOUT_SECS))
            .connect_lazy();
        Ok(Arc::new(WalletClient::new(ch)))
    }

}

#[async_trait]
pub trait TronOperations {
    async fn tron_get_current_block_number(&self) -> Result<u64>;
    async fn tron_estimate_block_time(&self) -> Result<u64>;
    async fn tron_estimate_params_batch(
        &self,
        tx: &TransactionRequest,
        sender: &Address,
    ) -> Result<RequiredTxParams>;
    async fn tron_broadcast_signed_transactions(
        &self,
        txns: Vec<TransactionReceipt>,
    ) -> Result<Vec<TransactionReceipt>>;
    async fn tron_update_transactions_receipt(
        &self,
        txns: &mut [&mut HistoricalTransaction],
    ) -> Result<()>;
    async fn tron_fill_block_ref(&self, tx: &mut TronTransactionRequest) -> Result<()>;
}

#[async_trait]
impl TronOperations for NetworkProvider {
    async fn tron_get_current_block_number(&self) -> Result<u64> {
        tron_retry!(self, "get_block_number", |client| {
            let mut c = WalletClient::clone(&Arc::clone(&client));
            c.get_now_block2(protocol::EmptyMessage {})
                .await
                .map_err(grpc_err)?
                .into_inner()
                .block_header
                .and_then(|h| h.raw_data)
                .map(|r| r.number as u64)
                .ok_or(NetworkErrors::ResponseParseError)
        })
    }

    async fn tron_estimate_block_time(&self) -> Result<u64> {
        tron_retry!(self, "estimate_block_time", |client| {
            let mut c = WalletClient::clone(&Arc::clone(&client));
            let current = c
                .get_now_block2(protocol::EmptyMessage {})
                .await
                .map_err(grpc_err)?
                .into_inner();

            let header = current
                .block_header
                .and_then(|h| h.raw_data)
                .ok_or(NetworkErrors::ResponseParseError)?;
            let current_num = header.number as u64;
            let current_ts = header.timestamp as u64;

            if current_num < BLOCK_SAMPLE_SIZE {
                return Ok(TRON_BLOCK_TIME_SECS);
            }

            let earlier_ts = c
                .get_block_by_num(protocol::NumberMessage {
                    num: (current_num - BLOCK_SAMPLE_SIZE) as i64,
                })
                .await
                .map_err(grpc_err)?
                .into_inner()
                .block_header
                .and_then(|h| h.raw_data)
                .map(|r| r.timestamp as u64)
                .ok_or(NetworkErrors::ResponseParseError)?;

            let time_diff_ms = current_ts.saturating_sub(earlier_ts);
            if time_diff_ms == 0 {
                return Ok(TRON_BLOCK_TIME_SECS);
            }

            Ok((time_diff_ms / (BLOCK_SAMPLE_SIZE * 1000)).max(1))
        })
    }

    async fn tron_estimate_params_batch(
        &self,
        tx: &TransactionRequest,
        sender: &Address,
    ) -> Result<RequiredTxParams> {
        tron_retry!(self, "estimate_params_batch", |client| {
            let mut c = WalletClient::clone(&Arc::clone(&client));

            let chain_params = c
                .get_chain_parameters(protocol::EmptyMessage {})
                .await
                .ok()
                .map(|r| r.into_inner());

            let energy_fee = chain_params
                .as_ref()
                .and_then(|cp| {
                    cp.chain_parameter
                        .iter()
                        .find(|p| p.key == "getEnergyFee")
                        .map(|p| p.value as u64)
                })
                .unwrap_or(TRON_DEFAULT_ENERGY_FEE);

            let fee_estimate = match tx {
                TransactionRequest::Tron((tron_tx, _)) => match &tron_tx.contract {
                    TronContractCall::Transfer { .. } => {
                        TRON_BANDWIDTH_PER_TRANSFER * TRON_BANDWIDTH_PRICE
                    }
                    TronContractCall::TriggerSmartContract {
                        contract_address,
                        call_value,
                        data,
                        ..
                    } => {
                        let contract_bytes = contract_address.to_tron_bytes();

                        let trigger = protocol::TriggerSmartContract {
                            owner_address: sender.to_tron_bytes(),
                            contract_address: contract_bytes.clone(),
                            call_value: *call_value,
                            data: data.clone(),
                            ..Default::default()
                        };

                        let estimate = c
                            .estimate_energy(trigger.clone())
                            .await
                            .map_err(grpc_err)?
                            .into_inner();

                        let energy_required = if estimate.energy_required > 0 {
                            estimate.energy_required as u64
                        } else {
                            let simulated = c
                                .trigger_constant_contract(trigger)
                                .await
                                .map_err(grpc_err)?
                                .into_inner()
                                .energy_used as u64;
                            if simulated == 0 {
                                return Err(NetworkErrors::RPCError(
                                    "Failed to estimate energy: all methods returned 0".into(),
                                ));
                            }
                            simulated
                        };

                        let energy_factor = c
                            .get_contract_info(protocol::BytesMessage {
                                value: contract_bytes,
                            })
                            .await
                            .ok()
                            .and_then(|r| r.into_inner().contract_state)
                            .map(|s| s.energy_factor.max(0) as u64)
                            .unwrap_or(0);

                        let adjusted_energy =
                            energy_required * (10000 + energy_factor) / 10000;

                        adjusted_energy * energy_fee
                    }
                    _ => 0u64,
                },
                _ => 0u64,
            };

            let base = U256::from(fee_estimate);

            Ok(RequiredTxParams {
                gas_price: U256::from(energy_fee),
                max_priority_fee: U256::ZERO,
                fee_history: GasFeeHistory::default(),
                tx_estimate_gas: U256::from(fee_estimate),
                blob_base_fee: U256::ZERO,
                nonce: 0,
                slow: base,
                market: base * U256::from(105) / U256::from(100),
                fast: base * U256::from(110) / U256::from(100),
                current: base * U256::from(105) / U256::from(100),
            })
        })
    }

    async fn tron_broadcast_signed_transactions(
        &self,
        mut txns: Vec<TransactionReceipt>,
    ) -> Result<Vec<TransactionReceipt>> {
        for tx in &txns {
            if !tx.verify()? {
                return Err(TransactionErrors::SignatureError(
                    SignatureError::InvalidLength,
                ))?;
            }
        }

        tron_retry!(self, "broadcast_txns", |client| {
            let mut c = WalletClient::clone(&Arc::clone(&client));
            for tx in txns.iter_mut() {
                let (tron_tx, metadata) = match tx {
                    TransactionReceipt::Tron((t, m)) => (t, m),
                    _ => {
                        return Err(NetworkErrors::RPCError(
                            "Expected Tron transaction".to_string(),
                        ))
                    }
                };

                let tx_id_hex = alloy::hex::encode(tron_tx.tx_id);

                let raw = protocol::transaction::Raw::decode(tron_tx.raw_data_bytes.as_slice())
                    .map_err(|e| NetworkErrors::RPCError(format!("Decode raw_data: {}", e)))?;

                let ret = c
                    .broadcast_transaction(protocol::Transaction {
                        raw_data: Some(raw),
                        signature: vec![tron_tx.signature.clone()],
                        ret: Vec::new(),
                    })
                    .await
                    .map_err(grpc_err)?
                    .into_inner();

                if !ret.result {
                    let msg = String::from_utf8(ret.message)
                        .unwrap_or_else(|e| format!("Invalid UTF-8: {}", e));
                    return Err(NetworkErrors::RPCError(format!(
                        "Broadcast failed: {}",
                        msg
                    )));
                }

                metadata.hash = Some(tx_id_hex);
            }

            Ok(txns.clone())
        })
    }

    async fn tron_update_transactions_receipt(
        &self,
        txns: &mut [&mut HistoricalTransaction],
    ) -> Result<()> {
        tron_retry!(self, "update_tx_receipt", |client| {
            let mut c = WalletClient::clone(&Arc::clone(&client));
            for tx in txns.iter_mut() {
                let tx_id = match tx
                    .get_tron()
                    .and_then(|t| t.get("txID").and_then(|id| id.as_str()).map(String::from))
                    .or_else(|| tx.metadata.hash.clone())
                {
                    Some(id) => id,
                    None => continue,
                };

                let tx_id_bytes =
                    alloy::hex::decode(&tx_id).map_err(|_| NetworkErrors::ResponseParseError)?;

                let info = c
                    .get_transaction_info_by_id(protocol::BytesMessage { value: tx_id_bytes })
                    .await
                    .map_err(grpc_err)?
                    .into_inner();

                if info.id.is_empty() {
                    continue;
                }

                let mut tron_data = tx.get_tron().unwrap_or_else(|| json!({}));

                if let Some(obj) = tron_data.as_object_mut() {
                    obj.insert("txID".to_string(), json!(tx_id));
                    obj.insert("blockNumber".to_string(), json!(info.block_number));
                    obj.insert("fee".to_string(), json!(info.fee));

                    if let Some(receipt) = &info.receipt {
                        let contract_result =
                            protocol::transaction::result::ContractResult::try_from(receipt.result)
                                .ok();
                        obj.insert(
                            "receipt".to_string(),
                            json!({ "result": contract_result.map(|r| r.as_str_name().to_string()) }),
                        );
                    }

                    obj.insert("result".to_string(), json!(info.result));

                    if !info.contract_result.is_empty() {
                        let hex_results: Vec<String> = info
                            .contract_result
                            .iter()
                            .map(alloy::hex::encode)
                            .collect();
                        obj.insert("contractResult".to_string(), json!(hex_results));
                    }
                }

                tx.set_tron(tron_data);

                if info.block_number > 0 {
                    let receipt_result = info.receipt.as_ref().and_then(|r| {
                        protocol::transaction::result::ContractResult::try_from(r.result).ok()
                    });

                    tx.status = match receipt_result {
                        Some(protocol::transaction::result::ContractResult::Revert)
                        | Some(protocol::transaction::result::ContractResult::OutOfEnergy) => {
                            TransactionStatus::Failed
                        }
                        _ if info.result == protocol::transaction_info::Code::Failed as i32 => {
                            TransactionStatus::Failed
                        }
                        _ => TransactionStatus::Success,
                    };
                }
            }

            Ok(())
        })
    }

    async fn tron_fill_block_ref(&self, tx: &mut TronTransactionRequest) -> Result<()> {
        tron_retry!(self, "fill_block_ref", |client| {
            let mut c = WalletClient::clone(&Arc::clone(&client));
            let block = c
                .get_now_block2(protocol::EmptyMessage {})
                .await
                .map_err(grpc_err)?
                .into_inner();

            if block.blockid.len() < 16 {
                return Err(NetworkErrors::ResponseParseError);
            }

            tx.ref_block_bytes = block.blockid[6..8].to_vec();
            tx.ref_block_hash = block.blockid[8..16].to_vec();

            let timestamp = block
                .block_header
                .and_then(|h| h.raw_data)
                .map(|r| r.timestamp)
                .ok_or(NetworkErrors::ResponseParseError)?;

            tx.timestamp = timestamp;
            tx.expiration = timestamp + 300_000;

            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::dyn_abi::{DynSolValue, JsonAbiExt};
    use alloy::json_abi::JsonAbi;
    use config::abi::ERC20_ABI;
    use std::time::Instant;
    use test_data::gen_tron_testnet_conf;

    #[test]
    fn test_tron_endpoints_grpc_prefix() {
        let mut conf = gen_tron_testnet_conf();
        conf.rpc = vec!["grpc://grpc.nile.trongrid.io:50051".to_string()];
        let provider = NetworkProvider::new(conf);
        let endpoints = provider.tron_endpoints();
        assert_eq!(endpoints, vec!["http://grpc.nile.trongrid.io:50051"]);
    }

    #[test]
    fn test_tron_endpoints_skips_jsonrpc() {
        let mut conf = gen_tron_testnet_conf();
        conf.rpc = vec![
            "http://localhost:50051".to_string(),
            "https://secure.node:50051".to_string(),
        ];
        let provider = NetworkProvider::new(conf);
        let endpoints = provider.tron_endpoints();
        assert!(endpoints.is_empty());
    }

    #[test]
    fn test_tron_endpoints_bare_host() {
        let mut conf = gen_tron_testnet_conf();
        conf.rpc = vec!["grpc.nile.trongrid.io:50051".to_string()];
        let provider = NetworkProvider::new(conf);
        let endpoints = provider.tron_endpoints();
        assert_eq!(endpoints, vec!["http://grpc.nile.trongrid.io:50051"]);
    }

    #[test]
    fn test_tron_endpoints_mixed() {
        let mut conf = gen_tron_testnet_conf();
        conf.rpc = vec![
            "https://api.trongrid.io".to_string(),
            "grpc://grpc.nile.trongrid.io:50051".to_string(),
            "http://localhost:8090".to_string(),
            "some.node:50051".to_string(),
        ];
        let provider = NetworkProvider::new(conf);
        let endpoints = provider.tron_endpoints();
        assert_eq!(
            endpoints,
            vec![
                "http://grpc.nile.trongrid.io:50051",
                "http://some.node:50051",
            ]
        );
    }

    #[tokio::test]
    async fn test_tron_connect_timeout_unreachable() {
        let mut conf = gen_tron_testnet_conf();
        conf.rpc = vec!["grpc://192.0.2.1:50051".to_string()];
        let provider = NetworkProvider::new(conf);

        let start = Instant::now();
        let result = provider.tron_get_current_block_number().await;
        let elapsed = start.elapsed();

        assert!(result.is_err());
        assert!(
            elapsed.as_secs() <= TRON_REQUEST_TIMEOUT_SECS + 2,
            "Request took {}s, expected <= {}s",
            elapsed.as_secs(),
            TRON_REQUEST_TIMEOUT_SECS + 2
        );
    }

    #[tokio::test]
    async fn test_tron_connect_invalid_host_fails_fast() {
        let mut conf = gen_tron_testnet_conf();
        conf.rpc = vec!["localhost:1".to_string()];
        let provider = NetworkProvider::new(conf);

        let start = Instant::now();
        let result = provider.tron_get_current_block_number().await;
        let elapsed = start.elapsed();

        assert!(result.is_err());
        assert!(
            elapsed.as_secs() < TRON_REQUEST_TIMEOUT_SECS,
            "Connection refused should fail fast, took {}s",
            elapsed.as_secs()
        );
    }

    #[tokio::test]
    async fn test_tron_retry_skips_bad_node() {
        let mut conf = gen_tron_testnet_conf();
        conf.rpc = vec![
            "localhost:1".to_string(),
            "grpc://grpc.nile.trongrid.io:50051".to_string(),
        ];
        let provider = NetworkProvider::new(conf);

        let start = Instant::now();
        let result = provider.tron_get_current_block_number().await;
        let elapsed = start.elapsed();

        assert!(
            result.is_ok(),
            "Should succeed via second node: {:?}",
            result
        );
        assert!(
            elapsed.as_secs() <= TRON_REQUEST_TIMEOUT_SECS + 2,
            "Retry took {}s, too slow",
            elapsed.as_secs()
        );
    }

    #[tokio::test]
    async fn test_tron_get_block_number() {
        let provider = NetworkProvider::new(gen_tron_testnet_conf());
        let block_number = provider.tron_get_current_block_number().await.unwrap();
        assert!(block_number > 0);
    }

    #[tokio::test]
    async fn test_tron_estimate_block_time() {
        let provider = NetworkProvider::new(gen_tron_testnet_conf());
        let block_time = provider.tron_estimate_block_time().await.unwrap();
        assert!(block_time >= 1 && block_time <= 10);
    }

    #[tokio::test]
    async fn test_tron_estimate_params_batch() {
        let provider = NetworkProvider::new(gen_tron_testnet_conf());
        let sender = Address::from_tron_address(test_data::tron_addresses::ADDR_0).unwrap();
        let to = Address::from_tron_address(test_data::tron_addresses::ADDR_1).unwrap();

        let tron_tx = proto::tron_tx::TronTransactionRequest {
            owner_address: sender.clone(),
            ref_block_bytes: vec![],
            ref_block_hash: vec![],
            expiration: 0,
            timestamp: 0,
            fee_limit: 0,
            contract: TronContractCall::Transfer {
                to_address: to,
                amount: 1_000_000,
            },
        };
        let tx = TransactionRequest::Tron((tron_tx, proto::tx::TransactionMetadata::default()));

        let params = provider
            .tron_estimate_params_batch(&tx, &sender)
            .await
            .unwrap();

        assert!(params.gas_price > U256::ZERO);
        assert!(params.tx_estimate_gas > U256::ZERO);
        assert!(params.current > U256::ZERO);
    }

    #[tokio::test]
    async fn test_tron_estimate_params_trc20() {
        let provider = NetworkProvider::new(gen_tron_testnet_conf());
        let sender = Address::from_tron_address(test_data::tron_addresses::ADDR_0).unwrap();
        let contract = Address::from_tron_address("TNuoKL1ni8aoshfFL1ASca1Gou9RXwAzfn").unwrap();

        let abi: JsonAbi = serde_json::from_str(ERC20_ABI).unwrap();
        let to = Address::from_tron_address(test_data::tron_addresses::ADDR_1).unwrap();
        let func = abi.function("transfer").and_then(|f| f.first()).unwrap();
        let data = func
            .abi_encode_input(&[
                DynSolValue::Address(to.to_alloy_addr()),
                DynSolValue::Uint(U256::from(1_000_000), 256),
            ])
            .unwrap();

        let tron_tx = proto::tron_tx::TronTransactionRequest {
            owner_address: sender.clone(),
            ref_block_bytes: vec![],
            ref_block_hash: vec![],
            expiration: 0,
            timestamp: 0,
            fee_limit: 0,
            contract: TronContractCall::TriggerSmartContract {
                contract_address: contract,
                call_value: 0,
                data,
                call_token_value: 0,
                token_id: 0,
            },
        };
        let tx = TransactionRequest::Tron((tron_tx, proto::tx::TransactionMetadata::default()));

        let params = provider
            .tron_estimate_params_batch(&tx, &sender)
            .await
            .unwrap();

        assert!(params.gas_price > U256::ZERO);
        assert!(params.tx_estimate_gas > U256::ZERO);
        assert!(params.fast > params.slow);
    }
}
