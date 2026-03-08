use crate::evm::{GasFeeHistory, RequiredTxParams};
use crate::provider::NetworkProvider;
use crate::Result;
use alloy::dyn_abi::{DynSolValue, FunctionExt, JsonAbiExt};
use alloy::json_abi::JsonAbi;
use alloy::primitives::U256;
use async_trait::async_trait;
use config::abi::ERC20_ABI;
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
use token::ft::FToken;
use tokio::task::JoinSet;
use tonic::transport::Channel;

const TRON_TIMEOUT_SECS: u64 = 5;
const TRON_TOTAL_TIMEOUT_SECS: u64 = 15;
const TRON_MAX_RETRIES: usize = 3;
const TRON_BLOCK_TIME_SECS: u64 = 3;
const TRON_DEFAULT_ENERGY_FEE: u64 = 420;
const TRON_DEFAULT_FREE_BANDWIDTH: u64 = 600;
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
            let per_attempt = Duration::from_secs(TRON_TIMEOUT_SECS).min(remaining);
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
                        TRON_TIMEOUT_SECS, endpoint
                    )));
                }
            }
        }
        Err(last_error
            .unwrap_or_else(|| NetworkErrors::RPCError("No Tron nodes configured".into())))
    }};
}

struct AbiHelper {
    abi: JsonAbi,
}

impl AbiHelper {
    fn new() -> std::result::Result<Self, NetworkErrors> {
        let abi = serde_json::from_str(ERC20_ABI).map_err(|_| NetworkErrors::ResponseParseError)?;
        Ok(Self { abi })
    }

    fn encode(
        &self,
        name: &str,
        inputs: &[DynSolValue],
    ) -> std::result::Result<Vec<u8>, NetworkErrors> {
        self.abi
            .function(name)
            .and_then(|f| f.first())
            .ok_or(NetworkErrors::ResponseParseError)?
            .abi_encode_input(inputs)
            .map_err(|_| NetworkErrors::ResponseParseError)
    }

    fn decode(
        &self,
        name: &str,
        data: &[u8],
    ) -> std::result::Result<Vec<DynSolValue>, NetworkErrors> {
        self.abi
            .function(name)
            .and_then(|f| f.first())
            .ok_or(NetworkErrors::ResponseParseError)?
            .abi_decode_output(data)
            .map_err(|_| NetworkErrors::ResponseParseError)
    }

    fn decode_string(&self, name: &str, data: &[u8]) -> std::result::Result<String, NetworkErrors> {
        self.decode(name, data)?
            .into_iter()
            .next()
            .and_then(|v| v.as_str().map(String::from))
            .ok_or(NetworkErrors::ResponseParseError)
    }

    fn decode_u8(&self, name: &str, data: &[u8]) -> std::result::Result<u8, NetworkErrors> {
        self.decode(name, data)?
            .into_iter()
            .next()
            .and_then(|v| v.as_uint())
            .map(|(val, _)| val.to::<u8>())
            .ok_or(NetworkErrors::ResponseParseError)
    }
}

fn addr_to_tron_bytes(addr: &Address) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(21);
    bytes.push(0x41);
    bytes.extend_from_slice(addr.as_ref());
    bytes
}

fn grpc_err(e: tonic::Status) -> NetworkErrors {
    NetworkErrors::RPCError(format!("gRPC: {}", e))
}

impl NetworkProvider {
    fn tron_endpoints(&self) -> Vec<String> {
        self.config
            .rpc
            .iter()
            .map(|url| {
                if url.starts_with("http://") || url.starts_with("https://") {
                    url.clone()
                } else if url.starts_with("grpc://") {
                    format!("http://{}", &url[7..])
                } else {
                    format!("http://{}", url)
                }
            })
            .collect()
    }

    async fn tron_connect(endpoint: &str) -> std::result::Result<TronClient, NetworkErrors> {
        let ch = Channel::from_shared(endpoint.to_string())
            .map_err(|e| NetworkErrors::RPCError(format!("{}: {}", endpoint, e)))?
            .connect_timeout(Duration::from_secs(TRON_TIMEOUT_SECS))
            .timeout(Duration::from_secs(TRON_TIMEOUT_SECS))
            .connect_lazy();
        Ok(Arc::new(WalletClient::new(ch)))
    }

    async fn tron_trigger_constant(
        client: &TronClient,
        owner: Vec<u8>,
        contract_addr: Vec<u8>,
        data: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let mut c = WalletClient::clone(&Arc::clone(client));
        c.trigger_constant_contract(protocol::TriggerSmartContract {
            owner_address: owner,
            contract_address: contract_addr,
            data,
            ..Default::default()
        })
        .await
        .map_err(grpc_err)?
        .into_inner()
        .constant_result
        .into_iter()
        .next()
        .ok_or(NetworkErrors::ResponseParseError.into())
    }

    async fn tron_get_native_balance(client: &TronClient, account: &Address) -> U256 {
        let mut c = WalletClient::clone(&Arc::clone(client));
        c.get_account(protocol::Account {
            address: addr_to_tron_bytes(account),
            ..Default::default()
        })
        .await
        .ok()
        .map(|r| U256::from(r.into_inner().balance.max(0) as u64))
        .unwrap_or(U256::ZERO)
    }

    async fn tron_get_trc20_balance(
        client: &TronClient,
        contract: &Address,
        account: &Address,
    ) -> U256 {
        let abi = match AbiHelper::new() {
            Ok(a) => a,
            Err(_) => return U256::ZERO,
        };
        let data = match abi.encode(
            "balanceOf",
            &[DynSolValue::Address(account.to_alloy_addr())],
        ) {
            Ok(d) => d,
            Err(_) => return U256::ZERO,
        };

        Self::tron_trigger_constant(
            client,
            addr_to_tron_bytes(account),
            addr_to_tron_bytes(contract),
            data,
        )
        .await
        .ok()
        .filter(|b| !b.is_empty())
        .map(|b| U256::from_be_slice(&b))
        .unwrap_or(U256::ZERO)
    }

    async fn tron_fetch_balance(
        client: &TronClient,
        native: bool,
        contract: &Address,
        account: &Address,
    ) -> U256 {
        if native {
            Self::tron_get_native_balance(client, account).await
        } else {
            Self::tron_get_trc20_balance(client, contract, account).await
        }
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
    async fn tron_update_balances(
        &self,
        tokens: Vec<&mut FToken>,
        accounts: &[&Address],
    ) -> Result<()>;
    async fn tron_ftoken_meta(&self, contract: Address, accounts: &[&Address]) -> Result<FToken>;
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
            let account_resource = c
                .get_account_resource(protocol::Account {
                    address: addr_to_tron_bytes(sender),
                    ..Default::default()
                })
                .await
                .ok()
                .map(|r| r.into_inner());

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
                        let free_bw = account_resource
                            .as_ref()
                            .map(|r| r.free_net_limit as u64)
                            .unwrap_or(TRON_DEFAULT_FREE_BANDWIDTH);
                        let used_bw = account_resource
                            .as_ref()
                            .map(|r| r.free_net_used as u64)
                            .unwrap_or(0);

                        if free_bw.saturating_sub(used_bw) > TRON_BANDWIDTH_PER_TRANSFER {
                            0u64
                        } else {
                            TRON_BANDWIDTH_PER_TRANSFER * TRON_BANDWIDTH_PRICE
                        }
                    }
                    TronContractCall::TriggerSmartContract {
                        contract_address,
                        call_value,
                        data,
                        ..
                    } => {
                        let estimate = c
                            .estimate_energy(protocol::TriggerSmartContract {
                                owner_address: addr_to_tron_bytes(sender),
                                contract_address: addr_to_tron_bytes(contract_address),
                                call_value: *call_value,
                                data: data.clone(),
                                ..Default::default()
                            })
                            .await
                            .map_err(grpc_err)?
                            .into_inner();

                        (estimate.energy_required as u64) * energy_fee
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

                let tx_id_hex = alloy::hex::encode(&tron_tx.tx_id);

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

    async fn tron_update_balances(
        &self,
        mut tokens: Vec<&mut FToken>,
        accounts: &[&Address],
    ) -> Result<()> {
        if accounts.is_empty() || tokens.is_empty() {
            return Ok(());
        }

        tron_retry!(self, "update_balances", |client| {
            for token in tokens.iter_mut() {
                let mut set = JoinSet::new();
                for (idx, account) in accounts.iter().enumerate() {
                    let c = Arc::clone(&client);
                    let native = token.native;
                    let addr = token.addr.clone();
                    let acc = (*account).clone();
                    set.spawn(async move {
                        (
                            idx,
                            NetworkProvider::tron_fetch_balance(&c, native, &addr, &acc).await,
                        )
                    });
                }
                while let Some(Ok((idx, balance))) = set.join_next().await {
                    token.balances.insert(idx, balance);
                }
            }

            Ok(())
        })
    }

    async fn tron_ftoken_meta(&self, contract: Address, accounts: &[&Address]) -> Result<FToken> {
        tron_retry!(self, "ftoken_meta", |client| {
            let abi = AbiHelper::new()?;
            let contract_bytes = addr_to_tron_bytes(&contract);
            let owner_bytes = accounts
                .first()
                .map(|a| addr_to_tron_bytes(a))
                .unwrap_or_else(|| contract_bytes.clone());

            let (name_res, symbol_res, decimals_res) = tokio::join!(
                Self::tron_trigger_constant(
                    &client,
                    owner_bytes.clone(),
                    contract_bytes.clone(),
                    abi.encode("name", &[])?,
                ),
                Self::tron_trigger_constant(
                    &client,
                    owner_bytes.clone(),
                    contract_bytes.clone(),
                    abi.encode("symbol", &[])?,
                ),
                Self::tron_trigger_constant(
                    &client,
                    owner_bytes,
                    contract_bytes,
                    abi.encode("decimals", &[])?,
                ),
            );

            let name = abi.decode_string("name", &name_res?)?;
            let symbol = abi.decode_string("symbol", &symbol_res?)?;
            let decimals = abi.decode_u8("decimals", &decimals_res?)?;

            let mut set = JoinSet::new();
            for (idx, account) in accounts.iter().enumerate() {
                let c = Arc::clone(&client);
                let contract = contract.clone();
                let acc = (*account).clone();
                set.spawn(async move {
                    (
                        idx,
                        NetworkProvider::tron_get_trc20_balance(&c, &contract, &acc).await,
                    )
                });
            }
            let mut balances = std::collections::HashMap::new();
            while let Some(Ok((idx, bal))) = set.join_next().await {
                balances.insert(idx, bal);
            }

            Ok(FToken {
                balances,
                name,
                symbol,
                decimals,
                addr: contract.clone(),
                logo: None,
                default: false,
                native: false,
                chain_hash: self.config.hash(),
                rate: 0f64,
            })
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
    fn test_tron_endpoints_http_passthrough() {
        let mut conf = gen_tron_testnet_conf();
        conf.rpc = vec![
            "http://localhost:50051".to_string(),
            "https://secure.node:50051".to_string(),
        ];
        let provider = NetworkProvider::new(conf);
        let endpoints = provider.tron_endpoints();
        assert_eq!(
            endpoints,
            vec!["http://localhost:50051", "https://secure.node:50051",]
        );
    }

    #[test]
    fn test_tron_endpoints_bare_host() {
        let mut conf = gen_tron_testnet_conf();
        conf.rpc = vec!["grpc.nile.trongrid.io:50051".to_string()];
        let provider = NetworkProvider::new(conf);
        let endpoints = provider.tron_endpoints();
        assert_eq!(endpoints, vec!["http://grpc.nile.trongrid.io:50051"]);
    }

    #[tokio::test]
    async fn test_tron_connect_timeout_unreachable() {
        let mut conf = gen_tron_testnet_conf();
        conf.rpc = vec!["http://192.0.2.1:50051".to_string()];
        let provider = NetworkProvider::new(conf);

        let start = Instant::now();
        let result = provider.tron_get_current_block_number().await;
        let elapsed = start.elapsed();

        assert!(result.is_err());
        assert!(
            elapsed.as_secs() <= TRON_TIMEOUT_SECS + 2,
            "Request took {}s, expected <= {}s",
            elapsed.as_secs(),
            TRON_TIMEOUT_SECS + 2
        );
    }

    #[tokio::test]
    async fn test_tron_connect_invalid_host_fails_fast() {
        let mut conf = gen_tron_testnet_conf();
        conf.rpc = vec!["http://localhost:1".to_string()];
        let provider = NetworkProvider::new(conf);

        let start = Instant::now();
        let result = provider.tron_get_current_block_number().await;
        let elapsed = start.elapsed();

        assert!(result.is_err());
        assert!(
            elapsed.as_secs() < TRON_TIMEOUT_SECS,
            "Connection refused should fail fast, took {}s",
            elapsed.as_secs()
        );
    }

    #[tokio::test]
    async fn test_tron_retry_skips_bad_node() {
        let mut conf = gen_tron_testnet_conf();
        conf.rpc = vec![
            "http://localhost:1".to_string(),
            "http://grpc.nile.trongrid.io:50051".to_string(),
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
            elapsed.as_secs() <= TRON_TIMEOUT_SECS + 2,
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
    async fn test_tron_update_balances() {
        let provider = NetworkProvider::new(gen_tron_testnet_conf());
        let addr = Address::from_tron_address(test_data::tron_addresses::ADDR_0).unwrap();
        let accounts = [&addr];
        let mut trx_token = test_data::gen_tron_token();

        provider
            .tron_update_balances(vec![&mut trx_token], &accounts)
            .await
            .unwrap();

        assert!(trx_token.balances.contains_key(&0));
    }

    #[tokio::test]
    async fn test_tron_ftoken_meta() {
        let provider = NetworkProvider::new(gen_tron_testnet_conf());
        let contract = Address::from_tron_address("TNuoKL1ni8aoshfFL1ASca1Gou9RXwAzfn").unwrap();
        let addr = Address::from_tron_address(test_data::tron_addresses::ADDR_0).unwrap();
        let accounts = [&addr];

        let token = provider
            .tron_ftoken_meta(contract, &accounts)
            .await
            .unwrap();

        assert!(!token.name.is_empty());
        assert!(!token.symbol.is_empty());
        assert!(token.decimals > 0);
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
    }

    #[tokio::test]
    async fn test_tron_estimate_params_trc20() {
        let provider = NetworkProvider::new(gen_tron_testnet_conf());
        let sender = Address::from_tron_address(test_data::tron_addresses::ADDR_0).unwrap();
        let contract = Address::from_tron_address("TNuoKL1ni8aoshfFL1ASca1Gou9RXwAzfn").unwrap();

        let abi = AbiHelper::new().unwrap();
        let to = Address::from_tron_address(test_data::tron_addresses::ADDR_1).unwrap();
        let data = abi
            .encode(
                "transfer",
                &[
                    DynSolValue::Address(to.to_alloy_addr()),
                    DynSolValue::Uint(U256::from(1_000_000), 256),
                ],
            )
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
