use crate::evm::{GasFeeHistory, RequiredTxParams};
use crate::provider::NetworkProvider;
use crate::Result;
use alloy::dyn_abi::FunctionExt;
use alloy::json_abi::JsonAbi;
use alloy::primitives::U256;
use async_trait::async_trait;
use config::abi::ERC20_ABI;
use errors::crypto::SignatureError;
use errors::network::NetworkErrors;
use errors::tx::TransactionErrors;
use history::status::TransactionStatus;
use history::transaction::HistoricalTransaction;
use proto::address::Address;
use proto::tron_tx::TronContractCall;
use proto::tx::{TransactionReceipt, TransactionRequest};
use serde_json::{json, Value};
use token::ft::FToken;

const TRON_BLOCK_TIME_SECS: u64 = 3;
const TRON_DEFAULT_FEE_LIMIT: u64 = 100_000_000;
const TRON_DEFAULT_ENERGY_FEE: u64 = 420;
const TRON_DEFAULT_FREE_BANDWIDTH: u64 = 600;
const TRON_BANDWIDTH_PER_TRANSFER: u64 = 280;
const TRON_BANDWIDTH_PRICE: u64 = 1000;
const TRON_SMART_CONTRACT_ENERGY: u64 = 30_000;
const BLOCK_SAMPLE_SIZE: u64 = 10;

fn addr_to_tron_hex(addr: &Address) -> String {
    let mut bytes = Vec::with_capacity(21);
    bytes.push(0x41);
    bytes.extend_from_slice(addr.as_ref());
    alloy::hex::encode(bytes)
}

fn trigger_constant_body(
    owner_hex: &str,
    contract_hex: &str,
    selector: &str,
    parameter: &str,
) -> Value {
    json!({
        "owner_address": owner_hex,
        "contract_address": contract_hex,
        "function_selector": selector,
        "parameter": parameter,
        "visible": false,
    })
}

fn decode_constant_result(response: &Value) -> Option<Vec<u8>> {
    response
        .get("constant_result")
        .and_then(|r| r.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_str())
        .and_then(|s| alloy::hex::decode(s).ok())
}

fn decode_u256(response: &Value) -> U256 {
    decode_constant_result(response)
        .filter(|b| !b.is_empty())
        .map(|b| U256::from_be_slice(&b))
        .unwrap_or(U256::ZERO)
}

fn decode_abi_string(response: &Value, func_name: &str) -> Option<String> {
    let bytes = decode_constant_result(response)?;
    let abi: JsonAbi = serde_json::from_str(ERC20_ABI).ok()?;
    let func = abi.function(func_name)?.first()?;
    let values = func.abi_decode_output(&bytes).ok()?;
    values.first()?.as_str().map(String::from)
}

fn decode_abi_decimals(response: &Value) -> Option<u8> {
    let bytes = decode_constant_result(response)?;
    let abi: JsonAbi = serde_json::from_str(ERC20_ABI).ok()?;
    let func = abi.function("decimals")?.first()?;
    let values = func.abi_decode_output(&bytes).ok()?;
    let (val, _) = values.first()?.as_uint()?;
    Some(val.to::<u8>())
}

fn block_number(block: &Value) -> Option<u64> {
    block
        .get("block_header")
        .and_then(|h| h.get("raw_data"))
        .and_then(|r| r.get("number"))
        .and_then(|n| n.as_u64())
}

fn block_timestamp(block: &Value) -> Option<u64> {
    block
        .get("block_header")
        .and_then(|h| h.get("raw_data"))
        .and_then(|r| r.get("timestamp"))
        .and_then(|t| t.as_u64())
}

fn chain_energy_fee(params: &Value) -> u64 {
    params
        .get("chainParameter")
        .and_then(|p| p.as_array())
        .and_then(|arr| {
            arr.iter().find_map(|p| {
                if p.get("key").and_then(|k| k.as_str()) == Some("getEnergyFee") {
                    p.get("value").and_then(|v| v.as_u64())
                } else {
                    None
                }
            })
        })
        .unwrap_or(TRON_DEFAULT_ENERGY_FEE)
}

fn decode_broadcast_error(msg: &str) -> String {
    alloy::hex::decode(msg)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_else(|| msg.to_string())
}

impl NetworkProvider {
    async fn tron_post(&self, path: &str, body: Value) -> Result<Value> {
        let client = reqwest::Client::new();
        let mut last_error = None;

        for url in &self.config.rpc {
            let endpoint = format!("{}{}", url.trim_end_matches('/'), path);

            match client
                .post(&endpoint)
                .header("Content-Type", "application/json")
                .json(&body)
                .send()
                .await
            {
                Ok(resp) => match resp.json::<Value>().await {
                    Ok(value) => {
                        if let Some(err) = value.get("Error").and_then(|e| e.as_str()) {
                            last_error =
                                Some(NetworkErrors::RPCError(format!("{}: {}", endpoint, err)));
                            continue;
                        }
                        return Ok(value);
                    }
                    Err(e) => {
                        last_error = Some(NetworkErrors::RPCError(format!(
                            "Parse error {}: {}",
                            endpoint, e
                        )));
                    }
                },
                Err(e) => {
                    last_error = Some(NetworkErrors::RPCError(format!(
                        "Connection error {}: {}",
                        endpoint, e
                    )));
                }
            }
        }

        Err(last_error
            .unwrap_or_else(|| NetworkErrors::RPCError("No RPC URLs configured".to_string())))
    }

    async fn tron_get_native_balance(&self, account: &Address) -> U256 {
        self.tron_post(
            "/wallet/getaccount",
            json!({"address": addr_to_tron_hex(account), "visible": false}),
        )
        .await
        .ok()
        .and_then(|r| r.get("balance").and_then(|b| b.as_u64()))
        .map(U256::from)
        .unwrap_or(U256::ZERO)
    }

    async fn tron_get_trc20_balance(&self, contract: &Address, account: &Address) -> U256 {
        let body = trigger_constant_body(
            &addr_to_tron_hex(account),
            &addr_to_tron_hex(contract),
            "balanceOf(address)",
            &format!("{:0>64}", alloy::hex::encode(account.as_ref())),
        );

        self.tron_post("/wallet/triggerconstantcontract", body)
            .await
            .map(|r| decode_u256(&r))
            .unwrap_or(U256::ZERO)
    }

    async fn tron_call_string(
        &self,
        owner_hex: &str,
        contract_hex: &str,
        selector: &str,
    ) -> Result<String> {
        let func_name = selector.split('(').next().unwrap_or(selector);
        let body = trigger_constant_body(owner_hex, contract_hex, selector, "");
        let response = self
            .tron_post("/wallet/triggerconstantcontract", body)
            .await?;

        decode_abi_string(&response, func_name).ok_or(NetworkErrors::ResponseParseError.into())
    }

    async fn tron_call_decimals(&self, owner_hex: &str, contract_hex: &str) -> Result<u8> {
        let body = trigger_constant_body(owner_hex, contract_hex, "decimals()", "");
        let response = self
            .tron_post("/wallet/triggerconstantcontract", body)
            .await?;

        decode_abi_decimals(&response).ok_or(NetworkErrors::ResponseParseError.into())
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
}

#[async_trait]
impl TronOperations for NetworkProvider {
    async fn tron_get_current_block_number(&self) -> Result<u64> {
        let block = self.tron_post("/wallet/getnowblock", json!({})).await?;
        block_number(&block).ok_or(NetworkErrors::ResponseParseError)
    }

    async fn tron_estimate_block_time(&self) -> Result<u64> {
        let current = self.tron_post("/wallet/getnowblock", json!({})).await?;
        let current_num = block_number(&current).ok_or(NetworkErrors::ResponseParseError)?;
        let current_ts = block_timestamp(&current).ok_or(NetworkErrors::ResponseParseError)?;

        if current_num < BLOCK_SAMPLE_SIZE {
            return Ok(TRON_BLOCK_TIME_SECS);
        }

        let earlier = self
            .tron_post(
                "/wallet/getblockbynum",
                json!({"num": current_num - BLOCK_SAMPLE_SIZE}),
            )
            .await?;
        let earlier_ts = block_timestamp(&earlier).ok_or(NetworkErrors::ResponseParseError)?;

        let time_diff_ms = current_ts.saturating_sub(earlier_ts);
        if time_diff_ms == 0 {
            return Ok(TRON_BLOCK_TIME_SECS);
        }

        Ok((time_diff_ms / (BLOCK_SAMPLE_SIZE * 1000)).max(1))
    }

    async fn tron_estimate_params_batch(
        &self,
        tx: &TransactionRequest,
        sender: &Address,
    ) -> Result<RequiredTxParams> {
        let sender_hex = addr_to_tron_hex(sender);

        let account_resource = self
            .tron_post(
                "/wallet/getaccountresource",
                json!({"address": sender_hex, "visible": false}),
            )
            .await
            .unwrap_or_default();

        let chain_params = self
            .tron_post("/wallet/getchainparameters", json!({}))
            .await
            .unwrap_or_default();

        let energy_fee = chain_energy_fee(&chain_params);

        let (fee_estimate, is_smart_contract) = match tx {
            TransactionRequest::Tron((tron_tx, _)) => match &tron_tx.contract {
                TronContractCall::Transfer { .. } => {
                    let free_bw = account_resource
                        .get("freeNetLimit")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(TRON_DEFAULT_FREE_BANDWIDTH);
                    let used_bw = account_resource
                        .get("freeNetUsed")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);

                    if free_bw.saturating_sub(used_bw) > TRON_BANDWIDTH_PER_TRANSFER {
                        (0u64, false)
                    } else {
                        (TRON_BANDWIDTH_PER_TRANSFER * TRON_BANDWIDTH_PRICE, false)
                    }
                }
                TronContractCall::TriggerSmartContract { .. } => {
                    (TRON_SMART_CONTRACT_ENERGY * energy_fee, true)
                }
                _ => (0u64, false),
            },
            _ => (0u64, false),
        };

        let fast = if is_smart_contract {
            U256::from(TRON_DEFAULT_FEE_LIMIT)
        } else {
            U256::from(fee_estimate)
        };

        Ok(RequiredTxParams {
            gas_price: U256::from(energy_fee),
            max_priority_fee: U256::ZERO,
            fee_history: GasFeeHistory::default(),
            tx_estimate_gas: U256::from(fee_estimate),
            blob_base_fee: U256::ZERO,
            nonce: 0,
            slow: U256::from(fee_estimate),
            market: U256::from(fee_estimate),
            fast,
            current: U256::from(fee_estimate),
        })
    }

    async fn tron_broadcast_signed_transactions(
        &self,
        mut txns: Vec<TransactionReceipt>,
    ) -> Result<Vec<TransactionReceipt>> {
        for tx in &txns {
            if !tx.verify()? {
                return Err(TransactionErrors::SignatureError(SignatureError::InvalidLength))?;
            }
        }

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
            let body = json!({
                "raw_data_hex": alloy::hex::encode(&tron_tx.raw_data_bytes),
                "txID": tx_id_hex,
                "signature": [alloy::hex::encode(&tron_tx.signature)],
                "visible": false,
            });

            let response = self.tron_post("/wallet/broadcasttransaction", body).await?;

            if !response
                .get("result")
                .and_then(|r| r.as_bool())
                .unwrap_or(false)
            {
                let msg = response
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("Unknown error");
                return Err(NetworkErrors::RPCError(format!(
                    "Broadcast failed: {}",
                    decode_broadcast_error(msg)
                )));
            }

            metadata.hash = Some(tx_id_hex);
        }

        Ok(txns)
    }

    async fn tron_update_transactions_receipt(
        &self,
        txns: &mut [&mut HistoricalTransaction],
    ) -> Result<()> {
        for tx in txns.iter_mut() {
            let tx_id = match tx
                .get_tron()
                .and_then(|t| t.get("txID").and_then(|id| id.as_str()).map(String::from))
                .or_else(|| tx.metadata.hash.clone())
            {
                Some(id) => id,
                None => continue,
            };

            let response = self
                .tron_post("/wallet/gettransactioninfobyid", json!({"value": tx_id}))
                .await?;

            if response.as_object().map_or(true, |o| o.is_empty()) {
                continue;
            }

            let mut tron_data = tx.get_tron().unwrap_or_else(|| json!({}));

            if let Some(obj) = tron_data.as_object_mut() {
                obj.insert("txID".to_string(), json!(tx_id));

                for key in &["blockNumber", "fee", "receipt", "result", "contractResult"] {
                    if let Some(val) = response.get(*key) {
                        obj.insert(key.to_string(), val.clone());
                    }
                }
            }

            tx.set_tron(tron_data);

            if response.get("blockNumber").and_then(|n| n.as_u64()).is_some() {
                tx.status = match response
                    .get("receipt")
                    .and_then(|r| r.get("result"))
                    .and_then(|s| s.as_str())
                {
                    Some("REVERT") | Some("OUT_OF_ENERGY") | Some("FAILED") => {
                        TransactionStatus::Failed
                    }
                    _ => TransactionStatus::Success,
                };
            }
        }

        Ok(())
    }

    async fn tron_update_balances(
        &self,
        mut tokens: Vec<&mut FToken>,
        accounts: &[&Address],
    ) -> Result<()> {
        if accounts.is_empty() || tokens.is_empty() {
            return Ok(());
        }

        for token in tokens.iter_mut() {
            for (idx, account) in accounts.iter().enumerate() {
                let balance = if token.native {
                    self.tron_get_native_balance(account).await
                } else {
                    self.tron_get_trc20_balance(&token.addr, account).await
                };

                token.balances.insert(idx, balance);
            }
        }

        Ok(())
    }

    async fn tron_ftoken_meta(&self, contract: Address, accounts: &[&Address]) -> Result<FToken> {
        let contract_hex = addr_to_tron_hex(&contract);
        let owner_hex = accounts
            .first()
            .map(|a| addr_to_tron_hex(a))
            .unwrap_or_else(|| contract_hex.clone());

        let name = self
            .tron_call_string(&owner_hex, &contract_hex, "name()")
            .await?;
        let symbol = self
            .tron_call_string(&owner_hex, &contract_hex, "symbol()")
            .await?;
        let decimals = self.tron_call_decimals(&owner_hex, &contract_hex).await?;

        let mut balances = std::collections::HashMap::new();
        for (idx, account) in accounts.iter().enumerate() {
            balances.insert(idx, self.tron_get_trc20_balance(&contract, account).await);
        }

        Ok(FToken {
            balances,
            name,
            symbol,
            decimals,
            addr: contract,
            logo: None,
            default: false,
            native: false,
            chain_hash: self.config.hash(),
            rate: 0f64,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_data::gen_tron_testnet_conf;

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
        let contract = Address::from_tron_address("TG3XXyExBkPp9nzdajDZsozEu4BkaSJozs").unwrap();
        let addr = Address::from_tron_address(test_data::tron_addresses::ADDR_0).unwrap();
        let accounts = [&addr];

        let token = provider.tron_ftoken_meta(contract, &accounts).await.unwrap();

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
        let tx = TransactionRequest::Tron((
            tron_tx,
            proto::tx::TransactionMetadata::default(),
        ));

        let params = provider
            .tron_estimate_params_batch(&tx, &sender)
            .await
            .unwrap();

        assert!(params.gas_price > U256::ZERO);
    }
}
