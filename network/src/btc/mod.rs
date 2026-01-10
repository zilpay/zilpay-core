use crate::evm::RequiredTxParams;
use crate::provider::NetworkProvider;
use crate::Result;
use alloy::primitives::U256;
use async_trait::async_trait;
use electrum_client::{Batch, Client as ElectrumClient, ConfigBuilder, ElectrumApi, Param};
use errors::crypto::SignatureError;
use errors::network::NetworkErrors;
use errors::tx::TransactionErrors;
use history::status::TransactionStatus;
use history::transaction::HistoricalTransaction;
use proto::address::Address;
use proto::tx::{TransactionReceipt, TransactionRequest};
use token::ft::FToken;

const DEFAULT_FEE_RATE_BTC: f64 = 0.00001;
const SATOSHIS_PER_BTC: f64 = 100_000_000.0;
const BYTES_PER_KB: f64 = 1000.0;
const DEFAULT_TX_SIZE_BYTES: u64 = 250;

fn calculate_tx_vsize(tx: &TransactionRequest) -> u64 {
    match tx {
        TransactionRequest::Bitcoin((btc_tx, _)) => {
            (btc_tx.input.len() * 148 + btc_tx.output.len() * 34 + 10) as u64
        }
        _ => DEFAULT_TX_SIZE_BYTES,
    }
}

fn btc_fee_rate_to_sat_per_byte(fee_btc: f64) -> u64 {
    if fee_btc < 0.0 {
        (DEFAULT_FEE_RATE_BTC * SATOSHIS_PER_BTC / BYTES_PER_KB) as u64
    } else {
        (fee_btc * SATOSHIS_PER_BTC / BYTES_PER_KB) as u64
    }
}

fn build_required_params(
    slow_rate: u64,
    market_rate: u64,
    fast_rate: u64,
    vsize: u64,
) -> RequiredTxParams {
    use crate::evm::GasFeeHistory;

    let slow_fee_sat = U256::from(vsize * slow_rate);
    let market_fee_sat = U256::from(vsize * market_rate);
    let fast_fee_sat = U256::from(vsize * fast_rate);

    RequiredTxParams {
        gas_price: U256::from(market_rate),
        max_priority_fee: U256::ZERO,
        fee_history: GasFeeHistory {
            max_fee: U256::from(fast_rate),
            priority_fee: U256::ZERO,
            base_fee: U256::from(slow_rate),
        },
        tx_estimate_gas: U256::from(vsize),
        blob_base_fee: U256::ZERO,
        nonce: 0,
        slow: slow_fee_sat,
        market: market_fee_sat,
        fast: fast_fee_sat,
        current: market_fee_sat,
    }
}

fn parse_fee_histogram(value: &serde_json::Value) -> Option<(u64, u64, u64)> {
    let histogram = value.as_array()?;

    if histogram.is_empty() {
        return None;
    }

    let mut fee_rates: Vec<f64> = Vec::new();
    let mut total_vsize: u64 = 0;

    for entry in histogram {
        let arr = entry.as_array()?;
        if arr.len() != 2 {
            continue;
        }

        let fee_rate = arr[0].as_f64()?;
        let vsize = arr[1].as_u64()?;

        fee_rates.push(fee_rate);
        total_vsize += vsize;
    }

    if fee_rates.is_empty() || total_vsize == 0 {
        return None;
    }

    let fast_rate = fee_rates.first().copied().unwrap_or(10.0).max(1.0) as u64;

    let market_idx = fee_rates.len() / 2;
    let market_rate = fee_rates.get(market_idx).copied().unwrap_or(5.0).max(1.0) as u64;

    let slow_rate = fee_rates.last().copied().unwrap_or(2.0).max(1.0) as u64;

    Some((slow_rate, market_rate, fast_rate))
}

impl NetworkProvider {
    fn with_electrum_client<F, T>(&self, mut operation: F) -> Result<T>
    where
        F: FnMut(&ElectrumClient) -> Result<T>,
    {
        let mut last_error = None;
        let mut errors = String::with_capacity(200);

        for url in &self.config.rpc {
            let config = ConfigBuilder::new().timeout(Some(5)).build();

            match ElectrumClient::from_config(url, config) {
                Ok(client) => match operation(&client) {
                    Ok(result) => return Ok(result),
                    Err(e) => {
                        errors.push_str(&format!("Operation failed on {}: {}. ", url, e));
                        last_error = Some(e);
                    }
                },
                Err(e) => {
                    errors.push_str(&format!("Failed to connect to {}: {}. ", url, e));
                    last_error = Some(NetworkErrors::RPCError(e.to_string()));
                }
            }
        }

        Err(last_error
            .unwrap_or_else(|| NetworkErrors::RPCError("No RPC URLs configured".to_string())))
    }
}

#[async_trait]
pub trait BtcOperations {
    async fn btc_get_current_block_number(&self) -> Result<u64>;
    async fn btc_estimate_params_batch(&self, tx: &TransactionRequest) -> Result<RequiredTxParams>;
    async fn btc_estimate_block_time(&self) -> Result<u64>;
    async fn btc_update_transactions_receipt(
        &self,
        txns: &mut [&mut HistoricalTransaction],
    ) -> Result<()>;
    async fn btc_broadcast_signed_transactions(
        &self,
        txns: Vec<TransactionReceipt>,
    ) -> Result<Vec<TransactionReceipt>>;
    async fn btc_update_balances(
        &self,
        tokens: Vec<&mut FToken>,
        accounts: &[&Address],
    ) -> Result<()>;
    async fn btc_list_unspent(
        &self,
        address: &Address,
    ) -> Result<Vec<electrum_client::ListUnspentRes>>;
}

#[async_trait]
impl BtcOperations for NetworkProvider {
    async fn btc_get_current_block_number(&self) -> Result<u64> {
        self.with_electrum_client(|client| {
            let header_notification = client.block_headers_subscribe().map_err(|e| {
                NetworkErrors::RPCError(format!("Failed to get block header: {}", e))
            })?;
            Ok(header_notification.height as u64)
        })
    }

    async fn btc_estimate_params_batch(&self, tx: &TransactionRequest) -> Result<RequiredTxParams> {
        const MARKET_BLOCKS: usize = 3;

        let vsize = calculate_tx_vsize(tx);

        self.with_electrum_client(|client| {
            let mut batch = Batch::default();
            batch.raw("mempool.get_fee_histogram".to_string(), vec![]);

            let results = client.batch_call(&batch);

            if let Ok(histogram_results) = results {
                if let Some(histogram_value) = histogram_results.get(0) {
                    if let Some((slow_rate, market_rate, fast_rate)) =
                        parse_fee_histogram(histogram_value)
                    {
                        return Ok(build_required_params(
                            slow_rate,
                            market_rate,
                            fast_rate,
                            vsize,
                        ));
                    }
                }
            }

            let mut batch = Batch::default();
            batch.estimate_fee(MARKET_BLOCKS);

            let results = client
                .batch_call(&batch)
                .map_err(|e| NetworkErrors::RPCError(format!("Failed to estimate fee: {}", e)))?;

            let base_fee_btc = results
                .get(0)
                .and_then(|v| v.as_f64())
                .unwrap_or(DEFAULT_FEE_RATE_BTC);

            let base_rate = btc_fee_rate_to_sat_per_byte(base_fee_btc);

            let market_fee_rate = base_rate;
            let slow_fee_rate = (base_rate / 2).max(1);
            let fast_fee_rate = base_rate + (base_rate / 2);

            Ok(build_required_params(
                slow_fee_rate,
                market_fee_rate,
                fast_fee_rate,
                vsize,
            ))
        })
    }

    async fn btc_estimate_block_time(&self) -> Result<u64> {
        const BLOCK_SAMPLE_SIZE: usize = 100;

        self.with_electrum_client(|client| {
            let current_header = client.block_headers_subscribe().map_err(|e| {
                NetworkErrors::RPCError(format!("Failed to get current block: {}", e))
            })?;

            let current_height = current_header.height;
            let start_height = current_height.saturating_sub(BLOCK_SAMPLE_SIZE);

            let heights = vec![start_height as u32, current_height as u32];
            let headers = client.batch_block_header(heights).map_err(|e| {
                NetworkErrors::RPCError(format!("Failed to get block headers: {}", e))
            })?;

            if headers.len() < 2 {
                return Ok(600);
            }

            let time_diff = headers[1].time.saturating_sub(headers[0].time);
            let block_diff = current_height.saturating_sub(start_height);

            if block_diff == 0 || time_diff == 0 {
                return Ok(600);
            }

            let avg_block_time = time_diff as u64 / block_diff as u64;

            if avg_block_time == 0 {
                return Ok(1);
            }

            Ok(avg_block_time)
        })
    }

    async fn btc_update_transactions_receipt(
        &self,
        txns: &mut [&mut HistoricalTransaction],
    ) -> Result<()> {
        use std::collections::HashMap;

        if txns.is_empty() {
            return Ok(());
        }

        self.with_electrum_client(|client| {
            let mut txid_to_index: HashMap<String, usize> = HashMap::new();
            let mut batch = Batch::default();

            for (idx, tx) in txns.iter().enumerate() {
                let txid_str = match tx
                    .get_btc()
                    .and_then(|b| {
                        b.get("txid")
                            .and_then(|t| t.as_str())
                            .map(|s| s.to_string())
                    })
                    .or_else(|| tx.metadata.hash.clone())
                {
                    Some(s) => s,
                    None => continue,
                };

                batch.raw(
                    "blockchain.transaction.get".to_string(),
                    vec![Param::String(txid_str.clone()), Param::Bool(true)],
                );
                txid_to_index.insert(txid_str, idx);
            }

            if txid_to_index.is_empty() {
                return Ok(());
            }

            let results = client.batch_call(&batch).map_err(|e| {
                NetworkErrors::RPCError(format!("Failed to batch get transactions: {}", e))
            })?;

            for (_txid_str, idx) in txid_to_index.iter() {
                let tx = &mut txns[*idx];

                if let Some(result) = results.get(*idx) {
                    let confirmations = result
                        .get("confirmations")
                        .and_then(|c| c.as_u64())
                        .unwrap_or(0);

                    let mut tx_data = result.clone();
                    if let Some(obj) = tx_data.as_object_mut() {
                        obj.remove("hex");
                    }

                    tx.set_btc(tx_data);

                    if confirmations >= 1 {
                        tx.status = TransactionStatus::Success;
                    } else {
                        tx.status = TransactionStatus::Pending;
                    }
                }
            }

            Ok(())
        })
    }

    async fn btc_broadcast_signed_transactions(
        &self,
        mut txns: Vec<TransactionReceipt>,
    ) -> Result<Vec<TransactionReceipt>> {
        for tx_receipt in &txns {
            if !tx_receipt.verify()? {
                return Err(TransactionErrors::SignatureError(
                    SignatureError::InvalidLength,
                ))?;
            }
        }

        for tx_receipt in txns.iter_mut() {
            if let TransactionReceipt::Bitcoin((tx, metadata)) = tx_receipt {
                let txid = self.with_electrum_client(|client| {
                    let txid = client.transaction_broadcast(tx).map_err(|e| {
                        NetworkErrors::RPCError(format!("Failed to broadcast transaction: {}", e))
                    })?;

                    Ok(txid)
                })?;

                metadata.hash = Some(txid.to_string());
            } else {
                return Err(NetworkErrors::RPCError(
                    "Expected Bitcoin transaction".to_string(),
                ));
            }
        }

        Ok(txns)
    }

    async fn btc_update_balances(
        &self,
        mut tokens: Vec<&mut FToken>,
        accounts: &[&Address],
    ) -> Result<()> {
        if accounts.is_empty() || tokens.is_empty() {
            return Ok(());
        }

        let mut scripts = Vec::with_capacity(accounts.len());
        for addr in accounts {
            let btc_addr = addr
                .to_bitcoin_addr()
                .map_err(|e| NetworkErrors::RPCError(e.to_string()))?;
            scripts.push(btc_addr.script_pubkey());
        }

        let script_refs: Vec<_> = scripts.iter().map(|s| s.as_ref()).collect();
        let balances = self.with_electrum_client(|client| {
            client
                .batch_script_get_balance(&script_refs)
                .map_err(|e| NetworkErrors::RPCError(format!("Failed to get balances: {}", e)))
        })?;

        for token in tokens.iter_mut() {
            if token.native {
                for (account_idx, balance) in balances.iter().enumerate() {
                    let confirmed = balance.confirmed;
                    let unconfirmed = if balance.unconfirmed < 0 {
                        0u64
                    } else {
                        balance.unconfirmed as u64
                    };
                    let total_balance = confirmed + unconfirmed;
                    token
                        .balances
                        .insert(account_idx, U256::from(total_balance));
                }
            }
        }

        Ok(())
    }

    async fn btc_list_unspent(
        &self,
        address: &Address,
    ) -> Result<Vec<electrum_client::ListUnspentRes>> {
        let btc_addr = address
            .to_bitcoin_addr()
            .map_err(|e| NetworkErrors::RPCError(e.to_string()))?;
        let script = btc_addr.script_pubkey();

        self.with_electrum_client(|client| {
            let unspents = client
                .script_list_unspent(script.as_ref())
                .map_err(|e| NetworkErrors::RPCError(format!("Failed to list unspent: {}", e)))?;
            Ok(unspents)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_data::{gen_btc_testnet_conf, gen_btc_token};

    #[tokio::test]
    async fn test_get_block_number_btc() {
        let net_conf = gen_btc_testnet_conf();
        let provider = NetworkProvider::new(net_conf);

        let block_number = provider.btc_get_current_block_number().await.unwrap();
        assert!(block_number > 0);
    }

    #[tokio::test]
    async fn test_update_balances_btc() {
        let net_conf = gen_btc_testnet_conf();
        let provider = NetworkProvider::new(net_conf);

        let mut btc_token = gen_btc_token();

        let test_addr = "bcrt1q6klf3cny45skpulz4kazm9dx9fd44usmccdp6z";
        let addr = Address::Secp256k1Bitcoin(test_addr.as_bytes().to_vec());
        let accounts = [&addr];

        let tokens_refs = vec![&mut btc_token];

        provider
            .btc_update_balances(tokens_refs, &accounts)
            .await
            .unwrap();

        assert!(btc_token.balances.contains_key(&0));
    }

    #[tokio::test]
    async fn test_estimate_block_time_btc() {
        let net_conf = gen_btc_testnet_conf();
        let provider = NetworkProvider::new(net_conf);
        let block_time = provider.btc_estimate_block_time().await.unwrap();

        assert!(block_time > 0);
        assert!(block_time < 3600);
    }

    #[tokio::test]
    async fn test_estimate_params_batch_btc() {
        use bitcoin::{Amount, ScriptBuf, Transaction, TxIn, TxOut};
        use proto::tx::TransactionMetadata;

        let net_conf = gen_btc_testnet_conf();
        let provider = NetworkProvider::new(net_conf);

        let dummy_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let tx_request = TransactionRequest::Bitcoin((dummy_tx, TransactionMetadata::default()));

        let params = provider
            .btc_estimate_params_batch(&tx_request)
            .await
            .unwrap();

        assert!(params.gas_price > U256::ZERO);
        assert_eq!(params.max_priority_fee, U256::ZERO);
        assert_eq!(params.blob_base_fee, U256::ZERO);
        assert!(params.tx_estimate_gas > U256::ZERO);
        assert!(params.slow > U256::ZERO);
        assert!(params.market > U256::ZERO);
        assert!(params.fast > U256::ZERO);
        assert_eq!(params.current, params.market);
        assert!(params.slow <= params.market);
        assert!(params.market <= params.fast);
    }

    #[tokio::test]
    async fn test_btc_update_transactions_receipt() {
        use proto::tx::TransactionMetadata;
        use serde_json::json;

        let net_conf = gen_btc_testnet_conf();
        let provider = NetworkProvider::new(net_conf);

        let tx_hash = "2c7e682a78010b47c812e4785c52831002b28486dc16998c77133510de9076a1";

        let mut test_tx = HistoricalTransaction {
            status: TransactionStatus::Pending,
            metadata: TransactionMetadata {
                hash: Some(tx_hash.to_string()),
                ..Default::default()
            },
            evm: None,
            scilla: None,
            btc: Some(json!({"txid": tx_hash}).to_string()),
            signed_message: None,
            timestamp: 0,
        };

        let mut txns = vec![&mut test_tx];

        let result = provider.btc_update_transactions_receipt(&mut txns).await;

        if let Ok(_) = result {
            if let Some(btc_data) = test_tx.get_btc() {
                println!("{}", serde_json::to_string_pretty(&btc_data).unwrap());
            }
        }

        assert!(result.is_ok());
    }
}
