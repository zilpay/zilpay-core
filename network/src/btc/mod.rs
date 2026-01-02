use crate::evm::RequiredTxParams;
use crate::provider::NetworkProvider;
use crate::Result;
use alloy::primitives::U256;
use async_trait::async_trait;
use electrum_client::{Client as ElectrumClient, ConfigBuilder, ElectrumApi};
use errors::crypto::SignatureError;
use errors::network::NetworkErrors;
use errors::tx::TransactionErrors;
use history::transaction::HistoricalTransaction;
use proto::address::Address;
use proto::tx::TransactionReceipt;
use token::ft::FToken;

const DEFAULT_FEE_RATE_BTC: f64 = 0.00001;
const SATOSHIS_PER_BTC: f64 = 100_000_000.0;
const BYTES_PER_KB: f64 = 1000.0;
const DEFAULT_TX_SIZE_BYTES: u64 = 250;
const DEFAULT_BLOCK_TARGET: u64 = 6;

impl NetworkProvider {
    fn with_electrum_client<F, T>(&self, operation: F) -> Result<T>
    where
        F: Fn(&ElectrumClient) -> Result<T>,
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
    async fn btc_estimate_params_batch(&self, block_count: u64) -> Result<RequiredTxParams>;
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

    async fn btc_estimate_params_batch(&self, block_count: u64) -> Result<RequiredTxParams> {
        use crate::evm::GasFeeHistory;

        let target_blocks = if block_count == 0 {
            DEFAULT_BLOCK_TARGET
        } else {
            block_count
        };

        self.with_electrum_client(|client| {
            let fee_estimate = client
                .estimate_fee(target_blocks as usize)
                .map_err(|e| NetworkErrors::RPCError(format!("Failed to estimate fee: {}", e)))?;

            let fee_rate_btc = if fee_estimate < 0.0 {
                DEFAULT_FEE_RATE_BTC
            } else {
                fee_estimate
            };

            let fee_rate_sat_per_byte = (fee_rate_btc * SATOSHIS_PER_BTC / BYTES_PER_KB) as u64;

            Ok(RequiredTxParams {
                gas_price: U256::from(fee_rate_sat_per_byte),
                max_priority_fee: U256::ZERO,
                fee_history: GasFeeHistory {
                    max_fee: U256::from(fee_rate_sat_per_byte),
                    priority_fee: U256::ZERO,
                    base_fee: U256::from(fee_rate_sat_per_byte),
                },
                tx_estimate_gas: U256::from(DEFAULT_TX_SIZE_BYTES),
                blob_base_fee: U256::ZERO,
                nonce: 0,
            })
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
        _txns: &mut [&mut HistoricalTransaction],
    ) -> Result<()> {
        Err(NetworkErrors::RPCError(
            "Bitcoin support not yet implemented".to_string(),
        ))
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

        dbg!(&btc_token);
        assert!(btc_token.balances.contains_key(&0));
    }

    #[tokio::test]
    async fn test_estimate_block_time_btc() {
        let net_conf = gen_btc_testnet_conf();
        let provider = NetworkProvider::new(net_conf);
        let block_time = provider.btc_estimate_block_time().await.unwrap();

        dbg!(&block_time);

        assert!(block_time > 0);
        assert!(block_time < 3600);
    }

    #[tokio::test]
    async fn test_estimate_params_batch_btc() {
        let net_conf = gen_btc_testnet_conf();
        let provider = NetworkProvider::new(net_conf);

        let params = provider.btc_estimate_params_batch(6).await.unwrap();

        assert!(params.gas_price > U256::ZERO);
        assert_eq!(params.max_priority_fee, U256::ZERO);
        assert_eq!(params.blob_base_fee, U256::ZERO);
        assert_eq!(params.tx_estimate_gas, U256::from(DEFAULT_TX_SIZE_BYTES));
    }
}
