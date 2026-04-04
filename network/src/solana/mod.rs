mod responses;

use crate::evm::{GasFeeHistory, RequiredTxParams};
use crate::provider::NetworkProvider;
use crate::Result;
use alloy::primitives::U256;
use async_trait::async_trait;
use base64::Engine;
use errors::network::NetworkErrors;
use history::transaction::HistoricalTransaction;
use history::status::TransactionStatus;
use proto::address::Address;
use proto::tx::{TransactionReceipt, TransactionRequest};
use responses::*;
use rpc::common::JsonRPC;
use rpc::methods::SolanaMethod;
use rpc::network_config::ChainConfig;
use rpc::provider::RpcProvider;
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};
use token::ft::FToken;

const SOLANA_BASE_FEE_LAMPORTS: u64 = 5000;
const SOLANA_BLOCK_TIME_SECS: u64 = 1;
const SOLANA_TX_PENDING_TIMEOUT_SECS: u64 = 600;

#[async_trait]
pub trait SolanaOperations {
    async fn solana_get_current_block_number(&self) -> Result<u64>;
    async fn solana_estimate_block_time(&self) -> Result<u64>;
    async fn solana_get_latest_blockhash(&self) -> Result<String>;
    async fn solana_estimate_params_batch(
        &self,
        tx: &TransactionRequest,
        sender: &Address,
    ) -> Result<RequiredTxParams>;
    async fn solana_broadcast_signed_transactions(
        &self,
        txns: Vec<TransactionReceipt>,
    ) -> Result<Vec<TransactionReceipt>>;
    async fn solana_update_transactions_receipt(
        &self,
        txns: &mut [&mut HistoricalTransaction],
    ) -> Result<()>;
    async fn solana_update_balances(
        &self,
        tokens: Vec<&mut FToken>,
        accounts: &[&Address],
    ) -> Result<()>;
}

#[async_trait]
impl SolanaOperations for NetworkProvider {
    async fn solana_get_current_block_number(&self) -> Result<u64> {
        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);
        let payload = RpcProvider::<ChainConfig>::build_payload(json!([]), SolanaMethod::GetSlot);
        let res: SolanaResultRes<u64> = provider
            .req(payload)
            .await
            .map_err(NetworkErrors::Request)?;

        res.result
            .ok_or_else(|| NetworkErrors::RPCError(solana_err_msg(&res.error)))
    }

    async fn solana_estimate_block_time(&self) -> Result<u64> {
        Ok(SOLANA_BLOCK_TIME_SECS)
    }

    async fn solana_get_latest_blockhash(&self) -> Result<String> {
        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);
        let payload = RpcProvider::<ChainConfig>::build_payload(
            json!([{"commitment": "finalized"}]),
            SolanaMethod::GetLatestBlockhash,
        );
        let res: SolanaResultRes<SolanaValueResponse<BlockhashValue>> = provider
            .req(payload)
            .await
            .map_err(NetworkErrors::Request)?;

        let value = res
            .result
            .ok_or_else(|| NetworkErrors::RPCError(solana_err_msg(&res.error)))?;

        Ok(value.value.blockhash)
    }

    async fn solana_estimate_params_batch(
        &self,
        _tx: &TransactionRequest,
        _sender: &Address,
    ) -> Result<RequiredTxParams> {
        let fee = U256::from(SOLANA_BASE_FEE_LAMPORTS);

        Ok(RequiredTxParams {
            gas_price: fee,
            max_priority_fee: U256::ZERO,
            fee_history: GasFeeHistory::default(),
            tx_estimate_gas: U256::from(1u64),
            blob_base_fee: U256::ZERO,
            nonce: 0,
            slow: fee,
            market: fee,
            fast: fee,
            current: fee,
        })
    }

    async fn solana_broadcast_signed_transactions(
        &self,
        mut txns: Vec<TransactionReceipt>,
    ) -> Result<Vec<TransactionReceipt>> {
        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);

        for receipt in &mut txns {
            let TransactionReceipt::Solana((ref solana_receipt, ref mut metadata)) = receipt else {
                continue;
            };

            let encoded = base64::engine::general_purpose::STANDARD.encode(solana_receipt.encode());
            let payload = RpcProvider::<ChainConfig>::build_payload(
                json!([encoded, {"encoding": "base64"}]),
                SolanaMethod::SendTransaction,
            );

            let res: SolanaResultRes<String> = provider
                .req(payload)
                .await
                .map_err(NetworkErrors::Request)?;

            let signature = res
                .result
                .ok_or_else(|| NetworkErrors::RPCError(solana_err_msg(&res.error)))?;

            metadata.hash = Some(signature);
        }

        Ok(txns)
    }

    async fn solana_update_transactions_receipt(
        &self,
        txns: &mut [&mut HistoricalTransaction],
    ) -> Result<()> {
        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for tx in txns.iter_mut() {
            if tx.status != TransactionStatus::Pending {
                continue;
            }

            let signature = match tx.get_solana().and_then(|v| {
                v.get("transactionHash")
                    .and_then(|h| h.as_str())
                    .map(|s| s.to_string())
            }) {
                Some(sig) => sig,
                None => continue,
            };

            let pending_secs = now.saturating_sub(tx.timestamp / 1000);
            if pending_secs > SOLANA_TX_PENDING_TIMEOUT_SECS {
                tx.status = TransactionStatus::Failed;
                continue;
            }

            let payload = RpcProvider::<ChainConfig>::build_payload(
                json!([signature, {"encoding": "json", "maxSupportedTransactionVersion": 0}]),
                SolanaMethod::GetTransaction,
            );

            let res: SolanaResultRes<SolanaGetTransactionResult> = provider
                .req(payload)
                .await
                .map_err(NetworkErrors::Request)?;

            match res.result {
                None => {}
                Some(result) => {
                    let success = result
                        .meta
                        .as_ref()
                        .map(|m| m.err.is_none())
                        .unwrap_or(false);

                    tx.status = if success {
                        TransactionStatus::Success
                    } else {
                        TransactionStatus::Failed
                    };

                    if let Some(mut solana_data) = tx.get_solana() {
                        if let Some(fee) = result.meta.and_then(|m| m.fee) {
                            solana_data["fee"] = json!(fee.to_string());
                        }
                        if let Some(slot) = result.slot {
                            solana_data["slot"] = json!(slot.to_string());
                        }
                        tx.set_solana(solana_data);
                    }
                }
            }
        }

        Ok(())
    }

    async fn solana_update_balances(
        &self,
        tokens: Vec<&mut FToken>,
        accounts: &[&Address],
    ) -> Result<()> {
        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);

        for token in tokens {
            for (index, account) in accounts.iter().enumerate() {
                let Address::Ed25519Solana(pubkey_bytes) = account else {
                    continue;
                };

                let address_b58 = bs58::encode(pubkey_bytes).into_string();
                let payload = RpcProvider::<ChainConfig>::build_payload(
                    json!([address_b58, {"commitment": "finalized"}]),
                    SolanaMethod::GetBalance,
                );

                let res: SolanaResultRes<SolanaValueResponse<u64>> = provider
                    .req(payload)
                    .await
                    .map_err(NetworkErrors::Request)?;

                let lamports = res
                    .result
                    .ok_or_else(|| NetworkErrors::RPCError(solana_err_msg(&res.error)))?
                    .value;

                token.balances.insert(index, U256::from(lamports));
            }
        }

        Ok(())
    }
}

fn solana_err_msg(err: &Option<SolanaErrorRes>) -> String {
    err.as_ref()
        .map(|e| format!("Solana RPC error {}: {}", e.code, e.message))
        .unwrap_or_else(|| "Solana RPC: empty result".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto::solana_tx::SolanaTransaction;
    use proto::tx::TransactionMetadata;
    use test_data::{gen_sol_devnet_conf, gen_sol_token};

    #[tokio::test]
    async fn test_solana_get_block_number() {
        let provider = NetworkProvider::new(gen_sol_devnet_conf());
        let slot = provider.solana_get_current_block_number().await.unwrap();
        assert!(slot > 0);
    }

    #[tokio::test]
    async fn test_solana_estimate_block_time() {
        let provider = NetworkProvider::new(gen_sol_devnet_conf());
        let t = provider.solana_estimate_block_time().await.unwrap();
        assert_eq!(t, SOLANA_BLOCK_TIME_SECS);
    }

    #[tokio::test]
    async fn test_solana_get_latest_blockhash() {
        let provider = NetworkProvider::new(gen_sol_devnet_conf());
        let hash = provider.solana_get_latest_blockhash().await.unwrap();
        assert!(hash.len() >= 32, "blockhash too short: {}", hash);
        let decoded = bs58::decode(&hash).into_vec();
        assert!(decoded.is_ok(), "blockhash is not valid base58");
        assert_eq!(decoded.unwrap().len(), 32);
    }

    #[tokio::test]
    async fn test_solana_estimate_params_batch() {
        let provider = NetworkProvider::new(gen_sol_devnet_conf());
        let tx =
            TransactionRequest::Solana((SolanaTransaction { message: vec![] }, Default::default()));
        let sender = Address::Ed25519Solana([0u8; 32]);
        let params = provider
            .solana_estimate_params_batch(&tx, &sender)
            .await
            .unwrap();

        assert_eq!(params.gas_price, U256::from(SOLANA_BASE_FEE_LAMPORTS));
        assert_eq!(params.slow, U256::from(SOLANA_BASE_FEE_LAMPORTS));
        assert_eq!(params.market, U256::from(SOLANA_BASE_FEE_LAMPORTS));
        assert_eq!(params.fast, U256::from(SOLANA_BASE_FEE_LAMPORTS));
        assert_eq!(params.nonce, 0);
        assert_eq!(params.blob_base_fee, U256::ZERO);
    }

    #[tokio::test]
    async fn test_solana_update_balances_zero_address() {
        let provider = NetworkProvider::new(gen_sol_devnet_conf());
        let mut token = gen_sol_token();
        let zero_account = Address::Ed25519Solana([0u8; 32]);

        provider
            .solana_update_balances(vec![&mut token], &[&zero_account])
            .await
            .unwrap();

        assert!(token.balances.contains_key(&0));
    }

    #[tokio::test]
    async fn test_solana_update_balances_skips_non_solana() {
        let provider = NetworkProvider::new(gen_sol_devnet_conf());
        let mut token = gen_sol_token();
        let eth_account = Address::Secp256k1Keccak256([0u8; 20]);

        provider
            .solana_update_balances(vec![&mut token], &[&eth_account])
            .await
            .unwrap();

        assert!(token.balances.is_empty());
    }

    #[tokio::test]
    async fn test_solana_update_transactions_receipt_unknown_sig() {
        let provider = NetworkProvider::new(gen_sol_devnet_conf());
        let mut tx = HistoricalTransaction {
            status: TransactionStatus::Pending,
            metadata: TransactionMetadata {
                chain_hash: gen_sol_devnet_conf().hash(),
                hash: Some("1111111111111111111111111111111111111111111111111111111111111111".to_string()),
                broadcast: true,
                ..Default::default()
            },
            solana: serde_json::to_string(&json!({
                "transactionHash": "1111111111111111111111111111111111111111111111111111111111111111"
            })).ok(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            ..Default::default()
        };

        let mut list = vec![&mut tx];
        provider
            .solana_update_transactions_receipt(&mut list)
            .await
            .unwrap();

        assert_eq!(list[0].status, TransactionStatus::Pending);
    }
}
