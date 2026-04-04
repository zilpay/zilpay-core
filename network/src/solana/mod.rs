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

    const DEVNET_RICH_ADDRESS: &str = "vines1vzrYbzLMRdu58ou5XTby4qAqVRLmqo36NKPTg";
    const DEVNET_ZERO_ADDRESS: &str = "4fYNw3dojWmQ4dXtSGE9epjRGy9GHeo5UCCbg6NbyNjF";
    const DEVNET_CONFIRMED_TX_SIG: &str = "x7SUrZF6nV97XF1hg2NPZpLimi6StUbpH2nVdGC4jR2ojnnzYQ18y4CpLnCR6JkcH4gCQgW3sobJC2wVcnQE2xR";
    const DEVNET_FAILED_TX_SIG: &str = "2V2erUdPadyTiFRFS98g6kkXHDVFgWX1ZeDMH67bpsPekm9BaCCkLs6rN15Y6oDeHWETFb5sagfR7syifbWLPMcG";

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

    #[tokio::test]
    async fn test_solana_get_block_number_devnet() {
        let provider = NetworkProvider::new(gen_sol_devnet_conf());
        let slot = provider.solana_get_current_block_number().await.unwrap();
        dbg!(&slot);
        assert!(slot > 453_000_000, "Slot should be > 453M on devnet, got: {}", slot);
    }

    #[tokio::test]
    async fn test_solana_get_latest_blockhash_devnet() {
        let provider = NetworkProvider::new(gen_sol_devnet_conf());
        let hash = provider.solana_get_latest_blockhash().await.unwrap();
        dbg!(&hash);
        assert!(!hash.is_empty(), "Blockhash should not be empty");
        let decoded = bs58::decode(&hash).into_vec().unwrap();
        assert_eq!(decoded.len(), 32, "Blockhash must decode to 32 bytes");
        println!("Blockhash decoded {} bytes successfully", decoded.len());
    }

    #[tokio::test]
    async fn test_solana_update_balances_rich_address() {
        let provider = NetworkProvider::new(gen_sol_devnet_conf());
        let mut token = gen_sol_token();
        let rich_account = Address::from_solana_address(DEVNET_RICH_ADDRESS).unwrap();
        println!("Querying balance for address: {}", DEVNET_RICH_ADDRESS);

        provider
            .solana_update_balances(vec![&mut token], &[&rich_account])
            .await
            .unwrap();

        let balance = token.balances.get(&0).unwrap();
        dbg!(balance);
        assert!(*balance > U256::from(0), "Rich address should have SOL balance");
        println!(
            "Balance: {} lamports ({} SOL)",
            balance,
            balance / U256::from(1_000_000_000u64)
        );
    }

    #[tokio::test]
    async fn test_solana_update_balances_zero_address_real() {
        let provider = NetworkProvider::new(gen_sol_devnet_conf());
        let mut token = gen_sol_token();
        let zero_account = Address::from_solana_address(DEVNET_ZERO_ADDRESS).unwrap();
        println!("Querying balance for zero-balance address: {}", DEVNET_ZERO_ADDRESS);

        provider
            .solana_update_balances(vec![&mut token], &[&zero_account])
            .await
            .unwrap();

        let balance = token.balances.get(&0).unwrap();
        dbg!(balance);
        assert_eq!(*balance, U256::from(0), "Empty address should have zero balance");
        println!("Balance confirmed: 0 lamports");
    }

    #[tokio::test]
    async fn test_solana_update_balances_multiple_accounts() {
        let provider = NetworkProvider::new(gen_sol_devnet_conf());
        let mut token = gen_sol_token();
        let rich_account = Address::from_solana_address(DEVNET_RICH_ADDRESS).unwrap();
        let zero_account = Address::from_solana_address(DEVNET_ZERO_ADDRESS).unwrap();
        let accounts: Vec<&Address> = vec![&rich_account, &zero_account];

        println!("Querying balances for {} accounts", accounts.len());
        provider
            .solana_update_balances(vec![&mut token], &accounts)
            .await
            .unwrap();

        let rich_balance = token.balances.get(&0).unwrap();
        let zero_balance = token.balances.get(&1).unwrap();
        dbg!(rich_balance, zero_balance);

        assert!(*rich_balance > U256::from(0));
        assert_eq!(*zero_balance, U256::from(0));
        println!("Multi-account balance check passed");
    }

    #[tokio::test]
    async fn test_solana_update_tx_receipt_confirmed() {
        let provider = NetworkProvider::new(gen_sol_devnet_conf());
        let mut tx = HistoricalTransaction {
            status: TransactionStatus::Pending,
            metadata: TransactionMetadata {
                chain_hash: gen_sol_devnet_conf().hash(),
                hash: Some(DEVNET_CONFIRMED_TX_SIG.to_string()),
                broadcast: true,
                ..Default::default()
            },
            solana: serde_json::to_string(&json!({
                "transactionHash": DEVNET_CONFIRMED_TX_SIG
            })).ok(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            ..Default::default()
        };

        println!("Querying confirmed tx: {}", DEVNET_CONFIRMED_TX_SIG);
        let mut list = vec![&mut tx];
        provider
            .solana_update_transactions_receipt(&mut list)
            .await
            .unwrap();

        let solana_data = list[0].get_solana().unwrap();
        dbg!(&solana_data);
        dbg!(&list[0].status);
        assert_eq!(list[0].status, TransactionStatus::Success, "Confirmed tx should be Success");

        let fee = solana_data.get("fee").and_then(|v| v.as_str());
        assert!(fee.is_some(), "Fee should be set in solana data");
        println!("Confirmed tx fee: {:?}", fee);

        let slot = solana_data.get("slot").and_then(|v| v.as_str());
        assert!(slot.is_some(), "Slot should be set in solana data");
        println!("Confirmed tx slot: {:?}", slot);
    }

    #[tokio::test]
    async fn test_solana_update_tx_receipt_failed() {
        let provider = NetworkProvider::new(gen_sol_devnet_conf());
        let mut tx = HistoricalTransaction {
            status: TransactionStatus::Pending,
            metadata: TransactionMetadata {
                chain_hash: gen_sol_devnet_conf().hash(),
                hash: Some(DEVNET_FAILED_TX_SIG.to_string()),
                broadcast: true,
                ..Default::default()
            },
            solana: serde_json::to_string(&json!({
                "transactionHash": DEVNET_FAILED_TX_SIG
            })).ok(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            ..Default::default()
        };

        println!("Querying failed tx: {}", DEVNET_FAILED_TX_SIG);
        let mut list = vec![&mut tx];
        provider
            .solana_update_transactions_receipt(&mut list)
            .await
            .unwrap();

        dbg!(&list[0].status);
        assert_eq!(list[0].status, TransactionStatus::Failed, "Failed tx should be Failed status");

        let solana_data = list[0].get_solana().unwrap();
        dbg!(&solana_data);
        println!("Failed tx data: {:?}", solana_data);
    }

    #[tokio::test]
    async fn test_solana_update_tx_receipt_skips_non_pending() {
        let provider = NetworkProvider::new(gen_sol_devnet_conf());
        let mut tx = HistoricalTransaction {
            status: TransactionStatus::Success,
            metadata: TransactionMetadata {
                chain_hash: gen_sol_devnet_conf().hash(),
                hash: Some(DEVNET_CONFIRMED_TX_SIG.to_string()),
                broadcast: true,
                ..Default::default()
            },
            solana: serde_json::to_string(&json!({
                "transactionHash": DEVNET_CONFIRMED_TX_SIG
            })).ok(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            ..Default::default()
        };

        println!("Testing that non-pending tx is skipped");
        let mut list = vec![&mut tx];
        provider
            .solana_update_transactions_receipt(&mut list)
            .await
            .unwrap();

        assert_eq!(list[0].status, TransactionStatus::Success, "Should remain Success");
        println!("Non-pending tx correctly skipped");
    }

    #[tokio::test]
    async fn test_solana_estimate_params_batch_devnet() {
        let provider = NetworkProvider::new(gen_sol_devnet_conf());
        let tx = TransactionRequest::Solana((SolanaTransaction { message: vec![] }, Default::default()));
        let sender = Address::from_solana_address(DEVNET_RICH_ADDRESS).unwrap();

        let params = provider
            .solana_estimate_params_batch(&tx, &sender)
            .await
            .unwrap();

        dbg!(&params);
        assert_eq!(params.gas_price, U256::from(SOLANA_BASE_FEE_LAMPORTS));
        assert_eq!(params.slow, U256::from(SOLANA_BASE_FEE_LAMPORTS));
        assert_eq!(params.market, U256::from(SOLANA_BASE_FEE_LAMPORTS));
        assert_eq!(params.fast, U256::from(SOLANA_BASE_FEE_LAMPORTS));
        assert_eq!(params.tx_estimate_gas, U256::from(1u64));
        assert_eq!(params.nonce, 0);
        println!("Fee params validated: gas_price={} lamports", SOLANA_BASE_FEE_LAMPORTS);
    }
}
