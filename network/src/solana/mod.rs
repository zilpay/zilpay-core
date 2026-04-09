pub mod tx_builder;
mod responses;

use crate::evm::{GasFeeHistory, RequiredTxParams};
use crate::provider::NetworkProvider;
use crate::solana::tx_builder::build_sol_transfer_message;
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
use rpc::zil_interfaces::{ErrorRes, ResultRes};
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::HashMap;
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
    async fn solana_get_fee_for_message(&self, message: &[u8]) -> Result<u64>;
    async fn solana_ftoken_meta(
        &self,
        contract: Address,
        accounts: &[&Address],
    ) -> Result<FToken>;
}

#[async_trait]
impl SolanaOperations for NetworkProvider {
    async fn solana_get_current_block_number(&self) -> Result<u64> {
        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);
        let payload = RpcProvider::<ChainConfig>::build_payload(json!([]), SolanaMethod::GetSlot);
        let res: ResultRes<u64> = provider
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
        let res: ResultRes<SolanaValueResponse<BlockhashValue>> = provider
            .req(payload)
            .await
            .map_err(NetworkErrors::Request)?;

        let value = res
            .result
            .ok_or_else(|| NetworkErrors::RPCError(solana_err_msg(&res.error)))?;

        Ok(value.value.blockhash)
    }

    async fn solana_get_fee_for_message(&self, message: &[u8]) -> Result<u64> {
        let encoded = base64::engine::general_purpose::STANDARD.encode(message);
        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);
        let payload = RpcProvider::<ChainConfig>::build_payload(
            json!([encoded, {"commitment": "confirmed"}]),
            SolanaMethod::GetFeeForMessage,
        );
        let res: ResultRes<SolanaValueResponse<Option<u64>>> = provider
            .req(payload)
            .await
            .map_err(NetworkErrors::Request)?;

        let value = res
            .result
            .ok_or_else(|| NetworkErrors::RPCError(solana_err_msg(&res.error)))?;

        value
            .value
            .ok_or_else(|| NetworkErrors::RPCError("blockhash expired".into()))
    }

    async fn solana_estimate_params_batch(
        &self,
        tx: &TransactionRequest,
        sender: &Address,
    ) -> Result<RequiredTxParams> {
        let fee = if let TransactionRequest::Solana((sol_tx, _)) = tx {
            let message = if sol_tx.message.is_empty() {
                let Address::Ed25519Solana(pk) = sender else {
                    return Ok(RequiredTxParams {
                        gas_price: U256::from(SOLANA_BASE_FEE_LAMPORTS),
                        max_priority_fee: U256::ZERO,
                        fee_history: GasFeeHistory::default(),
                        tx_estimate_gas: U256::from(1u64),
                        blob_base_fee: U256::ZERO,
                        nonce: 0,
                        slow: U256::from(SOLANA_BASE_FEE_LAMPORTS),
                        market: U256::from(SOLANA_BASE_FEE_LAMPORTS),
                        fast: U256::from(SOLANA_BASE_FEE_LAMPORTS),
                        current: U256::from(SOLANA_BASE_FEE_LAMPORTS),
                    });
                };
                let blockhash_str = self.solana_get_latest_blockhash().await?;
                let blockhash: [u8; 32] = bs58::decode(&blockhash_str)
                    .into_vec()
                    .map_err(|e| NetworkErrors::RPCError(e.to_string()))?
                    .try_into()
                    .map_err(|_| NetworkErrors::RPCError("blockhash must be 32 bytes".into()))?;
                build_sol_transfer_message(pk, pk, 0, &blockhash)
            } else {
                sol_tx.message.clone()
            };
            U256::from(self.solana_get_fee_for_message(&message).await?)
        } else {
            U256::from(SOLANA_BASE_FEE_LAMPORTS)
        };

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
        let mut payloads: Vec<Value> = Vec::with_capacity(txns.len());
        let mut valid_indices: Vec<usize> = Vec::with_capacity(txns.len());

        for (i, receipt) in txns.iter().enumerate() {
            let TransactionReceipt::Solana((ref solana_receipt, _)) = receipt else {
                continue;
            };
            let encoded = base64::engine::general_purpose::STANDARD.encode(solana_receipt.encode());
            payloads.push(build_send_transaction_req(&encoded));
            valid_indices.push(i);
        }

        if payloads.is_empty() {
            return Ok(txns);
        }

        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);
        let responses: Vec<ResultRes<String>> = provider
            .req(json!(payloads))
            .await
            .map_err(NetworkErrors::Request)?;

        for (offset, tx_idx) in valid_indices.iter().enumerate() {
            let TransactionReceipt::Solana((_, ref mut metadata)) = txns[*tx_idx] else {
                continue;
            };
            let res = &responses[offset];
            let signature = res
                .result
                .clone()
                .ok_or_else(|| NetworkErrors::RPCError(solana_err_msg(&res.error)))?;
            metadata.hash = Some(signature);
        }

        Ok(txns)
    }

    async fn solana_update_transactions_receipt(
        &self,
        txns: &mut [&mut HistoricalTransaction],
    ) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut payloads: Vec<Value> = Vec::with_capacity(txns.len());
        let mut valid_indices: Vec<usize> = Vec::with_capacity(txns.len());

        for (i, tx) in txns.iter_mut().enumerate() {
            if tx.status != TransactionStatus::Pending {
                continue;
            }

            let pending_secs = now.saturating_sub(tx.timestamp / 1000);
            if pending_secs > SOLANA_TX_PENDING_TIMEOUT_SECS {
                tx.status = TransactionStatus::Failed;
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

            payloads.push(build_get_transaction_req(&signature));
            valid_indices.push(i);
        }

        if payloads.is_empty() {
            return Ok(());
        }

        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);
        let responses: Vec<ResultRes<SolanaGetTransactionResult>> = provider
            .req(json!(payloads))
            .await
            .map_err(NetworkErrors::Request)?;

        for (offset, tx_idx) in valid_indices.iter().enumerate() {
            let tx = &mut txns[*tx_idx];
            let res = &responses[offset];

            if let Some(result) = &res.result {
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
                    if let Some(fee) = result.meta.as_ref().and_then(|m| m.fee) {
                        solana_data["fee"] = json!(fee.to_string());
                    }
                    if let Some(slot) = result.slot {
                        solana_data["slot"] = json!(slot.to_string());
                    }
                    tx.set_solana(solana_data);
                }
            }
        }

        Ok(())
    }

    async fn solana_update_balances(
        &self,
        mut tokens: Vec<&mut FToken>,
        accounts: &[&Address],
    ) -> Result<()> {
        let capacity = tokens.len() * accounts.len();
        let mut payloads: Vec<Value> = Vec::with_capacity(capacity);
        let mut mapping: Vec<(usize, usize, bool)> = Vec::with_capacity(capacity);

        for (token_idx, token) in tokens.iter().enumerate() {
            for (acc_idx, account) in accounts.iter().enumerate() {
                let Address::Ed25519Solana(pubkey) = account else {
                    continue;
                };
                let address_b58 = pubkey.to_string();

                if token.native {
                    payloads.push(build_get_balance_req(&address_b58));
                    mapping.push((token_idx, acc_idx, true));
                } else if let Address::Ed25519Solana(mint) = &token.addr {
                    payloads.push(build_get_token_accounts_req(&address_b58, &mint.to_string()));
                    mapping.push((token_idx, acc_idx, false));
                }
            }
        }

        if payloads.is_empty() {
            return Ok(());
        }

        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);
        let responses: Vec<ResultRes<Value>> = provider
            .req(json!(payloads))
            .await
            .map_err(NetworkErrors::Request)?;

        for (i, (token_idx, acc_idx, is_native)) in mapping.iter().enumerate() {
            let balance = if *is_native {
                parse_native_balance(&responses[i])
            } else {
                parse_spl_balance(&responses[i])
            };
            tokens[*token_idx].balances.insert(*acc_idx, balance);
        }

        Ok(())
    }

    async fn solana_ftoken_meta(
        &self,
        contract: Address,
        accounts: &[&Address],
    ) -> Result<FToken> {
        let Address::Ed25519Solana(mint) = contract else {
            return Err(NetworkErrors::RPCError(
                "Expected Ed25519Solana mint address".to_string(),
            ));
        };
        let mint_b58 = mint.to_string();

        let mut payloads: Vec<Value> = Vec::with_capacity(1 + accounts.len());
        payloads.push(build_get_account_info_req(&mint_b58));

        let mut valid_accounts: Vec<usize> = Vec::with_capacity(accounts.len());
        for (i, account) in accounts.iter().enumerate() {
            if let Address::Ed25519Solana(pubkey) = account {
                payloads.push(build_get_token_accounts_req(&pubkey.to_string(), &mint_b58));
                valid_accounts.push(i);
            }
        }

        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);
        let responses: Vec<ResultRes<Value>> = provider
            .req(json!(payloads))
            .await
            .map_err(NetworkErrors::Request)?;

        let decimals = responses[0]
            .result
            .as_ref()
            .and_then(|v| {
                serde_json::from_value::<SolanaValueResponse<Option<AccountInfoValue>>>(v.clone())
                    .ok()
            })
            .and_then(|r| r.value)
            .map(|v| v.data.parsed.info.decimals)
            .ok_or_else(|| NetworkErrors::RPCError("SPL mint account not found".to_string()))?;

        let mut balances = HashMap::new();
        for (offset, acc_idx) in valid_accounts.iter().enumerate() {
            balances.insert(*acc_idx, parse_spl_balance(&responses[1 + offset]));
        }

        Ok(FToken {
            name: String::new(),
            symbol: String::new(),
            decimals,
            addr: Address::Ed25519Solana(mint),
            logo: None,
            balances,
            default: false,
            native: false,
            chain_hash: self.config.hash(),
            rate: 0f64,
        })
    }
}

fn build_get_balance_req(address_b58: &str) -> Value {
    RpcProvider::<ChainConfig>::build_payload(
        json!([address_b58, {"commitment": "finalized"}]),
        SolanaMethod::GetBalance,
    )
}

fn build_get_token_accounts_req(address_b58: &str, mint_b58: &str) -> Value {
    RpcProvider::<ChainConfig>::build_payload(
        json!([address_b58, {"mint": mint_b58}, {"encoding": "jsonParsed", "commitment": "finalized"}]),
        SolanaMethod::GetTokenAccountsByOwner,
    )
}

fn build_get_account_info_req(mint_b58: &str) -> Value {
    RpcProvider::<ChainConfig>::build_payload(
        json!([mint_b58, {"encoding": "jsonParsed"}]),
        SolanaMethod::GetAccountInfo,
    )
}

fn build_get_transaction_req(sig: &str) -> Value {
    RpcProvider::<ChainConfig>::build_payload(
        json!([sig, {"encoding": "json", "maxSupportedTransactionVersion": 0}]),
        SolanaMethod::GetTransaction,
    )
}

fn build_send_transaction_req(encoded: &str) -> Value {
    RpcProvider::<ChainConfig>::build_payload(
        json!([encoded, {"encoding": "base64"}]),
        SolanaMethod::SendTransaction,
    )
}

fn parse_native_balance(raw: &ResultRes<Value>) -> U256 {
    raw.result
        .as_ref()
        .and_then(|v| serde_json::from_value::<SolanaValueResponse<u64>>(v.clone()).ok())
        .map(|r| U256::from(r.value))
        .unwrap_or(U256::ZERO)
}

fn parse_spl_balance(raw: &ResultRes<Value>) -> U256 {
    raw.result
        .as_ref()
        .and_then(|v| {
            serde_json::from_value::<SolanaValueResponse<Vec<TokenAccountEntry>>>(v.clone()).ok()
        })
        .and_then(|r| r.value.into_iter().next())
        .and_then(|e| {
            e.account
                .data
                .parsed
                .info
                .token_amount
                .amount
                .parse::<u64>()
                .ok()
        })
        .map(U256::from)
        .unwrap_or(U256::ZERO)
}

fn solana_err_msg(err: &Option<ErrorRes>) -> String {
    err.as_ref()
        .map(|e| e.to_string())
        .unwrap_or_else(|| "Solana RPC: empty result".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto::solana_tx::SolanaTransaction;
    use proto::tx::TransactionMetadata;
    use test_data::{gen_sol_devnet_conf, gen_sol_spl_token, gen_sol_token};

    const DEVNET_RICH_ADDRESS: &str = "vines1vzrYbzLMRdu58ou5XTby4qAqVRLmqo36NKPTg";
    const DEVNET_USDC_MINT: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
    const DEVNET_USDC_RICH_ADDRESS: &str = "DBD8hAwLDRQkTsu6EqviaYNGKPnsAMmQonxf7AH8ZcFY";
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
        let sender = Address::Ed25519Solana([1u8; 32].into());
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
        let zero_account = Address::Ed25519Solana([0u8; 32].into());

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

    fn usdc_mint_bytes() -> [u8; 32] {
        bs58::decode(DEVNET_USDC_MINT)
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap()
    }

    #[tokio::test]
    async fn test_solana_update_balances_spl_zero_address() {
        let conf = gen_sol_devnet_conf();
        let provider = NetworkProvider::new(conf.clone());
        let mut token = gen_sol_spl_token(usdc_mint_bytes(), conf.hash());
        let zero_account = Address::from_solana_address(DEVNET_ZERO_ADDRESS).unwrap();
        println!("Querying SPL USDC balance for zero-balance address: {}", DEVNET_ZERO_ADDRESS);

        provider
            .solana_update_balances(vec![&mut token], &[&zero_account])
            .await
            .unwrap();

        let balance = token.balances.get(&0).unwrap();
        dbg!(balance);
        assert_eq!(*balance, U256::ZERO, "Empty address should have zero SPL balance");
        println!("SPL USDC balance confirmed: 0");
    }

    #[tokio::test]
    async fn test_solana_update_balances_spl_rich_address() {
        let conf = gen_sol_devnet_conf();
        let provider = NetworkProvider::new(conf.clone());
        let mut token = gen_sol_spl_token(usdc_mint_bytes(), conf.hash());
        let rich_account = Address::from_solana_address(DEVNET_USDC_RICH_ADDRESS).unwrap();
        println!("Querying SPL USDC balance for: {}", DEVNET_USDC_RICH_ADDRESS);

        provider
            .solana_update_balances(vec![&mut token], &[&rich_account])
            .await
            .unwrap();

        let balance = token.balances.get(&0).unwrap();
        dbg!(balance);
        assert!(*balance > U256::ZERO, "Rich address should have USDC balance");
        println!("SPL USDC balance: {} (raw units)", balance);
    }

    #[tokio::test]
    async fn test_solana_ftoken_meta_usdc() {
        let conf = gen_sol_devnet_conf();
        let provider = NetworkProvider::new(conf.clone());
        let mint = Address::Ed25519Solana(usdc_mint_bytes().into());
        let rich_account = Address::from_solana_address(DEVNET_USDC_RICH_ADDRESS).unwrap();
        let zero_account = Address::from_solana_address(DEVNET_ZERO_ADDRESS).unwrap();
        println!("Fetching SPL metadata for devnet USDC: {}", DEVNET_USDC_MINT);

        let ftoken = provider
            .solana_ftoken_meta(mint, &[&rich_account, &zero_account])
            .await
            .unwrap();

        dbg!(&ftoken.decimals);
        dbg!(ftoken.balances.get(&0));
        dbg!(ftoken.balances.get(&1));
        assert_eq!(ftoken.decimals, 6, "Devnet USDC should have 6 decimals");
        assert!(!ftoken.native);
        assert!(*ftoken.balances.get(&0).unwrap() > U256::ZERO, "Rich address should have USDC");
        assert_eq!(*ftoken.balances.get(&1).unwrap(), U256::ZERO, "Zero address should have no USDC");
        println!(
            "SPL ftoken_meta: decimals={}, rich={}, zero={}",
            ftoken.decimals,
            ftoken.balances[&0],
            ftoken.balances[&1]
        );
    }
}
