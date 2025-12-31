use crate::{bg_provider::ProvidersManagement, bg_wallet::WalletManagement, Result};
use alloy::{dyn_abi::TypedData, primitives::keccak256};
use async_trait::async_trait;
use cipher::argon2::Argon2Seed;
use config::sha::SHA256_SIZE;
use errors::{background::BackgroundError, tx::TransactionErrors, wallet::WalletErrors};
use history::{status::TransactionStatus, transaction::HistoricalTransaction};
use proto::{address::Address, pubkey::PubKey, signature::Signature, tx::TransactionReceipt};
use sha2::{Digest, Sha256};
use wallet::{wallet_crypto::WalletCrypto, wallet_storage::StorageOperations};

use crate::Background;

#[async_trait]
pub trait TransactionsManagement {
    type Error;

    async fn broadcast_signed_transactions<'a>(
        &self,
        wallet_index: usize,
        account_index: usize,
        txns: Vec<TransactionReceipt>,
    ) -> std::result::Result<Vec<HistoricalTransaction>, Self::Error>;

    async fn check_pending_txns(
        &self,
        wallet_index: usize,
    ) -> std::result::Result<Vec<HistoricalTransaction>, Self::Error>;

    fn sign_message(
        &self,
        wallet_index: usize,
        account_index: usize,
        seed_bytes: &Argon2Seed,
        passphrase: Option<&str>,
        message: &str,
        title: Option<String>,
        icon: Option<String>,
    ) -> std::result::Result<(PubKey, Signature), Self::Error>;

    fn prepare_message(
        &self,
        wallet_index: usize,
        account_index: usize,
        message: &str,
    ) -> std::result::Result<[u8; SHA256_SIZE], Self::Error>;

    fn prepare_eip712_message(
        &self,
        typed_data_json: String,
    ) -> std::result::Result<TypedData, Self::Error>;

    async fn sign_typed_data_eip712(
        &self,
        wallet_index: usize,
        account_index: usize,
        seed_bytes: &Argon2Seed,
        passphrase: Option<&str>,
        message: &str,
        title: Option<String>,
        icon: Option<String>,
    ) -> std::result::Result<(PubKey, Signature), Self::Error>;
}

#[async_trait]
impl TransactionsManagement for Background {
    type Error = BackgroundError;

    fn prepare_message(
        &self,
        wallet_index: usize,
        account_index: usize,
        message: &str,
    ) -> Result<[u8; SHA256_SIZE]> {
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let wallet_data = wallet.get_wallet_data()?;
        let account = wallet_data
            .accounts
            .get(account_index)
            .ok_or(WalletErrors::InvalidAccountIndex(account_index))?;

        match account.addr {
            Address::Secp256k1Bitcoin(_) => {
                return Err(BackgroundError::BincodeError(
                    "BTC not impl yet".to_string(),
                ));
            }
            Address::Secp256k1Sha256(_) => {
                let mut hasher = Sha256::new();
                hasher.update(message.as_bytes());
                let hash = hasher.finalize();

                Ok(hash.into())
            }
            Address::Secp256k1Keccak256(_) => {
                let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
                let full_message = format!("{}{}", prefix, message);
                let hash = keccak256(full_message.as_bytes());

                Ok(hash.0)
            }
        }
    }

    fn prepare_eip712_message(&self, typed_data_json: String) -> Result<TypedData> {
        let typed_data: TypedData = serde_json::from_str(&typed_data_json)
            .map_err(|e| BackgroundError::FailDeserializeTypedData(e.to_string()))?;

        Ok(typed_data)
    }

    async fn sign_typed_data_eip712(
        &self,
        wallet_index: usize,
        account_index: usize,
        seed_bytes: &Argon2Seed,
        passphrase: Option<&str>,
        typed_data_json: &str,
        title: Option<String>,
        icon: Option<String>,
    ) -> Result<(PubKey, Signature)> {
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let data = wallet.get_wallet_data()?;
        let account = data
            .accounts
            .get(account_index)
            .ok_or(WalletErrors::InvalidAccountIndex(account_index))?;
        let key_pair = wallet.reveal_keypair(account_index, seed_bytes, passphrase)?;
        let typed_data: TypedData = serde_json::from_str(&typed_data_json.to_string())
            .map_err(|e| BackgroundError::FailDeserializeTypedData(e.to_string()))?;
        let signature = key_pair.sign_typed_data_eip712(typed_data).await?;
        let pub_key = key_pair.get_pubkey()?;

        let history_entry = HistoricalTransaction::from_signed_typed_data(
            typed_data_json,
            &signature.to_hex_prefixed(),
            &pub_key.as_hex_str(),
            &account.addr.auto_format(),
            title,
            icon,
            account.chain_hash,
        );
        wallet.add_history(&[history_entry])?;

        Ok((pub_key, signature))
    }

    fn sign_message(
        &self,
        wallet_index: usize,
        account_index: usize,
        seed_bytes: &Argon2Seed,
        passphrase: Option<&str>,
        message: &str,
        title: Option<String>,
        icon: Option<String>,
    ) -> Result<(PubKey, Signature)> {
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let data = wallet.get_wallet_data()?;
        let account = data
            .accounts
            .get(account_index)
            .ok_or(WalletErrors::InvalidAccountIndex(account_index))?;

        let key_pair = wallet.reveal_keypair(account_index, seed_bytes, passphrase)?;
        let signature = match account.addr {
            Address::Secp256k1Bitcoin(_) => {
                return Err(BackgroundError::WalletError(
                    WalletErrors::InvalidHexToWalletType,
                ));
            }
            Address::Secp256k1Sha256(_) => {
                let mut hasher = Sha256::new();
                hasher.update(message.as_bytes());
                let hash = hasher.finalize();

                key_pair.sign_message(&hash)?
            }
            Address::Secp256k1Keccak256(_) => key_pair.sign_message(message.as_bytes())?,
        };
        let pub_key = key_pair.get_pubkey()?;

        let history_entry = HistoricalTransaction::from_signed_message(
            message,
            &signature.to_hex_prefixed(),
            &pub_key.as_hex_str(),
            &account.addr.auto_format(),
            title,
            icon,
            account.chain_hash,
        );
        wallet.add_history(&[history_entry])?;

        Ok((pub_key, signature))
    }

    async fn check_pending_txns(&self, wallet_index: usize) -> Result<Vec<HistoricalTransaction>> {
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let data = wallet.get_wallet_data()?;
        let account = data.get_selected_account()?;
        let chain = self.get_provider(account.chain_hash)?;
        let mut history = wallet.get_history()?;

        let mut matching_transactions = Vec::with_capacity(history.len());

        for tx in history.iter_mut() {
            if tx.metadata.chain_hash == account.chain_hash
                && tx.status == TransactionStatus::Pending
            {
                matching_transactions.push(tx);
            }
        }

        if matching_transactions.is_empty() {
            return Ok(history);
        }

        chain
            .update_transactions_receipt(&mut matching_transactions)
            .await?;
        wallet.save_history(&history)?;

        Ok(history)
    }

    async fn broadcast_signed_transactions<'a>(
        &self,
        wallet_index: usize,
        account_index: usize,
        txns: Vec<TransactionReceipt>,
    ) -> Result<Vec<HistoricalTransaction>> {
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let data = wallet.get_wallet_data()?;
        let selected_account =
            data.accounts
                .get(account_index)
                .ok_or(BackgroundError::WalletError(
                    errors::wallet::WalletErrors::NotExistsAccount(account_index),
                ))?;
        let provider = self.get_provider(selected_account.chain_hash)?;
        let txns = provider.broadcast_signed_transactions(txns).await?;
        let history = txns
            .into_iter()
            .map(|receipt| HistoricalTransaction::try_from(receipt))
            .collect::<std::result::Result<Vec<HistoricalTransaction>, TransactionErrors>>()?;

        wallet.add_history(&history)?;

        Ok(history)
    }
}

#[cfg(test)]
mod tests_background_transactions {
    use super::*;
    use crate::{
        bg_crypto::CryptoOperations, bg_storage::StorageManagement, BackgroundBip39Params,
    };
    use alloy::{primitives::U256, rpc::types::TransactionRequest as ETHTransactionRequest};
    use cipher::argon2;
    use crypto::slip44;
    use proto::{address::Address, tx::TransactionRequest, zil_tx::ZILTransactionRequest};
    use rand::Rng;
    use rpc::network_config::ChainConfig;
    use test_data::{
        gen_anvil_net_conf, gen_anvil_token, gen_device_indicators, gen_eth_account,
        gen_zil_account, gen_zil_testnet_conf, gen_zil_token, ANVIL_MNEMONIC, TEST_PASSWORD,
    };
    use token::ft::FToken;
    use tokio;
    use wallet::{wallet_crypto::WalletCrypto, wallet_transaction::WalletTransaction};

    fn setup_test_background() -> (Background, String) {
        let mut rng = rand::thread_rng();
        let dir = format!("/tmp/{}", rng.gen::<usize>());
        let bg = Background::from_storage_path(&dir).unwrap();
        (bg, dir)
    }

    // Helper function for BSC mainnet token (used only in history test)
    fn gen_bsc_mainnet_token(chain_hash: u64) -> FToken {
        use config::address::ADDR_LEN;
        use std::collections::HashMap;
        FToken {
            rate: 0f64,
            name: "BNB Smart Chain".to_string(),
            symbol: "BNB".to_string(),
            decimals: 18,
            addr: Address::Secp256k1Keccak256([0u8; ADDR_LEN]),
            logo: None,
            balances: HashMap::new(),
            default: true,
            native: true,
            chain_hash,
        }
    }

    #[tokio::test]
    async fn test_sign_and_send_zil_legacy_tx() {
        let (mut bg, _dir) = setup_test_background();
        let net_config = gen_zil_testnet_conf();

        bg.add_provider(net_config.clone()).unwrap();

        let accounts = [gen_zil_account(0, "ZIL Acc 0")];
        let device_indicators = gen_device_indicators("zil_test");

        bg.add_bip39_wallet(BackgroundBip39Params {
            mnemonic_check: true,
            password: TEST_PASSWORD,
            chain_hash: net_config.hash(),
            mnemonic_str: ANVIL_MNEMONIC,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: String::new(),
            biometric_type: Default::default(),
            device_indicators: &device_indicators,
            ftokens: vec![FToken::zil(net_config.hash())],
        })
        .unwrap();

        bg.swap_zilliqa_chain(0, 0).unwrap();

        let providers = bg.get_providers();
        let provider = providers.first().unwrap();
        let wallet = bg.get_wallet_by_index(0).unwrap();
        let data = wallet.get_wallet_data().unwrap();
        let addresses: Vec<&Address> = data.accounts.iter().map(|v| &v.addr).collect();

        let nonce = *provider
            .fetch_nonce(&addresses)
            .await
            .unwrap()
            .first()
            .unwrap();
        let zil_tx = ZILTransactionRequest {
            nonce: nonce + 1,
            chain_id: provider.config.chain_id() as u16,
            gas_price: 2000000100,
            gas_limit: 1000,
            to_addr: Address::from_zil_bech32("zil1sctmwt3zpy8scyck0pj3glky3fkm0z8lxa4ga7")
                .unwrap(),
            amount: 1, // in QA
            code: Vec::with_capacity(0),
            data: Vec::with_capacity(0),
        };
        let txn = TransactionRequest::Zilliqa((zil_tx, Default::default()));

        let device_indicator = device_indicators.join(":");
        let argon_seed = argon2::derive_key(
            TEST_PASSWORD.as_bytes(),
            &device_indicator,
            &data.settings.argon_params.into_config(),
        )
        .unwrap();

        let keypair = wallet.reveal_keypair(0, &argon_seed, None).unwrap();
        let txn = txn.sign(&keypair).await.unwrap();
        let txns = vec![txn];

        let txns = bg.broadcast_signed_transactions(0, 0, txns).await.unwrap();

        assert_eq!(txns.len(), 1);

        for tx in txns {
            assert!(tx.metadata.hash.is_some());
        }
    }

    #[tokio::test]
    async fn test_sign_and_verify_zil_swap_to_anvil() {
        let (mut bg, _dir) = setup_test_background();
        let zil_config = gen_zil_testnet_conf();
        let anvil_config = gen_anvil_net_conf();

        bg.add_provider(zil_config.clone()).unwrap();
        bg.add_provider(anvil_config.clone()).unwrap();

        let accounts = [gen_zil_account(0, "ZIL Acc 0")];
        let device_indicators = gen_device_indicators("zil_test");

        bg.add_bip39_wallet(BackgroundBip39Params {
            mnemonic_check: true,
            password: TEST_PASSWORD,
            chain_hash: zil_config.hash(),
            mnemonic_str: ANVIL_MNEMONIC,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: String::new(),
            biometric_type: Default::default(),
            device_indicators: &device_indicators,
            ftokens: vec![FToken::zil(zil_config.hash())],
        })
        .unwrap();

        bg.swap_zilliqa_chain(0, 0).unwrap();
        let wallet = bg.get_wallet_by_index(0).unwrap();

        let recipient =
            Address::from_eth_address("0x246C5881E3F109B2aF170F5C773EF969d3da581B").unwrap();
        let token_transfer_request = ETHTransactionRequest {
            to: Some(recipient.to_alloy_addr().into()),
            value: Some(U256::ZERO),
            max_fee_per_gas: Some(2_000_000_000),
            max_priority_fee_per_gas: Some(1_000_000_000),
            nonce: Some(0),
            gas: Some(21000),
            chain_id: Some(anvil_config.chain_id()),
            ..Default::default()
        };
        let zilpay_trasnfer_req =
            TransactionRequest::Ethereum((token_transfer_request, Default::default()));

        let argon_seed = bg
            .unlock_wallet_with_password(&TEST_PASSWORD, &device_indicators, 0)
            .unwrap();

        bg.select_accounts_chain(0, anvil_config.hash()).unwrap();

        let data = wallet.get_wallet_data().unwrap();
        let selected_account = data.get_selected_account().unwrap();

        // Verify we got a valid Ethereum address from the Anvil mnemonic
        assert!(selected_account.addr.to_string().starts_with("0x"));

        if let PubKey::Secp256k1Keccak256(_pub_key) = selected_account.pub_key {
            // Valid Keccak256 public key
        } else {
            panic!("invalid pubkey");
        }

        let tx = wallet
            .sign_transaction(zilpay_trasnfer_req, 0, &argon_seed, None)
            .await
            .unwrap();

        assert!(tx.verify().unwrap());
    }

    #[tokio::test]
    async fn test_sign_and_send_evm_tx() {
        let (mut bg, _dir) = setup_test_background();
        let net_config = gen_anvil_net_conf();

        bg.add_provider(net_config.clone()).unwrap();
        let accounts = [gen_eth_account(0, "Anvil Acc 0")];
        let device_indicators = gen_device_indicators("testanvil");

        bg.add_bip39_wallet(BackgroundBip39Params {
            mnemonic_check: true,
            password: TEST_PASSWORD,
            chain_hash: net_config.hash(),
            mnemonic_str: ANVIL_MNEMONIC,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: "Anvil wallet".to_string(),
            biometric_type: Default::default(),
            device_indicators: &device_indicators,
            ftokens: vec![gen_anvil_token()],
        })
        .unwrap();

        let providers = bg.get_providers();
        let provider = providers.first().unwrap();
        let wallet = bg.get_wallet_by_index(0).unwrap();
        let data = wallet.get_wallet_data().unwrap();

        // Verify we got the expected Anvil account (account 0)
        let account = data.accounts.first().unwrap();
        assert_eq!(
            account.addr.to_string().to_lowercase(),
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        );

        let addresses: Vec<&Address> = data.accounts.iter().map(|v| &v.addr).collect();
        let nonce = *provider
            .fetch_nonce(&addresses)
            .await
            .unwrap()
            .first()
            .unwrap();
        let recipient =
            Address::from_eth_address("0x246C5881E3F109B2aF170F5C773EF969d3da581B").unwrap();
        let transfer_request = ETHTransactionRequest {
            to: Some(recipient.to_alloy_addr().into()),
            value: Some(U256::from(10u128)),
            max_fee_per_gas: Some(2_000_000_000),
            max_priority_fee_per_gas: Some(1_000_000_000),
            nonce: Some(nonce),
            gas: Some(21_000),
            chain_id: Some(provider.config.chain_id()),
            ..Default::default()
        };
        let txn = TransactionRequest::Ethereum((transfer_request, Default::default()));

        let device_indicator = device_indicators.join(":");
        let argon_seed = argon2::derive_key(
            TEST_PASSWORD.as_bytes(),
            &device_indicator,
            &data.settings.argon_params.into_config(),
        )
        .unwrap();

        let keypair = wallet.reveal_keypair(0, &argon_seed, None).unwrap();
        let txn = txn.sign(&keypair).await.unwrap();
        let txns = vec![txn];
        let txns = bg.broadcast_signed_transactions(0, 0, txns).await.unwrap();

        assert_eq!(txns.len(), 1);

        for tx in txns {
            assert!(tx.metadata.hash.is_some());
        }
    }

    #[tokio::test]
    async fn test_update_history_evm() {
        let (mut bg, _dir) = setup_test_background();
        let net_config = ChainConfig {
            ftokens: vec![],
            logo: String::new(),
            diff_block_time: 0,
            testnet: None,
            chain_ids: [56, 0],
            name: "BNB Smart Chain mainnet".to_string(),
            chain: "BSC".to_string(),
            short_name: String::new(),
            rpc: vec![
                "https://bsc-dataseed1.binance.org/".to_string(),
                "https://bsc-dataseed2.binance.org/".to_string(),
                "https://bsc-dataseed3.binance.org/".to_string(),
                "https://bsc-dataseed4.binance.org/".to_string(),
            ],
            features: vec![155, 1559],
            slip_44: slip44::ETHEREUM,
            ens: None,
            explorers: vec![],
            fallback_enabled: true,
        };
        let net_hash = net_config.hash();
        let words = Background::gen_bip39(24).unwrap();

        bg.add_provider(net_config).unwrap();

        let accounts = [gen_eth_account(0, "BSC Acc 0")];
        let device_indicators = gen_device_indicators("testbnb");

        bg.add_bip39_wallet(BackgroundBip39Params {
            mnemonic_check: true,
            password: TEST_PASSWORD,
            chain_hash: net_hash,
            mnemonic_str: &words,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: "BSC wallet".to_string(),
            biometric_type: Default::default(),
            device_indicators: &device_indicators,
            ftokens: vec![gen_bsc_mainnet_token(net_hash)],
        })
        .unwrap();

        let tx_hash_1 = "0x3c5c16b756adf898dc9623445de94df709ffa2c1761d7579270dd292319981e5";
        let tx_hash_2 = "0x6f3c4cb8145acf658db0a8fcf628c1294263d7ed4f9a2bbd92f7bf0e2846fb29";
        let tx_history = vec![
            HistoricalTransaction {
                metadata: proto::tx::TransactionMetadata {
                    chain_hash: net_hash,
                    hash: Some(tx_hash_1.to_string()),
                    ..Default::default()
                },
                evm: Some(
                    serde_json::json!({
                        "transactionHash": tx_hash_1,
                    })
                    .to_string(),
                ),
                ..Default::default()
            },
            HistoricalTransaction {
                metadata: proto::tx::TransactionMetadata {
                    chain_hash: net_hash,
                    hash: Some(tx_hash_2.to_string()),
                    ..Default::default()
                },
                evm: Some(
                    serde_json::json!({
                        "transactionHash": tx_hash_2,
                    })
                    .to_string(),
                ),
                ..Default::default()
            },
        ];
        let walelt = bg.get_wallet_by_index(0).unwrap();

        walelt.add_history(&tx_history).unwrap();
        bg.check_pending_txns(0).await.unwrap();

        let filterd_history = walelt
            .get_history()
            .unwrap()
            .into_iter()
            .filter(|t| t.metadata.chain_hash == net_hash)
            .collect::<Vec<HistoricalTransaction>>();

        assert_eq!(
            filterd_history[0].metadata.hash,
            tx_history[0].metadata.hash
        );
        assert_eq!(
            filterd_history[1].metadata.hash,
            tx_history[1].metadata.hash
        );
        assert_eq!(filterd_history[0].status, TransactionStatus::Success);
        assert_eq!(filterd_history[1].status, TransactionStatus::Failed);
    }

    #[tokio::test]
    async fn test_sign_message_legacy_zilliqa() {
        let (mut bg, _dir) = setup_test_background();
        let net_config = gen_zil_testnet_conf();

        bg.add_provider(net_config.clone()).unwrap();
        let accounts = [gen_zil_account(0, "ZIL Acc 0")];
        let device_indicators = gen_device_indicators("zil_test");

        bg.add_bip39_wallet(BackgroundBip39Params {
            mnemonic_check: true,
            password: TEST_PASSWORD,
            chain_hash: net_config.hash(),
            mnemonic_str: ANVIL_MNEMONIC,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: "ZIL wallet".to_string(),
            biometric_type: Default::default(),
            device_indicators: &device_indicators,
            ftokens: vec![FToken::zil(net_config.hash())],
        })
        .unwrap();

        bg.swap_zilliqa_chain(0, 0).unwrap();

        let device_indicator = device_indicators.join(":");
        let argon_seed = argon2::derive_key(
            TEST_PASSWORD.as_bytes(),
            &device_indicator,
            &bg.get_wallet_by_index(0)
                .unwrap()
                .get_wallet_data()
                .unwrap()
                .settings
                .argon_params
                .into_config(),
        )
        .unwrap();

        let message = "Hello, Zilliqa!";
        let (pubkey, signature) = bg
            .sign_message(0, 0, &argon_seed, None, message, None, None)
            .unwrap();

        let hashed_message = Sha256::digest(message.as_bytes());
        let key_pair = bg
            .get_wallet_by_index(0)
            .unwrap()
            .reveal_keypair(0, &argon_seed, None)
            .unwrap();

        assert_eq!(pubkey.as_bytes(), *key_pair.get_pubkey_bytes());
        let is_valid = key_pair.verify_sig(&hashed_message, &signature).unwrap();

        assert!(is_valid);
    }

    #[tokio::test]
    async fn test_unckeched_seed_phrase() {
        let (mut bg, _dir) = setup_test_background();
        let net_config = gen_zil_testnet_conf();

        bg.add_provider(net_config.clone()).unwrap();
        let accounts = [gen_zil_account(0, "Zil 0")];
        let device_indicators = gen_device_indicators("test_zilliqa");

        const UNCHECKSUMED_WORD: &str =
            "sword sure throw slide garden science six destroy canvas ceiling negative black";
        bg.add_bip39_wallet(BackgroundBip39Params {
            mnemonic_check: false,
            password: TEST_PASSWORD,
            chain_hash: net_config.hash(),
            mnemonic_str: UNCHECKSUMED_WORD,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: "Zilliqa legacy wallet".to_string(),
            biometric_type: Default::default(),
            device_indicators: &device_indicators,
            ftokens: vec![gen_zil_token()],
        })
        .unwrap();

        bg.swap_zilliqa_chain(0, 0).unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let data = wallet.get_wallet_data().unwrap();
        let device_indicator = device_indicators.join(":");
        let argon_seed = argon2::derive_key(
            TEST_PASSWORD.as_bytes(),
            &device_indicator,
            &data.settings.argon_params.into_config(),
        )
        .unwrap();
        let revealed_mnemonic = wallet.reveal_mnemonic(&argon_seed).unwrap();
        let keypair = wallet.reveal_keypair(0, &argon_seed, None).unwrap();

        assert_eq!(revealed_mnemonic.to_string(), UNCHECKSUMED_WORD);
        assert_eq!(
            "d7986cf4acc822c1a6cdc4170f5561a6cee1591c37ec6a887bb650d051e4ad71",
            hex::encode(&keypair.get_secretkey().unwrap().as_ref())
        );
        assert_eq!(
            "022b8e6855eaf04ec7bd2e01d5aaf4e46a111b509882e5456d97af60a6d1ed6f28",
            hex::encode(&keypair.get_pubkey().unwrap().as_bytes())
        );
    }
}
