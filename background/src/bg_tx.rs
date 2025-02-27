use crate::{bg_provider::ProvidersManagement, bg_wallet::WalletManagement, Result};
use alloy::dyn_abi::TypedData;
use async_trait::async_trait;
use cipher::argon2::Argon2Seed;
use errors::{background::BackgroundError, tx::TransactionErrors};
use history::{status::TransactionStatus, transaction::HistoricalTransaction};
use proto::{pubkey::PubKey, signature::Signature, tx::TransactionReceipt};
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
    ) -> std::result::Result<(PubKey, Signature), Self::Error>;

    async fn sign_typed_data_eip712(
        &self,
        wallet_index: usize,
        account_index: usize,
        seed_bytes: &Argon2Seed,
        passphrase: Option<&str>,
        message: &str,
    ) -> std::result::Result<(PubKey, Signature), Self::Error>;
}

#[async_trait]
impl TransactionsManagement for Background {
    type Error = BackgroundError;

    async fn sign_typed_data_eip712(
        &self,
        wallet_index: usize,
        account_index: usize,
        seed_bytes: &Argon2Seed,
        passphrase: Option<&str>,
        typed_data_json: &str,
    ) -> Result<(PubKey, Signature)> {
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let key_pair = wallet.reveal_keypair(account_index, seed_bytes, passphrase)?;
        let typed_data: TypedData = serde_json::from_str(&typed_data_json.to_string())
            .map_err(|e| BackgroundError::FailDeserializeTypedData(e.to_string()))?;
        let signature = key_pair.sign_typed_data_eip712(typed_data).await?;

        Ok((key_pair.get_pubkey()?, signature))
    }

    fn sign_message(
        &self,
        wallet_index: usize,
        account_index: usize,
        seed_bytes: &Argon2Seed,
        passphrase: Option<&str>,
        message: &str,
    ) -> Result<(PubKey, Signature)> {
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let key_pair = wallet.reveal_keypair(account_index, seed_bytes, passphrase)?;
        let signature = key_pair.sign_message(message.as_bytes())?;

        Ok((key_pair.get_pubkey()?, signature))
    }

    async fn check_pending_txns(&self, wallet_index: usize) -> Result<Vec<HistoricalTransaction>> {
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let data = wallet.get_wallet_data()?;
        let account = data.get_selected_account()?;
        let chain = self.get_provider(account.chain_hash)?;
        let mut history = wallet.get_history()?;

        let mut matching_transactions = Vec::with_capacity(history.len());

        for tx in history.iter_mut() {
            if tx.chain_hash == account.chain_hash && tx.status == TransactionStatus::Pending {
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
    use crypto::{bip49::DerivationPath, slip44};
    use proto::{address::Address, tx::TransactionRequest, zil_tx::ZILTransactionRequest};
    use rand::Rng;
    use rpc::network_config::ChainConfig;
    use token::ft::FToken;
    use tokio;
    use wallet::wallet_crypto::WalletCrypto;

    const PASSWORD: &str = "TEst password";
    const WORDS: &str =
        "future slot favorite conduct please organ trick seek goat easy chapter proud";

    fn setup_test_background() -> (Background, String) {
        let mut rng = rand::thread_rng();
        let dir = format!("/tmp/{}", rng.gen::<usize>());
        let bg = Background::from_storage_path(&dir).unwrap();
        (bg, dir)
    }

    fn gen_zil_net_conf() -> ChainConfig {
        ChainConfig {
            logo: String::new(),
            diff_block_time: 0,
            testnet: None,
            chain_ids: [333, 0],
            name: "Zilliqa(testnet)".to_string(),
            chain: "ZIL".to_string(),
            short_name: String::new(),
            rpc: vec!["https://dev-api.zilliqa.com".to_string()],
            features: vec![],
            slip_44: slip44::ZILLIQA,
            ens: None,
            explorers: vec![],
            fallback_enabled: true,
        }
    }

    fn gen_bsc_net_conf() -> ChainConfig {
        ChainConfig {
            logo: String::new(),
            diff_block_time: 0,
            testnet: None,
            chain_ids: [97, 0],
            name: "BNB Smart Chain Testnet".to_string(),
            chain: "BSC".to_string(),
            short_name: String::new(),
            rpc: vec![
                "https://data-seed-prebsc-2-s1.binance.org:8545/".to_string(),
                "http://data-seed-prebsc-1-s2.binance.org:8545/".to_string(),
            ],
            features: vec![155, 1559],
            slip_44: slip44::ETHEREUM,
            ens: None,
            explorers: vec![],
            fallback_enabled: true,
        }
    }

    fn gen_bsc_token() -> FToken {
        FToken {
            name: "BNB Smart Chain Testnet".to_string(),
            symbol: "tBNB".to_string(),
            decimals: 18,
            addr: Address::Secp256k1Sha256(Address::ZERO),
            logo: None,
            balances: Default::default(),
            default: true,
            native: true,
            chain_hash: gen_bsc_net_conf().hash(),
        }
    }

    #[tokio::test]
    async fn test_sign_and_send_zil_tx() {
        let (mut bg, _dir) = setup_test_background();
        let net_config = gen_zil_net_conf();

        bg.add_provider(net_config.clone()).unwrap();

        let accounts = [(
            DerivationPath::new(slip44::ZILLIQA, 0),
            "ZIL Acc 0".to_string(),
        )];
        let device_indicators = [String::from("5435h"), String::from("0000")];

        bg.add_bip39_wallet(BackgroundBip39Params {
            mnemonic_check: true,
            password: PASSWORD,
            chain_hash: net_config.hash(),
            mnemonic_str: WORDS,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: String::new(),
            biometric_type: Default::default(),
            device_indicators: &device_indicators,
            ftokens: vec![FToken::zil(net_config.hash())],
        })
        .unwrap();
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
            gas_price: 2000000000,
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
            PASSWORD.as_bytes(),
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
            assert!(!tx.transaction_hash.is_empty());
        }
    }

    #[tokio::test]
    async fn test_sign_and_send_evm_tx() {
        let (mut bg, _dir) = setup_test_background();
        let net_config = gen_bsc_net_conf();

        bg.add_provider(net_config.clone()).unwrap();
        let accounts = [(
            DerivationPath::new(slip44::ETHEREUM, 0),
            "BSC Acc 0".to_string(),
        )];
        let device_indicators = [String::from("testbnb"), String::from("0000")];

        bg.add_bip39_wallet(BackgroundBip39Params {
            mnemonic_check: true,
            password: PASSWORD,
            chain_hash: net_config.hash(),
            mnemonic_str: WORDS,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: "BSC wallet".to_string(),
            biometric_type: Default::default(),
            device_indicators: &device_indicators,
            ftokens: vec![gen_bsc_token()],
        })
        .unwrap();

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
            PASSWORD.as_bytes(),
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
            assert!(!tx.transaction_hash.is_empty());
        }
    }

    #[tokio::test]
    async fn test_update_history_evm() {
        let (mut bg, _dir) = setup_test_background();
        let net_config = ChainConfig {
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

        let accounts = [(
            DerivationPath::new(slip44::ETHEREUM, 0),
            "BSC Acc 0".to_string(),
        )];
        let device_indicators = [String::from("testbnb"), String::from("0000")];

        bg.add_bip39_wallet(BackgroundBip39Params {
            mnemonic_check: true,
            password: PASSWORD,
            chain_hash: net_hash,
            mnemonic_str: &words,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: "BSC wallet".to_string(),
            biometric_type: Default::default(),
            device_indicators: &device_indicators,
            ftokens: vec![gen_bsc_token()],
        })
        .unwrap();

        let tx_history = vec![
            HistoricalTransaction {
                transaction_hash: String::from(
                    "0x3c5c16b756adf898dc9623445de94df709ffa2c1761d7579270dd292319981e5",
                ),
                chain_hash: net_hash,
                chain_type: history::transaction::ChainType::EVM,
                ..Default::default()
            },
            HistoricalTransaction {
                transaction_hash: String::from(
                    "0x6f3c4cb8145acf658db0a8fcf628c1294263d7ed4f9a2bbd92f7bf0e2846fb29",
                ),
                chain_hash: net_hash,
                chain_type: history::transaction::ChainType::EVM,
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
            .filter(|t| t.chain_hash == net_hash)
            .collect::<Vec<HistoricalTransaction>>();

        assert_eq!(
            filterd_history[0].transaction_hash,
            tx_history[0].transaction_hash
        );
        assert_eq!(
            filterd_history[1].transaction_hash,
            tx_history[1].transaction_hash
        );
        assert_eq!(filterd_history[0].status, TransactionStatus::Confirmed);
        assert_eq!(filterd_history[1].status, TransactionStatus::Rejected);
    }
}
