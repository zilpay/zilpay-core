use crate::{bg_provider::ProvidersManagement, bg_wallet::WalletManagement, Result};
use async_trait::async_trait;
use proto::tx::TransactionReceipt;
use errors::background::BackgroundError;

use crate::Background;

#[async_trait]
pub trait TransactionsManagement {
    type Error;

    async fn broadcast_signed_transactions<'a>(
        &self,
        wallet_index: usize,
        txns: Vec<TransactionReceipt>,
    ) -> std::result::Result<Vec<TransactionReceipt>, Self::Error>;
}

#[async_trait]
impl TransactionsManagement for Background {
    type Error = BackgroundError;

    async fn broadcast_signed_transactions<'a>(
        &self,
        wallet_index: usize,
        txns: Vec<TransactionReceipt>,
    ) -> Result<Vec<TransactionReceipt>> {
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let provider = self.get_provider(wallet.data.provider_index)?;
        let txns = provider.broadcast_signed_transactions(txns).await?;

        Ok(txns)
    }
}

#[cfg(test)]
mod tests_background_transactions {
    use super::*;
    use crate::{bg_storage::StorageManagement, BackgroundBip39Params};
    use alloy::{primitives::U256, rpc::types::TransactionRequest as ETHTransactionRequest};
    use cipher::argon2;
    use crypto::bip49::Bip49DerivationPath;
    use proto::{address::Address, tx::TransactionRequest, zil_tx::ZILTransactionRequest};
    use rand::Rng;
    use rpc::network_config::NetworkConfig;
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

    fn gen_zil_net_conf() -> NetworkConfig {
        NetworkConfig::new(
            "Zilliqa(testnet)",
            333,
            vec!["https://dev-api.zilliqa.com".to_string()],
        )
    }

    fn gen_bsc_net_conf() -> NetworkConfig {
        NetworkConfig::new(
            "BNB Smart Chain Testnet",
            97,
            vec![
                "https://data-seed-prebsc-1-s1.binance.org:8545".to_string(),
                "https://data-seed-prebsc-2-s1.binance.org:8545/".to_string(),
                "http://data-seed-prebsc-1-s2.binance.org:8545/".to_string(),
                "https://bsctestapi.terminet.io/rpc".to_string(),
            ],
        )
    }

    fn gen_bsc_token() -> FToken {
        FToken {
            name: "BNB Smart Chain Testnet".to_string(),
            symbol: "tBNB".to_string(),
            decimals: 18,
            addr: Address::Secp256k1Keccak256Ethereum(Address::ZERO),
            logo: None,
            balances: Default::default(),
            default: true,
            native: true,
            provider_index: 0,
        }
    }

    #[tokio::test]
    async fn test_sign_and_send_zil_tx() {
        let (mut bg, _dir) = setup_test_background();

        bg.add_provider(gen_zil_net_conf()).unwrap();

        let accounts = [(Bip49DerivationPath::Zilliqa(0), "ZIL Acc 0".to_string())];
        let device_indicators = [String::from("5435h"), String::from("0000")];

        bg.add_bip39_wallet(BackgroundBip39Params {
            password: PASSWORD,
            provider: 0,
            mnemonic_str: WORDS,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: String::new(),
            biometric_type: Default::default(),
            device_indicators: &device_indicators,
            ftokens: vec![FToken::zil(0)],
        })
        .unwrap();
        let provider = bg.get_provider(0).unwrap();
        let wallet = bg.get_wallet_by_index(0).unwrap();
        let addresses: Vec<&Address> = wallet.data.accounts.iter().map(|v| &v.addr).collect();
        let nonce = *bg
            .get_provider(0)
            .unwrap()
            .fetch_nonce(&addresses)
            .await
            .unwrap()
            .first()
            .unwrap();
        let zil_tx = ZILTransactionRequest {
            nonce: nonce + 1,
            chain_id: provider.config.chain_id as u16,
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
            &wallet.data.settings.argon_params.into_config(),
        )
        .unwrap();

        let keypair = wallet.reveal_keypair(0, &argon_seed, None).unwrap();
        let txn = txn.sign(&keypair).await.unwrap();
        let txns = vec![txn];

        let txns = bg.broadcast_signed_transactions(0, txns).await.unwrap();

        assert_eq!(txns.len(), 1);

        for tx in txns {
            assert!(tx.hash().is_some());
        }
    }

    #[tokio::test]
    async fn test_sign_and_send_evm_tx() {
        let (mut bg, _dir) = setup_test_background();

        bg.add_provider(gen_bsc_net_conf()).unwrap();
        let accounts = [(Bip49DerivationPath::Ethereum(0), "BSC Acc 0".to_string())];
        let device_indicators = [String::from("testbnb"), String::from("0000")];

        bg.add_bip39_wallet(BackgroundBip39Params {
            password: PASSWORD,
            provider: 0,
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

        let provider = bg.get_provider(0).unwrap();
        let wallet = bg.get_wallet_by_index(0).unwrap();
        let addresses: Vec<&Address> = wallet.data.accounts.iter().map(|v| &v.addr).collect();
        let nonce = *bg
            .get_provider(0)
            .unwrap()
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
            chain_id: Some(provider.config.chain_id),
            ..Default::default()
        };
        let txn = TransactionRequest::Ethereum((transfer_request, Default::default()));

        let device_indicator = device_indicators.join(":");
        let argon_seed = argon2::derive_key(
            PASSWORD.as_bytes(),
            &device_indicator,
            &wallet.data.settings.argon_params.into_config(),
        )
        .unwrap();

        let keypair = wallet.reveal_keypair(0, &argon_seed, None).unwrap();
        let txn = txn.sign(&keypair).await.unwrap();
        let txns = vec![txn];
        let txns = bg.broadcast_signed_transactions(0, txns).await.unwrap();

        assert_eq!(txns.len(), 1);

        for tx in txns {
            assert!(tx.hash().is_some());
        }
    }
}
