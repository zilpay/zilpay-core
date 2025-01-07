use crate::{bg_provider::ProvidersManagement, bg_wallet::WalletManagement, Background, Result};
use async_trait::async_trait;
use errors::background::BackgroundError;
use proto::address::Address;
use token::ft::FToken;
use wallet::wallet_storage::StorageOperations;

#[async_trait]
pub trait TokensManagement {
    type Error;

    async fn fetch_ftoken_meta(
        &self,
        wallet_index: usize,
        contract: Address,
    ) -> std::result::Result<FToken, Self::Error>;

    async fn sync_ftokens_balances(
        &mut self,
        wallet_index: usize,
    ) -> std::result::Result<(), Self::Error>;
}

#[async_trait]
impl TokensManagement for Background {
    type Error = BackgroundError;

    async fn fetch_ftoken_meta(&self, wallet_index: usize, contract: Address) -> Result<FToken> {
        let w = self.get_wallet_by_index(wallet_index)?;
        let data = w.get_wallet_data()?;
        let provider = self.get_provider(data.provider_index)?;
        let accounts = data
            .accounts
            .iter()
            .map(|a| &a.addr)
            .collect::<Vec<&Address>>();
        let token_meta = provider.ftoken_meta(contract, &accounts).await?;

        Ok(token_meta)
    }

    async fn sync_ftokens_balances(&mut self, wallet_index: usize) -> Result<()> {
        let w = self
            .wallets
            .get_mut(wallet_index)
            .ok_or(BackgroundError::WalletNotExists(wallet_index))?;
        let mut ftokens = w.get_ftokens()?;
        let data = w.get_wallet_data()?;

        if ftokens.is_empty() {
            return Ok(());
        }

        let addresses: Vec<&Address> = data.accounts.iter().map(|a| &a.addr).collect();

        let matching_end =
            ftokens.partition_point(|token| token.provider_index == data.provider_index);
        let matching_tokens = &mut ftokens[..matching_end];
        let provider = self
            .providers
            .get(data.provider_index)
            .ok_or(BackgroundError::ProviderNotExists(0))?;

        provider
            .update_balances(matching_tokens, &addresses)
            .await?;

        w.save_ftokens(&ftokens)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests_background_tokens {
    use std::collections::HashMap;

    use super::*;
    use crate::{
        bg_crypto::CryptoOperations, bg_storage::StorageManagement, BackgroundBip39Params,
    };
    use config::address::ADDR_LEN;
    use crypto::bip49::Bip49DerivationPath;
    use rand::Rng;
    use rpc::network_config::NetworkConfig;
    use tokio;
    use wallet::wallet_token::TokenManagement;

    const PASSWORD: &str = "TEst password";
    const USDT_TOKEN: &str = "0x55d398326f99059fF775485246999027B3197955";

    fn setup_test_background() -> (Background, String) {
        let mut rng = rand::thread_rng();
        let dir = format!("/tmp/{}", rng.gen::<usize>());
        let bg = Background::from_storage_path(&dir).unwrap();
        (bg, dir)
    }

    fn gen_net_conf() -> NetworkConfig {
        NetworkConfig::new(
            "Binance-smart-chain",
            56,
            vec!["https://bsc-dataseed.binance.org".to_string()],
        )
    }

    fn gen_bsc_token() -> FToken {
        FToken {
            provider_index: 0,
            default: true,
            name: "Binance Smart Chain".to_string(),
            symbol: "BSC".to_string(),
            decimals: 18,
            addr: Address::Secp256k1Keccak256Ethereum([0u8; ADDR_LEN]),
            logo: None,
            balances: HashMap::new(),
            native: true,
        }
    }

    #[tokio::test]
    async fn test_fetch_ftoken_meta() {
        let (mut bg, _dir) = setup_test_background();

        let words = Background::gen_bip39(24).unwrap();
        let accounts = [(
            Bip49DerivationPath::Ethereum(0),
            "Bsc account 1".to_string(),
        )];

        bg.add_provider(gen_net_conf()).unwrap();
        bg.add_bip39_wallet(BackgroundBip39Params {
            password: PASSWORD,
            provider: 0,
            mnemonic_str: &words,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: String::new(),
            biometric_type: Default::default(),
            device_indicators: &[String::from("apple"), String::from("0000")],
            ftokens: vec![gen_bsc_token()],
        })
        .unwrap();

        assert_eq!(bg.wallets.len(), 1);
        assert_eq!(bg.providers.len(), 1);
        assert_eq!(
            bg.wallets
                .first()
                .unwrap()
                .get_wallet_data()
                .unwrap()
                .accounts
                .len(),
            1
        );

        let token_addr = Address::from_eth_address(USDT_TOKEN).unwrap();
        let meta = bg.fetch_ftoken_meta(0, token_addr).await.unwrap();

        assert_eq!(&meta.name, "Tether USD");
        assert_eq!(&meta.symbol, "USDT");
        assert_eq!(meta.decimals, 18u8);
        assert_eq!(meta.provider_index, 0);
        assert!(!meta.default);
        assert!(!meta.native);

        assert!(meta.balances.contains_key(&0));
        assert_eq!(meta.balances.get(&0).unwrap().to::<usize>(), 0);

        bg.wallets.first_mut().unwrap().add_ftoken(meta).unwrap();

        let tokens = bg.wallets.first().unwrap().get_ftokens().unwrap();

        assert!(tokens[0].native);
        assert!(tokens[0].default);
        assert_eq!(tokens[0].provider_index, 0);
    }

    #[tokio::test]
    async fn test_sync_ft_balances() {
        let (mut bg, _dir) = setup_test_background();

        let words = Background::gen_bip39(24).unwrap();
        let accounts = [
            (Bip49DerivationPath::Ethereum(0), "account 0".to_string()),
            (Bip49DerivationPath::Ethereum(1), "account 1".to_string()),
            (Bip49DerivationPath::Ethereum(2), "account 2".to_string()),
            (Bip49DerivationPath::Ethereum(3), "account 3".to_string()),
            (Bip49DerivationPath::Ethereum(4), "account 4".to_string()),
            (Bip49DerivationPath::Ethereum(5), "account 5".to_string()),
            (Bip49DerivationPath::Ethereum(6), "account 6".to_string()),
        ];

        bg.add_provider(gen_net_conf()).unwrap();
        bg.add_bip39_wallet(BackgroundBip39Params {
            password: PASSWORD,
            provider: 0,
            mnemonic_str: &words,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: String::new(),
            biometric_type: Default::default(),
            device_indicators: &[String::from("5435h"), String::from("0000")],
            ftokens: vec![gen_bsc_token()],
        })
        .unwrap();

        assert_eq!(bg.wallets.len(), 1);
        assert_eq!(bg.providers.len(), 1);
        assert_eq!(
            bg.wallets
                .first()
                .unwrap()
                .get_wallet_data()
                .unwrap()
                .accounts
                .len(),
            7
        );

        let token_addr = Address::from_eth_address(USDT_TOKEN).unwrap();
        let meta = bg.fetch_ftoken_meta(0, token_addr).await.unwrap();

        bg.wallets.first_mut().unwrap().add_ftoken(meta).unwrap();
        bg.sync_ftokens_balances(0).await.unwrap();

        let ftokens = bg.wallets[0].get_ftokens().unwrap();

        for token in ftokens {
            assert!(token.balances.contains_key(&0));
            assert!(token.balances.contains_key(&1));
            assert!(token.balances.contains_key(&2));
            assert!(token.balances.contains_key(&3));
            assert!(token.balances.contains_key(&4));
            assert!(token.balances.contains_key(&5));
            assert!(token.balances.contains_key(&6));
        }
    }
}
