use crate::{bg_provider::ProvidersManagement, bg_wallet::WalletManagement, Background, Result};
use async_trait::async_trait;
use proto::address::Address;
use token::ft::FToken;
use zil_errors::{background::BackgroundError, wallet::WalletErrors};

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
        let provider = self.get_provider(w.data.provider_index)?;
        let w = self.get_wallet_by_index(wallet_index)?;
        let accounts = w
            .data
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

        if w.ftokens.is_empty() {
            return Err(WalletErrors::KeyChainFailToGetProof)?;
        }

        let addresses: Vec<&Address> = w.data.accounts.iter().map(|a| &a.addr).collect();

        let provider_index = w.data.provider_index;
        let tokens = &mut w.ftokens;
        let matching_end = tokens.partition_point(|token| token.provider_index == provider_index);
        let matching_tokens = &mut tokens[..matching_end];

        let provider = self
            .providers
            .get(w.data.provider_index)
            .ok_or(BackgroundError::ProviderNotExists(0))?;

        provider
            .update_balances(matching_tokens, &addresses)
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests_background {
    use super::*;
    use crate::{
        bg_crypto::CryptoOperations, bg_storage::StorageManagement, BackgroundBip39Params,
    };
    use crypto::bip49::Bip49DerivationPath;
    use rand::Rng;
    use rpc::network_config::NetworkConfig;
    use tokio;

    fn setup_test_background() -> (Background, String) {
        let mut rng = rand::thread_rng();
        let dir = format!("/tmp/{}", rng.gen::<usize>());
        let bg = Background::from_storage_path(&dir).unwrap();
        (bg, dir)
    }

    #[tokio::test]
    async fn test_fetch_ftoken_meta() {
        let (mut bg, _dir) = setup_test_background();

        let password = "test_password";
        let words = Background::gen_bip39(24).unwrap();
        let accounts = [(Bip49DerivationPath::Ethereum(0), "Name".to_string())];
        let net_conf = NetworkConfig::new(
            "Binance-smart-chain",
            56,
            vec!["https://bsc-dataseed.binance.org".to_string()],
        );

        bg.add_provider(net_conf).unwrap();
        bg.add_bip39_wallet(BackgroundBip39Params {
            password,
            provider: 0,
            mnemonic_str: &words,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: String::new(),
            biometric_type: Default::default(),
            device_indicators: &[String::from("apple"), String::from("0000")],
        })
        .unwrap();

        assert_eq!(bg.wallets.len(), 1);
        assert_eq!(bg.providers.len(), 1);
        assert_eq!(bg.wallets[0].data.accounts.len(), 1);

        let token_addr =
            Address::from_eth_address("0x55d398326f99059fF775485246999027B3197955").unwrap();
        let meta = bg.fetch_ftoken_meta(0, token_addr).await.unwrap();

        assert_eq!(&meta.name, "Tether USD");
        assert_eq!(&meta.symbol, "USDT");
        assert_eq!(meta.decimals, 18u8);
        assert_eq!(meta.provider_index, 0);
        assert!(!meta.default);
        assert!(!meta.native);

        assert!(meta.balances.contains_key(&0));
    }
}
