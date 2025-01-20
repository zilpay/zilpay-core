use crate::{bg_provider::ProvidersManagement, bg_wallet::WalletManagement, Background, Result};
use async_trait::async_trait;
use errors::{background::BackgroundError, wallet::WalletErrors};
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
        &self,
        wallet_index: usize,
    ) -> std::result::Result<(), Self::Error>;
}

#[async_trait]
impl TokensManagement for Background {
    type Error = BackgroundError;

    async fn fetch_ftoken_meta(&self, wallet_index: usize, contract: Address) -> Result<FToken> {
        let w = self.get_wallet_by_index(wallet_index)?;
        let data = w.get_wallet_data()?;
        let accounts = data
            .accounts
            .iter()
            .map(|a| &a.addr)
            .collect::<Vec<&Address>>();
        let selected = &data.accounts[data.selected_account];
        let provider = self.get_provider(selected.chain_hash)?;
        let token_meta = provider.ftoken_meta(contract, &accounts).await?;

        Ok(token_meta)
    }

    async fn sync_ftokens_balances(&self, wallet_index: usize) -> Result<()> {
        let w = self
            .wallets
            .get(wallet_index)
            .ok_or(BackgroundError::WalletNotExists(wallet_index))?;
        let mut ftokens = w.get_ftokens()?;
        let data = w.get_wallet_data()?;

        if ftokens.is_empty() {
            return Ok(());
        }

        let selected_account = data
            .accounts
            .get(data.selected_account)
            .ok_or(WalletErrors::FailToGetAccount(data.selected_account))?;
        let addresses: Vec<&Address> = data.accounts.iter().map(|a| &a.addr).collect();
        let provider = self.get_provider(selected_account.chain_hash)?;

        let matching_end =
            ftokens.partition_point(|token| token.chain_hash == selected_account.chain_hash);
        let matching_tokens = &mut ftokens[..matching_end];

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
    use crypto::{bip49::DerivationPath, slip44};
    use rand::Rng;
    use rpc::network_config::{ChainConfig, Explorer};
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

    fn gen_net_conf() -> ChainConfig {
        ChainConfig {
            name: "Binance Smart Chain".to_string(),
            chain: "BSC".to_string(),
            icon: String::new(),
            rpc: vec!["https://bsc-dataseed.binance.org".to_string()],
            features: vec![155, 1559],
            chain_id: 56,
            slip_44: slip44::ETHEREUM,
            ens: Address::Secp256k1Keccak256Ethereum(Address::ZERO),
            explorers: vec![Explorer {
                name: "BscScan".to_string(),
                url: "https://bscscan.com".to_string(),
                icon: None,
                standard: 3091,
            }],
            fallback_enabled: true,
        }
    }

    fn gen_bsc_token(chain_hash: u64) -> FToken {
        FToken {
            chain_hash,
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
            DerivationPath::new(slip44::ETHEREUM, 0),
            "Bsc account 1".to_string(),
        )];
        let net_config = gen_net_conf();

        bg.add_provider(net_config.clone()).unwrap();
        bg.add_bip39_wallet(BackgroundBip39Params {
            password: PASSWORD,
            chain_hash: net_config.hash(),
            mnemonic_str: &words,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: String::new(),
            biometric_type: Default::default(),
            device_indicators: &[String::from("apple"), String::from("0000")],
            ftokens: vec![gen_bsc_token(net_config.hash())],
        })
        .unwrap();
        let providers = bg.get_providers();

        assert_eq!(bg.wallets.len(), 1);
        assert_eq!(providers.len(), 1);
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
        assert_eq!(meta.chain_hash, net_config.hash());
        assert!(!meta.default);
        assert!(!meta.native);

        assert!(meta.balances.contains_key(&0));
        assert_eq!(meta.balances.get(&0).unwrap().to::<usize>(), 0);

        bg.wallets.first_mut().unwrap().add_ftoken(meta).unwrap();

        let tokens = bg.wallets.first().unwrap().get_ftokens().unwrap();

        assert!(tokens[0].native);
        assert!(tokens[0].default);
        assert_eq!(tokens[0].chain_hash, net_config.hash());
    }

    #[tokio::test]
    async fn test_sync_ft_balances() {
        let (mut bg, _dir) = setup_test_background();

        let words = Background::gen_bip39(24).unwrap();
        let accounts = [
            (
                DerivationPath::new(slip44::ETHEREUM, 0),
                "account 0".to_string(),
            ),
            (
                DerivationPath::new(slip44::ETHEREUM, 1),
                "account 1".to_string(),
            ),
            (
                DerivationPath::new(slip44::ETHEREUM, 2),
                "account 2".to_string(),
            ),
            (
                DerivationPath::new(slip44::ETHEREUM, 3),
                "account 3".to_string(),
            ),
            (
                DerivationPath::new(slip44::ETHEREUM, 4),
                "account 4".to_string(),
            ),
            (
                DerivationPath::new(slip44::ETHEREUM, 5),
                "account 5".to_string(),
            ),
            (
                DerivationPath::new(slip44::ETHEREUM, 6),
                "account 6".to_string(),
            ),
        ];
        let net_config = gen_net_conf();

        bg.add_provider(net_config.clone()).unwrap();
        bg.add_bip39_wallet(BackgroundBip39Params {
            password: PASSWORD,
            chain_hash: net_config.hash(),
            mnemonic_str: &words,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: String::new(),
            biometric_type: Default::default(),
            device_indicators: &[String::from("5435h"), String::from("0000")],
            ftokens: vec![gen_bsc_token(net_config.hash())],
        })
        .unwrap();
        let providers = bg.get_providers();

        assert_eq!(bg.wallets.len(), 1);
        assert_eq!(providers.len(), 1);
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
