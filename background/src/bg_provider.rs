use crate::{bg_wallet::WalletManagement, Background, Result};
use async_trait::async_trait;
use errors::{background::BackgroundError, wallet::WalletErrors};
use network::{common::Provider, provider::NetworkProvider};
use proto::{address::Address, pubkey::PubKey};
use rpc::network_config::ChainConfig;
use std::sync::Arc;
use wallet::{wallet_storage::StorageOperations, wallet_types::WalletTypes};

#[async_trait]
pub trait ProvidersManagement {
    type Error;

    async fn update_block_diff_time(
        &self,
        chain_hash: u64,
        addr: &Address,
    ) -> std::result::Result<(), Self::Error>;
    fn get_provider(&self, chain_hash: u64) -> std::result::Result<NetworkProvider, Self::Error>;
    fn get_providers(&self) -> Vec<NetworkProvider>;
    fn select_accounts_chain(
        &self,
        wallet_index: usize,
        chain_hash: u64,
    ) -> std::result::Result<(), Self::Error>;
    fn add_provider(&self, config: ChainConfig) -> std::result::Result<u64, Self::Error>;
    fn remvoe_provider(&self, index: usize) -> std::result::Result<(), Self::Error>;
    fn update_providers(
        &self,
        providers: Vec<NetworkProvider>,
    ) -> std::result::Result<(), Self::Error>;
}

#[async_trait]
impl ProvidersManagement for Background {
    type Error = BackgroundError;

    async fn update_block_diff_time(&self, chain_hash: u64, addr: &Address) -> Result<()> {
        let mut chains = self.get_providers();
        let chain = chains
            .iter_mut()
            .find(|p| p.config.hash() == chain_hash)
            .ok_or(BackgroundError::ProviderNotExists(chain_hash))?;
        let block_time_diff = chain.estimate_block_time(addr).await?;

        chain.config.diff_block_time = block_time_diff;

        self.update_providers(chains)?;

        Ok(())
    }

    fn get_provider(&self, chain_hash: u64) -> std::result::Result<NetworkProvider, Self::Error> {
        self.get_providers()
            .into_iter()
            .find(|p| p.config.hash() == chain_hash)
            .ok_or(BackgroundError::ProviderNotExists(chain_hash))
    }

    fn get_providers(&self) -> Vec<NetworkProvider> {
        NetworkProvider::load_network_configs(Arc::clone(&self.storage))
    }

    fn update_providers(
        &self,
        providers: Vec<NetworkProvider>,
    ) -> std::result::Result<(), Self::Error> {
        NetworkProvider::save_network_configs(&providers, Arc::clone(&self.storage))?;

        Ok(())
    }

    fn add_provider(&self, mut config: ChainConfig) -> Result<u64> {
        let hash = config.hash();
        let mut providers = self.get_providers();

        config.ftokens.iter_mut().for_each(|t| {
            t.chain_hash = hash;
        });

        providers.retain(|p| p.config.hash() != hash);
        let new_provider = NetworkProvider::new(config);
        providers.push(new_provider);

        self.update_providers(providers)?;

        Ok(hash)
    }

    fn remvoe_provider(&self, index: usize) -> Result<()> {
        let mut providers = self.get_providers();

        if let Some(provider) = providers.get(index) {
            let hash = provider.config.hash();

            for wallet in &self.wallets {
                let data = wallet.get_wallet_data()?;

                if data.default_chain_hash == hash {
                    return Err(BackgroundError::ProviderDepends(data.wallet_name));
                }

                for account in data.accounts {
                    if account.chain_hash == hash {
                        return Err(BackgroundError::ProviderDepends(account.name));
                    }
                }
            }

            providers.remove(index);
            self.update_providers(providers)?;
        } else {
            return Err(BackgroundError::ProviderNotExists(index as u64));
        }

        Ok(())
    }

    fn select_accounts_chain(&self, wallet_index: usize, chain_hash: u64) -> Result<()> {
        let provider = self.get_provider(chain_hash)?;
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let mut data = wallet.get_wallet_data()?;
        let mut ftokens = wallet.get_ftokens()?;
        let default_provider = self.get_provider(data.default_chain_hash)?;

        if let WalletTypes::Ledger(_) = data.wallet_type {
            if default_provider.config.slip_44 == 313 {
                // old ledger doesn't support evm.
                return Err(WalletErrors::InvalidAccountType)?;
            }
        }

        for provider_ftoken in &provider.config.ftokens {
            if let Some(existing_ftoken) = ftokens.iter_mut().find(|t| {
                t.symbol == provider_ftoken.symbol && t.decimals == provider_ftoken.decimals
            }) {
                existing_ftoken.chain_hash = chain_hash;
                existing_ftoken.balances = Default::default();
            } else {
                let new_ftoken = provider_ftoken.clone();
                ftokens.insert(0, new_ftoken);
            }
        }

        data.accounts.iter_mut().for_each(|a| {
            if provider.config.slip_44 == 313 {
                match a.pub_key {
                    PubKey::Secp256k1Sha256(_pub_key) => {
                        if let Some(chain_id) = provider.config.chain_ids.last() {
                            a.chain_id = *chain_id;
                        }
                    }
                    PubKey::Secp256k1Keccak256(_pub_key) => {
                        if let Some(chain_id) = provider.config.chain_ids.first() {
                            a.chain_id = *chain_id;
                        }
                    }
                    _ => {}
                }
            } else if provider.config.slip_44 == 60 {
                a.pub_key = PubKey::Secp256k1Keccak256(a.pub_key.as_bytes());

                a.chain_id = provider.config.chain_id();
            } else {
                a.chain_id = provider.config.chain_id();
            }

            if let Some(addr) = a.pub_key.get_addr().ok() {
                a.addr = addr;
            }

            a.chain_hash = chain_hash;
            a.slip_44 = provider.config.slip_44;
        });

        wallet.save_wallet_data(data)?;
        wallet.save_ftokens(&ftokens)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests_providers {
    use super::*;
    use crate::bg_storage::StorageManagement;
    use rand::Rng;
    use rpc::network_config::Explorer;

    fn setup_test_background() -> (Background, String) {
        let mut rng = rand::thread_rng();
        let dir = format!("/tmp/{}", rng.gen::<usize>());
        let bg = Background::from_storage_path(&dir).unwrap();
        (bg, dir)
    }

    fn create_test_network_config(name: &str, chain_id: u64) -> ChainConfig {
        ChainConfig {
            ftokens: vec![],
            logo: String::new(),
            diff_block_time: 0,
            testnet: None,
            name: name.to_string(),
            chain: "TEST".to_string(),
            short_name: String::new(),
            rpc: vec!["http://localhost:8545".to_string()],
            features: vec![155, 1559],
            chain_ids: [chain_id, 0],
            slip_44: 60,
            ens: None,
            explorers: vec![Explorer {
                name: "TestExplorer".to_string(),
                url: "https://test.explorer".to_string(),
                icon: None,
                standard: 3091,
            }],
            fallback_enabled: true,
        }
    }

    #[test]
    fn test_add_providers() {
        let (bg, _dir) = setup_test_background();

        // Test adding a provider
        let config1 = create_test_network_config("Test Network 1", 1);
        bg.add_provider(config1.clone()).unwrap();
        let providers = bg.get_providers();

        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].config.name, "Test Network 1");

        // Test adding another provider
        let config2 = create_test_network_config("Test Network 2", 2);
        bg.add_provider(config2.clone()).unwrap();
        let providers = bg.get_providers();

        assert_eq!(providers.len(), 2);
        assert_eq!(providers[1].config.name, "Test Network 2");
    }

    #[test]
    fn test_remove_providers() {
        let (bg, _dir) = setup_test_background();

        // Add two providers
        let config1 = create_test_network_config("Test Network 1", 1);
        let config2 = create_test_network_config("Test Network 2", 2);

        bg.add_provider(config1.clone()).unwrap();
        bg.add_provider(config2.clone()).unwrap();

        let providers = bg.get_providers();

        assert_eq!(providers.len(), 2);

        // Remove the second provider
        bg.remvoe_provider(1).unwrap();
        let providers = bg.get_providers();

        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].config.name, "Test Network 1");
    }

    #[test]
    fn test_remove_nonexistent_provider() {
        let (bg, _dir) = setup_test_background();

        // Attempt to remove a provider when none exist
        let result = bg.remvoe_provider(0);

        assert!(result.is_err());

        if let Err(error) = result {
            assert!(matches!(error, BackgroundError::ProviderNotExists(0)));
        }
    }

    #[test]
    fn test_persistence() {
        let (bg, dir) = setup_test_background();

        // Add providers
        let config1 = create_test_network_config("Test Network 1", 1);
        let config2 = create_test_network_config("Test Network 2", 2);

        bg.add_provider(config1.clone()).unwrap();
        bg.add_provider(config2.clone()).unwrap();

        // Drop the background instance
        drop(bg);

        // Create new instance and verify providers were persisted
        let bg2 = Background::from_storage_path(&dir).unwrap();
        let providers = bg2.get_providers();

        assert_eq!(providers.len(), 2);
        assert_eq!(providers[0].config.name, "Test Network 1");
        assert_eq!(providers[1].config.name, "Test Network 2");
        assert_eq!(providers[0].config.chain_id(), 1);
        assert_eq!(providers[1].config.chain_id(), 2);
    }

    #[test]
    fn test_update_providers() {
        let (bg, dir) = setup_test_background();

        // Add initial providers
        let config1 = create_test_network_config("Test Network 1", 1);
        let config2 = create_test_network_config("Test Network 2", 2);

        bg.add_provider(config1.clone()).unwrap();
        bg.add_provider(config2.clone()).unwrap();

        let mut providers = bg.get_providers();

        // Modify providers directly and update
        providers[0].config.name = "Updated Network 1".to_string();
        bg.update_providers(providers).unwrap();

        // Verify persistence of update
        drop(bg);
        Background::from_storage_path(&dir).unwrap();
        let bg2 = Background::from_storage_path(&dir).unwrap();
        let providers = bg2.get_providers();

        assert_eq!(providers[0].config.name, "Updated Network 1");
        assert_eq!(providers[1].config.name, "Test Network 2");
        assert_eq!(providers[0].config.chain_id(), 1);
        assert_eq!(providers[1].config.chain_id(), 2);
    }

    #[test]
    fn test_duplicate_chain_id() {
        let (bg, _dir) = setup_test_background();

        let config1 = create_test_network_config("Test Network 1", 1);
        let config2 = create_test_network_config("Test Network 2", 1);

        bg.add_provider(config1.clone()).unwrap();
        assert_eq!(bg.get_providers().len(), 1);
        assert_eq!(bg.get_provider(config1.hash()).unwrap().config, config1);
        assert!(bg.add_provider(config2.clone()).is_ok());
        assert_eq!(bg.get_providers().len(), 1);
        assert_eq!(bg.get_provider(config2.hash()).unwrap().config, config2);
    }

    #[test]
    fn test_provider_features() {
        let (bg, _dir) = setup_test_background();

        let mut config = create_test_network_config("Test Network", 1);
        config.features = vec![155]; // Only EIP-155

        bg.add_provider(config).unwrap();
        let providers = bg.get_providers();

        assert_eq!(providers[0].config.features.len(), 1);
        assert!(providers[0].config.features.contains(&155));
    }
}
