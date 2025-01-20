use crate::{Background, Result};
use errors::background::BackgroundError;
use network::{common::Provider, provider::NetworkProvider};
use rpc::network_config::ChainConfig;
use std::sync::Arc;

pub trait ProvidersManagement {
    type Error;

    fn get_provider(&self, chain_id: u128) -> std::result::Result<&NetworkProvider, Self::Error>;
    fn get_mut_provider(
        &mut self,
        chain_id: u128,
    ) -> std::result::Result<&mut NetworkProvider, Self::Error>;
    fn add_provider(&mut self, config: ChainConfig) -> std::result::Result<(), Self::Error>;
    fn remvoe_providers(&mut self, index: usize) -> std::result::Result<(), Self::Error>;
    fn update_providers(&mut self) -> std::result::Result<(), Self::Error>;
}

impl ProvidersManagement for Background {
    type Error = BackgroundError;
    // TODO: add fetch more nodes
    // TODO: add method with rankeing node depends of network
    //

    fn get_mut_provider(
        &mut self,
        chain_id: u128,
    ) -> std::result::Result<&mut NetworkProvider, Self::Error> {
        self.providers
            .iter_mut()
            .find(|p| p.config.chain_id == chain_id)
            .ok_or(BackgroundError::ProviderNotExists(chain_id))
    }

    fn get_provider(&self, chain_id: u128) -> std::result::Result<&NetworkProvider, Self::Error> {
        self.providers
            .iter()
            .find(|p| p.config.chain_id == chain_id)
            .ok_or(BackgroundError::ProviderNotExists(chain_id))
    }

    fn update_providers(&mut self) -> std::result::Result<(), Self::Error> {
        NetworkProvider::save_network_configs(&self.providers, Arc::clone(&self.storage))?;

        Ok(())
    }

    fn add_provider(&mut self, config: ChainConfig) -> Result<()> {
        if self
            .providers
            .iter()
            .any(|p| p.config.chain_id == config.chain_id)
        {
            return Err(BackgroundError::ProviderAlreadyExists(config.chain_id));
        }

        let index = self.providers.len();
        let new_provider = NetworkProvider::new(config);

        self.providers.push(new_provider);
        self.update_providers()?;

        Ok(())
    }

    fn remvoe_providers(&mut self, index: usize) -> Result<()> {
        let provider = self
            .providers
            .get(index)
            .ok_or(BackgroundError::ProviderNotExists(index))?;

        if provider.config.default {
            return Err(BackgroundError::ProviderIsDefault(index));
        }

        self.providers.remove(index);
        self.update_providers()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests_providers {
    use crate::bg_storage::StorageManagement;

    use super::*;
    use crypto::bip49::ETH_PATH;
    use rand::Rng;
    use rpc::network_config::NetworkConfig;

    fn setup_test_background() -> (Background, String) {
        let mut rng = rand::thread_rng();
        let dir = format!("/tmp/{}", rng.gen::<usize>());
        let bg = Background::from_storage_path(&dir).unwrap();
        (bg, dir)
    }

    fn create_test_network_config(name: &str, default: bool) -> NetworkConfig {
        NetworkConfig {
            network_name: name.to_string(),
            fallback_enabled: false,
            urls: vec!["http://localhost:8545".to_string()],
            chain_id: 1,
            explorer_urls: Vec::new(),
            default,
            bip49: rpc::network_config::Bip44Network::Evm(ETH_PATH.to_string()),
            token_symbol: String::from("TST"),
            logo: None,
        }
    }

    #[test]
    fn test_add_providers() {
        let (mut bg, _dir) = setup_test_background();

        // Test adding a non-default provider
        let config1 = create_test_network_config("Test Network 1", false);
        bg.add_provider(config1.clone()).unwrap();

        assert_eq!(bg.providers.len(), 1);
        assert_eq!(bg.providers[0].config.network_name, "Test Network 1");

        // Test adding another provider
        let mut config2 = create_test_network_config("Test Network 2", false);

        config2.chain_id = 11;

        bg.add_provider(config2.clone()).unwrap();

        assert_eq!(bg.providers.len(), 2);
        assert_eq!(bg.providers[1].config.network_name, "Test Network 2");
    }

    #[test]
    fn test_remove_providers() {
        let (mut bg, _dir) = setup_test_background();

        // Add two providers
        let config1 = create_test_network_config("Test Network 1", false);
        let mut config2 = create_test_network_config("Test Network 2", false);

        bg.add_provider(config1.clone()).unwrap();

        config2.chain_id = 33;

        bg.add_provider(config2.clone()).unwrap();

        assert_eq!(bg.providers.len(), 2);

        // Remove the second provider
        bg.remvoe_providers(1).unwrap();

        assert_eq!(bg.providers.len(), 1);
        assert_eq!(bg.providers[0].config.network_name, "Test Network 1");
    }

    #[test]
    fn test_remove_default_provider() {
        let (mut bg, _dir) = setup_test_background();

        // Add a default provider
        let config = create_test_network_config("Default Network", true);
        bg.add_provider(config).unwrap();

        // Attempt to remove the default provider
        let result = bg.remvoe_providers(0);

        assert!(result.is_err());
        if let Err(error) = result {
            assert!(matches!(error, BackgroundError::ProviderIsDefault(0)));
        }
    }

    #[test]
    fn test_remove_nonexistent_provider() {
        let (mut bg, _dir) = setup_test_background();

        // Attempt to remove a provider when none exist
        let result = bg.remvoe_providers(0);

        assert!(result.is_err());
        if let Err(error) = result {
            assert!(matches!(error, BackgroundError::ProviderNotExists(0)));
        }
    }

    #[test]
    fn test_persistence() {
        let (mut bg, dir) = setup_test_background();

        // Add providers
        let config1 = create_test_network_config("Test Network 1", false);
        let mut config2 = create_test_network_config("Test Network 2", false);

        bg.add_provider(config1.clone()).unwrap();
        assert!(bg.add_provider(config2.clone()).is_err());
        config2.chain_id = 42;
        bg.add_provider(config2.clone()).unwrap();

        // Drop the background instance
        drop(bg);

        // Create new instance and verify providers were persisted
        let bg2 = Background::from_storage_path(&dir).unwrap();

        assert_eq!(bg2.providers.len(), 2);
        assert_eq!(bg2.providers[0].config.network_name, "Test Network 1");
        assert_eq!(bg2.providers[1].config.network_name, "Test Network 2");
    }

    #[test]
    fn test_update_providers() {
        let (mut bg, dir) = setup_test_background();

        // Add initial providers
        let config1 = create_test_network_config("Test Network 1", false);
        let mut config2 = create_test_network_config("Test Network 2", false);

        bg.add_provider(config1.clone()).unwrap();
        config2.chain_id = 3243;
        bg.add_provider(config2.clone()).unwrap();

        // Modify providers directly and update
        bg.providers[0].config.network_name = "Updated Network 1";
        bg.update_providers().unwrap();

        // Verify persistence of update
        drop(bg);
        let bg2 = Background::from_storage_path(&dir).unwrap();

        assert_eq!(bg2.providers[0].config.network_name, "Updated Network 1");
        assert_eq!(bg2.providers[1].config.network_name, "Test Network 2");
    }
}
