use crate::{Background, Result};
use errors::background::BackgroundError;
use network::{common::Provider, provider::NetworkProvider};
use rpc::network_config::ChainConfig;
use std::sync::Arc;

pub trait ProvidersManagement {
    type Error;

    fn get_provider(&self, chain_hash: u64) -> std::result::Result<NetworkProvider, Self::Error>;
    fn get_providers(&self) -> Vec<NetworkProvider>;
    fn add_provider(&self, config: ChainConfig) -> std::result::Result<(), Self::Error>;
    fn remvoe_providers(&self, index: usize) -> std::result::Result<(), Self::Error>;
    fn update_providers(
        &self,
        providers: Vec<NetworkProvider>,
    ) -> std::result::Result<(), Self::Error>;
}

impl ProvidersManagement for Background {
    type Error = BackgroundError;
    // TODO: add fetch more nodes
    // TODO: add method with rankeing node depends of network
    //

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

    fn add_provider(&self, config: ChainConfig) -> Result<()> {
        let hash = config.hash();
        let mut providers = self.get_providers();

        if providers.iter().any(|p| p.config.hash() == hash) {
            return Err(BackgroundError::ProviderAlreadyExists(config.chain_id));
        }

        let new_provider = NetworkProvider::new(config);

        providers.push(new_provider);
        self.update_providers(providers)?;

        Ok(())
    }

    fn remvoe_providers(&self, index: usize) -> Result<()> {
        let mut providers = self.get_providers();

        if providers.get(index).is_none() {
            return Err(BackgroundError::ProviderNotExists(index as u64));
        }

        providers.remove(index);
        self.update_providers(providers)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests_providers {
    use super::*;
    use crate::bg_storage::StorageManagement;
    use proto::address::Address;
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
            name: name.to_string(),
            chain: "TEST".to_string(),
            icon: String::new(),
            rpc: vec!["http://localhost:8545".to_string()],
            features: vec![155, 1559],
            chain_id,
            slip_44: 60,
            ens: Address::Secp256k1Keccak256Ethereum(Address::ZERO),
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
        bg.remvoe_providers(1).unwrap();
        let providers = bg.get_providers();

        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].config.name, "Test Network 1");
    }

    #[test]
    fn test_remove_nonexistent_provider() {
        let (bg, _dir) = setup_test_background();

        // Attempt to remove a provider when none exist
        let result = bg.remvoe_providers(0);

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
        assert_eq!(providers[0].config.chain_id, 1);
        assert_eq!(providers[1].config.chain_id, 2);
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
        assert_eq!(providers[0].config.chain_id, 1);
        assert_eq!(providers[1].config.chain_id, 2);
    }

    #[test]
    fn test_duplicate_chain_id() {
        let (bg, _dir) = setup_test_background();

        let config1 = create_test_network_config("Test Network 1", 1);
        let config2 = create_test_network_config("Test Network 2", 1); // Same chain_id

        bg.add_provider(config1).unwrap();
        assert!(bg.add_provider(config2).is_err()); // Should fail due to duplicate chain_id
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
