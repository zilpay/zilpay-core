use std::str::FromStr;

use errors::{network::NetworkErrors, rpc::RpcError};
use serde::{Deserialize, Serialize};

use crate::common::{NetworkConfigTrait, Result};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub enum Bip44Network {
    Evm(String),
    Bitcoin(String),
    Solana(String),
    Zilliqa(String),
}

impl std::fmt::Display for Bip44Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Bip44Network::Evm(value) => write!(f, "evm:{}", value),
            Bip44Network::Bitcoin(value) => write!(f, "btc:{}", value),
            Bip44Network::Solana(value) => write!(f, "sol:{}", value),
            Bip44Network::Zilliqa(value) => write!(f, "zil:{}", value),
        }
    }
}

impl FromStr for Bip44Network {
    type Err = NetworkErrors;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Err(NetworkErrors::InvlaidPathBip49Type);
        }

        let (network, value) = (parts[0], parts[1].to_string());
        match network {
            "evm" => Ok(Bip44Network::Evm(value)),
            "btc" => Ok(Bip44Network::Bitcoin(value)),
            "sol" => Ok(Bip44Network::Solana(value)),
            "zil" => Ok(Bip44Network::Zilliqa(value)),
            _ => Err(NetworkErrors::InvlaidPathBip49(network.to_string())),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct NetworkConfig {
    pub network_name: String,
    pub chain_id: u64,
    pub fallback_enabled: bool,
    pub urls: Vec<String>,
    pub explorer_urls: Vec<String>,
    pub default: bool,
    pub bip49: Bip44Network,
}

impl NetworkConfig {
    pub fn from_bytes(encoded: &[u8]) -> Result<Self> {
        let decoded: Self = bincode::deserialize(encoded)?;

        Ok(decoded)
    }

    pub fn new(
        network_name: impl Into<String>,
        chain_id: u64,
        urls: Vec<String>,
        bip49: Bip44Network,
    ) -> Self {
        Self {
            bip49,
            fallback_enabled: true,
            network_name: network_name.into(),
            chain_id,
            urls,
            default: false,
            explorer_urls: Vec::with_capacity(1),
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let encoded: Vec<u8> = bincode::serialize(&self)?;

        Ok(encoded)
    }

    pub fn network_name(&self) -> &str {
        &self.network_name
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn urls(&self) -> &[String] {
        &self.urls
    }

    pub fn with_fallback(mut self, enabled: bool) -> Self {
        self.fallback_enabled = enabled;
        self
    }

    pub fn is_fallback_enabled(&self) -> bool {
        self.fallback_enabled
    }
}

impl NetworkConfigTrait for NetworkConfig {
    fn add_node_group(&mut self, nodes: Vec<String>) -> Result<()> {
        for node in &nodes {
            if self.urls.contains(node) {
                return Err(RpcError::DuplicateNode(node.clone()));
            }
        }

        self.urls.extend(nodes);
        Ok(())
    }

    fn remove_node_group(&mut self, indexes: Vec<usize>) -> Result<()> {
        if indexes.is_empty() {
            return Ok(());
        }

        if indexes.contains(&0) {
            return Err(RpcError::DefaultNodeUnremovable);
        }

        if let Some(&max_index) = indexes.iter().max() {
            if max_index >= self.urls.len() {
                return Err(RpcError::NodeNotExits(max_index));
            }
        }

        let mut sorted_indexes = indexes.to_vec();
        sorted_indexes.sort_unstable_by(|a, b| b.cmp(a));

        for &index in &sorted_indexes {
            self.urls.remove(index);
        }

        Ok(())
    }

    fn default_node(&self) -> &str {
        self.urls().first().map(|s| s.as_str()).unwrap_or_default()
    }

    fn add_node(&mut self, node: String) -> Result<()> {
        if !self.urls.contains(&node) {
            self.urls.push(node);

            Ok(())
        } else {
            Err(RpcError::DuplicateNode(node))
        }
    }

    fn remove_node(&mut self, node_index: usize) -> Result<()> {
        match node_index {
            0 => Err(RpcError::DefaultNodeUnremovable),
            i if i >= self.urls.len() => Err(RpcError::NodeNotExits(i)),
            i => {
                self.urls.remove(i);
                Ok(())
            }
        }
    }

    fn nodes(&self) -> &[String] {
        if self.fallback_enabled {
            &self.urls
        } else {
            &self.urls[..1]
        }
    }
}

#[cfg(test)]
mod tests_network_config {
    use crypto::bip49::ETH_PATH;

    use super::*;

    fn setup_config() -> NetworkConfig {
        NetworkConfig::new(
            "test_network",
            1,
            vec!["http://default.com".to_string()],
            Bip44Network::Evm(ETH_PATH.to_string()),
        )
    }

    #[test]
    fn test_basic_config() {
        let config = setup_config();
        assert_eq!(config.network_name(), "test_network");
        assert_eq!(config.chain_id(), 1);
        assert_eq!(config.default_node(), "http://default.com");
        assert!(config.is_fallback_enabled());
    }

    #[test]
    fn test_fallback_settings() {
        let config = setup_config().with_fallback(false);
        assert!(!config.is_fallback_enabled());

        let config = setup_config().with_fallback(true);
        assert!(config.is_fallback_enabled());
    }

    #[test]
    fn test_add_node() {
        let mut config = setup_config();

        // Test successful addition
        assert!(config.add_node("http://new1.com".to_string()).is_ok());
        assert_eq!(config.urls().len(), 2);

        // Test duplicate addition
        let err = config.add_node("http://new1.com".to_string()).unwrap_err();
        assert!(matches!(err, RpcError::DuplicateNode(_)));
    }

    #[test]
    fn test_add_node_group() {
        let mut config = setup_config();

        // Test successful group addition
        let new_nodes = vec!["http://new1.com".to_string(), "http://new2.com".to_string()];
        assert!(config.add_node_group(new_nodes).is_ok());
        assert_eq!(config.urls().len(), 3);

        // Test duplicate in group
        let duplicate_nodes = vec!["http://new3.com".to_string(), "http://new1.com".to_string()];
        let err = config.add_node_group(duplicate_nodes).unwrap_err();
        assert!(matches!(err, RpcError::DuplicateNode(_)));
        // Verify no partial changes were made
        assert_eq!(config.urls().len(), 3);
    }

    #[test]
    fn test_remove_node() {
        let mut config = NetworkConfig::new(
            "test",
            1,
            vec![
                "http://default.com".to_string(),
                "http://second.com".to_string(),
                "http://third.com".to_string(),
            ],
            Bip44Network::Evm(ETH_PATH.to_string()),
        );

        // Test removing default node (should fail)
        let err = config.remove_node(0).unwrap_err();
        assert!(matches!(err, RpcError::DefaultNodeUnremovable));
        assert_eq!(config.urls().len(), 3);

        // Test successful removal
        assert!(config.remove_node(1).is_ok());
        assert_eq!(config.urls().len(), 2);

        let err = config.remove_node(5).unwrap_err();
        assert!(matches!(err, RpcError::NodeNotExits(_)));
    }

    #[test]
    fn test_remove_node_group() {
        let mut config = NetworkConfig::new(
            "test",
            1,
            vec![
                "http://default.com".to_string(),
                "http://second.com".to_string(),
                "http://third.com".to_string(),
                "http://fourth.com".to_string(),
            ],
            Bip44Network::Evm(ETH_PATH.to_string()),
        );

        // Test empty indexes
        assert!(config.remove_node_group(Vec::new()).is_ok());
        assert_eq!(config.urls().len(), 4);

        // Test removing multiple nodes
        assert!(config.remove_node_group([2, 1].to_vec()).is_ok());
        assert_eq!(config.urls().len(), 2);

        // Test removing default node (should fail)
        let err = config.remove_node_group([0, 1].to_vec()).unwrap_err();
        assert!(matches!(err, RpcError::DefaultNodeUnremovable));

        // Test invalid index
        let err = config.remove_node_group([5].to_vec()).unwrap_err();
        assert!(matches!(err, RpcError::NodeNotExits(_)));

        // Test removing nodes in descending order
        let mut config = setup_config();
        config
            .add_node_group(vec![
                "http://second.com".to_string(),
                "http://third.com".to_string(),
                "http://fourth.com".to_string(),
            ])
            .unwrap();

        assert!(config.remove_node_group([3, 2, 1].to_vec()).is_ok());
        assert_eq!(config.urls().len(), 1);
        assert_eq!(config.default_node(), "http://default.com");
    }
}
