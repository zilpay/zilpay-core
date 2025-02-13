use std::hash::{DefaultHasher, Hash, Hasher};

use errors::rpc::RpcError;
use proto::address::Address;
use serde::{Deserialize, Serialize};

use crate::common::{NetworkConfigTrait, Result};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Explorer {
    pub name: String,
    pub url: String,
    pub icon: Option<String>,
    pub standard: u16,
}

#[derive(Debug, Default, PartialEq, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    pub name: String,
    pub chain: String,
    pub short_name: String,
    pub diff_block_time: u64,
    pub rpc: Vec<String>,
    pub features: Vec<u16>,
    pub chain_ids: [u64; 2],
    pub slip_44: u32,
    pub testnet: Option<bool>,
    pub ens: Option<Address>,
    pub explorers: Vec<Explorer>,
    pub fallback_enabled: bool,
}

impl ChainConfig {
    pub fn from_bytes(encoded: &[u8]) -> Result<Self> {
        let decoded: Self = bincode::deserialize(encoded)?;
        Ok(decoded)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let encoded: Vec<u8> = bincode::serialize(&self)?;
        Ok(encoded)
    }

    pub fn network_name(&self) -> &str {
        &self.name
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_ids[0]
    }

    pub fn urls(&self) -> &[String] {
        &self.rpc
    }

    pub fn with_fallback(mut self, enabled: bool) -> Self {
        self.fallback_enabled = enabled;
        self
    }

    pub fn is_fallback_enabled(&self) -> bool {
        self.fallback_enabled
    }

    pub fn hash(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.slip_44.hash(&mut hasher);
        self.chain_ids.hash(&mut hasher);
        self.chain.hash(&mut hasher);

        hasher.finish()
    }
}

impl NetworkConfigTrait for ChainConfig {
    fn add_node_group(&mut self, nodes: Vec<String>) -> Result<()> {
        for node in &nodes {
            if self.rpc.contains(node) {
                return Err(RpcError::DuplicateNode(node.clone()));
            }
        }

        self.rpc.extend(nodes);
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
            if max_index >= self.rpc.len() {
                return Err(RpcError::NodeNotExits(max_index));
            }
        }

        let mut sorted_indexes = indexes.to_vec();
        sorted_indexes.sort_unstable_by(|a, b| b.cmp(a));

        for &index in &sorted_indexes {
            self.rpc.remove(index);
        }

        Ok(())
    }

    fn default_node(&self) -> &str {
        self.rpc.first().map(|s| s.as_str()).unwrap_or_default()
    }

    fn add_node(&mut self, node: String) -> Result<()> {
        if !self.rpc.contains(&node) {
            self.rpc.push(node);
            Ok(())
        } else {
            Err(RpcError::DuplicateNode(node))
        }
    }

    fn remove_node(&mut self, node_index: usize) -> Result<()> {
        match node_index {
            0 => Err(RpcError::DefaultNodeUnremovable),
            i if i >= self.rpc.len() => Err(RpcError::NodeNotExits(i)),
            i => {
                self.rpc.remove(i);
                Ok(())
            }
        }
    }

    fn nodes(&self) -> &[String] {
        if self.fallback_enabled {
            &self.rpc
        } else {
            &self.rpc[..1]
        }
    }
}

impl Default for Explorer {
    fn default() -> Self {
        Self {
            name: String::new(),
            url: String::new(),
            icon: None,
            standard: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_config() -> ChainConfig {
        ChainConfig {
            diff_block_time: 0,
            testnet: None,
            chain_ids: [1, 0],
            name: "test_network".to_string(),
            chain: "TEST".to_string(),
            short_name: "test_icon".to_string(),
            rpc: vec!["http://default.com".to_string()],
            features: vec![155],
            slip_44: 60,
            ens: None,
            explorers: vec![Explorer {
                name: "test_explorer".to_string(),
                url: "https://test.explorer".to_string(),
                icon: None,
                standard: 3091,
            }],
            fallback_enabled: true,
        }
    }

    #[test]
    fn test_basic_config() {
        let config = setup_config();
        assert_eq!(config.network_name(), "test_network");
        assert_eq!(config.chain_id(), 1);
        assert_eq!(config.default_node(), "http://default.com");
        assert!(config.is_fallback_enabled());
        assert_eq!(config.features[0], 155);
        assert_eq!(config.slip_44, 60);
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
        let mut config = ChainConfig {
            diff_block_time: 0,
            testnet: None,
            chain_ids: [1, 0],
            name: "test".to_string(),
            chain: "TEST".to_string(),
            short_name: "test_icon".to_string(),
            rpc: vec![
                "http://default.com".to_string(),
                "http://second.com".to_string(),
                "http://third.com".to_string(),
            ],
            features: vec![155],
            slip_44: 60,
            ens: None,
            explorers: Vec::new(),
            fallback_enabled: true,
        };

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
        let mut config = ChainConfig {
            diff_block_time: 0,
            testnet: None,
            chain_ids: [1, 0],
            name: "test".to_string(),
            chain: "TEST".to_string(),
            short_name: "test_icon".to_string(),
            rpc: vec![
                "http://default.com".to_string(),
                "http://second.com".to_string(),
                "http://third.com".to_string(),
                "http://fourth.com".to_string(),
            ],
            features: vec![155],
            slip_44: 60,
            ens: None,
            explorers: Vec::new(),
            fallback_enabled: true,
        };

        // Test empty indexes
        assert!(config.remove_node_group(Vec::new()).is_ok());
        assert_eq!(config.urls().len(), 4);

        // Test removing multiple nodes
        assert!(config.remove_node_group(vec![2, 1]).is_ok());
        assert_eq!(config.urls().len(), 2);

        // Test removing default node (should fail)
        let err = config.remove_node_group(vec![0, 1]).unwrap_err();
        assert!(matches!(err, RpcError::DefaultNodeUnremovable));

        // Test invalid index
        let err = config.remove_node_group(vec![5]).unwrap_err();
        assert!(matches!(err, RpcError::NodeNotExits(_)));
    }

    #[test]
    fn test_default_explorer() {
        let explorer = Explorer::default();
        assert!(explorer.name.is_empty());
        assert!(explorer.url.is_empty());
        assert!(explorer.icon.is_none());
        assert!(explorer.standard == 0);
    }

    #[test]
    fn test_serialization() {
        let config = setup_config();
        let bytes = config.to_bytes().unwrap();
        let deserialized = ChainConfig::from_bytes(&bytes).unwrap();

        assert_eq!(config.name, deserialized.name);
        assert_eq!(config.chain, deserialized.chain);
        assert_eq!(config.chain_id(), deserialized.chain_id());
        assert_eq!(config.features, deserialized.features);
        assert_eq!(config.rpc, deserialized.rpc);
        assert_eq!(config.explorers.len(), deserialized.explorers.len());
    }
}
