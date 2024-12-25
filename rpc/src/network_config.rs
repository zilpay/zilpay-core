use zil_errors::rpc::RpcError;

use crate::common::{NetworkConfigTrait, Result};

#[derive(Debug, Clone)]
pub struct NetworkConfig {
    network_name: String,
    chain_id: u64,
    fallback_enabled: bool,
    urls: Vec<String>,
}

impl NetworkConfig {
    pub fn new(network_name: impl Into<String>, chain_id: u64, urls: Vec<String>) -> Self {
        Self {
            fallback_enabled: true,
            network_name: network_name.into(),
            chain_id,
            urls,
        }
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
    use super::*;

    fn setup_config() -> NetworkConfig {
        NetworkConfig::new("test_network", 1, vec!["http://default.com".to_string()])
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
