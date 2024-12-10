use cipher::options::CipherOrders;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Clone)]
pub struct WalletSettings {
    /// Ordered list of cipher algorithms for encryption
    pub cipher_orders: Vec<CipherOrders>,

    /// Configuration for various wallet features
    #[serde(default)]
    pub features: WalletFeatures,

    /// Network and performance settings
    #[serde(default)]
    pub network: NetworkSettings,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Clone)]
pub struct WalletFeatures {
    /// Enable Rates fetcher if some! the value is BTC, RUB, USD
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency_convert: Option<String>,

    /// Enable ENS domain resolution
    pub ens_enabled: bool,

    /// Enable IPFS gateway if Some, for ENS content node like dweb.link
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipfs_node: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Clone)]
pub struct NetworkSettings {
    /// Enable gas optimization features
    pub gas_control_enabled: bool,

    /// Enable node ranking for better performance
    pub node_ranking_enabled: bool,

    /// Maximum number of concurrent connections
    pub max_connections: u8,

    /// Timeout for network requests in seconds
    pub request_timeout_secs: u32,
}

impl NetworkSettings {
    const DEFAULT_MAX_CONNECTIONS: u8 = 5;
    const DEFAULT_TIMEOUT: u32 = 30;
}

impl WalletFeatures {
    const DEFAULT_IPFS_NODE: &str = "dweb.link";
    const DEFUALT_CURRENCY_CONVERT: &str = "BTC";
}

impl Default for WalletSettings {
    fn default() -> Self {
        Self {
            cipher_orders: vec![CipherOrders::AESGCM256, CipherOrders::NTRUP1277],
            features: WalletFeatures::default(),
            network: NetworkSettings::default(),
        }
    }
}

impl Default for WalletFeatures {
    fn default() -> Self {
        Self {
            currency_convert: Some(Self::DEFUALT_CURRENCY_CONVERT.to_string()),
            ens_enabled: true,
            ipfs_node: Some(Self::DEFAULT_IPFS_NODE.to_string()),
        }
    }
}

impl Default for NetworkSettings {
    fn default() -> Self {
        Self {
            gas_control_enabled: true,
            node_ranking_enabled: true,
            max_connections: Self::DEFAULT_MAX_CONNECTIONS,
            request_timeout_secs: Self::DEFAULT_TIMEOUT,
        }
    }
}

// Add tests
#[cfg(test)]
mod wallet_settings_tests {

    // #[test]
    // fn test_default_settings() {}
}
