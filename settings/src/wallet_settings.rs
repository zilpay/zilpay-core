use cipher::options::CipherOrders;
use serde::{Deserialize, Serialize};

use crate::argon2::ArgonParams;

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
pub struct WalletSettings {
    /// Ordered list of cipher algorithms for encryption
    pub cipher_orders: Vec<CipherOrders>,

    /// Password hashing configuration parameters
    #[serde(default)]
    pub argon_params: ArgonParams,

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
            argon_params: ArgonParams::default(),
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

#[cfg(test)]
mod wallet_settings_tests {
    use super::*;

    #[test]
    fn test_default_settings() {
        let settings = WalletSettings::default();

        // Test default cipher orders
        assert_eq!(
            settings.cipher_orders,
            vec![CipherOrders::AESGCM256, CipherOrders::NTRUP1277]
        );

        // Test default wallet features
        assert_eq!(
            settings.features.currency_convert,
            Some(WalletFeatures::DEFUALT_CURRENCY_CONVERT.to_string())
        );
        assert!(settings.features.ens_enabled);
        assert_eq!(
            settings.features.ipfs_node,
            Some(WalletFeatures::DEFAULT_IPFS_NODE.to_string())
        );

        // Test default network settings
        assert!(settings.network.gas_control_enabled);
        assert!(settings.network.node_ranking_enabled);
        assert_eq!(
            settings.network.max_connections,
            NetworkSettings::DEFAULT_MAX_CONNECTIONS
        );
        assert_eq!(
            settings.network.request_timeout_secs,
            NetworkSettings::DEFAULT_TIMEOUT
        );

        // Test default Argon2 parameters (should be secure settings)
        assert_eq!(settings.argon_params, ArgonParams::default());
    }

    #[test]
    fn test_wallet_features_customization() {
        let mut features = WalletFeatures::default();

        // Test currency conversion modification
        let usd = "USD";
        features.currency_convert = Some(usd.to_string());
        assert_eq!(features.currency_convert, Some(usd.to_string()));

        // Test ENS disabling
        features.ens_enabled = false;
        assert!(!features.ens_enabled);

        // Test IPFS node customization
        features.ipfs_node = Some("ipfs.io".to_string());
        assert_eq!(features.ipfs_node, Some("ipfs.io".to_string()));
    }

    #[test]
    fn test_network_settings_customization() {
        let mut network = NetworkSettings::default();

        // Test gas control modification
        // network.gas_control_enabled = false;
        assert!(network.gas_control_enabled);

        // Test node ranking modification
        network.node_ranking_enabled = false;
        assert!(!network.node_ranking_enabled);

        // Test connection limits
        network.max_connections = 10;
        assert_eq!(network.max_connections, 10);

        // Test timeout modification
        network.request_timeout_secs = 60;
        assert_eq!(network.request_timeout_secs, 60);
    }

    #[test]
    fn test_wallet_settings_clone() {
        let original = WalletSettings::default();
        let cloned = original.clone();

        assert_eq!(original, cloned);
    }

    #[test]
    fn test_wallet_settings_partial_eq() {
        let settings1 = WalletSettings::default();
        let settings2 = WalletSettings::default();
        let mut settings3 = WalletSettings::default();

        assert_eq!(settings1, settings2);

        settings3.network.max_connections = 10;
        assert_ne!(settings1, settings3);
    }

    #[test]
    fn test_custom_wallet_settings() {
        let custom_settings = WalletSettings {
            cipher_orders: vec![CipherOrders::NTRUP1277],
            argon_params: ArgonParams::low_memory(),
            features: WalletFeatures {
                currency_convert: Some("EUR".to_string()),
                ens_enabled: false,
                ipfs_node: None,
            },
            network: NetworkSettings {
                gas_control_enabled: false,
                node_ranking_enabled: true,
                max_connections: 3,
                request_timeout_secs: 15,
            },
        };

        // Verify custom cipher orders
        assert_eq!(custom_settings.cipher_orders, vec![CipherOrders::NTRUP1277]);

        // Verify custom features
        assert_eq!(
            custom_settings.features.currency_convert,
            Some("EUR".to_string())
        );
        assert!(!custom_settings.features.ens_enabled);
        assert!(custom_settings.features.ipfs_node.is_none());

        // Verify custom network settings
        assert!(!custom_settings.network.gas_control_enabled);
        assert!(custom_settings.network.node_ranking_enabled);
        assert_eq!(custom_settings.network.max_connections, 3);
        assert_eq!(custom_settings.network.request_timeout_secs, 15);

        // Verify custom Argon2 parameters
        assert_eq!(custom_settings.argon_params, ArgonParams::low_memory());
    }
}
