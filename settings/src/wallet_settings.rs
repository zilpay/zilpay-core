use crate::{crypto::CryptoSettings, currency::Currency, network::Network, security::Security};

#[derive(Debug)]
pub struct WalletSettings {
    pub crypto: CryptoSettings,
    pub currency: Currency,
    pub network: Network,
    pub security: Security,
}

impl Default for WalletSettings {
    fn default() -> Self {
        Self {
            crypto: CryptoSettings::default(),
            currency: Currency {},
            network: Network {},
            security: Security {},
        }
    }
}
