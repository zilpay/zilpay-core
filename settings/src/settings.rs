use crate::{
    crypto::CryptoSettings, currency::Currency, language::Language, network::Network,
    notificcations::Notificcations, security::Security, storage::Storage, theme::Theme,
};

#[derive(Debug)]
pub struct Settings {
    pub crypto: CryptoSettings,
    pub currency: Currency,
    pub language: Language,
    pub network: Network,
    pub notificcations: Notificcations,
    pub security: Security,
    pub storage: Storage,
    pub theme: Theme,
}
