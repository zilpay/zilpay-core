use crate::{account::Account, wallet_types::WalletTypes};
use errors::wallet::WalletErrors;
use serde::{Deserialize, Serialize};
use settings::wallet_settings::WalletSettings;

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub enum AuthMethod {
    FaceId,
    Fingerprint,
    Biometric,
    PinCode,
    #[default]
    None,
}

impl From<AuthMethod> for String {
    fn from(method: AuthMethod) -> Self {
        match method {
            AuthMethod::FaceId => "faceId".to_string(),
            AuthMethod::Fingerprint => "fingerprint".to_string(),
            AuthMethod::Biometric => "biometric".to_string(),
            AuthMethod::PinCode => "pinCode".to_string(),
            AuthMethod::None => "none".to_string(),
        }
    }
}

impl From<String> for AuthMethod {
    fn from(s: String) -> Self {
        match s.as_str() {
            "faceId" => AuthMethod::FaceId,
            "fingerprint" => AuthMethod::Fingerprint,
            "biometric" => AuthMethod::Biometric,
            "pinCode" => AuthMethod::PinCode,
            _ => AuthMethod::None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WalletData {
    pub proof_key: usize,
    pub wallet_type: WalletTypes,
    pub settings: WalletSettings,
    pub wallet_name: String,
    pub accounts: Vec<Account>,
    pub selected_account: usize,
    pub biometric_type: AuthMethod,
    pub default_chain_hash: u64,
}

impl WalletData {
    pub fn get_selected_account(&self) -> Result<&Account, WalletErrors> {
        self.accounts
            .get(self.selected_account)
            .ok_or(WalletErrors::InvalidAccountIndex(self.selected_account))
    }
}
