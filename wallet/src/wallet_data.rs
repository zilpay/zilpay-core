use crate::{account::Account, wallet_types::WalletTypes, WalletAddrType};
use serde::{Deserialize, Serialize};
use settings::wallet_settings::WalletSettings;
use zil_errors::wallet::WalletErrors;

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

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct WalletData {
    pub proof_key: usize,
    pub wallet_type: WalletTypes,
    pub settings: WalletSettings,
    pub wallet_name: String,
    pub wallet_address: WalletAddrType,
    pub accounts: Vec<Account>,
    pub selected_account: usize,
    pub biometric_type: AuthMethod,
}

impl WalletData {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WalletErrors> {
        bincode::deserialize(bytes)
            .map_err(|e| WalletErrors::FailToDeserializeWalletData(e.to_string()))
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, WalletErrors> {
        bincode::serialize(&self)
            .map_err(|e| WalletErrors::FailToSerializeWalletData(e.to_string()))
    }
}
