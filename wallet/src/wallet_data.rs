use crate::{account::Account, wallet_types::WalletTypes};
use config::session::AuthMethod;
use errors::wallet::WalletErrors;
use serde::{Deserialize, Serialize};
use settings::wallet_settings::WalletSettings;

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
