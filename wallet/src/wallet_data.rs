use crate::{account::Account, wallet_types::WalletTypes};
use serde::{Deserialize, Serialize};
use settings::wallet_settings::WalletSettings;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletData {
    pub proof_key: usize,
    pub wallet_type: WalletTypes,
    pub settings: WalletSettings,
    pub wallet_address: String,
    pub accounts: Vec<Account>,
    pub selected_account: usize,
}
