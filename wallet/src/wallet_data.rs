use std::collections::HashMap;

use crate::{
    account::{AccountV1, AccountV2},
    wallet_types::WalletTypes,
};
use config::session::AuthMethod;
use crypto::slip44::ETHEREUM;
use errors::wallet::WalletErrors;
use serde::{Deserialize, Serialize};
use settings::wallet_settings::WalletSettings;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WalletDataV1 {
    pub proof_key: usize,
    pub wallet_type: WalletTypes,
    pub settings: WalletSettings,
    pub wallet_name: String,
    pub accounts: Vec<AccountV1>,
    pub selected_account: usize,
    pub biometric_type: AuthMethod,
    pub default_chain_hash: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WalletDataV2 {
    pub proof_key: usize,
    pub wallet_type: WalletTypes,
    pub settings: WalletSettings,
    pub wallet_name: String,
    #[serde(default)]
    pub slip44_accounts: HashMap<u32, Vec<AccountV2>>,
    pub selected_account: usize,
    pub biometric_type: AuthMethod,
    pub chain_hash: u64,
    pub slip44: u32,
}

impl From<WalletDataV1> for WalletDataV2 {
    fn from(v1: WalletDataV1) -> Self {
        let slip44 = v1.accounts.first().map(|a| a.slip_44).unwrap_or(ETHEREUM);
        let mut slip44_accounts: HashMap<u32, Vec<AccountV2>> = HashMap::new();

        slip44_accounts.insert(slip44, v1.accounts.into_iter().map(Into::into).collect());

        Self {
            slip44_accounts,
            slip44,
            proof_key: v1.proof_key,
            wallet_type: v1.wallet_type,
            settings: v1.settings,
            wallet_name: v1.wallet_name,
            selected_account: v1.selected_account,
            biometric_type: v1.biometric_type,
            chain_hash: v1.default_chain_hash,
        }
    }
}

impl WalletDataV2 {
    pub fn get_selected_account(&self) -> Result<&AccountV2, WalletErrors> {
        self.get_account(self.selected_account)
    }

    pub fn get_account(&self, index: usize) -> Result<&AccountV2, WalletErrors> {
        self.slip44_accounts
            .get(&self.slip44)
            .and_then(|accounts| accounts.get(index))
            .ok_or(WalletErrors::InvalidAccountIndex(index))
    }

    pub fn get_accounts(&self) -> Result<&[AccountV2], WalletErrors> {
        self.slip44_accounts
            .get(&self.slip44)
            .map(|v| v.as_slice())
            .ok_or(WalletErrors::InvalidSlip44Index(self.slip44))
    }
}
