use crate::{wallet_token::TokenManagement, Result};
use cipher::argon2::Argon2Seed;
use zil_errors::wallet::WalletErrors;

use crate::Wallet;

/// Authentication and security operations
pub trait WalletSecurity {
    type Error;

    /// Unlocks the wallet using provided seed bytes
    fn unlock(&mut self, seed_bytes: &Argon2Seed) -> std::result::Result<(), Self::Error>;
}

impl WalletSecurity for Wallet {
    type Error = WalletErrors;

    fn unlock(&mut self, seed_bytes: &Argon2Seed) -> Result<()> {
        self.unlock_iternel(seed_bytes)?;

        let token_key = Wallet::get_token_db_key(&self.data.wallet_address);
        let ftokens_bytes = self.storage.get(&token_key)?;

        self.ftokens = bincode::deserialize(&ftokens_bytes).unwrap_or_default();

        Ok(())
    }
}
