use crate::Result;
use cipher::argon2::Argon2Seed;
use config::storage::FTOKENS_DB_KEY;
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
        let bytes = self.storage.get(FTOKENS_DB_KEY).unwrap_or_default();
        self.ftokens = bincode::deserialize(&bytes).unwrap_or_default();

        Ok(())
    }
}
