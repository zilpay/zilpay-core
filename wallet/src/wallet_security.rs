use crate::Result;
use crate::Wallet;
use cipher::argon2::Argon2Seed;
use errors::wallet::WalletErrors;

pub trait WalletSecurity {
    type Error;

    fn unlock(&self, seed_bytes: &Argon2Seed) -> std::result::Result<(), Self::Error>;
}

impl WalletSecurity for Wallet {
    type Error = WalletErrors;

    fn unlock(&self, seed_bytes: &Argon2Seed) -> Result<()> {
        self.unlock_iternel(seed_bytes)?;

        Ok(())
    }
}
