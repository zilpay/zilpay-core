use crate::Result;
use cipher::argon2::Argon2Seed;
use config::storage::FTOKENS_DB_KEY;
use proto::pubkey::PubKey;
use token::ft::FToken;
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
        let ftokens: Vec<FToken> = bincode::deserialize(&bytes).unwrap_or_default();
        let selected = self
            .data
            .accounts
            .get(self.data.selected_account)
            .ok_or(WalletErrors::FailToGetAccount(self.data.selected_account))?;

        // TODO: remake it. here we can add default token!
        match selected.pub_key {
            PubKey::Secp256k1Sha256Zilliqa(_) => self.ftokens = vec![FToken::zil(), FToken::zlp()],
            PubKey::Secp256k1Keccak256Ethereum(_) => self.ftokens = vec![FToken::eth()],
            _ => unreachable!(),
        }

        self.ftokens.extend_from_slice(&ftokens);

        Ok(())
    }
}
