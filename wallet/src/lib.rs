pub mod account;

use cipher::keychain::{CipherOrders, KeyChain};
use config::sha::SHA256_SIZE;
use session::Session;
use sha2::{Digest, Sha256};
use zil_errors::WalletErrors;

pub const N_BYTES_HASH: usize = 6;
pub const N_SALT: [u8; 26] = [
    167, 36, 156, 3, 14, 212, 191, 102, 69, 11, 214, 43, 181, 138, 7, 21, 241, 122, 104, 60, 132,
    106, 5, 135, 186, 182,
];
pub const CIPHER_SEED_SIZE: usize = 2578;

#[derive(Debug)]
pub enum WalletTypes {
    Ledger,
    SecretPhrase,
    SecretKey,
}

#[derive(Debug)]
pub struct Wallet {
    session: Session,
    pub wallet_type: WalletTypes,
    pub cipher_seed: [u8; CIPHER_SEED_SIZE],
    pub wallet_address: [u8; SHA256_SIZE],
    pub product_id: Option<usize>, // Ledger only device id
    pub accounts: Vec<account::Account>,
    pub selected: usize,
}

impl Wallet {
    pub fn from_bip39_words(
        session: Session,
        keychain: KeyChain,
        mnemonic_seed: &[u8], // Mnemonic seed bytes [u8; 64]
        indexes: &[u8],
    ) -> Result<Self, WalletErrors> {
        let options = [CipherOrders::AESGCM256, CipherOrders::NTRUP1277];
        let cipher_seed: [u8; CIPHER_SEED_SIZE] = keychain
            .encrypt(mnemonic_seed.to_vec(), &options)
            .map_err(|_| WalletErrors::KeyChainErrors)?
            .try_into()
            .map_err(|_| WalletErrors::KeyChainSliceError)?;
        let mut combined = [0u8; 32];

        combined[..6].copy_from_slice(&mnemonic_seed[..6]);
        combined[6..].copy_from_slice(&N_SALT);

        let mut hasher = Sha256::new();
        hasher.update(combined);

        let wallet_address: [u8; SHA256_SIZE] = hasher.finalize().into();
        let mut accounts: Vec<account::Account> = Vec::with_capacity(indexes.len());

        for index in indexes {}

        Ok(Self {
            session,
            wallet_address,
            cipher_seed,
            wallet_type: WalletTypes::SecretPhrase,
            product_id: None,
            accounts: Vec::new(),
            selected: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use bip39::Mnemonic;
    use cipher::{argon2::derive_key, keychain::KeyChain};
    use session::Session;

    use crate::Wallet;

    #[test]
    fn test_init_from_bip39() {
        let mnemonic_str =
            "green process gate doctor slide whip priority shrug diamond crumble average help";
        let password = b"Test_password";
        let passphrase = "";
        let argon_seed = derive_key(password).unwrap();
        let (session, key) = Session::unlock(&argon_seed).unwrap();
        let keychain = KeyChain::from_seed(argon_seed).unwrap();
        let mnemonic =
            Mnemonic::parse_in_normalized(bip39::Language::English, mnemonic_str).unwrap();
        let mnemonic_seed = mnemonic.to_seed_normalized(passphrase);
        let indexes = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let wallet = Wallet::from_bip39_words(session, keychain, &mnemonic_seed, &indexes).unwrap();

        dbg!(wallet);
    }
}
