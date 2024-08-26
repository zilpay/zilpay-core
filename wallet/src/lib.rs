pub mod account;

use bip39::{Language, Mnemonic};
use cipher::{
    argon2::derive_key,
    keychain::{CipherOrders, KeyChain},
};
use config::sha::SHA256_SIZE;
use session::Session;
use sha2::{Digest, Sha256};
use zil_errors::WalletErrors;

pub const N_BYTES_HASH: usize = 6;
pub const N_SALT: [u8; 26] = [
    167, 36, 156, 3, 14, 212, 191, 102, 69, 11, 214, 43, 181, 138, 7, 21, 241, 122, 104, 60, 132,
    106, 5, 135, 186, 182,
];

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
    pub cipher_seed: Vec<u8>, // TODO: make sure how long can be seed in encrypted.
    pub wallet_address: [u8; SHA256_SIZE],
    pub product_id: Option<usize>, // Ledger only device id
    pub accounts: Vec<account::Account>,
    pub selected: usize,
}

impl Wallet {
    pub fn from_bip39_words<'a>(
        words: &str,
        language: Language,
        password: &'a [u8],
        passphrase: &str,
    ) -> Result<Self, WalletErrors<'a>> {
        let seed_bytes = derive_key(password).map_err(WalletErrors::InvalidArgon2Key)?;
        let (session, key) = // TODO: return a key
            Session::unlock(&seed_bytes).map_err(|_| WalletErrors::WalletSessionError)?;
        let keychain =
            KeyChain::from_seed(seed_bytes).map_err(WalletErrors::WalletKeychainError)?;

        let mnemonic = Mnemonic::parse_in_normalized(language, words)
            .map_err(|e| WalletErrors::Bip39NotValid(e.to_string()))?;
        let seed = mnemonic.to_seed_normalized(passphrase);
        let options = [CipherOrders::AESGCM256, CipherOrders::NTRUP1277];
        let cipher_seed = keychain
            .encrypt(seed.to_vec(), &options)
            .map_err(|_| WalletErrors::KeyChainErrors)?;
        let mut combined = [0u8; 32];

        combined[..6].copy_from_slice(&seed[..6]);
        combined[6..].copy_from_slice(&N_SALT);

        let mut hasher = Sha256::new();
        hasher.update(combined);

        let wallet_address: [u8; SHA256_SIZE] = hasher.finalize().into();

        dbg!(cipher_seed.len());

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
