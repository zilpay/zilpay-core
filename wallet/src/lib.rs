pub mod account;

use config::sha::SHA256_SIZE;
use session::Session;

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
    pub cipher_seed: [u8; 12], // TODO: make sure how long can be seed in encrypted.
    pub wallet_address: [u8; SHA256_SIZE],
    pub product_id: Option<usize>, // Ledger only device id
    pub accounts: Vec<account::Account>,
    pub selected: usize,
}

impl Wallet {
    pub fn from_bip39_words() {}
}