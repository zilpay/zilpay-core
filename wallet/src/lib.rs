pub mod account;

use bip39::Mnemonic;
use cipher::keychain::KeyChain;
use config::sha::SHA256_SIZE;
use config::wallet::{CIPHER_SEED_SIZE, N_BYTES_HASH, N_SALT};
use session::Session;
use settings::wallet_settings::WalletSettings;
use sha2::{Digest, Sha256};
use zil_errors::WalletErrors;

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
    pub settings: WalletSettings,
    pub cipher_entropy: [u8; CIPHER_SEED_SIZE],
    pub wallet_address: [u8; SHA256_SIZE],
    pub product_id: Option<usize>, // Ledger only device id
    pub accounts: Vec<account::Account>,
    pub selected: usize,
    pub passphrase: bool,
}

impl Wallet {
    pub fn from_bip39_words(
        session: Session,
        keychain: KeyChain,
        mnemonic: &Mnemonic,
        passphrase: &str,
        indexes: &[usize],
        settings: WalletSettings,
    ) -> Result<Self, WalletErrors> {
        let cipher_entropy: [u8; CIPHER_SEED_SIZE] = keychain
            .encrypt(mnemonic.to_entropy(), &settings.crypto.cipher_orders)
            .map_err(|_| WalletErrors::KeyChainErrors)?
            .try_into()
            .map_err(|_| WalletErrors::KeyChainSliceError)?;
        let mut combined = [0u8; 32];
        let mnemonic_seed = mnemonic.to_seed_normalized(passphrase);

        combined[..N_BYTES_HASH].copy_from_slice(&mnemonic_seed[..N_BYTES_HASH]);
        combined[N_BYTES_HASH..].copy_from_slice(&N_SALT);

        let mut hasher = Sha256::new();
        hasher.update(combined);

        let wallet_address: [u8; SHA256_SIZE] = hasher.finalize().into();
        let mut accounts: Vec<account::Account> = Vec::with_capacity(indexes.len());

        // TODO: list accounts by index
        for index in indexes {
            let hd_account = account::Account::from_hd(&mnemonic_seed, index);
        }

        Ok(Self {
            session,
            settings,
            wallet_address,
            cipher_entropy,
            wallet_type: WalletTypes::SecretPhrase,
            product_id: None,
            accounts: Vec::new(),
            selected: 0,
            passphrase: !passphrase.is_empty(),
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
        let indexes = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let wallet = Wallet::from_bip39_words(
            session,
            keychain,
            &mnemonic,
            passphrase,
            &indexes,
            Default::default(),
        )
        .unwrap();

        // dbg!(wallet);
    }
}
