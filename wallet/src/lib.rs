pub mod account;

use proto::secret_key::SecretKey;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use bip39::Mnemonic;
use cipher::keychain::KeyChain;
use config::sha::SHA256_SIZE;
use config::wallet::{CIPHER_SEED_SIZE, CIPHER_SK_SIZE, N_BYTES_HASH, N_SALT};
use crypto::bip49::Bip49DerivationPath;
use session::Session;
use settings::wallet_settings::WalletSettings;
use sha2::{Digest, Sha256};
use storage::LocalStorage;
use zil_errors::WalletErrors;

#[derive(Debug)]
pub enum WalletTypes {
    Ledger(usize), // Ledger product_id
    // Cipher for entropy secret words storage_key / passphrase
    SecretPhrase((usize, bool)),
    SecretKey,
}

#[derive(Debug)]
pub struct Wallet {
    session: Session,
    pub wallet_type: WalletTypes,
    pub settings: WalletSettings,
    pub wallet_address: [u8; SHA256_SIZE],
    pub accounts: Vec<account::Account>,
    pub selected_account: usize,
}

fn safe_storage_save(cipher_entropy: &[u8], storage: &LocalStorage) -> Result<usize, WalletErrors> {
    let mut rng = ChaCha20Rng::from_entropy();
    let mut cipher_entropy_key: usize;

    loop {
        cipher_entropy_key = rng.r#gen();
        let key = usize::to_le_bytes(cipher_entropy_key);
        let is_exists_key = storage
            .exists(&key)
            .map_err(WalletErrors::FailToSaveCipher)?;

        if is_exists_key {
            continue;
        }

        storage
            .set(&key, cipher_entropy)
            .map_err(WalletErrors::FailToSaveCipher)?;

        break;
    }

    Ok(cipher_entropy_key)
}

impl Wallet {
    pub fn from_sk(
        sk: &SecretKey,
        name: String,
        storage: &LocalStorage,
        session: Session,
        keychain: KeyChain,
        settings: WalletSettings,
    ) -> Result<Self, WalletErrors> {
        let sk_as_vec = sk.to_vec();
        let mut combined = [0u8; SHA256_SIZE];

        combined[..N_BYTES_HASH].copy_from_slice(&sk_as_vec[..N_BYTES_HASH]);
        combined[N_BYTES_HASH..].copy_from_slice(&N_SALT);

        let cipher_sk: [u8; CIPHER_SK_SIZE] = keychain
            .encrypt(sk_as_vec, &settings.crypto.cipher_orders)
            .or(Err(WalletErrors::TryEncryptSecretKeyError))?
            .try_into()
            .or(Err(WalletErrors::SKSliceError))?;
        let cipher_entropy_key = safe_storage_save(&cipher_sk, storage)?;

        let mut hasher = Sha256::new();
        hasher.update(combined);

        let wallet_address: [u8; SHA256_SIZE] = hasher.finalize().into();
        // SecretKey may stores only one account.
        let account = account::Account::from_secret_key(sk, name, cipher_entropy_key)
            .or(Err(WalletErrors::InvalidSecretKeyAccount))?;
        let accounts: Vec<account::Account> = vec![account];

        Ok(Self {
            session,
            settings,
            wallet_address,
            accounts,
            wallet_type: WalletTypes::SecretKey,
            selected_account: 0,
        })
    }

    pub fn from_bip39_words(
        session: Session,
        keychain: KeyChain,
        mnemonic: &Mnemonic,
        storage: &LocalStorage,
        passphrase: &str,
        indexes: &[(Bip49DerivationPath, String)],
        settings: WalletSettings,
    ) -> Result<Self, WalletErrors> {
        let cipher_entropy: [u8; CIPHER_SEED_SIZE] = keychain
            .encrypt(mnemonic.to_entropy(), &settings.crypto.cipher_orders)
            .map_err(|_| WalletErrors::KeyChainErrors)?
            .try_into()
            .map_err(|_| WalletErrors::KeyChainSliceError)?;
        let mut combined = [0u8; SHA256_SIZE];
        let mnemonic_seed = mnemonic.to_seed_normalized(passphrase);
        let cipher_entropy_key = safe_storage_save(&cipher_entropy, storage)?;

        combined[..N_BYTES_HASH].copy_from_slice(&mnemonic_seed[..N_BYTES_HASH]);
        combined[N_BYTES_HASH..].copy_from_slice(&N_SALT);

        let mut hasher = Sha256::new();
        hasher.update(combined);

        let wallet_address: [u8; SHA256_SIZE] = hasher.finalize().into();
        let mut accounts: Vec<account::Account> = Vec::with_capacity(indexes.len());

        for index in indexes {
            let (bip49, name) = index;
            let hd_account = account::Account::from_hd(&mnemonic_seed, name.to_owned(), bip49)
                .or(Err(WalletErrors::InvalidBip39Account))?;

            accounts.push(hd_account);
        }

        Ok(Self {
            session,
            settings,
            wallet_address,
            accounts,
            wallet_type: WalletTypes::SecretPhrase((cipher_entropy_key, passphrase.is_empty())),
            selected_account: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use bip39::Mnemonic;
    use cipher::{argon2::derive_key, keychain::KeyChain};
    use crypto::bip49::Bip49DerivationPath;
    use session::Session;
    use storage::LocalStorage;

    use crate::Wallet;

    #[test]
    fn test_init_from_bip39() {
        let mnemonic_str =
            "green process gate doctor slide whip priority shrug diamond crumble average help";
        let password = b"Test_password";
        let passphrase = "";
        let argon_seed = derive_key(password).unwrap();
        let (session, key) = Session::unlock(&argon_seed).unwrap();
        let storage = LocalStorage::new(
            "com.test_write_wallet",
            "WriteTest Wallet Corp",
            "WalletWriteTest App",
        )
        .unwrap();
        let keychain = KeyChain::from_seed(argon_seed).unwrap();
        let mnemonic =
            Mnemonic::parse_in_normalized(bip39::Language::English, mnemonic_str).unwrap();
        let indexes = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
            .map(|i| (Bip49DerivationPath::Zilliqa(i), format!("account {i}")));
        let wallet = Wallet::from_bip39_words(
            session,
            keychain,
            &mnemonic,
            &storage,
            passphrase,
            &indexes,
            Default::default(),
        )
        .unwrap();

        dbg!(wallet);
    }
}
