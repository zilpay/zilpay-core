pub mod account;

use cipher::aes::AES_GCM_KEY_SIZE;
use cipher::argon2::derive_key;
use config::argon::KEY_SIZE;
use config::cipher::PROOF_SIZE;
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

pub struct WalletConfig<'a> {
    storage: &'a LocalStorage,
    session: Session,
    keychain: KeyChain,
    settings: WalletSettings,
}

pub struct Wallet<'a> {
    session: Session,
    storage: &'a LocalStorage,
    proof_key: usize,
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

impl<'a> Wallet<'a> {
    pub fn from_sk(
        sk: &SecretKey,
        name: String,
        proof: &[u8; KEY_SIZE],
        config: WalletConfig<'a>,
    ) -> Result<Self, WalletErrors> {
        let sk_as_vec = sk.to_vec();
        let mut combined = [0u8; SHA256_SIZE];

        combined[..N_BYTES_HASH].copy_from_slice(&sk_as_vec[..N_BYTES_HASH]);
        combined[N_BYTES_HASH..].copy_from_slice(&N_SALT);

        let cipher_sk: [u8; CIPHER_SK_SIZE] = config
            .keychain
            .encrypt(sk_as_vec, &config.settings.crypto.cipher_orders)
            .or(Err(WalletErrors::TryEncryptSecretKeyError))?
            .try_into()
            .or(Err(WalletErrors::SKSliceError))?;
        let cipher_proof = config
            .keychain
            .make_proof(proof, &config.settings.crypto.cipher_orders)
            .or(Err(WalletErrors::KeyChainMakeCipherProofError))?;
        let proof_key = safe_storage_save(&cipher_proof, config.storage)?;
        drop(cipher_proof);
        let cipher_entropy_key = safe_storage_save(&cipher_sk, config.storage)?;

        let mut hasher = Sha256::new();
        hasher.update(combined);

        let wallet_address: [u8; SHA256_SIZE] = hasher.finalize().into();
        // SecretKey may stores only one account.
        let account = account::Account::from_secret_key(sk, name, cipher_entropy_key)
            .or(Err(WalletErrors::InvalidSecretKeyAccount))?;
        let accounts: Vec<account::Account> = vec![account];

        Ok(Self {
            proof_key,
            session: config.session,
            settings: config.settings,
            wallet_address,
            accounts,
            storage: config.storage,
            wallet_type: WalletTypes::SecretKey,
            selected_account: 0,
        })
    }

    pub fn from_bip39_words(
        proof: &[u8; KEY_SIZE],
        mnemonic: &Mnemonic,
        passphrase: &str,
        indexes: &[(Bip49DerivationPath, String)],
        config: WalletConfig<'a>,
    ) -> Result<Self, WalletErrors> {
        let cipher_entropy: [u8; CIPHER_SEED_SIZE] = config
            .keychain
            .encrypt(mnemonic.to_entropy(), &config.settings.crypto.cipher_orders)
            .map_err(|_| WalletErrors::KeyChainErrors)?
            .try_into()
            .map_err(|_| WalletErrors::KeyChainSliceError)?;
        let mut combined = [0u8; SHA256_SIZE];
        let mnemonic_seed = mnemonic.to_seed_normalized(passphrase);
        let cipher_proof = config
            .keychain
            .make_proof(proof, &config.settings.crypto.cipher_orders)
            .or(Err(WalletErrors::KeyChainMakeCipherProofError))?;
        let proof_key = safe_storage_save(&cipher_proof, config.storage)?;
        drop(cipher_proof);
        let cipher_entropy_key = safe_storage_save(&cipher_entropy, config.storage)?;

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
            proof_key,
            session: config.session,
            settings: config.settings,
            storage: config.storage,
            wallet_address,
            accounts,
            wallet_type: WalletTypes::SecretPhrase((cipher_entropy_key, passphrase.is_empty())),
            selected_account: 0,
        })
    }

    pub fn reveal_mnemonic(
        &self,
        cipher_key: &[u8; AES_GCM_KEY_SIZE],
    ) -> Result<Mnemonic, WalletErrors> {
        if !self.session.is_enabdle {
            return Err(WalletErrors::DisabledSessions);
        }

        match self.wallet_type {
            WalletTypes::SecretPhrase((key, _)) => {
                let keychain = self
                    .session
                    .decrypt_keychain(cipher_key)
                    .or(Err(WalletErrors::KeyChainErrors))?;
                let storage_key = usize::to_le_bytes(key);
                let cipher_entropy = self
                    .storage
                    .get(&storage_key)
                    .map_err(WalletErrors::FailToGetContent)?;
                let entropy = keychain
                    .decrypt(cipher_entropy, &self.settings.crypto.cipher_orders)
                    .map_err(|_| WalletErrors::KeyChainErrors)?;
                // TODO: add more Languages
                let m = Mnemonic::from_entropy_in(bip39::Language::English, &entropy)
                    .map_err(|e| WalletErrors::MnemonicError(e.to_string()))?;

                Ok(m)
            }
            _ => Err(WalletErrors::InvalidAccountType),
        }
    }

    pub fn lock(&mut self) {
        self.session.logout();
    }

    pub fn unlock(&mut self, password: &[u8]) -> Result<[u8; AES_GCM_KEY_SIZE], WalletErrors> {
        let argon_seed = derive_key(password).map_err(WalletErrors::ArgonCipherErrors)?;
        let (session, key) =
            Session::unlock(&argon_seed).or(Err(WalletErrors::UnlockSessionError))?;
        let proof_key = usize::to_le_bytes(self.proof_key);
        let cipher_proof = self
            .storage
            .get(&proof_key)
            .map_err(WalletErrors::FailToGetProofFromStorage)?;
        let keychain = session
            .decrypt_keychain(&key)
            .or(Err(WalletErrors::SessionDecryptError))?;
        let origin_proof = keychain
            .get_proof(&cipher_proof, &self.settings.crypto.cipher_orders)
            .or(Err(WalletErrors::KeyChainFailToGetProof))?;
        let proof =
            derive_key(&argon_seed[..PROOF_SIZE]).map_err(WalletErrors::ArgonCipherErrors)?;

        if proof != origin_proof {
            return Err(WalletErrors::ProofNotMatch);
        }

        self.session = session;

        Ok(key)
    }
}

impl<'a> std::fmt::Debug for Wallet<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wallet")
            .field("wallet_type", &self.wallet_type)
            .field("settings", &self.settings)
            .field("wallet_address", &self.wallet_address)
            .field("accounts", &self.accounts)
            .field("selected_account", &self.selected_account)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use bip39::Mnemonic;
    use cipher::{argon2::derive_key, keychain::KeyChain};
    use config::cipher::PROOF_SIZE;
    use crypto::bip49::Bip49DerivationPath;
    use proto::keypair::KeyPair;
    use session::Session;
    use storage::LocalStorage;
    use zil_errors::WalletErrors;

    use crate::{Wallet, WalletConfig};

    const MNEMONIC_STR: &str =
        "green process gate doctor slide whip priority shrug diamond crumble average help";
    const PASSWORD: &[u8] = b"Test_password";
    const PASSPHRASE: &str = "";

    #[test]
    fn test_init_from_bip39_zil() {
        let argon_seed = derive_key(PASSWORD).unwrap();
        let (session, key) = Session::unlock(&argon_seed).unwrap();
        let storage = LocalStorage::new(
            "com.test_write_wallet",
            "WriteTest Wallet Corp",
            "WalletWriteTest App",
        )
        .unwrap();
        let keychain = KeyChain::from_seed(&argon_seed).unwrap();
        let mnemonic =
            Mnemonic::parse_in_normalized(bip39::Language::English, MNEMONIC_STR).unwrap();
        let indexes = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
            .map(|i| (Bip49DerivationPath::Zilliqa(i), format!("account {i}")));
        let proof = derive_key(&argon_seed[..PROOF_SIZE]).unwrap();
        let wallet_config = WalletConfig {
            session,
            keychain,
            storage: &storage,
            settings: Default::default(),
        };
        let mut wallet =
            Wallet::from_bip39_words(&proof, &mnemonic, PASSPHRASE, &indexes, wallet_config)
                .unwrap();

        assert_eq!(wallet.accounts.len(), indexes.len());
        assert_eq!(wallet.reveal_mnemonic(&key).unwrap(), mnemonic);

        wallet.lock();

        assert!(wallet.reveal_mnemonic(&key).is_err());
        assert!(wallet.unlock(b"worng password").is_err());

        let new_right_key = wallet.unlock(PASSWORD).unwrap();

        assert_eq!(
            wallet.reveal_mnemonic(&key),
            Err(WalletErrors::KeyChainErrors)
        );

        assert_eq!(wallet.reveal_mnemonic(&new_right_key).unwrap(), mnemonic);
    }

    #[test]
    fn test_init_from_sk() {
        let argon_seed = derive_key(PASSWORD).unwrap();
        let proof = derive_key(&argon_seed[..PROOF_SIZE]).unwrap();
        let (session, key) = Session::unlock(&argon_seed).unwrap();
        let storage = LocalStorage::new(
            "com.test_write_wallet_sk",
            "WriteTest Wallet_sk Corp",
            "WalletWriteTest App_sk",
        )
        .unwrap();
        let keychain = KeyChain::from_seed(&argon_seed).unwrap();
        let keypair = KeyPair::gen_keccak256().unwrap();
        let sk = keypair.get_secretkey().unwrap();
        let name = "SK Account 0";
        let wallet_config = WalletConfig {
            session,
            keychain,
            storage: &storage,
            settings: Default::default(),
        };
        let wallet = Wallet::from_sk(&sk, name.to_string(), &proof, wallet_config).unwrap();

        assert_eq!(wallet.accounts.len(), 1);
        assert_eq!(
            wallet.reveal_mnemonic(&key),
            Err(WalletErrors::InvalidAccountType)
        );
    }
}
