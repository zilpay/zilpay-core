pub mod account;
pub mod account_type;
pub mod wallet_data;
pub mod wallet_types;

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
use config::wallet::{N_BYTES_HASH, N_SALT};
use crypto::bip49::Bip49DerivationPath;
use session::Session;
use settings::wallet_settings::WalletSettings;
use sha2::{Digest, Sha256};
use storage::LocalStorage;
use wallet_data::WalletData;
use wallet_types::WalletTypes;
use zil_errors::wallet::WalletErrors;

pub struct WalletConfig<'a> {
    pub storage: &'a LocalStorage,
    pub session: Session,
    pub keychain: KeyChain,
    pub settings: WalletSettings,
}

pub struct Wallet<'a> {
    session: Session,
    storage: &'a LocalStorage,
    data: WalletData,
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
    pub fn load_from_storage(
        key: &[u8; SHA256_SIZE],
        storage: &'a LocalStorage,
        session: Session,
    ) -> Result<Self, WalletErrors> {
        let data = storage
            .get(key)
            .map_err(WalletErrors::FailToLoadWalletData)?;
        let data = serde_json::from_slice::<WalletData>(&data)
            .or(Err(WalletErrors::FailToDeserializeWalletData))?;

        Ok(Self {
            session,
            storage,
            data,
        })
    }

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

        let cipher_sk = config
            .keychain
            .encrypt(sk_as_vec, &config.settings.crypto.cipher_orders)
            .or(Err(WalletErrors::TryEncryptSecretKeyError))?;
        let cipher_proof = config
            .keychain
            .make_proof(proof, &config.settings.crypto.cipher_orders)
            .map_err(WalletErrors::KeyChainMakeCipherProofError)?;
        let proof_key = safe_storage_save(&cipher_proof, config.storage)?;
        drop(cipher_proof);
        let cipher_entropy_key = safe_storage_save(&cipher_sk, config.storage)?;

        let mut hasher = Sha256::new();
        hasher.update(combined);

        let wallet_address: [u8; SHA256_SIZE] = hasher.finalize().into();
        let wallet_address = hex::encode(wallet_address);
        // SecretKey may stores only one account.
        let account = account::Account::from_secret_key(sk, name, cipher_entropy_key)
            .or(Err(WalletErrors::InvalidSecretKeyAccount))?;
        let accounts: Vec<account::Account> = vec![account];
        let data = WalletData {
            proof_key,
            settings: config.settings,
            accounts,
            wallet_address,
            wallet_type: WalletTypes::SecretKey,
            selected_account: 0,
        };

        Ok(Self {
            session: config.session,
            storage: config.storage,
            data,
        })
    }

    pub fn from_bip39_words(
        proof: &[u8; KEY_SIZE],
        mnemonic: &Mnemonic,
        passphrase: &str,
        indexes: &[(Bip49DerivationPath, String)],
        config: WalletConfig<'a>,
    ) -> Result<Self, WalletErrors> {
        let cipher_entropy = config
            .keychain
            .encrypt(mnemonic.to_entropy(), &config.settings.crypto.cipher_orders)
            .map_err(WalletErrors::EncryptKeyChainErrors)?;
        let mut combined = [0u8; SHA256_SIZE];
        let mnemonic_seed = mnemonic.to_seed_normalized(passphrase);
        let cipher_proof = config
            .keychain
            .make_proof(proof, &config.settings.crypto.cipher_orders)
            .map_err(WalletErrors::KeyChainMakeCipherProofError)?;
        let proof_key = safe_storage_save(&cipher_proof, config.storage)?;
        drop(cipher_proof);
        let cipher_entropy_key = safe_storage_save(&cipher_entropy, config.storage)?;

        combined[..N_BYTES_HASH].copy_from_slice(&mnemonic_seed[..N_BYTES_HASH]);
        combined[N_BYTES_HASH..].copy_from_slice(&N_SALT);

        let mut hasher = Sha256::new();
        hasher.update(combined);

        let wallet_address: [u8; SHA256_SIZE] = hasher.finalize().into();
        let wallet_address = hex::encode(wallet_address);
        let mut accounts: Vec<account::Account> = Vec::with_capacity(indexes.len());

        for index in indexes {
            let (bip49, name) = index;
            let hd_account = account::Account::from_hd(&mnemonic_seed, name.to_owned(), bip49)
                .or(Err(WalletErrors::InvalidBip39Account))?;

            accounts.push(hd_account);
        }

        let data = WalletData {
            proof_key,
            settings: config.settings,
            wallet_address,
            accounts,
            wallet_type: WalletTypes::SecretPhrase((cipher_entropy_key, passphrase.is_empty())),
            selected_account: 0,
        };

        Ok(Self {
            session: config.session,
            storage: config.storage,
            data,
        })
    }

    pub fn reveal_mnemonic(
        &self,
        cipher_key: &[u8; AES_GCM_KEY_SIZE],
    ) -> Result<Mnemonic, WalletErrors> {
        if !self.session.is_enabdle {
            return Err(WalletErrors::DisabledSessions);
        }

        match self.data.wallet_type {
            WalletTypes::SecretPhrase((key, _)) => {
                let keychain = self
                    .session
                    .decrypt_keychain(cipher_key)
                    .map_err(WalletErrors::SessionDecryptKeychainError)?;
                let storage_key = usize::to_le_bytes(key);
                let cipher_entropy = self
                    .storage
                    .get(&storage_key)
                    .map_err(WalletErrors::FailToGetContent)?;
                let entropy = keychain
                    .decrypt(cipher_entropy, &self.data.settings.crypto.cipher_orders)
                    .map_err(WalletErrors::DecryptKeyChainErrors)?;
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
        let proof_key = usize::to_le_bytes(self.data.proof_key);
        let cipher_proof = self
            .storage
            .get(&proof_key)
            .map_err(WalletErrors::FailToGetProofFromStorage)?;
        let keychain = session
            .decrypt_keychain(&key)
            .or(Err(WalletErrors::SessionDecryptError))?;
        let origin_proof = keychain
            .get_proof(&cipher_proof, &self.data.settings.crypto.cipher_orders)
            .or(Err(WalletErrors::KeyChainFailToGetProof))?;
        let proof =
            derive_key(&argon_seed[..PROOF_SIZE]).map_err(WalletErrors::ArgonCipherErrors)?;

        if proof != origin_proof {
            return Err(WalletErrors::ProofNotMatch);
        }

        self.session = session;

        Ok(key)
    }

    pub fn save_to_storage(&self) -> Result<(), WalletErrors> {
        let json_bytes =
            serde_json::to_vec(&self.data).or(Err(WalletErrors::FailToSerializeWalletData))?;
        let key = self.key()?;

        self.storage
            .set(&key, &json_bytes)
            .map_err(WalletErrors::FailtoSaveWalletDataToStorage)?;

        Ok(())
    }

    #[inline]
    pub fn key(&self) -> Result<[u8; SHA256_SIZE], WalletErrors> {
        hex::decode(&self.data.wallet_address)
            .or(Err(WalletErrors::InvalidWalletAddressHex))?
            .try_into()
            .or(Err(WalletErrors::InvalidWalletAddressSize))
    }
}

#[cfg(test)]
mod tests {
    use bip39::Mnemonic;
    use cipher::{argon2::derive_key, keychain::KeyChain};
    use config::{cipher::PROOF_SIZE, sha::SHA256_SIZE};
    use crypto::bip49::Bip49DerivationPath;
    use proto::keypair::KeyPair;
    use session::Session;
    use storage::LocalStorage;
    use zil_errors::wallet::WalletErrors;

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
        let wallet =
            Wallet::from_bip39_words(&proof, &mnemonic, PASSPHRASE, &indexes, wallet_config)
                .unwrap();

        wallet.save_to_storage().unwrap();

        assert_eq!(wallet.data.accounts.len(), indexes.len());

        let wallet_addr: [u8; SHA256_SIZE] = hex::decode(wallet.data.wallet_address.clone())
            .unwrap()
            .try_into()
            .unwrap();

        drop(wallet);

        let (session, new_key) = Session::unlock(&argon_seed).unwrap();
        let res_wallet = Wallet::load_from_storage(&wallet_addr, &storage, session).unwrap();

        assert!(res_wallet.reveal_mnemonic(&key).is_err());
        assert!(res_wallet.reveal_mnemonic(&new_key).is_ok());

        dbg!(res_wallet.data);
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

        assert_eq!(wallet.data.accounts.len(), 1);
        assert_eq!(
            wallet.reveal_mnemonic(&key),
            Err(WalletErrors::InvalidAccountType)
        );

        let wallet_addr: [u8; SHA256_SIZE] = hex::decode(wallet.data.wallet_address.clone())
            .unwrap()
            .try_into()
            .unwrap();
        wallet.save_to_storage().unwrap();

        let (session, key) = Session::unlock(&argon_seed).unwrap();
        let w = Wallet::load_from_storage(&wallet_addr, &storage, session).unwrap();

        assert_eq!(w.data, wallet.data);
    }
}
