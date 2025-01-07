use crate::{wallet_storage::StorageOperations, wallet_types::WalletTypes, Result, Wallet};
use bip39::Mnemonic;
use cipher::{argon2::Argon2Seed, keychain::KeyChain};
use errors::wallet::WalletErrors;
use proto::{keypair::KeyPair, secret_key::SecretKey, signature::Signature};

/// Cryptographic operations for wallet security
pub trait WalletCrypto {
    type Error;

    /// Retrieves the keypair for a specific account index
    fn reveal_keypair(
        &self,
        account_index: usize,
        seed_bytes: &Argon2Seed,
        passphrase: Option<&str>,
    ) -> std::result::Result<KeyPair, Self::Error>;

    /// Retrieves the BIP39 mnemonic phrase
    fn reveal_mnemonic(
        &self,
        seed_bytes: &Argon2Seed,
    ) -> std::result::Result<Mnemonic, Self::Error>;

    /// Signs a message using the specified account
    fn sign_message(
        &self,
        msg: &[u8],
        account_index: usize,
        seed_bytes: &Argon2Seed,
        passphrase: Option<&str>,
    ) -> std::result::Result<Signature, Self::Error>;
}

impl WalletCrypto for Wallet {
    type Error = WalletErrors;

    fn reveal_keypair(
        &self,
        account_index: usize,
        seed_bytes: &Argon2Seed,
        passphrase: Option<&str>,
    ) -> Result<KeyPair> {
        let keychain = KeyChain::from_seed(seed_bytes)?;
        let data = self.get_wallet_data()?;

        match data.wallet_type {
            WalletTypes::SecretKey => {
                let account = data
                    .accounts
                    .get(account_index)
                    .ok_or(WalletErrors::FailToGetAccount(account_index))?;
                let storage_key = usize::to_le_bytes(account.account_type.value());
                let cipher_sk = self.storage.get(&storage_key)?;
                let sk_bytes = keychain.decrypt(cipher_sk, &data.settings.cipher_orders)?;
                let sk = SecretKey::from_bytes(sk_bytes.into())
                    .map_err(WalletErrors::FailParseSKBytes)?;
                let keypair =
                    KeyPair::from_secret_key(sk).map_err(WalletErrors::FailToCreateKeyPair)?;

                Ok(keypair)
            }
            WalletTypes::SecretPhrase((_key, is_phr)) => {
                if is_phr && passphrase.is_none() {
                    return Err(WalletErrors::PassphraseIsNone);
                }

                let account = data
                    .accounts
                    .get(account_index)
                    .ok_or(WalletErrors::FailToGetAccount(account_index))?;
                let m = self.reveal_mnemonic(seed_bytes)?;
                let seed = m.to_seed(passphrase.unwrap_or(""));
                let bip49 = account.get_bip49().map_err(WalletErrors::InvalidBip49)?;
                let keypair = KeyPair::from_bip39_seed(&seed, &bip49)
                    .map_err(WalletErrors::FailToCreateKeyPair)?;

                Ok(keypair)
            }
            _ => Err(WalletErrors::InvalidAccountType),
        }
    }

    fn reveal_mnemonic(&self, seed_bytes: &Argon2Seed) -> Result<Mnemonic> {
        let data = self.get_wallet_data()?;

        match data.wallet_type {
            WalletTypes::SecretPhrase((key, _)) => {
                let keychain =
                    KeyChain::from_seed(seed_bytes).map_err(WalletErrors::KeyChainError)?;
                let storage_key = usize::to_le_bytes(key);
                let cipher_entropy = self.storage.get(&storage_key)?;
                let entropy = keychain.decrypt(cipher_entropy, &data.settings.cipher_orders)?;
                // TODO: add more Languages
                let m = Mnemonic::from_entropy_in(bip39::Language::English, &entropy)
                    .map_err(|e| WalletErrors::MnemonicError(e.to_string()))?;

                Ok(m)
            }
            _ => Err(WalletErrors::InvalidAccountType),
        }
    }

    fn sign_message(
        &self,
        msg: &[u8],
        account_index: usize,
        seed_bytes: &Argon2Seed,
        passphrase: Option<&str>,
    ) -> Result<Signature> {
        let keypair = self.reveal_keypair(account_index, seed_bytes, passphrase)?;
        let sig = keypair
            .sign_message(msg)
            .map_err(WalletErrors::FailSignMessage)?;
        let vrify = keypair
            .verify_sig(msg, &sig)
            .map_err(WalletErrors::FailVerifySig)?;

        if !vrify {
            return Err(WalletErrors::InvalidVerifySig);
        }

        Ok(sig)
    }
}
