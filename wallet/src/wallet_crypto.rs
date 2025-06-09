use std::sync::Arc;

use crate::{wallet_storage::StorageOperations, wallet_types::WalletTypes, Result, Wallet};
use cipher::{argon2::Argon2Seed, keychain::KeyChain};
use config::bip39::EN_WORDS;
use errors::wallet::WalletErrors;
use network::{common::Provider, provider::NetworkProvider};
use pqbip39::mnemonic::Mnemonic;
use proto::{address::Address, keypair::KeyPair, secret_key::SecretKey, signature::Signature};

pub trait WalletCrypto {
    type Error;

    fn reveal_keypair(
        &self,
        account_index: usize,
        seed_bytes: &Argon2Seed,
        passphrase: Option<&str>,
    ) -> std::result::Result<KeyPair, Self::Error>;
    fn reveal_mnemonic(
        &self,
        seed_bytes: &Argon2Seed,
    ) -> std::result::Result<Mnemonic, Self::Error>;
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
                let sk = SecretKey::from_bytes(sk_bytes.into())?;
                let keypair = KeyPair::from_secret_key(sk)?;

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
                let providers = NetworkProvider::load_network_configs(Arc::clone(&self.storage));

                let provider = providers
                    .iter()
                    .find(|&p| p.config.hash() == data.default_chain_hash)
                    .ok_or(WalletErrors::ProviderNotExist(data.default_chain_hash))?;
                let m = self.reveal_mnemonic(seed_bytes)?;
                let seed = m.to_seed(passphrase.unwrap_or(""))?;
                let hd_index = account.account_type.value();
                let bip49 = provider.get_bip49(hd_index);
                let mut keypair = KeyPair::from_bip39_seed(&seed, &bip49)?;

                match account.addr {
                    Address::Secp256k1Sha256(_) => {
                        keypair = keypair.to_sha256();
                    }
                    Address::Secp256k1Keccak256(_) => {
                        keypair = keypair.to_keccak256();
                    }
                }

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
                let m = Mnemonic::from_entropy(&EN_WORDS, &entropy)?;

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
        let sig = keypair.sign_message(msg)?;
        let vrify = keypair.verify_sig(msg, &sig)?;

        if !vrify {
            return Err(WalletErrors::InvalidVerifySig);
        }

        Ok(sig)
    }
}
