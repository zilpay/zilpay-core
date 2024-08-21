use crate::{
    aes::{aes_gcm_decrypt, aes_gcm_encrypt, AES_GCM_KEY_SIZE},
    argon2::derive_key,
    ntrup::{ntru_decrypt, ntru_encrypt, ntru_keys_from_seed},
};
use config::sha::SHA256_SIZE;
use ntrulp::key::{priv_key::PrivKey, pub_key::PubKey};
use std::sync::Arc;
use zil_errors::KeyChainErrors;

pub enum CipherOrders {
    AESGCM256,
    NTRUP1277,
}

pub struct KeyChain {
    pub ntrup_keys: (Arc<PubKey>, Arc<PrivKey>),
    pub aes_key: [u8; AES_GCM_KEY_SIZE],
}

impl KeyChain {
    pub fn from_pass(password: &[u8]) -> Result<Self, KeyChainErrors> {
        let seed_bytes = derive_key(password).map_err(KeyChainErrors::Argon2CipherErrors)?;
        let (pk, sk) = ntru_keys_from_seed(&seed_bytes).map_err(KeyChainErrors::NTRUPrimeError)?;
        let aes_key: [u8; AES_GCM_KEY_SIZE] = seed_bytes[SHA256_SIZE..]
            .try_into()
            .map_err(KeyChainErrors::AESKeySliceError)?;

        Ok(Self {
            ntrup_keys: (Arc::new(pk), Arc::new(sk)),
            aes_key,
        })
    }

    pub fn decrypt(
        &self,
        mut ciphertext: Vec<u8>,
        options: &[CipherOrders],
    ) -> Result<Vec<u8>, KeyChainErrors> {
        for o in options.iter().rev() {
            match o {
                CipherOrders::AESGCM256 => {
                    ciphertext = aes_gcm_decrypt(&self.aes_key, &ciphertext)
                        .map_err(KeyChainErrors::AESDecryptError)?
                }
                CipherOrders::NTRUP1277 => {
                    ciphertext = ntru_decrypt(&self.ntrup_keys.1, ciphertext)
                        .map_err(KeyChainErrors::NTRUPrimeDecryptError)?
                }
            };
        }

        Ok(ciphertext)
    }

    pub fn encrypt(
        &self,
        mut plaintext: Vec<u8>,
        options: &[CipherOrders],
    ) -> Result<Vec<u8>, KeyChainErrors> {
        let pk = &self.ntrup_keys.0;

        for o in options {
            match o {
                CipherOrders::AESGCM256 => {
                    plaintext = aes_gcm_encrypt(&self.aes_key, &plaintext)
                        .map_err(KeyChainErrors::AESEncryptError)?
                }
                CipherOrders::NTRUP1277 => {
                    plaintext = ntru_encrypt(pk, plaintext)
                        .map_err(KeyChainErrors::NTRUPrimeEncryptError)?
                }
            };
        }

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use core::panic;

    use super::{CipherOrders, KeyChain};
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use zil_errors::{AesGCMErrors, KeyChainErrors};

    #[test]
    fn test_init_keychain() {
        let mut rng = ChaCha20Rng::from_entropy();
        let mut password = [0u8; 32];

        rng.fill_bytes(&mut password);

        let keychain = KeyChain::from_pass(&password);

        assert!(keychain.is_ok());
    }

    #[test]
    fn test_encrypt_and_decrypt() {
        let mut rng = ChaCha20Rng::from_entropy();
        let mut password = [0u8; 32];
        let mut plaintext = [0u8; 1024];

        rng.fill_bytes(&mut password);
        rng.fill_bytes(&mut plaintext);

        let keychain = KeyChain::from_pass(&password).unwrap();
        let options = [CipherOrders::AESGCM256, CipherOrders::NTRUP1277];
        let ciphertext = keychain.encrypt(plaintext.to_vec(), &options).unwrap();
        let res_plaintext = keychain.decrypt(ciphertext.clone(), &options).unwrap();

        assert_eq!(res_plaintext, plaintext);

        let invalid_options = [CipherOrders::NTRUP1277, CipherOrders::AESGCM256];

        match keychain.decrypt(ciphertext, &invalid_options) {
            Ok(_) => panic!("invalid options should be fail decrypt"),
            Err(e) => match e {
                KeyChainErrors::AESDecryptError(AesGCMErrors::DecryptError(err)) => {
                    assert_eq!("aead::Error", err);
                }
                _ => panic!("should be fall with AESDecryptError"),
            },
        };
    }
}
