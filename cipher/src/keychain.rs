use crate::{
    aes::{aes_gcm_decrypt, aes_gcm_encrypt, AES_GCM_KEY_SIZE},
    argon2::derive_key,
    ntrup::{ntru_decrypt, ntru_encrypt, ntru_keys_from_seed},
};
use config::argon::KEY_SIZE;
use config::sha::SHA256_SIZE;
use ntrulp::{
    key::{priv_key::PrivKey, pub_key::PubKey},
    params::params1277::{PUBLICKEYS_BYTES, SECRETKEYS_BYTES},
};
use std::sync::Arc;
use zil_errors::KeyChainErrors;

pub const KEYCHAIN_BYTES_SIZE: usize = PUBLICKEYS_BYTES + SECRETKEYS_BYTES + AES_GCM_KEY_SIZE;

#[derive(Debug)]
pub enum CipherOrders {
    AESGCM256,
    NTRUP1277,
}

pub struct KeyChain {
    pub ntrup_keys: (Arc<PubKey>, Arc<PrivKey>),
    pub aes_key: [u8; AES_GCM_KEY_SIZE],
}

impl KeyChain {
    pub fn from_bytes<'a>(bytes: &[u8; KEYCHAIN_BYTES_SIZE]) -> Result<Self, KeyChainErrors<'a>> {
        let pq_pk_bytes: [u8; PUBLICKEYS_BYTES] = bytes[..PUBLICKEYS_BYTES]
            .try_into()
            .map_err(KeyChainErrors::AESKeySliceError)?;
        let pq_sk_bytes: [u8; SECRETKEYS_BYTES] = bytes
            [PUBLICKEYS_BYTES..PUBLICKEYS_BYTES + SECRETKEYS_BYTES]
            .try_into()
            .map_err(KeyChainErrors::AESKeySliceError)?;
        let pq_pk =
            PubKey::import(&pq_pk_bytes).map_err(|_| KeyChainErrors::NTRUPrimeImportKeyError)?;
        let pq_sk =
            PrivKey::import(&pq_sk_bytes).map_err(|_| KeyChainErrors::NTRUPrimeImportKeyError)?;

        let mut aes_key = [0u8; AES_GCM_KEY_SIZE];

        aes_key.copy_from_slice(&bytes[PUBLICKEYS_BYTES + SECRETKEYS_BYTES..]);

        Ok(Self {
            ntrup_keys: (Arc::new(pq_pk), Arc::new(pq_sk)),
            aes_key,
        })
    }

    pub fn from_seed<'a>(seed_bytes: &[u8; KEY_SIZE]) -> Result<Self, KeyChainErrors<'a>> {
        let (pk, sk) = ntru_keys_from_seed(seed_bytes).map_err(KeyChainErrors::NTRUPrimeError)?;
        let aes_key: [u8; AES_GCM_KEY_SIZE] = seed_bytes[SHA256_SIZE..]
            .try_into()
            .map_err(KeyChainErrors::AESKeySliceError)?;

        Ok(Self {
            ntrup_keys: (Arc::new(pk), Arc::new(sk)),
            aes_key,
        })
    }

    pub fn from_pass(password: &[u8]) -> Result<Self, KeyChainErrors> {
        let seed_bytes = derive_key(password).map_err(KeyChainErrors::Argon2CipherErrors)?;

        Self::from_seed(&seed_bytes)
    }

    pub fn to_bytes(&self) -> [u8; KEYCHAIN_BYTES_SIZE] {
        let mut res = [0u8; PUBLICKEYS_BYTES + SECRETKEYS_BYTES + AES_GCM_KEY_SIZE];
        let pq_pk = self.ntrup_keys.0.as_bytes();
        let pq_sk = self.ntrup_keys.1.as_bytes();

        res[..PUBLICKEYS_BYTES].copy_from_slice(&pq_pk);
        res[PUBLICKEYS_BYTES..PUBLICKEYS_BYTES + SECRETKEYS_BYTES].copy_from_slice(&pq_sk);
        res[PUBLICKEYS_BYTES + SECRETKEYS_BYTES..].copy_from_slice(&self.aes_key);

        res
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

    pub fn make_proof(
        &self,
        seed: &[u8; KEY_SIZE],
        options: &[CipherOrders],
    ) -> Result<Vec<u8>, KeyChainErrors> {
        let cipher = self.encrypt(seed.to_vec(), options)?;

        Ok(cipher)
    }

    pub fn get_proof(
        &self,
        cipher_proof: &[u8],
        options: &[CipherOrders],
    ) -> Result<[u8; KEY_SIZE], KeyChainErrors> {
        let origin_seed: [u8; KEY_SIZE] = self
            .decrypt(cipher_proof.to_vec(), options)?
            .try_into()
            .or(Err(KeyChainErrors::FailSlicedProofCipher))?;

        Ok(origin_seed)
    }
}

#[cfg(test)]
mod tests {
    use core::panic;

    use crate::argon2::derive_key;

    use super::{CipherOrders, KeyChain};
    use config::cipher::PROOF_SIZE;
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
    fn test_bytes() {
        let mut rng = ChaCha20Rng::from_entropy();
        let mut password = [0u8; 32];
        let mut plaintext = [0u8; 1024];

        rng.fill_bytes(&mut password);
        rng.fill_bytes(&mut plaintext);

        let keychain = KeyChain::from_pass(&password).unwrap();
        let bytes = keychain.to_bytes();
        let restore_keychain = KeyChain::from_bytes(&bytes).unwrap();

        assert_eq!(restore_keychain.aes_key, keychain.aes_key);
        assert_eq!(
            restore_keychain.ntrup_keys.0.as_bytes(),
            keychain.ntrup_keys.0.as_bytes()
        );
        assert_eq!(
            restore_keychain.ntrup_keys.1.as_bytes(),
            keychain.ntrup_keys.1.as_bytes()
        );
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

    #[test]
    fn test_make_verify_proof() {
        let mut rng = ChaCha20Rng::from_entropy();
        let mut password = [0u8; 32];

        rng.fill_bytes(&mut password);

        let options = [CipherOrders::NTRUP1277, CipherOrders::AESGCM256];
        let seed_bytes = derive_key(&password).unwrap();
        let keychain = KeyChain::from_seed(&seed_bytes).unwrap();
        let origin_proof = derive_key(&seed_bytes[..PROOF_SIZE]).unwrap();
        let proof_cipher = keychain.make_proof(&origin_proof, &options).unwrap();
        let proof = keychain.get_proof(&proof_cipher, &options).unwrap();

        assert_eq!(origin_proof, proof);
    }
}
