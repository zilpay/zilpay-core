use cipher::{
    aes::{aes_gcm_decrypt, aes_gcm_encrypt, AES_GCM_KEY_SIZE},
    argon2::{derive_key, KEY_SIZE},
    keychain::KeyChain,
};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use zil_errors::SessionErrors;

pub const CIPHER_KEYCHAIN_SIZE: usize = 92;

#[derive(Debug)]
pub struct Session {
    cipher_keychain: [u8; CIPHER_KEYCHAIN_SIZE],
}

impl Session {
    pub fn unlock(password: &[u8]) -> Result<(Self, [u8; AES_GCM_KEY_SIZE]), SessionErrors> {
        let mut rng = ChaCha20Rng::from_entropy();
        let mut key = [0u8; AES_GCM_KEY_SIZE];

        rng.fill_bytes(&mut key);

        let seed_bytes = derive_key(password).map_err(SessionErrors::DeriveKeyError)?;
        let cipher_keychain: [u8; CIPHER_KEYCHAIN_SIZE] = aes_gcm_encrypt(&key, &seed_bytes)
            .map_err(SessionErrors::EncryptSessionError)?
            .try_into()
            .map_err(|_| SessionErrors::InvalidCipherKeySize)?;
        let cipher_keychain = Self { cipher_keychain };

        Ok((cipher_keychain, key))
    }

    pub fn decrypt_keychain(
        &self,
        key: &[u8; AES_GCM_KEY_SIZE],
    ) -> Result<KeyChain, SessionErrors> {
        let seed_bytes: [u8; KEY_SIZE] = aes_gcm_decrypt(key, &self.cipher_keychain)
            .map_err(SessionErrors::DecryptSessionError)?
            .try_into()
            .map_err(|_| SessionErrors::InvalidCipherKeySize)?;
        let keychain = KeyChain::from_seed(seed_bytes).map_err(SessionErrors::InvalidSeed)?;

        Ok(keychain)
    }
}

#[cfg(test)]
mod tests {
    use cipher::{argon2::derive_key, keychain::KeyChain};
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    use crate::Session;

    #[test]
    fn test_session_from_password() {
        let mut rng = ChaCha20Rng::from_entropy();
        let mut password = [0u8; 100];

        rng.fill_bytes(&mut password);

        let seed_bytes = derive_key(&password).unwrap();
        let keychain_shouldbe = KeyChain::from_seed(seed_bytes).unwrap();
        let (session, key) = Session::unlock(&password).unwrap();
        let keychain = session.decrypt_keychain(&key).unwrap();

        assert_eq!(
            keychain.ntrup_keys.0.as_bytes(),
            keychain_shouldbe.ntrup_keys.0.as_bytes()
        );
        assert_eq!(
            keychain.ntrup_keys.1.as_bytes(),
            keychain_shouldbe.ntrup_keys.1.as_bytes()
        );
        assert_eq!(keychain.aes_key, keychain_shouldbe.aes_key);
    }
}
