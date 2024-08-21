use config::sha::SHA256_SIZE;
use zil_errors::KeyChainErrors;

use crate::{argon2::derive_key, ntrup::ntru_keys_from_seed};

pub enum CipherOrders {
    AESGCM256,
    NTRUP1277,
}

pub struct KeyChain {
    pub ntrup_keys: (ntrulp::key::pub_key::PubKey, ntrulp::key::priv_key::PrivKey),
    pub aes_key: [u8; SHA256_SIZE],
}

impl KeyChain {
    pub fn from_pass(password: &[u8]) -> Result<Self, KeyChainErrors> {
        let seed_bytes = derive_key(password).map_err(KeyChainErrors::Argon2CipherErrors)?;
        let ntrup_keys =
            ntru_keys_from_seed(&seed_bytes).map_err(KeyChainErrors::NTRUPrimeError)?;
        let aes_key: [u8; SHA256_SIZE] = seed_bytes[SHA256_SIZE..]
            .try_into()
            .map_err(KeyChainErrors::AESKeySliceError)?;

        Ok(Self {
            ntrup_keys,
            aes_key,
        })
    }
}
