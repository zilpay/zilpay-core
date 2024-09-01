use bincode::{FromBytes, ToBytes};
use config::key::SECRET_KEY_SIZE;
use zil_errors::SecretKeyError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretKey {
    Secp256k1Sha256([u8; SECRET_KEY_SIZE]),    // ZILLIQA
    Secp256k1Keccak256([u8; SECRET_KEY_SIZE]), // Ethereum
}

impl SecretKey {
    pub fn get_sk(&self) -> &[u8; SECRET_KEY_SIZE] {
        match self {
            Self::Secp256k1Sha256(bytes) => bytes,
            Self::Secp256k1Keccak256(bytes) => bytes,
        }
    }
}

impl ToBytes<{ SECRET_KEY_SIZE + 1 }> for SecretKey {
    type Error = SecretKeyError;
    fn to_bytes(&self) -> Result<[u8; SECRET_KEY_SIZE + 1], Self::Error> {
        let mut result = [0u8; SECRET_KEY_SIZE + 1];

        result[0] = match self {
            SecretKey::Secp256k1Sha256(_) => 0,
            SecretKey::Secp256k1Keccak256(_) => 1,
        };
        result[1..].copy_from_slice(self.as_ref());

        Ok(result)
    }
}

impl FromBytes for SecretKey {
    type Error = SecretKeyError;

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Result<Self, Self::Error> {
        let key_type = bytes[0];
        let key_data: [u8; SECRET_KEY_SIZE] = bytes[1..]
            .try_into()
            .or(Err(SecretKeyError::SecretKeySliceError))?;

        match key_type {
            0 => Ok(SecretKey::Secp256k1Sha256(key_data)),
            1 => Ok(SecretKey::Secp256k1Keccak256(key_data)),
            _ => panic!("Invalid key type"),
        }
    }
}

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            SecretKey::Secp256k1Sha256(data) => data,
            SecretKey::Secp256k1Keccak256(data) => data,
        }
    }
}
