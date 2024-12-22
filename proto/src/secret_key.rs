use std::str::FromStr;

use bincode::{FromBytes, ToBytes};
use config::key::SECRET_KEY_SIZE;
use zil_errors::keypair::SecretKeyError;

type Result<T> = std::result::Result<T, SecretKeyError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretKey {
    Secp256k1Sha256Zilliqa([u8; SECRET_KEY_SIZE]), // ZILLIQA
    Secp256k1Keccak256Ethereum([u8; SECRET_KEY_SIZE]), // Ethereum
}

impl SecretKey {
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            SecretKey::Secp256k1Sha256Zilliqa(buf) => buf.to_vec(),
            SecretKey::Secp256k1Keccak256Ethereum(buf) => buf.to_vec(),
        }
    }
}

impl std::fmt::Display for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.to_bytes().unwrap()))
    }
}

impl ToBytes<{ SECRET_KEY_SIZE + 1 }> for SecretKey {
    type Error = SecretKeyError;
    fn to_bytes(&self) -> Result<[u8; SECRET_KEY_SIZE + 1]> {
        let mut result = [0u8; SECRET_KEY_SIZE + 1];

        result[0] = match self {
            SecretKey::Secp256k1Sha256Zilliqa(_) => 0,
            SecretKey::Secp256k1Keccak256Ethereum(_) => 1,
        };
        result[1..].copy_from_slice(self.as_ref());

        Ok(result)
    }
}

impl TryInto<Vec<u8>> for SecretKey {
    type Error = SecretKeyError;
    fn try_into(self) -> Result<Vec<u8>> {
        let bytes = self.to_bytes()?;

        Ok(bytes.to_vec())
    }
}

impl FromBytes for SecretKey {
    type Error = SecretKeyError;

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Result<Self> {
        let key_type = bytes[0];
        let key_data: [u8; SECRET_KEY_SIZE] = bytes[1..]
            .try_into()
            .or(Err(SecretKeyError::SecretKeySliceError))?;

        match key_type {
            0 => Ok(SecretKey::Secp256k1Sha256Zilliqa(key_data)),
            1 => Ok(SecretKey::Secp256k1Keccak256Ethereum(key_data)),
            _ => panic!("Invalid key type"),
        }
    }
}

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            SecretKey::Secp256k1Sha256Zilliqa(data) => data,
            SecretKey::Secp256k1Keccak256Ethereum(data) => data,
        }
    }
}

impl FromStr for SecretKey {
    type Err = SecretKeyError;

    fn from_str(s: &str) -> Result<Self> {
        let data = hex::decode(s).map_err(|_| SecretKeyError::InvalidHex)?;
        let bytes: [u8; SECRET_KEY_SIZE] = data[1..]
            .try_into()
            .map_err(|_| SecretKeyError::InvalidLength)?;
        let prefix = data[0];

        match prefix {
            0 => Ok(SecretKey::Secp256k1Sha256Zilliqa(bytes)),
            1 => Ok(SecretKey::Secp256k1Keccak256Ethereum(bytes)),
            _ => Err(SecretKeyError::InvalidKeyType),
        }
    }
}
