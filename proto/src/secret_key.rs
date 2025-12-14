use config::key::SECRET_KEY_SIZE;
use errors::keypair::SecretKeyError;
use std::str::FromStr;

type Result<T> = std::result::Result<T, SecretKeyError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretKey {
    Secp256k1Sha256Zilliqa([u8; SECRET_KEY_SIZE]),
    Secp256k1Keccak256Ethereum([u8; SECRET_KEY_SIZE]),
    Secp256k1Bitcoin([u8; SECRET_KEY_SIZE]),
}

impl SecretKey {
    pub fn to_bytes(&self) -> Result<[u8; SECRET_KEY_SIZE + 1]> {
        let mut result = [0u8; SECRET_KEY_SIZE + 1];

        result[0] = match self {
            SecretKey::Secp256k1Sha256Zilliqa(_) => 0,
            SecretKey::Secp256k1Keccak256Ethereum(_) => 1,
            SecretKey::Secp256k1Bitcoin(_) => 2,
        };
        result[1..].copy_from_slice(self.as_ref());

        Ok(result)
    }

    pub fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Result<Self> {
        let key_type = bytes[0];
        let key_data: [u8; SECRET_KEY_SIZE] = bytes[1..]
            .try_into()
            .or(Err(SecretKeyError::SecretKeySliceError))?;

        match key_type {
            0 => Ok(SecretKey::Secp256k1Sha256Zilliqa(key_data)),
            1 => Ok(SecretKey::Secp256k1Keccak256Ethereum(key_data)),
            2 => Ok(SecretKey::Secp256k1Bitcoin(key_data)),
            _ => panic!("Invalid key type"),
        }
    }
}

impl std::fmt::Display for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.to_bytes().unwrap()))
    }
}

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            SecretKey::Secp256k1Sha256Zilliqa(data) => data,
            SecretKey::Secp256k1Keccak256Ethereum(data) => data,
            SecretKey::Secp256k1Bitcoin(data) => data,
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
            2 => Ok(SecretKey::Secp256k1Bitcoin(bytes)),
            _ => Err(SecretKeyError::InvalidKeyType),
        }
    }
}
