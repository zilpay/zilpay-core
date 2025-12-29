use config::key::SECRET_KEY_SIZE;
use errors::keypair::SecretKeyError;
use std::str::FromStr;

use crate::btc_utils::ByteCodec;

type Result<T> = std::result::Result<T, SecretKeyError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretKey {
    Secp256k1Sha256Zilliqa([u8; SECRET_KEY_SIZE]),
    Secp256k1Keccak256Ethereum([u8; SECRET_KEY_SIZE]),
    Secp256k1Bitcoin(([u8; SECRET_KEY_SIZE], bitcoin::Network, bitcoin::AddressType)),
}

impl SecretKey {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        match self {
            SecretKey::Secp256k1Sha256Zilliqa(sk) => {
                let mut result = vec![0u8];
                result.extend_from_slice(sk);
                Ok(result)
            }
            SecretKey::Secp256k1Keccak256Ethereum(sk) => {
                let mut result = vec![1u8];
                result.extend_from_slice(sk);
                Ok(result)
            }
            SecretKey::Secp256k1Bitcoin((sk, network, addr_type)) => {
                let mut result = vec![2u8];
                result.push(network.to_byte());
                result.push(addr_type.to_byte());
                result.extend_from_slice(sk);
                Ok(result)
            }
        }
    }

    pub fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Result<Self> {
        if bytes.is_empty() {
            return Err(SecretKeyError::InvalidLength);
        }

        let key_type = bytes[0];

        match key_type {
            0 | 1 => {
                if bytes.len() != SECRET_KEY_SIZE + 1 {
                    return Err(SecretKeyError::InvalidLength);
                }
                let key_data: [u8; SECRET_KEY_SIZE] = bytes[1..]
                    .try_into()
                    .or(Err(SecretKeyError::SecretKeySliceError))?;

                match key_type {
                    0 => Ok(SecretKey::Secp256k1Sha256Zilliqa(key_data)),
                    1 => Ok(SecretKey::Secp256k1Keccak256Ethereum(key_data)),
                    _ => unreachable!(),
                }
            }
            2 => {
                if bytes.len() != SECRET_KEY_SIZE + 3 {
                    return Err(SecretKeyError::InvalidLength);
                }
                let network = bitcoin::Network::from_byte(bytes[1])
                    .map_err(|_| SecretKeyError::InvalidKeyType)?;
                let addr_type = bitcoin::AddressType::from_byte(bytes[2])
                    .map_err(|_| SecretKeyError::InvalidKeyType)?;
                let key_data: [u8; SECRET_KEY_SIZE] = bytes[3..]
                    .try_into()
                    .or(Err(SecretKeyError::SecretKeySliceError))?;

                Ok(SecretKey::Secp256k1Bitcoin((key_data, network, addr_type)))
            }
            _ => Err(SecretKeyError::InvalidKeyType),
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
            SecretKey::Secp256k1Bitcoin((data, _, _)) => data,
        }
    }
}

impl FromStr for SecretKey {
    type Err = SecretKeyError;

    fn from_str(s: &str) -> Result<Self> {
        let data = hex::decode(s).map_err(|_| SecretKeyError::InvalidHex)?;
        SecretKey::from_bytes(std::borrow::Cow::Borrowed(&data))
    }
}
