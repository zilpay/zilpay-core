use bincode::ToBytes;
use config::address::ADDR_LEN;
use config::key::PUB_KEY_SIZE;
use ethers::core::k256::ecdsa::VerifyingKey;
use ethers::utils::public_key_to_address;
use k256::PublicKey as K256PublicKey;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::str::FromStr;
use zil_errors::keypair::PubKeyError;

use crate::address::Address;
use crate::zil_address::from_zil_pub_key;

#[derive(Debug, PartialEq, Eq)]
pub enum PubKey {
    Secp256k1Sha256Zilliqa([u8; PUB_KEY_SIZE]),     // ZILLIQA
    Secp256k1Keccak256Ethereum([u8; PUB_KEY_SIZE]), // Ethereum
    Secp256k1Bitcoin([u8; PUB_KEY_SIZE]),           // Bitcoin
    Ed25519Solana([u8; PUB_KEY_SIZE]),              // Solana
}

impl PubKey {
    pub fn get_bytes_addr(&self) -> Result<[u8; ADDR_LEN], PubKeyError> {
        match self {
            PubKey::Secp256k1Keccak256Ethereum(pk) => {
                let public_key =
                    VerifyingKey::from_sec1_bytes(pk).or(Err(PubKeyError::InvalidVerifyingKey))?;
                let addr = public_key_to_address(&public_key);

                Ok(addr.into())
            }
            PubKey::Secp256k1Sha256Zilliqa(pk) => {
                from_zil_pub_key(pk).or(Err(PubKeyError::InvalidPubKey))
            }
            PubKey::Secp256k1Bitcoin(_) => Err(PubKeyError::NotImpl),
            PubKey::Ed25519Solana(_) => Err(PubKeyError::NotImpl),
        }
    }

    pub fn as_bytes(&self) -> [u8; PUB_KEY_SIZE] {
        match self {
            PubKey::Secp256k1Keccak256Ethereum(v) => *v,
            PubKey::Secp256k1Sha256Zilliqa(v) => *v,
            PubKey::Secp256k1Bitcoin(v) => *v,
            PubKey::Ed25519Solana(v) => *v,
        }
    }

    pub fn get_addr(&self) -> Result<Address, PubKeyError> {
        let buf = self.get_bytes_addr()?;

        match self {
            PubKey::Secp256k1Keccak256Ethereum(_) => Ok(Address::Secp256k1Keccak256Ethereum(buf)),
            PubKey::Secp256k1Sha256Zilliqa(_) => Ok(Address::Secp256k1Sha256Zilliqa(buf)),
            PubKey::Secp256k1Bitcoin(_) => Err(PubKeyError::NotImpl),
            PubKey::Ed25519Solana(_) => Err(PubKeyError::NotImpl),
        }
    }
}

impl TryInto<K256PublicKey> for PubKey {
    type Error = PubKeyError;

    fn try_into(self) -> Result<K256PublicKey, Self::Error> {
        let pk =
            K256PublicKey::from_sec1_bytes(self.as_ref()).or(Err(PubKeyError::FailIntoPubKey))?;

        Ok(pk)
    }
}

impl TryFrom<&PubKey> for K256PublicKey {
    type Error = PubKeyError;

    fn try_from(pk: &PubKey) -> Result<Self, Self::Error> {
        K256PublicKey::from_sec1_bytes(pk.as_ref()).map_err(|_| PubKeyError::FailIntoPubKey)
    }
}

impl ToBytes<{ PUB_KEY_SIZE + 1 }> for PubKey {
    type Error = PubKeyError;
    fn to_bytes(&self) -> Result<[u8; PUB_KEY_SIZE + 1], Self::Error> {
        let mut result = [0u8; PUB_KEY_SIZE + 1];

        result[0] = match self {
            PubKey::Secp256k1Sha256Zilliqa(_) => 0,
            PubKey::Secp256k1Keccak256Ethereum(_) => 1,
            PubKey::Secp256k1Bitcoin(_) => 2,
            PubKey::Ed25519Solana(_) => 3,
        };
        result[1..].copy_from_slice(self.as_ref());

        Ok(result)
    }
}

impl std::fmt::Display for PubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.to_bytes().unwrap()))
    }
}

impl Serialize for PubKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for PubKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        PubKey::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl From<[u8; PUB_KEY_SIZE + 1]> for PubKey {
    fn from(bytes: [u8; PUB_KEY_SIZE + 1]) -> Self {
        let key_type = bytes[0];
        let key_data: [u8; PUB_KEY_SIZE] = bytes[1..].try_into().unwrap();

        match key_type {
            0 => PubKey::Secp256k1Sha256Zilliqa(key_data),
            1 => PubKey::Secp256k1Keccak256Ethereum(key_data),
            2 => PubKey::Secp256k1Bitcoin(key_data),
            3 => PubKey::Ed25519Solana(key_data),
            _ => panic!("Invalid key type"),
        }
    }
}

impl TryFrom<&[u8]> for PubKey {
    type Error = PubKeyError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        if slice.len() != PUB_KEY_SIZE + 1 {
            return Err(PubKeyError::InvalidLength);
        }

        let key_type = slice[0];
        let key_data: [u8; PUB_KEY_SIZE] = slice[1..]
            .try_into()
            .map_err(|_| PubKeyError::InvalidLength)?;

        match key_type {
            0 => Ok(PubKey::Secp256k1Sha256Zilliqa(key_data)),
            1 => Ok(PubKey::Secp256k1Keccak256Ethereum(key_data)),
            _ => Err(PubKeyError::InvalidKeyType),
        }
    }
}

impl AsRef<[u8]> for PubKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            PubKey::Secp256k1Sha256Zilliqa(data) => data,
            PubKey::Secp256k1Keccak256Ethereum(data) => data,
            PubKey::Secp256k1Bitcoin(data) => data,
            PubKey::Ed25519Solana(data) => data,
        }
    }
}

impl FromStr for PubKey {
    type Err = PubKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = hex::decode(s).map_err(|_| PubKeyError::InvalidHex)?;
        let bytes: [u8; PUB_KEY_SIZE] = data[1..]
            .try_into()
            .map_err(|_| PubKeyError::InvalidLength)?;
        let prefix = data[0];

        match prefix {
            0 => Ok(PubKey::Secp256k1Sha256Zilliqa(bytes)),
            1 => Ok(PubKey::Secp256k1Keccak256Ethereum(bytes)),
            2 => Ok(PubKey::Secp256k1Bitcoin(bytes)),
            3 => Ok(PubKey::Ed25519Solana(bytes)),
            _ => Err(PubKeyError::InvalidKeyType),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_bytes() {
        let zil_bytes = [0u8; PUB_KEY_SIZE + 1];
        let eth_bytes = [1u8; PUB_KEY_SIZE + 1];

        let zil_key = PubKey::from(zil_bytes);
        let eth_key = PubKey::from(eth_bytes);

        assert!(matches!(zil_key, PubKey::Secp256k1Sha256Zilliqa(_)));
        assert!(matches!(eth_key, PubKey::Secp256k1Keccak256Ethereum(_)));
    }

    #[test]
    fn test_try_from_slice() {
        let zil_slice = &[0u8; PUB_KEY_SIZE + 1][..];
        let eth_slice = &[1u8; PUB_KEY_SIZE + 1][..];
        let invalid_slice = &[2u8; PUB_KEY_SIZE + 1][..];
        let short_slice = &[0u8; PUB_KEY_SIZE][..];

        assert!(matches!(
            PubKey::try_from(zil_slice),
            Ok(PubKey::Secp256k1Sha256Zilliqa(_))
        ));
        assert!(matches!(
            PubKey::try_from(eth_slice),
            Ok(PubKey::Secp256k1Keccak256Ethereum(_))
        ));
        assert!(matches!(
            PubKey::try_from(invalid_slice),
            Err(PubKeyError::InvalidKeyType)
        ));
        assert!(matches!(
            PubKey::try_from(short_slice),
            Err(PubKeyError::InvalidLength)
        ));
    }

    #[test]
    fn test_as_ref() {
        let data = [42u8; PUB_KEY_SIZE];
        let zil_key = PubKey::Secp256k1Sha256Zilliqa(data);
        let eth_key = PubKey::Secp256k1Keccak256Ethereum(data);

        assert_eq!(zil_key.as_ref(), &data);
        assert_eq!(eth_key.as_ref(), &data);
    }

    #[test]
    fn test_to_bytes() {
        let data = [42u8; PUB_KEY_SIZE];
        let zil_key = PubKey::Secp256k1Sha256Zilliqa(data);
        let eth_key = PubKey::Secp256k1Keccak256Ethereum(data);

        let zil_bytes = zil_key.to_bytes().unwrap();
        let eth_bytes = eth_key.to_bytes().unwrap();

        assert_eq!(zil_bytes[0], 0);
        assert_eq!(eth_bytes[0], 1);
        assert_eq!(&zil_bytes[1..], &data);
        assert_eq!(&eth_bytes[1..], &data);
    }

    #[test]
    fn test_roundtrip() {
        let original_data = [42u8; PUB_KEY_SIZE];
        let zil_key = PubKey::Secp256k1Sha256Zilliqa(original_data);
        let eth_key = PubKey::Secp256k1Keccak256Ethereum(original_data);

        let zil_bytes = zil_key.to_bytes().unwrap();
        let eth_bytes = eth_key.to_bytes().unwrap();

        let zil_key_roundtrip = PubKey::from(zil_bytes);
        let eth_key_roundtrip = PubKey::from(eth_bytes);

        assert_eq!(zil_key, zil_key_roundtrip);
        assert_eq!(eth_key, eth_key_roundtrip);
    }

    #[test]
    fn test_pubkey_to_string() {
        let zil_data = [42u8; PUB_KEY_SIZE];
        let eth_data = [69u8; PUB_KEY_SIZE];

        let zil_key = PubKey::Secp256k1Sha256Zilliqa(zil_data);
        let eth_key = PubKey::Secp256k1Keccak256Ethereum(eth_data);

        let zil_str = zil_key.to_string();
        let eth_str = eth_key.to_string();

        assert_eq!(PubKey::from_str(&zil_str).unwrap(), zil_key);
        assert_eq!(PubKey::from_str(&eth_str).unwrap(), eth_key);

        assert_eq!(PubKey::from_str("invalid"), Err(PubKeyError::InvalidHex));
        assert_eq!(
            PubKey::from_str(
                "0903150a7f37063b134cde30070431a69148d60b252f4c7b38de33d813d329a7b7da"
            ),
            Err(PubKeyError::InvalidKeyType)
        );
        assert_eq!(
            PubKey::from_str(
                "0030303150a7f37063b134cde30070431a69148d60b252f4c7b38de33d813d329a7b7da"
            ),
            Err(PubKeyError::InvalidHex)
        );
    }

    #[test]
    fn test_str_pubkey() {
        let pubkey_eth: PubKey =
            "0103150a7f37063b134cde30070431a69148d60b252f4c7b38de33d813d329a7b7da"
                .parse()
                .unwrap();
        let pubkey_zil: PubKey =
            "0003150a7f37063b134cde30070431a69148d60b252f4c7b38de33d813d329a7b7da"
                .parse()
                .unwrap();

        let addr_eth = pubkey_eth.get_bytes_addr().unwrap();
        let addr_zil = pubkey_zil.get_bytes_addr().unwrap();

        assert_eq!(
            hex::encode(addr_eth),
            "c315295101461753b838e0be8688e744cf52dd6b"
        );
        assert_eq!(
            hex::encode(addr_zil),
            "ebd8b370dddb636faf641040d2181c55190840fb"
        );
    }
}
