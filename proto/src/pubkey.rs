use config::key::PUB_KEY_SIZE;
use errors::keypair::PubKeyError;
use k256::PublicKey as K256PublicKey;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::str::FromStr;

use crate::address::Address;
use crate::btc_utils::ByteCodec;

type Result<T> = std::result::Result<T, PubKeyError>;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PubKey {
    Secp256k1Sha256([u8; PUB_KEY_SIZE]),    // ZILLIQA
    Secp256k1Keccak256([u8; PUB_KEY_SIZE]), // Ethereum
    Secp256k1Bitcoin(([u8; PUB_KEY_SIZE], bitcoin::Network, bitcoin::AddressType)), // Bitcoin
    Ed25519Solana([u8; PUB_KEY_SIZE]),      // Solana
}

impl PubKey {
    pub fn from_compressed_hex(value: &str) -> Result<[u8; PUB_KEY_SIZE]> {
        let pk_bytes: [u8; PUB_KEY_SIZE] = hex::decode(value)
            .map_err(|_| PubKeyError::InvalidHex)?
            .try_into()
            .map_err(|_| PubKeyError::InvalidHex)?;

        Ok(pk_bytes)
    }

    pub fn from_uncompressed_hex(value: &str) -> Result<[u8; PUB_KEY_SIZE]> {
        let pk_bytes_vec = alloy::hex::decode(value).map_err(|_| PubKeyError::InvalidHex)?;
        let pk = K256PublicKey::from_sec1_bytes(&pk_bytes_vec)
            .map_err(|_| PubKeyError::InvalidLength)?;
        let pk_bytes: [u8; PUB_KEY_SIZE] = pk
            .to_sec1_bytes()
            .to_vec()
            .try_into()
            .map_err(|_| PubKeyError::InvalidHex)?;

        Ok(pk_bytes)
    }
}

impl PubKey {
    pub fn as_hex_str(&self) -> String {
        hex::encode(self.as_bytes())
    }

    pub fn as_bytes<'a>(&'a self) -> &'a [u8] {
        match self {
            PubKey::Secp256k1Keccak256(v) => v,
            PubKey::Secp256k1Sha256(v) => v,
            PubKey::Secp256k1Bitcoin((v, _, _)) => v,
            PubKey::Ed25519Solana(v) => v,
        }
    }

    pub fn get_addr(&self) -> Result<Address> {
        let addr = Address::from_pubkey(&self)?;

        Ok(addr)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        match self {
            PubKey::Secp256k1Sha256(pk) => {
                let mut result = vec![0u8];
                result.extend_from_slice(pk);
                Ok(result)
            }
            PubKey::Secp256k1Keccak256(pk) => {
                let mut result = vec![1u8];
                result.extend_from_slice(pk);
                Ok(result)
            }
            PubKey::Secp256k1Bitcoin((pk, network, addr_type)) => {
                let mut result = vec![2u8];
                result.push(network.to_byte());
                result.push(addr_type.to_byte());
                result.extend_from_slice(pk);
                Ok(result)
            }
            PubKey::Ed25519Solana(pk) => {
                let mut result = vec![3u8];
                result.extend_from_slice(pk);
                Ok(result)
            }
        }
    }
}

impl TryInto<K256PublicKey> for PubKey {
    type Error = PubKeyError;

    fn try_into(self) -> Result<K256PublicKey> {
        let pk =
            K256PublicKey::from_sec1_bytes(self.as_ref()).or(Err(PubKeyError::FailIntoPubKey))?;

        Ok(pk)
    }
}

impl TryFrom<&PubKey> for K256PublicKey {
    type Error = PubKeyError;

    fn try_from(pk: &PubKey) -> Result<Self> {
        K256PublicKey::from_sec1_bytes(pk.as_ref()).map_err(|_| PubKeyError::FailIntoPubKey)
    }
}

impl TryFrom<&PubKey> for alloy::signers::k256::ecdsa::VerifyingKey {
    type Error = PubKeyError;

    fn try_from(pk: &PubKey) -> Result<Self> {
        alloy::signers::k256::ecdsa::VerifyingKey::from_sec1_bytes(pk.as_ref())
            .map_err(|e| PubKeyError::InvalidVerifyingKey(e.to_string()))
    }
}

impl TryFrom<&PubKey> for bitcoin::PublicKey {
    type Error = PubKeyError;

    fn try_from(pk: &PubKey) -> Result<Self> {
        bitcoin::PublicKey::from_slice(pk.as_ref()).map_err(|_| PubKeyError::FailIntoPubKey)
    }
}

impl std::fmt::Display for PubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.to_bytes().unwrap()))
    }
}

impl Serialize for PubKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for PubKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        PubKey::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl TryFrom<&[u8]> for PubKey {
    type Error = PubKeyError;

    fn try_from(slice: &[u8]) -> Result<Self> {
        if slice.is_empty() {
            return Err(PubKeyError::InvalidLength);
        }

        let key_type = slice[0];

        match key_type {
            0 | 1 | 3 => {
                // Zilliqa, Ethereum, Solana: 1 + 33 bytes
                if slice.len() != PUB_KEY_SIZE + 1 {
                    return Err(PubKeyError::InvalidLength);
                }
                let key_data: [u8; PUB_KEY_SIZE] = slice[1..]
                    .try_into()
                    .map_err(|_| PubKeyError::InvalidLength)?;

                match key_type {
                    0 => Ok(PubKey::Secp256k1Sha256(key_data)),
                    1 => Ok(PubKey::Secp256k1Keccak256(key_data)),
                    3 => Ok(PubKey::Ed25519Solana(key_data)),
                    _ => unreachable!(),
                }
            }
            2 => {
                // Bitcoin: 1 + 1 + 1 + 33 bytes
                if slice.len() != PUB_KEY_SIZE + 3 {
                    return Err(PubKeyError::InvalidLength);
                }
                let network = bitcoin::Network::from_byte(slice[1])?;
                let addr_type = bitcoin::AddressType::from_byte(slice[2])?;
                let key_data: [u8; PUB_KEY_SIZE] = slice[3..]
                    .try_into()
                    .map_err(|_| PubKeyError::InvalidLength)?;

                Ok(PubKey::Secp256k1Bitcoin((key_data, network, addr_type)))
            }
            _ => Err(PubKeyError::InvalidKeyType),
        }
    }
}

impl AsRef<[u8]> for PubKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            PubKey::Secp256k1Sha256(data) => data,
            PubKey::Secp256k1Keccak256(data) => data,
            PubKey::Secp256k1Bitcoin((data, _, _)) => data,
            PubKey::Ed25519Solana(data) => data,
        }
    }
}

impl FromStr for PubKey {
    type Err = PubKeyError;

    fn from_str(s: &str) -> Result<Self> {
        let data = hex::decode(s).map_err(|_| PubKeyError::InvalidHex)?;
        PubKey::try_from(data.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_bytes() {
        let zil_bytes = vec![0u8; PUB_KEY_SIZE + 1];
        let eth_bytes = vec![1u8; PUB_KEY_SIZE + 1];

        let zil_key: PubKey = zil_bytes.as_slice().try_into().unwrap();
        let eth_key: PubKey = eth_bytes.as_slice().try_into().unwrap();

        assert!(matches!(zil_key, PubKey::Secp256k1Sha256(_)));
        assert!(matches!(eth_key, PubKey::Secp256k1Keccak256(_)));
    }

    #[test]
    fn test_try_from_slice() {
        let zil_slice = &[0u8; PUB_KEY_SIZE + 1][..];
        let eth_slice = &[1u8; PUB_KEY_SIZE + 1][..];
        let btc_wrong_length_slice = &[2u8; PUB_KEY_SIZE + 1][..];
        let invalid_type_slice = &[99u8; PUB_KEY_SIZE + 1][..];
        let short_slice = &[0u8; PUB_KEY_SIZE][..];

        assert!(matches!(
            PubKey::try_from(zil_slice),
            Ok(PubKey::Secp256k1Sha256(_))
        ));
        assert!(matches!(
            PubKey::try_from(eth_slice),
            Ok(PubKey::Secp256k1Keccak256(_))
        ));
        assert!(matches!(
            PubKey::try_from(btc_wrong_length_slice),
            Err(PubKeyError::InvalidLength)
        ));
        assert!(matches!(
            PubKey::try_from(invalid_type_slice),
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
        let zil_key = PubKey::Secp256k1Sha256(data);
        let eth_key = PubKey::Secp256k1Keccak256(data);

        assert_eq!(zil_key.as_ref(), &data);
        assert_eq!(eth_key.as_ref(), &data);
    }

    #[test]
    fn test_to_bytes() {
        let data = [42u8; PUB_KEY_SIZE];
        let zil_key = PubKey::Secp256k1Sha256(data);
        let eth_key = PubKey::Secp256k1Keccak256(data);

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
        let zil_key = PubKey::Secp256k1Sha256(original_data);
        let eth_key = PubKey::Secp256k1Keccak256(original_data);

        let zil_bytes = zil_key.to_bytes().unwrap();
        let eth_bytes = eth_key.to_bytes().unwrap();

        let zil_key_roundtrip: PubKey = zil_bytes.as_slice().try_into().unwrap();
        let eth_key_roundtrip: PubKey = eth_bytes.as_slice().try_into().unwrap();

        assert_eq!(zil_key, zil_key_roundtrip);
        assert_eq!(eth_key, eth_key_roundtrip);
    }

    #[test]
    fn test_pubkey_to_string() {
        let zil_data = [42u8; PUB_KEY_SIZE];
        let eth_data = [69u8; PUB_KEY_SIZE];

        let zil_key = PubKey::Secp256k1Sha256(zil_data);
        let eth_key = PubKey::Secp256k1Keccak256(eth_data);

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
    fn test_bitcoin_pubkey_to_bytes() {
        let pk_data = [42u8; PUB_KEY_SIZE];
        let network = bitcoin::Network::Bitcoin;
        let addr_type = bitcoin::AddressType::P2wpkh;
        let btc_key = PubKey::Secp256k1Bitcoin((pk_data, network, addr_type));

        let bytes = btc_key.to_bytes().unwrap();

        assert_eq!(bytes[0], 2);
        assert_eq!(bytes[1], network.to_byte());
        assert_eq!(bytes[2], addr_type.to_byte());
        assert_eq!(&bytes[3..], &pk_data);
        assert_eq!(bytes.len(), PUB_KEY_SIZE + 3);
    }

    #[test]
    fn test_bitcoin_pubkey_from_bytes() {
        let pk_data = [42u8; PUB_KEY_SIZE];
        let network = bitcoin::Network::Bitcoin;
        let addr_type = bitcoin::AddressType::P2wpkh;
        let btc_key = PubKey::Secp256k1Bitcoin((pk_data, network, addr_type));

        let bytes = btc_key.to_bytes().unwrap();
        let recovered: PubKey = bytes.as_slice().try_into().unwrap();

        assert_eq!(btc_key, recovered);
    }

    #[test]
    fn test_bitcoin_pubkey_roundtrip_all_networks() {
        let pk_data = [111u8; PUB_KEY_SIZE];
        let networks = vec![
            bitcoin::Network::Bitcoin,
            bitcoin::Network::Testnet,
            bitcoin::Network::Testnet4,
            bitcoin::Network::Signet,
            bitcoin::Network::Regtest,
        ];

        for network in networks {
            let btc_key =
                PubKey::Secp256k1Bitcoin((pk_data, network, bitcoin::AddressType::P2wpkh));
            let bytes = btc_key.to_bytes().unwrap();
            let recovered: PubKey = bytes.as_slice().try_into().unwrap();

            assert_eq!(btc_key, recovered);
        }
    }

    #[test]
    fn test_bitcoin_pubkey_roundtrip_all_address_types() {
        let pk_data = [222u8; PUB_KEY_SIZE];
        let addr_types = vec![
            bitcoin::AddressType::P2pkh,
            bitcoin::AddressType::P2sh,
            bitcoin::AddressType::P2wpkh,
            bitcoin::AddressType::P2wsh,
            bitcoin::AddressType::P2tr,
            bitcoin::AddressType::P2a,
        ];

        for addr_type in addr_types {
            let btc_key = PubKey::Secp256k1Bitcoin((pk_data, bitcoin::Network::Bitcoin, addr_type));
            let bytes = btc_key.to_bytes().unwrap();
            let recovered: PubKey = bytes.as_slice().try_into().unwrap();

            assert_eq!(btc_key, recovered);
        }
    }

    #[test]
    fn test_bitcoin_pubkey_roundtrip_combinations() {
        let pk_data = [99u8; PUB_KEY_SIZE];
        let test_cases = vec![
            (bitcoin::Network::Bitcoin, bitcoin::AddressType::P2pkh),
            (bitcoin::Network::Bitcoin, bitcoin::AddressType::P2wpkh),
            (bitcoin::Network::Bitcoin, bitcoin::AddressType::P2tr),
            (bitcoin::Network::Testnet, bitcoin::AddressType::P2pkh),
            (bitcoin::Network::Testnet, bitcoin::AddressType::P2wpkh),
            (bitcoin::Network::Signet, bitcoin::AddressType::P2wpkh),
            (bitcoin::Network::Regtest, bitcoin::AddressType::P2pkh),
        ];

        for (network, addr_type) in test_cases {
            let btc_key = PubKey::Secp256k1Bitcoin((pk_data, network, addr_type));
            let bytes = btc_key.to_bytes().unwrap();
            let recovered: PubKey = bytes.as_slice().try_into().unwrap();

            assert_eq!(btc_key, recovered);
        }
    }

    #[test]
    fn test_bitcoin_pubkey_to_string_roundtrip() {
        let pk_data = [123u8; PUB_KEY_SIZE];
        let btc_key = PubKey::Secp256k1Bitcoin((
            pk_data,
            bitcoin::Network::Bitcoin,
            bitcoin::AddressType::P2wpkh,
        ));

        let btc_str = btc_key.to_string();
        let recovered = PubKey::from_str(&btc_str).unwrap();

        assert_eq!(btc_key, recovered);
    }

    #[test]
    fn test_bitcoin_pubkey_invalid_length() {
        let bytes = vec![2u8; PUB_KEY_SIZE + 2];
        let result = PubKey::try_from(bytes.as_slice());
        assert!(matches!(result, Err(PubKeyError::InvalidLength)));

        let bytes = vec![2u8; PUB_KEY_SIZE + 1];
        let result = PubKey::try_from(bytes.as_slice());
        assert!(matches!(result, Err(PubKeyError::InvalidLength)));
    }

    #[test]
    fn test_all_pubkey_types_roundtrip() {
        let data = [55u8; PUB_KEY_SIZE];

        let zil = PubKey::Secp256k1Sha256(data);
        let eth = PubKey::Secp256k1Keccak256(data);
        let btc = PubKey::Secp256k1Bitcoin((
            data,
            bitcoin::Network::Bitcoin,
            bitcoin::AddressType::P2wpkh,
        ));
        let sol = PubKey::Ed25519Solana(data);

        for key in [zil, eth, btc, sol] {
            let bytes = key.to_bytes().unwrap();
            let recovered: PubKey = bytes.as_slice().try_into().unwrap();
            assert_eq!(key, recovered);
        }
    }

    #[test]
    fn test_bitcoin_pubkey_as_bytes() {
        let pk_data = [77u8; PUB_KEY_SIZE];
        let btc_key = PubKey::Secp256k1Bitcoin((
            pk_data,
            bitcoin::Network::Bitcoin,
            bitcoin::AddressType::P2wpkh,
        ));

        assert_eq!(btc_key.as_bytes(), &pk_data);
    }
}
