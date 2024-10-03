use crate::{
    pubkey::PubKey,
    zil_address::{
        from_zil_base16, from_zil_bech32_address, from_zil_pub_key, to_checksum_address,
        to_zil_bech32,
    },
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::str::FromStr;

use config::address::ADDR_LEN;
use zil_errors::address::AddressError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    Secp256k1Sha256Zilliqa([u8; ADDR_LEN]),     // ZILLIQA
    Secp256k1Keccak256Ethereum([u8; ADDR_LEN]), // Ethereum
}

impl Address {
    pub fn from_zil_base16(addr: &str) -> Result<Self, AddressError> {
        let addr = from_zil_base16(addr).ok_or(AddressError::InvalidBase16Address)?;

        Ok(Self::Secp256k1Sha256Zilliqa(addr))
    }

    pub fn from_zil_bech32(addr: &str) -> Result<Self, AddressError> {
        let addr = from_zil_bech32_address(addr)?;
        Ok(Self::Secp256k1Sha256Zilliqa(addr))
    }

    pub fn to_eth_checksummed(&self) -> Result<String, AddressError> {
        let addr = alloy::primitives::Address::from_slice(self.as_ref());

        // TODO: check chain id;
        Ok(addr.to_checksum(None))
    }

    pub fn from_pubkey(pk: &PubKey) -> Result<Self, AddressError> {
        match pk {
            PubKey::Secp256k1Sha256Zilliqa(pk) => {
                let addr = from_zil_pub_key(pk)?;

                Ok(Self::Secp256k1Sha256Zilliqa(addr))
            }
            PubKey::Secp256k1Keccak256Ethereum(pk) => {
                let addr = alloy::primitives::Address::from_raw_public_key(pk);

                Ok(Self::Secp256k1Keccak256Ethereum(addr.into()))
            }
            PubKey::Secp256k1Bitcoin(_) => Err(AddressError::NotImpl),
            PubKey::Ed25519Solana(_) => Err(AddressError::NotImpl),
        }
    }

    pub fn to_bytes(&self) -> [u8; ADDR_LEN + 1] {
        let mut result = [0u8; ADDR_LEN + 1];
        result[0] = match self {
            Address::Secp256k1Sha256Zilliqa(_) => 0,
            Address::Secp256k1Keccak256Ethereum(_) => 1,
        };
        result[1..].copy_from_slice(self.as_ref());
        result
    }

    pub fn addr_bytes(&self) -> &[u8; ADDR_LEN] {
        match self {
            Address::Secp256k1Sha256Zilliqa(v) => v,
            Address::Secp256k1Keccak256Ethereum(v) => v,
        }
    }

    pub fn get_bech32(&self) -> Result<String, AddressError> {
        match self {
            Address::Secp256k1Sha256Zilliqa(v) => to_zil_bech32(v),
            _ => Err(AddressError::InvalidSecp256k1Sha256Type),
        }
    }

    pub fn get_zil_check_sum_addr(&self) -> Result<String, AddressError> {
        match self {
            Address::Secp256k1Sha256Zilliqa(v) => {
                let addr = hex::encode(v);

                to_checksum_address(&addr)
            }
            _ => Err(AddressError::InvalidSecp256k1Sha256Type),
        }
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Secp256k1Sha256Zilliqa(bytes) => {
                // unwrap shouldn't execpt
                write!(f, "{}", to_zil_bech32(bytes).unwrap())
            }
            Self::Secp256k1Keccak256Ethereum(bytes) => {
                let h = alloy::primitives::Address::from_slice(bytes);
                // TODO: chain id.
                write!(f, "{}", h.to_checksum(None))
            }
        }
    }
}

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.to_bytes();
        serializer.serialize_str(&hex::encode(bytes))
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Address::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl FromStr for Address {
    type Err = AddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = hex::decode(s).map_err(|_| AddressError::InvalidHex)?;
        let bytes: [u8; ADDR_LEN] = data[1..]
            .try_into()
            .map_err(|_| AddressError::InvalidLength)?;
        let prefix = data[0];

        match prefix {
            0 => Ok(Address::Secp256k1Sha256Zilliqa(bytes)),
            1 => Ok(Address::Secp256k1Keccak256Ethereum(bytes)),
            _ => Err(AddressError::InvalidKeyType),
        }
    }
}

impl From<[u8; ADDR_LEN + 1]> for Address {
    fn from(bytes: [u8; ADDR_LEN + 1]) -> Self {
        let key_type = bytes[0];
        let key_data: [u8; ADDR_LEN] = bytes[1..].try_into().unwrap();

        match key_type {
            0 => Address::Secp256k1Sha256Zilliqa(key_data),
            1 => Address::Secp256k1Keccak256Ethereum(key_data),
            _ => panic!("Invalid key type"),
        }
    }
}

impl TryFrom<&[u8]> for Address {
    type Error = AddressError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        if slice.len() != ADDR_LEN + 1 {
            return Err(AddressError::InvalidLength);
        }

        let key_type = slice[0];
        let key_data: [u8; ADDR_LEN] = slice[1..]
            .try_into()
            .map_err(|_| AddressError::InvalidLength)?;

        match key_type {
            0 => Ok(Address::Secp256k1Sha256Zilliqa(key_data)),
            1 => Ok(Address::Secp256k1Keccak256Ethereum(key_data)),
            _ => Err(AddressError::InvalidKeyType),
        }
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        match self {
            Address::Secp256k1Sha256Zilliqa(data) => data,
            Address::Secp256k1Keccak256Ethereum(data) => data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_creation() {
        let zil_data = [1u8; ADDR_LEN];
        let eth_data = [2u8; ADDR_LEN];

        let zil_addr = Address::Secp256k1Sha256Zilliqa(zil_data);
        let eth_addr = Address::Secp256k1Keccak256Ethereum(eth_data);

        assert_eq!(zil_addr.as_ref(), &zil_data);
        assert_eq!(eth_addr.as_ref(), &eth_data);
    }

    #[test]
    fn test_to_bytes() {
        let zil_data = [1u8; ADDR_LEN];
        let eth_data = [2u8; ADDR_LEN];

        let zil_addr = Address::Secp256k1Sha256Zilliqa(zil_data);
        let eth_addr = Address::Secp256k1Keccak256Ethereum(eth_data);

        let zil_bytes = zil_addr.to_bytes();
        let eth_bytes = eth_addr.to_bytes();

        assert_eq!(zil_bytes[0], 0);
        assert_eq!(eth_bytes[0], 1);
        assert_eq!(&zil_bytes[1..], &zil_data);
        assert_eq!(&eth_bytes[1..], &eth_data);
    }

    #[test]
    fn test_display() {
        let zil_data = [1u8; ADDR_LEN];
        let zil_addr = Address::Secp256k1Sha256Zilliqa(zil_data);

        let expected = to_zil_bech32(&zil_data).unwrap();
        assert_eq!(zil_addr.to_string(), expected);
    }

    #[test]
    fn test_from_bytes() {
        let mut zil_bytes = [0u8; ADDR_LEN + 1];
        zil_bytes[0] = 0;
        zil_bytes[1..].fill(1);

        let addr = Address::from(zil_bytes);
        assert!(matches!(addr, Address::Secp256k1Sha256Zilliqa(_)));
        assert_eq!(addr.as_ref(), &zil_bytes[1..]);
    }

    #[test]
    fn test_try_from_slice() {
        let mut zil_slice = vec![0u8; ADDR_LEN + 1];
        zil_slice[1..].fill(1);

        let addr = Address::try_from(zil_slice.as_slice()).unwrap();
        assert!(matches!(addr, Address::Secp256k1Sha256Zilliqa(_)));

        // Test invalid length
        let invalid_slice = vec![0u8; ADDR_LEN];
        assert!(matches!(
            Address::try_from(invalid_slice.as_slice()),
            Err(AddressError::InvalidLength)
        ));

        // Test invalid key type
        let invalid_type_slice = vec![2u8; ADDR_LEN + 1];
        assert!(matches!(
            Address::try_from(invalid_type_slice.as_slice()),
            Err(AddressError::InvalidKeyType)
        ));
    }

    #[test]
    fn test_as_ref() {
        let data = [1u8; ADDR_LEN];
        let addr = Address::Secp256k1Sha256Zilliqa(data);
        assert_eq!(addr.as_ref(), &data);
    }

    #[test]
    fn test_roundtrip() {
        let original_data = [1u8; ADDR_LEN];
        let addr = Address::Secp256k1Sha256Zilliqa(original_data);
        let bytes = addr.to_bytes();
        let roundtrip_addr = Address::from(bytes);
        assert_eq!(addr, roundtrip_addr);
    }

    #[test]
    fn test_addr() {
        let pubkey_eth: PubKey =
            "0103150a7f37063b134cde30070431a69148d60b252f4c7b38de33d813d329a7b7da"
                .parse()
                .unwrap();
        let pubkey_zil: PubKey =
            "0003150a7f37063b134cde30070431a69148d60b252f4c7b38de33d813d329a7b7da"
                .parse()
                .unwrap();
        let addr_eth = Address::from_pubkey(&pubkey_eth).unwrap();
        let addr_zil = Address::from_pubkey(&pubkey_zil).unwrap();

        assert_eq!(
            addr_eth.to_string(),
            "0xC315295101461753b838E0BE8688E744cf52Dd6b"
        );
        assert_eq!(
            addr_zil.to_string(),
            "zil1a0vtxuxamd3kltmyzpqdyxqu25vsss8mp58jtu"
        );
    }
}
