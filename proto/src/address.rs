use crate::zil_address::{from_zil_base16, from_zil_pub_key, to_zil_bech32};

use config::address::ADDR_LEN;
use serde::{Deserialize, Serialize};
use zil_errors::AddressError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Address {
    Secp256k1Sha256([u8; ADDR_LEN]),    // ZILLIQA
    Secp256k1Keccak256([u8; ADDR_LEN]), // Ethereum
}

impl Address {
    pub fn from_zil_base16(addr: &str) -> Result<Self, AddressError> {
        let addr = from_zil_base16(addr).ok_or(AddressError::InvalidBase16Address)?;

        Ok(Self::Secp256k1Sha256(addr))
    }

    pub fn from_zil_pub_key(pk: &[u8]) -> Result<Self, AddressError> {
        let addr = from_zil_pub_key(pk)?;

        Ok(Self::Secp256k1Sha256(addr))
    }

    pub fn to_bytes(&self) -> [u8; ADDR_LEN + 1] {
        let mut result = [0u8; ADDR_LEN + 1];
        result[0] = match self {
            Address::Secp256k1Sha256(_) => 0,
            Address::Secp256k1Keccak256(_) => 1,
        };
        result[1..].copy_from_slice(self.as_ref());
        result
    }

    pub fn addr_bytes(&self) -> &[u8; ADDR_LEN] {
        match self {
            Address::Secp256k1Sha256(v) => v,
            Address::Secp256k1Keccak256(v) => v,
        }
    }

    pub fn get_bech32(&self) -> Result<String, AddressError> {
        match self {
            Address::Secp256k1Sha256(v) => {
                to_zil_bech32(v).ok_or(AddressError::InvalidAddressBytesForBech32)
            }
            _ => Err(AddressError::InvalidSecp256k1Sha256Type),
        }
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.to_bytes()))
    }
}

impl From<[u8; ADDR_LEN + 1]> for Address {
    fn from(bytes: [u8; ADDR_LEN + 1]) -> Self {
        let key_type = bytes[0];
        let key_data: [u8; ADDR_LEN] = bytes[1..].try_into().unwrap();

        match key_type {
            0 => Address::Secp256k1Sha256(key_data),
            1 => Address::Secp256k1Keccak256(key_data),
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
            0 => Ok(Address::Secp256k1Sha256(key_data)),
            1 => Ok(Address::Secp256k1Keccak256(key_data)),
            _ => Err(AddressError::InvalidKeyType),
        }
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        match self {
            Address::Secp256k1Sha256(data) => data,
            Address::Secp256k1Keccak256(data) => data,
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

        let zil_addr = Address::Secp256k1Sha256(zil_data);
        let eth_addr = Address::Secp256k1Keccak256(eth_data);

        assert_eq!(zil_addr.as_ref(), &zil_data);
        assert_eq!(eth_addr.as_ref(), &eth_data);
    }

    #[test]
    fn test_to_bytes() {
        let zil_data = [1u8; ADDR_LEN];
        let eth_data = [2u8; ADDR_LEN];

        let zil_addr = Address::Secp256k1Sha256(zil_data);
        let eth_addr = Address::Secp256k1Keccak256(eth_data);

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
        let zil_addr = Address::Secp256k1Sha256(zil_data);

        let expected = format!("00{}", hex::encode(zil_data));
        assert_eq!(zil_addr.to_string(), expected);
    }

    #[test]
    fn test_from_bytes() {
        let mut zil_bytes = [0u8; ADDR_LEN + 1];
        zil_bytes[0] = 0;
        zil_bytes[1..].fill(1);

        let addr = Address::from(zil_bytes);
        assert!(matches!(addr, Address::Secp256k1Sha256(_)));
        assert_eq!(addr.as_ref(), &zil_bytes[1..]);
    }

    #[test]
    fn test_try_from_slice() {
        let mut zil_slice = vec![0u8; ADDR_LEN + 1];
        zil_slice[1..].fill(1);

        let addr = Address::try_from(zil_slice.as_slice()).unwrap();
        assert!(matches!(addr, Address::Secp256k1Sha256(_)));

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
        let addr = Address::Secp256k1Sha256(data);
        assert_eq!(addr.as_ref(), &data);
    }

    #[test]
    fn test_roundtrip() {
        let original_data = [1u8; ADDR_LEN];
        let addr = Address::Secp256k1Sha256(original_data);
        let bytes = addr.to_bytes();
        let roundtrip_addr = Address::from(bytes);
        assert_eq!(addr, roundtrip_addr);
    }
}
