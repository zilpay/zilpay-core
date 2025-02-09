use crate::{
    pubkey::PubKey,
    zil_address::{
        from_zil_base16, from_zil_bech32_address, from_zil_pub_key, to_bech32, to_checksum_address,
    },
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use config::address::{ADDR_LEN, HRP_ZIL};
use errors::address::AddressError;

type Result<T> = std::result::Result<T, AddressError>;

#[derive(Clone, PartialEq, Eq)]
pub enum Address {
    Secp256k1Sha256([u8; ADDR_LEN]),    // ZILLIQA
    Secp256k1Keccak256([u8; ADDR_LEN]), // Ethereum
}

impl Address {
    pub const ZERO: [u8; ADDR_LEN] = [0u8; ADDR_LEN];

    pub fn from_zil_base16(addr: &str) -> Result<Self> {
        let addr = from_zil_base16(addr.trim_start_matches("0x"))
            .ok_or(AddressError::InvalidBase16Address)?;

        Ok(Self::Secp256k1Sha256(addr))
    }

    pub fn auto_format(&self) -> String {
        match self {
            Address::Secp256k1Sha256(_) => self.get_zil_bech32().unwrap_or_default(),
            Address::Secp256k1Keccak256(_) => self.to_eth_checksummed().unwrap_or_default(),
        }
    }

    pub fn from_str_hex(addr: &str) -> Result<Self> {
        if addr.starts_with(HRP_ZIL) {
            return Self::from_zil_bech32(addr);
        }

        if addr.starts_with("0x") {
            return Self::from_eth_address(addr);
        }

        let bytes = hex::decode(addr).map_err(|_| AddressError::InvalidHex)?;
        if bytes.len() != ADDR_LEN {
            return Err(AddressError::InvalidLength);
        }

        let eth_addr = format!("0x{}", addr);
        if let Ok(addr) = Self::from_eth_address(&eth_addr) {
            return Ok(addr);
        }

        let zil_addr = format!("0x{}", addr);
        Self::from_zil_base16(&zil_addr)
    }

    pub fn from_zil_bech32(addr: &str) -> Result<Self> {
        let addr = from_zil_bech32_address(addr)?;
        Ok(Self::Secp256k1Sha256(addr))
    }

    pub fn from_eth_address(addr: &str) -> Result<Self> {
        let addr = alloy::primitives::Address::from_str(addr)
            .map_err(|e| AddressError::InvalidETHAddress(e.to_string()))?;
        let bytes: [u8; ADDR_LEN] = addr
            .as_slice()
            .try_into()
            .map_err(|_| AddressError::InvalidETHAddress(addr.to_string()))?;

        Ok(Self::Secp256k1Keccak256(bytes))
    }

    pub fn to_alloy_addr(&self) -> alloy::primitives::Address {
        alloy::primitives::Address::from_slice(self.as_ref())
    }

    pub fn to_eth_checksummed(&self) -> Result<String> {
        let addr = alloy::primitives::Address::from_slice(self.as_ref());

        // TODO: check chain id;
        Ok(addr.to_checksum(None))
    }

    pub fn from_pubkey(pk: &PubKey) -> Result<Self> {
        match pk {
            PubKey::Secp256k1Sha256Zilliqa(pk) => {
                let addr = from_zil_pub_key(pk)?;

                Ok(Self::Secp256k1Sha256(addr))
            }
            PubKey::Secp256k1Keccak256Ethereum(pk) => {
                let k256_pubkey = alloy::signers::k256::ecdsa::VerifyingKey::from_sec1_bytes(pk)
                    .map_err(|e| AddressError::InvalidVerifyingKey(e.to_string()))?;
                let addr = alloy::primitives::Address::from_public_key(&k256_pubkey);

                Ok(Self::Secp256k1Keccak256(addr.into()))
            }
            PubKey::Secp256k1Bitcoin(_) => Err(AddressError::NotImpl),
            PubKey::Ed25519Solana(_) => Err(AddressError::NotImpl),
        }
    }

    pub fn prefix_type(&self) -> u8 {
        match self {
            Address::Secp256k1Sha256(_) => 0,
            Address::Secp256k1Keccak256(_) => 1,
        }
    }

    pub fn to_bytes(&self) -> [u8; ADDR_LEN + 1] {
        let mut result = [0u8; ADDR_LEN + 1];
        result[0] = self.prefix_type();
        result[1..].copy_from_slice(self.as_ref());
        result
    }

    pub fn addr_bytes(&self) -> &[u8; ADDR_LEN] {
        match self {
            Address::Secp256k1Sha256(v) => v,
            Address::Secp256k1Keccak256(v) => v,
        }
    }

    pub fn get_zil_bech32(&self) -> Result<String> {
        let value = self.addr_bytes();

        to_bech32(HRP_ZIL, value)
    }

    pub fn get_zil_base16(&self) -> Result<String> {
        match self {
            Address::Secp256k1Sha256(v) => {
                let addr = hex::encode(v);

                Ok(addr)
            }
            _ => Err(AddressError::InvalidSecp256k1Sha256Type),
        }
    }

    pub fn get_zil_check_sum_addr(&self) -> Result<String> {
        match self {
            Address::Secp256k1Sha256(v) => {
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
            Self::Secp256k1Sha256(bytes) => {
                // unwrap shouldn't execpt
                write!(f, "{}", to_bech32(HRP_ZIL, bytes).unwrap())
            }
            Self::Secp256k1Keccak256(bytes) => {
                let h = alloy::primitives::Address::from_slice(bytes);
                // TODO: chain id.
                write!(f, "{}", h.to_checksum(None))
            }
        }
    }
}

impl std::fmt::Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Secp256k1Sha256(bytes) => {
                // unwrap shouldn't execpt
                write!(f, "{}", to_bech32(HRP_ZIL, bytes).unwrap())
            }
            Self::Secp256k1Keccak256(bytes) => {
                let h = alloy::primitives::Address::from_slice(bytes);
                // TODO: chain id.
                write!(f, "{}", h.to_checksum(None))
            }
        }
    }
}

impl Hash for Address {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            Address::Secp256k1Sha256(_) => 0u8.hash(state),
            Address::Secp256k1Keccak256(_) => 1u8.hash(state),
        }

        self.as_ref().hash(state);
    }
}

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.to_bytes();
        serializer.serialize_str(&hex::encode(bytes))
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Address::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl FromStr for Address {
    type Err = AddressError;

    fn from_str(s: &str) -> Result<Self> {
        let data = hex::decode(s).map_err(|_| AddressError::InvalidHex)?;
        let bytes: [u8; ADDR_LEN] = data[1..]
            .try_into()
            .map_err(|_| AddressError::InvalidLength)?;
        let prefix = data[0];

        match prefix {
            0 => Ok(Address::Secp256k1Sha256(bytes)),
            1 => Ok(Address::Secp256k1Keccak256(bytes)),
            _ => Err(AddressError::InvalidKeyType),
        }
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

    fn try_from(slice: &[u8]) -> Result<Self> {
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

        let expected = to_bech32(HRP_ZIL, &zil_data).unwrap();
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

    #[test]
    fn test_from_eth_address() {
        let hex_eth_adr = "0xf06686B5Eb5cAe38c09f12412B729045647E74e3";
        let addr = Address::from_eth_address(hex_eth_adr).unwrap();

        assert!(matches!(addr, Address::Secp256k1Keccak256(_)));
        assert_eq!(addr.to_eth_checksummed().unwrap(), hex_eth_adr);
        assert!(Address::from_eth_address("0x1234").is_err());

        let hex_sha256_type = "0x7aa13D6AE95fb8E843d3bCC2eea365F71c3bACbe";
        let addr = Address::from_eth_address(hex_sha256_type).unwrap();

        assert!(matches!(addr, Address::Secp256k1Keccak256(_)));
        assert_eq!(addr.to_eth_checksummed().unwrap(), hex_sha256_type);
    }

    #[test]
    fn test_alloy_addr() {
        let hex_eth_adr = "0xf06686B5Eb5cAe38c09f12412B729045647E74e3";
        let addr = Address::from_eth_address(hex_eth_adr).unwrap();
        let alloy_addr = addr.to_alloy_addr();

        assert_eq!(alloy_addr.to_checksum(None), hex_eth_adr);
    }
}
