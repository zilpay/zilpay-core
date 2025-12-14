use crate::{
    pubkey::PubKey,
    zil_address::{
        from_zil_base16, from_zil_bech32_address, from_zil_pub_key, to_bech32, to_checksum_address,
    },
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::Digest;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use config::address::{ADDR_LEN, HRP_ZIL};
use errors::address::AddressError;

type Result<T> = std::result::Result<T, AddressError>;

#[derive(Clone, PartialEq, Eq)]
pub enum Address {
    Secp256k1Sha256([u8; ADDR_LEN]),    // ZILLIQA
    Secp256k1Keccak256([u8; ADDR_LEN]), // Ethereum
    Secp256k1Bitcoin([u8; ADDR_LEN]),   // Bitcoin (hash160)
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
            Address::Secp256k1Bitcoin(_) => self.to_btc_bech32().unwrap_or_default(),
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
            PubKey::Secp256k1Sha256(pk) => {
                let addr = from_zil_pub_key(pk)?;

                Ok(Self::Secp256k1Sha256(addr))
            }
            PubKey::Secp256k1Keccak256(pk) => {
                let k256_pubkey = alloy::signers::k256::ecdsa::VerifyingKey::from_sec1_bytes(pk)
                    .map_err(|e| AddressError::InvalidVerifyingKey(e.to_string()))?;
                let addr = alloy::primitives::Address::from_public_key(&k256_pubkey);

                Ok(Self::Secp256k1Keccak256(addr.into()))
            }
            PubKey::Secp256k1Bitcoin(pk) => {
                use crate::btc_addr::public_key_to_bitcoin_address;

                let btc_addr = public_key_to_bitcoin_address(pk, 0x00);
                let hash160: [u8; ADDR_LEN] = btc_addr[1..21]
                    .try_into()
                    .map_err(|_| AddressError::InvalidLength)?;

                Ok(Self::Secp256k1Bitcoin(hash160))
            }
            PubKey::Ed25519Solana(_) => Err(AddressError::NotImpl),
        }
    }

    pub fn prefix_type(&self) -> u8 {
        match self {
            Address::Secp256k1Sha256(_) => 0,
            Address::Secp256k1Keccak256(_) => 1,
            Address::Secp256k1Bitcoin(_) => 2,
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
            Address::Secp256k1Bitcoin(v) => v,
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
            Address::Secp256k1Keccak256(v) => {
                let addr = hex::encode(v);

                Ok(addr)
            }
            Address::Secp256k1Bitcoin(_) => Err(AddressError::InvalidAddressType),
        }
    }

    pub fn get_zil_check_sum_addr(&self) -> Result<String> {
        match self {
            Address::Secp256k1Sha256(v) => {
                let addr = hex::encode(v);

                to_checksum_address(&addr)
            }
            Address::Secp256k1Keccak256(v) => {
                let addr = hex::encode(v);

                to_checksum_address(&addr)
            }
            Address::Secp256k1Bitcoin(_) => Err(AddressError::InvalidAddressType),
        }
    }

    pub fn to_btc_p2pkh(&self) -> Result<String> {
        match self {
            Address::Secp256k1Bitcoin(hash160) => {
                let mut payload = [0u8; 21];
                payload[0] = 0x00;
                payload[1..].copy_from_slice(hash160);

                let checksum = sha2::Sha256::digest(sha2::Sha256::digest(&payload));
                let mut full_payload = [0u8; 25];
                full_payload[..21].copy_from_slice(&payload);
                full_payload[21..].copy_from_slice(&checksum[..4]);

                Ok(bs58::encode(&full_payload).into_string())
            }
            _ => Err(AddressError::InvalidAddressType),
        }
    }

    pub fn to_btc_bech32(&self) -> Result<String> {
        self.to_btc_bech32_with_hrp("bc")
    }

    pub fn to_btc_bech32_testnet(&self) -> Result<String> {
        self.to_btc_bech32_with_hrp("tb")
    }

    fn to_btc_bech32_with_hrp(&self, hrp_str: &str) -> Result<String> {
        use bech32::{segwit, Hrp};

        match self {
            Address::Secp256k1Bitcoin(hash160) => {
                let hrp = Hrp::parse(hrp_str).map_err(|_| AddressError::InvalidHrp)?;
                let addr = segwit::encode(hrp, segwit::VERSION_0, hash160)
                    .map_err(|e| AddressError::Bech32Error(e.to_string()))?;

                Ok(addr)
            }
            _ => Err(AddressError::InvalidAddressType),
        }
    }

    pub fn from_btc_p2pkh(addr: &str) -> Result<Self> {
        let decoded = bs58::decode(addr)
            .into_vec()
            .map_err(|_| AddressError::InvalidBase58)?;

        if decoded.len() != 25 {
            return Err(AddressError::InvalidLength);
        }

        let payload = &decoded[..21];
        let checksum = &decoded[21..];
        let expected_checksum = sha2::Sha256::digest(sha2::Sha256::digest(payload));

        if checksum != &expected_checksum[..4] {
            return Err(AddressError::InvalidChecksum);
        }

        if decoded[0] != 0x00 {
            return Err(AddressError::InvalidVersion);
        }

        let hash160: [u8; ADDR_LEN] = decoded[1..21]
            .try_into()
            .map_err(|_| AddressError::InvalidLength)?;

        Ok(Address::Secp256k1Bitcoin(hash160))
    }

    pub fn from_btc_bech32(addr: &str) -> Result<Self> {
        use bech32::segwit;

        let (hrp, version, program) = segwit::decode(addr)
            .map_err(|e| AddressError::Bech32Error(e.to_string()))?;

        let hrp_str = hrp.as_str();
        if hrp_str != "bc" && hrp_str != "tb" {
            return Err(AddressError::InvalidHrp);
        }

        if version != segwit::VERSION_0 {
            return Err(AddressError::InvalidVersion);
        }

        if program.len() != ADDR_LEN {
            return Err(AddressError::InvalidLength);
        }

        let hash160: [u8; ADDR_LEN] = program
            .try_into()
            .map_err(|_| AddressError::InvalidLength)?;

        Ok(Address::Secp256k1Bitcoin(hash160))
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Secp256k1Sha256(bytes) => {
                write!(f, "{}", to_bech32(HRP_ZIL, bytes).unwrap())
            }
            Self::Secp256k1Keccak256(bytes) => {
                let h = alloy::primitives::Address::from_slice(bytes);
                write!(f, "{}", h.to_checksum(None))
            }
            Self::Secp256k1Bitcoin(_) => {
                write!(f, "{}", self.to_btc_bech32().unwrap_or_default())
            }
        }
    }
}

impl std::fmt::Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Secp256k1Sha256(bytes) => {
                write!(f, "{}", to_bech32(HRP_ZIL, bytes).unwrap())
            }
            Self::Secp256k1Keccak256(bytes) => {
                let h = alloy::primitives::Address::from_slice(bytes);
                write!(f, "{}", h.to_checksum(None))
            }
            Self::Secp256k1Bitcoin(_) => {
                write!(f, "{}", self.to_btc_bech32().unwrap_or_default())
            }
        }
    }
}

impl Hash for Address {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            Address::Secp256k1Sha256(_) => 0u8.hash(state),
            Address::Secp256k1Keccak256(_) => 1u8.hash(state),
            Address::Secp256k1Bitcoin(_) => 2u8.hash(state),
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
            2 => Ok(Address::Secp256k1Bitcoin(bytes)),
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
            2 => Address::Secp256k1Bitcoin(key_data),
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
            2 => Ok(Address::Secp256k1Bitcoin(key_data)),
            _ => Err(AddressError::InvalidKeyType),
        }
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        match self {
            Address::Secp256k1Sha256(data) => data,
            Address::Secp256k1Keccak256(data) => data,
            Address::Secp256k1Bitcoin(data) => data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::key::PUB_KEY_SIZE;

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
        let invalid_type_slice = vec![3u8; ADDR_LEN + 1];
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

    #[test]
    fn test_bitcoin_address_creation() {
        let btc_data = [42u8; ADDR_LEN];
        let btc_addr = Address::Secp256k1Bitcoin(btc_data);

        assert_eq!(btc_addr.as_ref(), &btc_data);
        assert_eq!(btc_addr.prefix_type(), 2);
    }

    #[test]
    fn test_bitcoin_to_bytes() {
        let btc_data = [42u8; ADDR_LEN];
        let btc_addr = Address::Secp256k1Bitcoin(btc_data);
        let btc_bytes = btc_addr.to_bytes();

        assert_eq!(btc_bytes[0], 2);
        assert_eq!(&btc_bytes[1..], &btc_data);
    }

    #[test]
    fn test_bitcoin_from_bytes() {
        let mut btc_bytes = [0u8; ADDR_LEN + 1];
        btc_bytes[0] = 2;
        btc_bytes[1..].fill(42);

        let addr = Address::from(btc_bytes);
        assert!(matches!(addr, Address::Secp256k1Bitcoin(_)));
        assert_eq!(addr.as_ref(), &btc_bytes[1..]);
    }

    #[test]
    fn test_bitcoin_p2pkh_encoding_decoding() {
        let hash160 = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13
        ];
        let btc_addr = Address::Secp256k1Bitcoin(hash160);

        let p2pkh = btc_addr.to_btc_p2pkh().unwrap();
        assert!(p2pkh.starts_with('1'));

        let decoded = Address::from_btc_p2pkh(&p2pkh).unwrap();
        assert_eq!(decoded, btc_addr);
    }

    #[test]
    fn test_bitcoin_from_pubkey() {
        let pk = PubKey::Secp256k1Bitcoin([
            0x03, 0x15, 0x0a, 0x7f, 0x37, 0x06, 0x3b, 0x13,
            0x4c, 0xde, 0x30, 0x07, 0x04, 0x31, 0xa6, 0x91,
            0x48, 0xd6, 0x0b, 0x25, 0x2f, 0x4c, 0x7b, 0x38,
            0xde, 0x33, 0xd8, 0x13, 0xd3, 0x29, 0xa7, 0xb7, 0xda
        ]);

        let addr = Address::from_pubkey(&pk).unwrap();
        assert!(matches!(addr, Address::Secp256k1Bitcoin(_)));
    }

    #[test]
    fn test_bitcoin_address_roundtrip() {
        let original_data = [123u8; ADDR_LEN];
        let addr = Address::Secp256k1Bitcoin(original_data);
        let bytes = addr.to_bytes();
        let roundtrip_addr = Address::from(bytes);

        assert_eq!(addr, roundtrip_addr);
    }

    #[test]
    fn test_bitcoin_p2pkh_valid_address() {
        let valid_btc_addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let result = Address::from_btc_p2pkh(valid_btc_addr);
        assert!(result.is_ok());
    }

    #[test]
    fn test_bitcoin_display() {
        let hash160 = [1u8; ADDR_LEN];
        let btc_addr = Address::Secp256k1Bitcoin(hash160);
        let display_str = btc_addr.to_string();

        assert!(!display_str.is_empty());
    }

    #[test]
    fn test_bitcoin_native_segwit_testnet() {
        let public_key_hex = "028b9b0e596dbefb2055c0bfd7bb34b90d491030df81a2659ca5dbf941647e28ea";
        let expected_segwit_hash = "36d653232e46b66c576c98983172a9531e8278ea";
        let expected_native_address = "tb1qxmt9xgewg6mxc4mvnzvrzu4f2v0gy782fydg0w";

        let pk_bytes = hex::decode(public_key_hex).unwrap();
        let pk_array: [u8; PUB_KEY_SIZE] = pk_bytes.try_into().unwrap();
        let pubkey = PubKey::Secp256k1Bitcoin(pk_array);

        let address = Address::from_pubkey(&pubkey).unwrap();

        let hash160_hex = hex::encode(address.addr_bytes());
        assert_eq!(hash160_hex, expected_segwit_hash);

        let testnet_addr = address.to_btc_bech32_testnet().unwrap();
        assert_eq!(testnet_addr, expected_native_address);
        assert!(testnet_addr.starts_with("tb1q"));
    }

    #[test]
    fn test_bitcoin_native_segwit_mainnet() {
        let hash160 = hex::decode("36d653232e46b66c576c98983172a9531e8278ea").unwrap();
        let hash160_array: [u8; ADDR_LEN] = hash160.try_into().unwrap();
        let address = Address::Secp256k1Bitcoin(hash160_array);

        let mainnet_addr = address.to_btc_bech32().unwrap();
        assert!(mainnet_addr.starts_with("bc1q"));

        let testnet_addr = address.to_btc_bech32_testnet().unwrap();
        assert!(testnet_addr.starts_with("tb1q"));
        assert_eq!(testnet_addr, "tb1qxmt9xgewg6mxc4mvnzvrzu4f2v0gy782fydg0w");
    }

    #[test]
    fn test_bitcoin_bech32_roundtrip_testnet() {
        let original_addr = "tb1qxmt9xgewg6mxc4mvnzvrzu4f2v0gy782fydg0w";
        let decoded = Address::from_btc_bech32(original_addr).unwrap();
        let encoded = decoded.to_btc_bech32_testnet().unwrap();

        assert_eq!(encoded, original_addr);
    }

    #[test]
    fn test_bitcoin_bech32_roundtrip_mainnet() {
        let hash160 = [42u8; ADDR_LEN];
        let address = Address::Secp256k1Bitcoin(hash160);

        let bech32_addr = address.to_btc_bech32().unwrap();
        assert!(bech32_addr.starts_with("bc1"));

        let decoded = Address::from_btc_bech32(&bech32_addr).unwrap();
        assert_eq!(decoded, address);
    }

    #[test]
    fn test_bitcoin_segwit_hash_from_pubkey() {
        let public_key_hex = "028b9b0e596dbefb2055c0bfd7bb34b90d491030df81a2659ca5dbf941647e28ea";
        let expected_hash = "36d653232e46b66c576c98983172a9531e8278ea";

        let pk_bytes = hex::decode(public_key_hex).unwrap();
        let pk_array: [u8; PUB_KEY_SIZE] = pk_bytes.try_into().unwrap();
        let pubkey = PubKey::Secp256k1Bitcoin(pk_array);

        let address = Address::from_pubkey(&pubkey).unwrap();
        let hash_hex = hex::encode(address.addr_bytes());

        assert_eq!(hash_hex, expected_hash);
    }

    #[test]
    fn test_bitcoin_multiple_address_formats() {
        let hash160 = hex::decode("36d653232e46b66c576c98983172a9531e8278ea").unwrap();
        let hash160_array: [u8; ADDR_LEN] = hash160.try_into().unwrap();
        let address = Address::Secp256k1Bitcoin(hash160_array);

        let p2pkh = address.to_btc_p2pkh().unwrap();
        assert!(p2pkh.starts_with('1'));

        let bech32_mainnet = address.to_btc_bech32().unwrap();
        assert!(bech32_mainnet.starts_with("bc1"));

        let bech32_testnet = address.to_btc_bech32_testnet().unwrap();
        assert!(bech32_testnet.starts_with("tb1"));
        assert_eq!(bech32_testnet, "tb1qxmt9xgewg6mxc4mvnzvrzu4f2v0gy782fydg0w");
    }

    #[test]
    fn test_bitcoin_p2wpkh_mainnet_from_python() {
        let public_key_hex = "024447e68ff4efc6dccac32b60c9af9421654763a93d9573d7284567b70f7993ef";
        let expected_segwit_hash = "4d4d385e7877c07ccf49e1cac94322ea182e58e7";
        let expected_native_address = "bc1qf4xnshncwlq8en6fu89vjsezagvzuk88php8q3";

        let pk_bytes = hex::decode(public_key_hex).unwrap();
        let pk_array: [u8; PUB_KEY_SIZE] = pk_bytes.try_into().unwrap();
        let pubkey = PubKey::Secp256k1Bitcoin(pk_array);

        let address = Address::from_pubkey(&pubkey).unwrap();

        let hash160_hex = hex::encode(address.addr_bytes());
        assert_eq!(hash160_hex, expected_segwit_hash);

        let mainnet_addr = address.to_btc_bech32().unwrap();
        assert_eq!(mainnet_addr, expected_native_address);
        assert!(mainnet_addr.starts_with("bc1q"));
    }

    #[test]
    fn test_bitcoin_bech32_roundtrip_python_address() {
        let original_addr = "bc1qf4xnshncwlq8en6fu89vjsezagvzuk88php8q3";
        let decoded = Address::from_btc_bech32(original_addr).unwrap();
        let encoded = decoded.to_btc_bech32().unwrap();

        assert_eq!(encoded, original_addr);

        let expected_hash = hex::decode("4d4d385e7877c07ccf49e1cac94322ea182e58e7").unwrap();
        let expected_hash_array: [u8; ADDR_LEN] = expected_hash.try_into().unwrap();
        assert_eq!(decoded.addr_bytes(), &expected_hash_array);
    }

    #[test]
    fn test_bitcoin_bech32_invalid_hrp() {
        let invalid_addr = "ltc1qxmt9xgewg6mxc4mvnzvrzu4f2v0gy782abc123";
        let result = Address::from_btc_bech32(invalid_addr);

        assert!(result.is_err());
    }
}
