use config::key::SECRET_KEY_SIZE;
use errors::keypair::SecretKeyError;
use std::str::FromStr;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::btc_utils::ByteCodec;

type Result<T> = std::result::Result<T, SecretKeyError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretKey {
    Secp256k1Sha256Zilliqa([u8; SECRET_KEY_SIZE]),
    Secp256k1Keccak256Ethereum([u8; SECRET_KEY_SIZE]),
    Secp256k1Bitcoin(
        (
            [u8; SECRET_KEY_SIZE],
            bitcoin::Network,
            bitcoin::AddressType,
        ),
    ),
    Secp256k1Tron([u8; SECRET_KEY_SIZE]),
}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        match self {
            SecretKey::Secp256k1Sha256Zilliqa(key) => key.zeroize(),
            SecretKey::Secp256k1Keccak256Ethereum(key) => key.zeroize(),
            SecretKey::Secp256k1Bitcoin((key, _, _)) => key.zeroize(),
            SecretKey::Secp256k1Tron(key) => key.zeroize(),
        }
    }
}

impl ZeroizeOnDrop for SecretKey {}

impl SecretKey {
    pub fn from_wif(wif: &str, addr_type: bitcoin::AddressType) -> Result<Self> {
        use bitcoin::NetworkKind;

        let private_key = bitcoin::PrivateKey::from_wif(wif)
            .map_err(|e| SecretKeyError::InvalidWif(e.to_string()))?;

        let secret_bytes: [u8; SECRET_KEY_SIZE] = private_key
            .inner
            .secret_bytes()
            .try_into()
            .map_err(|_| SecretKeyError::InvalidLength)?;

        let network = match private_key.network {
            NetworkKind::Main => bitcoin::Network::Bitcoin,
            NetworkKind::Test => bitcoin::Network::Testnet,
        };

        Ok(Self::Secp256k1Bitcoin((secret_bytes, network, addr_type)))
    }

    pub fn to_wif(&self, compressed: bool) -> Result<String> {
        match self {
            Self::Secp256k1Bitcoin((sk, network, _)) => {
                let secret_key = bitcoin::secp256k1::SecretKey::from_slice(sk)
                    .map_err(|e| SecretKeyError::InvalidWif(e.to_string()))?;

                let private_key = if compressed {
                    bitcoin::PrivateKey::new(secret_key, *network)
                } else {
                    bitcoin::PrivateKey::new_uncompressed(secret_key, *network)
                };

                Ok(private_key.to_wif())
            }
            _ => Err(SecretKeyError::InvalidWif(
                "WIF format only supported for Bitcoin keys".to_string(),
            )),
        }
    }

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
            SecretKey::Secp256k1Tron(sk) => {
                let mut result = vec![3u8];
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
            0 | 1 | 3 => {
                if bytes.len() != SECRET_KEY_SIZE + 1 {
                    return Err(SecretKeyError::InvalidLength);
                }
                let key_data: [u8; SECRET_KEY_SIZE] = bytes[1..]
                    .try_into()
                    .or(Err(SecretKeyError::SecretKeySliceError))?;

                match key_type {
                    0 => Ok(SecretKey::Secp256k1Sha256Zilliqa(key_data)),
                    1 => Ok(SecretKey::Secp256k1Keccak256Ethereum(key_data)),
                    3 => Ok(SecretKey::Secp256k1Tron(key_data)),
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
            SecretKey::Secp256k1Tron(data) => data,
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

#[cfg(test)]
mod tests {
    use super::*;
    use config::key::SECRET_KEY_SIZE;

    #[test]
    fn test_secret_key_to_bytes_zilliqa() {
        let sk_data = [42u8; SECRET_KEY_SIZE];
        let sk = SecretKey::Secp256k1Sha256Zilliqa(sk_data);

        let bytes = sk.to_bytes().unwrap();

        assert_eq!(bytes[0], 0);
        assert_eq!(&bytes[1..], &sk_data);
        assert_eq!(bytes.len(), SECRET_KEY_SIZE + 1);
    }

    #[test]
    fn test_secret_key_to_bytes_ethereum() {
        let sk_data = [69u8; SECRET_KEY_SIZE];
        let sk = SecretKey::Secp256k1Keccak256Ethereum(sk_data);

        let bytes = sk.to_bytes().unwrap();

        assert_eq!(bytes[0], 1);
        assert_eq!(&bytes[1..], &sk_data);
        assert_eq!(bytes.len(), SECRET_KEY_SIZE + 1);
    }

    #[test]
    fn test_secret_key_to_bytes_bitcoin() {
        let sk_data = [123u8; SECRET_KEY_SIZE];
        let network = bitcoin::Network::Bitcoin;
        let addr_type = bitcoin::AddressType::P2wpkh;
        let sk = SecretKey::Secp256k1Bitcoin((sk_data, network, addr_type));

        let bytes = sk.to_bytes().unwrap();

        assert_eq!(bytes[0], 2);
        assert_eq!(bytes[1], network.to_byte());
        assert_eq!(bytes[2], addr_type.to_byte());
        assert_eq!(&bytes[3..], &sk_data);
        assert_eq!(bytes.len(), SECRET_KEY_SIZE + 3);
    }

    #[test]
    fn test_secret_key_from_bytes_zilliqa() {
        let sk_data = [42u8; SECRET_KEY_SIZE];
        let sk = SecretKey::Secp256k1Sha256Zilliqa(sk_data);
        let bytes = sk.to_bytes().unwrap();

        let recovered = SecretKey::from_bytes(std::borrow::Cow::Borrowed(&bytes)).unwrap();

        assert_eq!(sk, recovered);
    }

    #[test]
    fn test_secret_key_from_bytes_ethereum() {
        let sk_data = [69u8; SECRET_KEY_SIZE];
        let sk = SecretKey::Secp256k1Keccak256Ethereum(sk_data);
        let bytes = sk.to_bytes().unwrap();

        let recovered = SecretKey::from_bytes(std::borrow::Cow::Borrowed(&bytes)).unwrap();

        assert_eq!(sk, recovered);
    }

    #[test]
    fn test_secret_key_from_bytes_bitcoin() {
        let sk_data = [123u8; SECRET_KEY_SIZE];
        let network = bitcoin::Network::Bitcoin;
        let addr_type = bitcoin::AddressType::P2wpkh;
        let sk = SecretKey::Secp256k1Bitcoin((sk_data, network, addr_type));
        let bytes = sk.to_bytes().unwrap();

        let recovered = SecretKey::from_bytes(std::borrow::Cow::Borrowed(&bytes)).unwrap();

        assert_eq!(sk, recovered);
    }

    #[test]
    fn test_bitcoin_roundtrip_all_networks() {
        let sk_data = [111u8; SECRET_KEY_SIZE];
        let networks = vec![
            bitcoin::Network::Bitcoin,
            bitcoin::Network::Testnet,
            bitcoin::Network::Testnet4,
            bitcoin::Network::Signet,
            bitcoin::Network::Regtest,
        ];

        for network in networks {
            let sk = SecretKey::Secp256k1Bitcoin((sk_data, network, bitcoin::AddressType::P2wpkh));
            let bytes = sk.to_bytes().unwrap();
            let recovered = SecretKey::from_bytes(std::borrow::Cow::Borrowed(&bytes)).unwrap();

            assert_eq!(sk, recovered);
        }
    }

    #[test]
    fn test_bitcoin_roundtrip_all_address_types() {
        let sk_data = [222u8; SECRET_KEY_SIZE];
        let addr_types = vec![
            bitcoin::AddressType::P2pkh,
            bitcoin::AddressType::P2sh,
            bitcoin::AddressType::P2wpkh,
            bitcoin::AddressType::P2wsh,
            bitcoin::AddressType::P2tr,
            bitcoin::AddressType::P2a,
        ];

        for addr_type in addr_types {
            let sk = SecretKey::Secp256k1Bitcoin((sk_data, bitcoin::Network::Bitcoin, addr_type));
            let bytes = sk.to_bytes().unwrap();
            let recovered = SecretKey::from_bytes(std::borrow::Cow::Borrowed(&bytes)).unwrap();

            assert_eq!(sk, recovered);
        }
    }

    #[test]
    fn test_bitcoin_roundtrip_combinations() {
        let sk_data = [99u8; SECRET_KEY_SIZE];
        let test_cases = vec![
            (bitcoin::Network::Bitcoin, bitcoin::AddressType::P2pkh),
            (bitcoin::Network::Bitcoin, bitcoin::AddressType::P2wpkh),
            (bitcoin::Network::Bitcoin, bitcoin::AddressType::P2tr),
            (bitcoin::Network::Testnet, bitcoin::AddressType::P2pkh),
            (bitcoin::Network::Testnet, bitcoin::AddressType::P2wpkh),
            (bitcoin::Network::Signet, bitcoin::AddressType::P2wpkh),
        ];

        for (network, addr_type) in test_cases {
            let sk = SecretKey::Secp256k1Bitcoin((sk_data, network, addr_type));
            let bytes = sk.to_bytes().unwrap();
            let recovered = SecretKey::from_bytes(std::borrow::Cow::Borrowed(&bytes)).unwrap();

            assert_eq!(sk, recovered);
        }
    }

    #[test]
    fn test_from_bytes_invalid_length() {
        let bytes = vec![0u8; SECRET_KEY_SIZE];
        let result = SecretKey::from_bytes(std::borrow::Cow::Borrowed(&bytes));
        assert!(matches!(result, Err(SecretKeyError::InvalidLength)));

        let bytes = vec![2u8; SECRET_KEY_SIZE + 2];
        let result = SecretKey::from_bytes(std::borrow::Cow::Borrowed(&bytes));
        assert!(matches!(result, Err(SecretKeyError::InvalidLength)));
    }

    #[test]
    fn test_from_bytes_invalid_key_type() {
        let mut bytes = vec![0u8; SECRET_KEY_SIZE + 1];
        bytes[0] = 99;
        let result = SecretKey::from_bytes(std::borrow::Cow::Borrowed(&bytes));
        assert!(matches!(result, Err(SecretKeyError::InvalidKeyType)));
    }

    #[test]
    fn test_secret_key_display() {
        let sk_data = [42u8; SECRET_KEY_SIZE];
        let sk_zil = SecretKey::Secp256k1Sha256Zilliqa(sk_data);
        let sk_eth = SecretKey::Secp256k1Keccak256Ethereum(sk_data);
        let sk_btc = SecretKey::Secp256k1Bitcoin((
            sk_data,
            bitcoin::Network::Bitcoin,
            bitcoin::AddressType::P2wpkh,
        ));

        let zil_str = sk_zil.to_string();
        let eth_str = sk_eth.to_string();
        let btc_str = sk_btc.to_string();

        assert_eq!(SecretKey::from_str(&zil_str).unwrap(), sk_zil);
        assert_eq!(SecretKey::from_str(&eth_str).unwrap(), sk_eth);
        assert_eq!(SecretKey::from_str(&btc_str).unwrap(), sk_btc);
    }

    #[test]
    fn test_wif_mainnet_compressed() {
        let wif = "L5oLkpV3aqBJ4BgssVAsax1iRa77G5CVYnv9adQ6Z87te7TyUdSC";
        let sk = SecretKey::from_wif(wif, bitcoin::AddressType::P2wpkh).unwrap();

        match sk {
            SecretKey::Secp256k1Bitcoin((_, network, _)) => {
                assert_eq!(network, bitcoin::Network::Bitcoin);
            }
            _ => panic!("Expected Bitcoin key"),
        }

        let wif_output = sk.to_wif(true).unwrap();
        assert_eq!(wif, wif_output);
    }

    #[test]
    fn test_wif_mainnet_uncompressed() {
        let wif = "5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss";
        let sk = SecretKey::from_wif(wif, bitcoin::AddressType::P2pkh).unwrap();

        match sk {
            SecretKey::Secp256k1Bitcoin((_, network, _)) => {
                assert_eq!(network, bitcoin::Network::Bitcoin);
            }
            _ => panic!("Expected Bitcoin key"),
        }

        let wif_output = sk.to_wif(false).unwrap();
        assert_eq!(wif, wif_output);
    }

    #[test]
    fn test_wif_testnet_compressed() {
        let wif = "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy";
        let sk = SecretKey::from_wif(wif, bitcoin::AddressType::P2wpkh).unwrap();

        match sk {
            SecretKey::Secp256k1Bitcoin((_, network, _)) => {
                assert_eq!(network, bitcoin::Network::Testnet);
            }
            _ => panic!("Expected Bitcoin key"),
        }

        let wif_output = sk.to_wif(true).unwrap();
        assert_eq!(wif, wif_output);
    }

    #[test]
    fn test_wif_roundtrip() {
        let sk_data = [123u8; SECRET_KEY_SIZE];
        let sk = SecretKey::Secp256k1Bitcoin((
            sk_data,
            bitcoin::Network::Bitcoin,
            bitcoin::AddressType::P2wpkh,
        ));

        let wif = sk.to_wif(true).unwrap();
        let recovered = SecretKey::from_wif(&wif, bitcoin::AddressType::P2wpkh).unwrap();

        assert_eq!(sk, recovered);
    }

    #[test]
    fn test_wif_invalid_format() {
        let invalid_wif = "invalid_wif_string";
        let result = SecretKey::from_wif(invalid_wif, bitcoin::AddressType::P2wpkh);
        assert!(matches!(result, Err(SecretKeyError::InvalidWif(_))));
    }

    #[test]
    fn test_wif_non_bitcoin_key() {
        let sk_data = [42u8; SECRET_KEY_SIZE];
        let sk_eth = SecretKey::Secp256k1Keccak256Ethereum(sk_data);
        let result = sk_eth.to_wif(true);
        assert!(matches!(result, Err(SecretKeyError::InvalidWif(_))));

        let sk_zil = SecretKey::Secp256k1Sha256Zilliqa(sk_data);
        let result = sk_zil.to_wif(true);
        assert!(matches!(result, Err(SecretKeyError::InvalidWif(_))));
    }

    #[test]
    fn test_tron_private_keys_from_csv() {
        use crate::keypair::KeyPair;

        let test_cases = vec![
            (
                "15f0bbb1774be40b7a8d7965d637f324bda2f711fc5726a3dcc19585c6950954",
                "TWer2Ygk5TEheHp3TPuYeqxmB6SsGZmaL6",
            ),
            (
                "9b6ac6a6faf1dc64240f654475a7e668141e4205262367feb7269ef332113929",
                "TPjjvMwjPoDC32V2dGDYTkLH4E5LAtBZ6C",
            ),
            (
                "0c88a7fee5bfbe5a354c225bfa8a9d09557466cdf56f887cc2d000e7354f9453",
                "TB7mhtkvfhsRBRhe5FuRa4tFXSEyGDe4eA",
            ),
            (
                "68c9a7dcaa4677fdeba9f72c8a1d86d0adf34932cdbdb52d90a2d01504d9d4be",
                "TEb822rMZ5QkYReuqdqK61zkheaan97PZZ",
            ),
            (
                "a01527c0c2d83e71c8827f2f0ee5c1a6f715a0c9bace1c3da50c6690a4e69fe7",
                "TYc2iBENTQ7kwx5jbjW3JDqugR7kogQZn3",
            ),
            (
                "679733f6af4143c82ea340e70029e86fda0fc0232a434172b7f233d96f6ff70f",
                "TNWtoufpsNepTJdNzbcimHrPEUSHLDCJE1",
            ),
            (
                "c41ac8920442be2469a0d6f04c9959e7e9faa3c6be4c3723224a2e06f4fd3aec",
                "TYMprjNZ1Lhc2zAsmRbGuBzY6iQ4FB4amn",
            ),
            (
                "ff46c996d2494137bff12940698eae445b696e6da4769933687d607a8fa06dc3",
                "TDmEWPYotmrXW4X49WMJTMostcezCiksPw",
            ),
            (
                "47e922c77f526dea6dcd1bb5d9af55239815fd982799745abe1f646f04ffe776",
                "TPoh8thAmjTXgxPwtFT9oYVyJXPVqLJHhh",
            ),
            (
                "529ca9c20dd90893928ef9ce2bdfcecbc191ffc5ee93a0171427d9a28ea77718",
                "TJtuRzHcZ12gHZA8gKjqq589S7h4fYW8N1",
            ),
        ];

        for (private_key_hex, expected_address) in test_cases {
            let sk_bytes = hex::decode(private_key_hex).unwrap();
            let sk_array: [u8; SECRET_KEY_SIZE] = sk_bytes.try_into().unwrap();
            let sk = SecretKey::Secp256k1Tron(sk_array);

            let keypair = KeyPair::from_secret_key(sk).unwrap();
            let addr = keypair.get_addr().unwrap();
            let addr_str = addr.auto_format();

            assert_eq!(
                addr_str, expected_address,
                "Address mismatch for private key: {}",
                private_key_hex
            );
        }
    }

    #[test]
    fn test_tron_secret_key_roundtrip() {
        let test_keys = vec![
            "15f0bbb1774be40b7a8d7965d637f324bda2f711fc5726a3dcc19585c6950954",
            "9b6ac6a6faf1dc64240f654475a7e668141e4205262367feb7269ef332113929",
            "0c88a7fee5bfbe5a354c225bfa8a9d09557466cdf56f887cc2d000e7354f9453",
        ];

        for key_hex in test_keys {
            let sk_bytes = hex::decode(key_hex).unwrap();
            let sk_array: [u8; SECRET_KEY_SIZE] = sk_bytes.try_into().unwrap();
            let sk = SecretKey::Secp256k1Tron(sk_array);

            let bytes = sk.to_bytes().unwrap();
            let recovered = SecretKey::from_bytes(std::borrow::Cow::Borrowed(&bytes)).unwrap();

            assert_eq!(sk, recovered);
        }
    }

    #[test]
    fn test_tron_secret_key_display_roundtrip() {
        let sk_hex = "15f0bbb1774be40b7a8d7965d637f324bda2f711fc5726a3dcc19585c6950954";
        let sk_bytes = hex::decode(sk_hex).unwrap();
        let sk_array: [u8; SECRET_KEY_SIZE] = sk_bytes.try_into().unwrap();
        let sk = SecretKey::Secp256k1Tron(sk_array);

        let sk_str = sk.to_string();
        let recovered = SecretKey::from_str(&sk_str).unwrap();

        assert_eq!(sk, recovered);
    }

    #[test]
    fn test_tron_secret_key_as_ref() {
        let sk_hex = "15f0bbb1774be40b7a8d7965d637f324bda2f711fc5726a3dcc19585c6950954";
        let sk_bytes = hex::decode(sk_hex).unwrap();
        let sk_array: [u8; SECRET_KEY_SIZE] = sk_bytes.try_into().unwrap();
        let sk = SecretKey::Secp256k1Tron(sk_array);

        assert_eq!(sk.as_ref(), sk_array.as_slice());
    }

    #[test]
    fn test_all_csv_tron_addresses() {
        use crate::keypair::KeyPair;

        let test_cases = vec![
            (
                "15f0bbb1774be40b7a8d7965d637f324bda2f711fc5726a3dcc19585c6950954",
                "TWer2Ygk5TEheHp3TPuYeqxmB6SsGZmaL6",
            ),
            (
                "9b6ac6a6faf1dc64240f654475a7e668141e4205262367feb7269ef332113929",
                "TPjjvMwjPoDC32V2dGDYTkLH4E5LAtBZ6C",
            ),
            (
                "0c88a7fee5bfbe5a354c225bfa8a9d09557466cdf56f887cc2d000e7354f9453",
                "TB7mhtkvfhsRBRhe5FuRa4tFXSEyGDe4eA",
            ),
            (
                "68c9a7dcaa4677fdeba9f72c8a1d86d0adf34932cdbdb52d90a2d01504d9d4be",
                "TEb822rMZ5QkYReuqdqK61zkheaan97PZZ",
            ),
            (
                "a01527c0c2d83e71c8827f2f0ee5c1a6f715a0c9bace1c3da50c6690a4e69fe7",
                "TYc2iBENTQ7kwx5jbjW3JDqugR7kogQZn3",
            ),
            (
                "679733f6af4143c82ea340e70029e86fda0fc0232a434172b7f233d96f6ff70f",
                "TNWtoufpsNepTJdNzbcimHrPEUSHLDCJE1",
            ),
            (
                "c41ac8920442be2469a0d6f04c9959e7e9faa3c6be4c3723224a2e06f4fd3aec",
                "TYMprjNZ1Lhc2zAsmRbGuBzY6iQ4FB4amn",
            ),
            (
                "ff46c996d2494137bff12940698eae445b696e6da4769933687d607a8fa06dc3",
                "TDmEWPYotmrXW4X49WMJTMostcezCiksPw",
            ),
            (
                "47e922c77f526dea6dcd1bb5d9af55239815fd982799745abe1f646f04ffe776",
                "TPoh8thAmjTXgxPwtFT9oYVyJXPVqLJHhh",
            ),
            (
                "529ca9c20dd90893928ef9ce2bdfcecbc191ffc5ee93a0171427d9a28ea77718",
                "TJtuRzHcZ12gHZA8gKjqq589S7h4fYW8N1",
            ),
            (
                "0f3f9e6e0e5852633037bac2027ed1348d0f838a074606a97fbb25e2fa73bdd5",
                "TQJXL6yjWWMwHBG7Pc8ofcsoChoyzMx6EJ",
            ),
            (
                "440a44e5fe4fe4dbb66bc52dadc48339b6f5c23a162013cec1eb103ee996e0c2",
                "TY36GCuD93n6qZXYM1G7zFaSLJNcydNSbE",
            ),
            (
                "9eb62d6eeebe7b2aa685e9348662bd4f321ff89f8780e9ad69144393f5de8340",
                "TPoMkBpKEtMKjRDEjuj18wwrDawmmui1xr",
            ),
            (
                "be9c96cb4108418357640ee207035aff222758d3017310776360d97d6d125be0",
                "TV9zSp3gCzZV3Vb7dSFKiszz758ssHxkZk",
            ),
            (
                "619e85874210d20343f60017456af0944ba2e5a05d9958cf69acef07233feae1",
                "TXBqVsdSZxK8TWVELkszohx2isK14oHXQr",
            ),
            (
                "6cdc8a402c9587011d70ef5241bcd83165d78c36ab18f87c78e14ee2f01c9928",
                "TRgTpCjTj588SszvJSBEesjGo6BcMopxEw",
            ),
            (
                "91c353acfc7a8b6ee175f105aac745ce93c84454edf5a8afec3e1c6c4368a380",
                "TDqFiJvNmfmprXueksX1gHqpujpKrNcEYm",
            ),
            (
                "a3c85975131f7c2a4a54af27a4f31f9425972049a03919cd35140ccb211141f8",
                "TUZN9nyGkpc1VEWHXt4kzcPnJaDoPXNiSM",
            ),
            (
                "b910cc7612f40a9a340d0e91d8d0dc9387a45e1222cc0ace2fbae73e9d8fc5c5",
                "TMyzpv258fdLbG1RNSWA1xYQZyk3XNSduP",
            ),
            (
                "ef0ae59787ca357e93f2eca372bcb2cdcc66aef2cd9aa54d1ab6ee2b5ed6a5e0",
                "TECoRud4FyZnEqRqwjAkYsqWT7Xbf5pBUi",
            ),
        ];

        for (private_key_hex, expected_address) in test_cases {
            let sk_bytes = hex::decode(private_key_hex).unwrap();
            let sk_array: [u8; SECRET_KEY_SIZE] = sk_bytes.try_into().unwrap();
            let sk = SecretKey::Secp256k1Tron(sk_array);

            let keypair = KeyPair::from_secret_key(sk).unwrap();
            let addr = keypair.get_addr().unwrap();
            let addr_str = addr.auto_format();

            assert_eq!(
                addr_str, expected_address,
                "Address mismatch for private key: {}",
                private_key_hex
            );
        }
    }

    #[test]
    fn test_tron_public_key_derivation() {
        use crate::keypair::KeyPair;

        let test_cases = vec![
            (
                "15f0bbb1774be40b7a8d7965d637f324bda2f711fc5726a3dcc19585c6950954",
                "030738c1aa72b07ff1a894198374a34c760913db0e6a5679d48477873b8f1fa865",
            ),
            (
                "9b6ac6a6faf1dc64240f654475a7e668141e4205262367feb7269ef332113929",
                "02c535cb0bdd16fa25620fd200879166cafbf31c269880fc033879ad2b280e8742",
            ),
            (
                "0c88a7fee5bfbe5a354c225bfa8a9d09557466cdf56f887cc2d000e7354f9453",
                "03c86b9ec1fb63bd8dc2ce65c666f98ef986a9d1b476f8be37d334431c0be784fa",
            ),
        ];

        for (private_key_hex, expected_pubkey_hex) in test_cases {
            let sk_bytes = hex::decode(private_key_hex).unwrap();
            let sk_array: [u8; SECRET_KEY_SIZE] = sk_bytes.try_into().unwrap();
            let sk = SecretKey::Secp256k1Tron(sk_array);

            let keypair = KeyPair::from_secret_key(sk).unwrap();
            let pubkey = keypair.get_pubkey().unwrap();
            let pubkey_hex = pubkey.as_hex_str();

            assert_eq!(
                pubkey_hex, expected_pubkey_hex,
                "Public key mismatch for private key: {}",
                private_key_hex
            );
        }
    }
}
