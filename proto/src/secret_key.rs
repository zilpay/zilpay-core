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
}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        match self {
            SecretKey::Secp256k1Sha256Zilliqa(key) => key.zeroize(),
            SecretKey::Secp256k1Keccak256Ethereum(key) => key.zeroize(),
            SecretKey::Secp256k1Bitcoin((key, _, _)) => key.zeroize(),
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
}
