use bincode::{FromBytes, ToBytes};
use config::key::{BIP39_SEED_SIZE, PUB_KEY_SIZE, SECRET_KEY_SIZE};
use crypto::bip49::Bip49DerivationPath;
use k256::{ecdsa, PublicKey as K256PublicKey, SecretKey as K256SecretKey};

use super::secret_key::SecretKey;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use tiny_hderive::bip32::ExtendedPrivKey;
use zil_errors::KeyPairError;

// One byte for enum type
pub const KEYPAIR_BYTES_SIZE: usize = PUB_KEY_SIZE + SECRET_KEY_SIZE + 1;

#[derive(Debug, PartialEq)]
pub enum KeyPair {
    Secp256k1Sha256(([u8; PUB_KEY_SIZE], [u8; SECRET_KEY_SIZE])), // ZILLIQA
    Secp256k1Keccak256(([u8; PUB_KEY_SIZE], [u8; SECRET_KEY_SIZE])), // Ethereum
}

impl KeyPair {
    pub fn gen_sha256() -> Result<Self, KeyPairError> {
        let keys = Self::gen_keys_bytes()?;

        Ok(Self::Secp256k1Sha256(keys))
    }

    pub fn gen_keccak256() -> Result<Self, KeyPairError> {
        let keys = Self::gen_keys_bytes()?;

        Ok(Self::Secp256k1Keccak256(keys))
    }

    pub fn gen_keys_bytes() -> Result<([u8; PUB_KEY_SIZE], [u8; SECRET_KEY_SIZE]), KeyPairError> {
        let mut rng = ChaCha20Rng::from_entropy();
        let mut sk_bytes = [0u8; SECRET_KEY_SIZE];

        rng.fill_bytes(&mut sk_bytes);

        let secret_key =
            K256SecretKey::from_slice(&sk_bytes).or(Err(KeyPairError::InvalidEntropy))?;
        let pub_key: [u8; PUB_KEY_SIZE] = secret_key
            .public_key()
            .to_sec1_bytes()
            .to_vec()
            .try_into()
            .or(Err(KeyPairError::InvalidSecretKey))?;
        let secret_key: [u8; SECRET_KEY_SIZE] = secret_key.to_bytes().into();

        Ok((pub_key, secret_key))
    }

    pub fn from_secret_key(sk: SecretKey) -> Result<Self, KeyPairError> {
        let secret_key: K256SecretKey =
            K256SecretKey::from_slice(sk.as_ref()).or(Err(KeyPairError::InvalidSecretKey))?;
        let pub_key: [u8; PUB_KEY_SIZE] = secret_key
            .public_key()
            .to_sec1_bytes()
            .to_vec()
            .try_into()
            .or(Err(KeyPairError::InvalidSecretKey))?;

        match sk {
            SecretKey::Secp256k1Keccak256(sk) => Ok(KeyPair::Secp256k1Keccak256((pub_key, sk))),
            SecretKey::Secp256k1Sha256(sk) => Ok(KeyPair::Secp256k1Sha256((pub_key, sk))),
        }
    }

    pub fn from_bip39_seed(
        seed: &[u8; BIP39_SEED_SIZE],
        bip49: &Bip49DerivationPath,
    ) -> Result<Self, KeyPairError> {
        let path = bip49.get_path();
        let ext = ExtendedPrivKey::derive(seed, path.as_str())
            .map_err(|_| KeyPairError::ExtendedPrivKeyDeriveError)?;
        let secret_key =
            K256SecretKey::from_slice(&ext.secret()).or(Err(KeyPairError::InvalidEntropy))?;
        let pub_key: [u8; PUB_KEY_SIZE] = secret_key
            .public_key()
            .to_sec1_bytes()
            .to_vec()
            .try_into()
            .or(Err(KeyPairError::InvalidSecretKey))?;
        let secret_key: [u8; SECRET_KEY_SIZE] = secret_key.to_bytes().into();

        match bip49 {
            Bip49DerivationPath::Zilliqa(_) => Ok(Self::Secp256k1Sha256((pub_key, secret_key))),
            Bip49DerivationPath::Ethereum(_) => Ok(Self::Secp256k1Keccak256((pub_key, secret_key))),
        }
    }
}

impl ToBytes<{ KEYPAIR_BYTES_SIZE }> for KeyPair {
    type Error = KeyPairError;
    fn to_bytes(&self) -> Result<[u8; KEYPAIR_BYTES_SIZE], Self::Error> {
        let mut result = [0u8; KEYPAIR_BYTES_SIZE];

        match self {
            KeyPair::Secp256k1Sha256((pk, sk)) => {
                result[0] = 0;
                result[1..PUB_KEY_SIZE + 1].copy_from_slice(pk);
                result[PUB_KEY_SIZE + 1..].copy_from_slice(sk);
            }
            KeyPair::Secp256k1Keccak256((pk, sk)) => {
                result[0] = 1;
                result[1..PUB_KEY_SIZE + 1].copy_from_slice(pk);
                result[PUB_KEY_SIZE + 1..].copy_from_slice(sk);
            }
        };

        Ok(result)
    }
}

impl FromBytes for KeyPair {
    type Error = KeyPairError;

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Result<Self, Self::Error> {
        if bytes.len() != KEYPAIR_BYTES_SIZE {
            return Err(KeyPairError::InvalidLength);
        }

        let key_type = bytes[0];
        let pk: [u8; PUB_KEY_SIZE] = bytes[1..PUB_KEY_SIZE + 1]
            .try_into()
            .map_err(|_| KeyPairError::InvalidPublicKey)?;
        let sk: [u8; SECRET_KEY_SIZE] = bytes[PUB_KEY_SIZE + 1..]
            .try_into()
            .map_err(|_| KeyPairError::InvalidSecretKey)?;

        match key_type {
            0 => Ok(KeyPair::Secp256k1Sha256((pk, sk))),
            1 => Ok(KeyPair::Secp256k1Keccak256((pk, sk))),
            _ => Err(KeyPairError::InvalidKeyType),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;

    fn create_test_keypair(key_type: u8) -> KeyPair {
        let pk = [1u8; PUB_KEY_SIZE];
        let sk = [2u8; SECRET_KEY_SIZE];
        match key_type {
            0 => KeyPair::Secp256k1Sha256((pk, sk)),
            1 => KeyPair::Secp256k1Keccak256((pk, sk)),
            _ => panic!("Invalid key type for test"),
        }
    }

    #[test]
    fn test_to_bytes_secp256k1_sha256() {
        let keypair = create_test_keypair(0);
        let bytes = keypair.to_bytes().unwrap();
        assert_eq!(bytes[0], 0);
        assert_eq!(&bytes[1..PUB_KEY_SIZE + 1], &[1u8; PUB_KEY_SIZE]);
        assert_eq!(&bytes[PUB_KEY_SIZE + 1..], &[2u8; SECRET_KEY_SIZE]);
    }

    #[test]
    fn test_to_bytes_secp256k1_keccak256() {
        let keypair = create_test_keypair(1);
        let bytes = keypair.to_bytes().unwrap();
        assert_eq!(bytes[0], 1);
        assert_eq!(&bytes[1..PUB_KEY_SIZE + 1], &[1u8; PUB_KEY_SIZE]);
        assert_eq!(&bytes[PUB_KEY_SIZE + 1..], &[2u8; SECRET_KEY_SIZE]);
    }

    #[test]
    fn test_from_bytes_secp256k1_sha256() {
        let original = create_test_keypair(0);
        let bytes = original.to_bytes().unwrap();
        let recovered = KeyPair::from_bytes(Cow::Borrowed(&bytes)).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_from_bytes_secp256k1_keccak256() {
        let original = create_test_keypair(1);
        let bytes = original.to_bytes().unwrap();
        let recovered = KeyPair::from_bytes(Cow::Borrowed(&bytes)).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_from_bytes_invalid_length() {
        let bytes = vec![0u8; KEYPAIR_BYTES_SIZE - 1];
        let result = KeyPair::from_bytes(Cow::Borrowed(&bytes));
        assert!(matches!(result, Err(KeyPairError::InvalidLength)));
    }

    #[test]
    fn test_from_bytes_invalid_key_type() {
        let mut bytes = vec![0u8; KEYPAIR_BYTES_SIZE];
        bytes[0] = 2; // Invalid key type
        let result = KeyPair::from_bytes(Cow::Borrowed(&bytes));
        assert!(matches!(result, Err(KeyPairError::InvalidKeyType)));
    }

    #[test]
    fn test_roundtrip() {
        let original = create_test_keypair(0);
        let bytes = original.to_bytes().unwrap();
        let recovered = KeyPair::from_bytes(Cow::Borrowed(&bytes)).unwrap();
        assert_eq!(original, recovered);

        let original = create_test_keypair(1);
        let bytes = original.to_bytes().unwrap();
        let recovered = KeyPair::from_bytes(Cow::Borrowed(&bytes)).unwrap();
        assert_eq!(original, recovered);
    }
}
