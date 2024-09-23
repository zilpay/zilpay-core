use bincode::{FromBytes, ToBytes};
use config::key::{BIP39_SEED_SIZE, PUB_KEY_SIZE, SECRET_KEY_SIZE};
use crypto::bip49::Bip49DerivationPath;
use crypto::schnorr;
use k256::SecretKey as K256SecretKey;

use crate::{address::Address, pubkey::PubKey, signature::Signature};

use ethers::{core::k256::ecdsa::SigningKey, signers::LocalWallet, utils::hash_message};

use super::secret_key::SecretKey;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use tiny_hderive::bip32::ExtendedPrivKey;
use zil_errors::keypair::KeyPairError;

// One byte for enum type
pub const KEYPAIR_BYTES_SIZE: usize = PUB_KEY_SIZE + SECRET_KEY_SIZE + 1;

#[derive(Debug, PartialEq)]
pub enum KeyPair {
    Secp256k1Sha256Zilliqa(([u8; PUB_KEY_SIZE], [u8; SECRET_KEY_SIZE])), // ZILLIQA
    Secp256k1Keccak256Ethereum(([u8; PUB_KEY_SIZE], [u8; SECRET_KEY_SIZE])), // Ethereum
}

impl KeyPair {
    pub fn gen_sha256() -> Result<Self, KeyPairError> {
        let keys = Self::gen_keys_bytes()?;

        Ok(Self::Secp256k1Sha256Zilliqa(keys))
    }

    pub fn gen_keccak256() -> Result<Self, KeyPairError> {
        let keys = Self::gen_keys_bytes()?;

        Ok(Self::Secp256k1Keccak256Ethereum(keys))
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

    pub fn from_secret_key(sk: &SecretKey) -> Result<Self, KeyPairError> {
        let secret_key: K256SecretKey =
            K256SecretKey::from_slice(sk.as_ref()).or(Err(KeyPairError::InvalidSecretKey))?;
        let pub_key: [u8; PUB_KEY_SIZE] = secret_key
            .public_key()
            .to_sec1_bytes()
            .to_vec()
            .try_into()
            .or(Err(KeyPairError::InvalidSecretKey))?;

        match sk {
            SecretKey::Secp256k1Keccak256Ethereum(sk) => {
                Ok(KeyPair::Secp256k1Keccak256Ethereum((pub_key, *sk)))
            }
            SecretKey::Secp256k1Sha256Zilliqa(sk) => {
                Ok(KeyPair::Secp256k1Sha256Zilliqa((pub_key, *sk)))
            }
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
            Bip49DerivationPath::Zilliqa(_) => {
                Ok(Self::Secp256k1Sha256Zilliqa((pub_key, secret_key)))
            }
            Bip49DerivationPath::Ethereum(_) => {
                Ok(Self::Secp256k1Keccak256Ethereum((pub_key, secret_key)))
            }
        }
    }

    pub fn get_addr(&self) -> Result<Address, KeyPairError> {
        let pk = self.get_pubkey()?;
        let addr = Address::from_pubkey(&pk).map_err(KeyPairError::AddressParseError)?;

        Ok(addr)
    }

    pub fn get_secretkey(&self) -> Result<SecretKey, KeyPairError> {
        match self {
            KeyPair::Secp256k1Sha256Zilliqa((_, sk)) => Ok(SecretKey::Secp256k1Sha256Zilliqa(*sk)),
            KeyPair::Secp256k1Keccak256Ethereum((_, sk)) => {
                Ok(SecretKey::Secp256k1Keccak256Ethereum(*sk))
            }
        }
    }

    pub fn get_pubkey(&self) -> Result<PubKey, KeyPairError> {
        match self {
            KeyPair::Secp256k1Sha256Zilliqa((pk, _)) => Ok(PubKey::Secp256k1Sha256Zilliqa(*pk)),
            KeyPair::Secp256k1Keccak256Ethereum((pk, _)) => {
                Ok(PubKey::Secp256k1Keccak256Ethereum(*pk))
            }
        }
    }

    pub fn sign_message(&self, msg: &[u8]) -> Result<Signature, KeyPairError> {
        match self {
            KeyPair::Secp256k1Keccak256Ethereum((_, sk)) => {
                let hash_msg = hash_message(msg);
                let signing_key = SigningKey::from_slice(sk)
                    .map_err(|e| KeyPairError::EthersInvalidSecretKey(e.to_string()))?;
                let wallet = LocalWallet::from(signing_key);

                let sig: Signature = wallet
                    .sign_hash(hash_msg)
                    .map_err(|e| KeyPairError::EthersInvalidSign(e.to_string()))?
                    .try_into()
                    .map_err(KeyPairError::InvalidSignature)?;

                Ok(sig)
            }
            KeyPair::Secp256k1Sha256Zilliqa((_, sk)) => {
                let secret_key =
                    K256SecretKey::from_slice(sk).or(Err(KeyPairError::InvalidSecretKey))?;
                let sig: Signature = schnorr::sign(msg, &secret_key)
                    .map_err(KeyPairError::SchorrError)?
                    .try_into()
                    .map_err(KeyPairError::InvalidSignature)?;

                Ok(sig)
            }
        }
    }

    pub fn verify_sig(&self, msg_bytes: &[u8], sig: &Signature) -> Result<bool, KeyPairError> {
        let pk = self.get_pubkey()?;
        let is_verify = sig
            .verify(msg_bytes, &pk)
            .map_err(KeyPairError::InvalidSignature)?;

        Ok(is_verify)
    }

    pub fn sign_tx(&self) -> Result<(), KeyPairError> {
        Ok(())
    }
}

impl ToBytes<{ KEYPAIR_BYTES_SIZE }> for KeyPair {
    type Error = KeyPairError;
    fn to_bytes(&self) -> Result<[u8; KEYPAIR_BYTES_SIZE], Self::Error> {
        let mut result = [0u8; KEYPAIR_BYTES_SIZE];

        match self {
            KeyPair::Secp256k1Sha256Zilliqa((pk, sk)) => {
                result[0] = 0;
                result[1..PUB_KEY_SIZE + 1].copy_from_slice(pk);
                result[PUB_KEY_SIZE + 1..].copy_from_slice(sk);
            }
            KeyPair::Secp256k1Keccak256Ethereum((pk, sk)) => {
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
            0 => Ok(KeyPair::Secp256k1Sha256Zilliqa((pk, sk))),
            1 => Ok(KeyPair::Secp256k1Keccak256Ethereum((pk, sk))),
            _ => Err(KeyPairError::InvalidKeyType),
        }
    }
}

#[cfg(test)]
mod tests {
    use bip39::Mnemonic;

    use super::*;
    use std::borrow::Cow;

    fn create_test_keypair(key_type: u8) -> KeyPair {
        let pk = [1u8; PUB_KEY_SIZE];
        let sk = [2u8; SECRET_KEY_SIZE];
        match key_type {
            0 => KeyPair::Secp256k1Sha256Zilliqa((pk, sk)),
            1 => KeyPair::Secp256k1Keccak256Ethereum((pk, sk)),
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

    #[test]
    fn test_sign_message() {
        use rand::{RngCore, SeedableRng};
        use rand_chacha::ChaCha20Rng;

        let mut rng = ChaCha20Rng::from_entropy();

        for _ in 0..10 {
            let key_pair = KeyPair::gen_sha256().unwrap();
            let mut message_bytes = [0u8; 100];

            rng.fill_bytes(&mut message_bytes);

            let signature = key_pair.sign_message(&message_bytes).unwrap();
            let verify = key_pair.verify_sig(&message_bytes, &signature);

            assert!(verify.is_ok());
            assert!(verify.unwrap());
        }

        for _ in 0..10 {
            let key_pair = KeyPair::gen_keccak256().unwrap();
            let mut message_bytes = [0u8; 100];

            rng.fill_bytes(&mut message_bytes);
            let signature = key_pair.sign_message(&message_bytes).unwrap();
            let verify = key_pair.verify_sig(&message_bytes, &signature);

            assert!(verify.is_ok());
            assert!(verify.unwrap());
        }
    }

    #[test]
    fn from_to_bytes() {
        use crate::keypair::KeyPair;

        let key_pair = KeyPair::gen_keccak256().unwrap();
        let bytes = key_pair.to_bytes().unwrap();
        let restored_key_pair = KeyPair::from_bytes(bytes[..].into()).unwrap();

        assert_eq!(restored_key_pair, key_pair);
    }

    #[test]
    fn test_bip39_zil() {
        let mnemonic_str =
            "green process gate doctor slide whip priority shrug diamond crumble average help";
        let m = Mnemonic::parse_normalized(mnemonic_str).unwrap();
        let index = 0;
        let seed = m.to_seed("");

        let zil_path = Bip49DerivationPath::Zilliqa(index);
        let eth_path = Bip49DerivationPath::Ethereum(index);

        assert_eq!(
            [
                143, 219, 233, 88, 72, 55, 94, 13, 19, 72, 66, 197, 121, 69, 163, 46, 15, 247, 4,
                104, 60, 132, 106, 5, 135, 186, 182, 62, 54, 56, 209, 5, 182, 104, 244, 78, 184,
                167, 36, 156, 3, 14, 212, 191, 102, 69, 11, 214, 43, 181, 138, 7, 21, 241, 122,
                192, 73, 244, 36, 136, 187, 175, 159, 181,
            ],
            seed
        );
        let zil_key_pair = KeyPair::from_bip39_seed(&seed, &zil_path).unwrap();
        let eth_key_pair = KeyPair::from_bip39_seed(&seed, &eth_path).unwrap();

        let addr_eth = eth_key_pair.get_addr().unwrap();
        let addr_zil = zil_key_pair.get_addr().unwrap();

        assert_eq!(
            addr_eth.to_string(),
            "0x7aa13D6AE95fb8E843d3bCC2eea365F71c3bACbe"
        );
        assert_eq!(
            addr_zil.to_string(),
            "zil1a0vtxuxamd3kltmyzpqdyxqu25vsss8mp58jtu"
        );

        assert_ne!(
            zil_key_pair.get_pubkey().unwrap(),
            eth_key_pair.get_pubkey().unwrap()
        );
        assert_ne!(
            zil_key_pair.get_secretkey().unwrap(),
            eth_key_pair.get_secretkey().unwrap()
        );

        assert_eq!(
            zil_key_pair.get_secretkey().unwrap().to_string(),
            "00e93c035175b08613c4b0251ca92cd007026ca032ba53bafa3c839838f8b52d04"
        );
        assert_eq!(
            eth_key_pair.get_secretkey().unwrap().to_string(),
            "01b8ef60193eec0a55db93ba692035a8b5a388579c8dc58acc62ea470aba529e1c"
        );
        assert_eq!(
            eth_key_pair.get_pubkey().unwrap().to_string(),
            "010315bd7b9301a2cde69ef8092d6fb275a077e3c94e5ed166c915426850cf606600"
        );
        assert_eq!(
            zil_key_pair.get_pubkey().unwrap().to_string(),
            "0003150a7f37063b134cde30070431a69148d60b252f4c7b38de33d813d329a7b7da"
        );
    }
}
