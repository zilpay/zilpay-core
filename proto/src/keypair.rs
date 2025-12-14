use alloy::dyn_abi::eip712::TypedData;
use alloy::signers::Signer;
use alloy::{
    network::EthereumWallet,
    signers::{local::PrivateKeySigner, SignerSync},
};
use config::key::{BIP39_SEED_SIZE, PUB_KEY_SIZE, SECRET_KEY_SIZE};
use crypto::{bip49::DerivationPath, schnorr, slip44};
use k256::SecretKey as K256SecretKey;

use crate::{
    address::Address,
    bip32::derive_private_key,
    pubkey::PubKey,
    signature::Signature,
    tx::{TransactionReceipt, TransactionRequest},
};

use super::secret_key::SecretKey;
use errors::{bip32::Bip329Errors, keypair::KeyPairError};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

// One byte for enum type
pub const KEYPAIR_BYTES_SIZE: usize = PUB_KEY_SIZE + SECRET_KEY_SIZE + 1;

type Result<T> = std::result::Result<T, KeyPairError>;

#[derive(Debug, PartialEq)]
pub enum KeyPair {
    Secp256k1Sha256(([u8; PUB_KEY_SIZE], [u8; SECRET_KEY_SIZE])),
    Secp256k1Keccak256(([u8; PUB_KEY_SIZE], [u8; SECRET_KEY_SIZE])),
    Secp256k1Bitcoin(([u8; PUB_KEY_SIZE], [u8; SECRET_KEY_SIZE])),
}

impl KeyPair {
    pub fn gen_sha256() -> Result<Self> {
        let keys = Self::gen_keys_bytes()?;

        Ok(Self::Secp256k1Sha256(keys))
    }

    pub fn gen_keccak256() -> Result<Self> {
        let keys = Self::gen_keys_bytes()?;

        Ok(Self::Secp256k1Keccak256(keys))
    }

    pub fn gen_bitcoin() -> Result<Self> {
        let keys = Self::gen_keys_bytes()?;

        Ok(Self::Secp256k1Bitcoin(keys))
    }

    pub fn to_sha256(self) -> Self {
        match self {
            Self::Secp256k1Sha256(vlaue) => Self::Secp256k1Sha256(vlaue),
            Self::Secp256k1Keccak256(value) => Self::Secp256k1Sha256(value),
            Self::Secp256k1Bitcoin(value) => Self::Secp256k1Sha256(value),
        }
    }

    pub fn to_keccak256(self) -> Self {
        match self {
            Self::Secp256k1Sha256(vlaue) => Self::Secp256k1Keccak256(vlaue),
            Self::Secp256k1Keccak256(value) => Self::Secp256k1Keccak256(value),
            Self::Secp256k1Bitcoin(value) => Self::Secp256k1Keccak256(value),
        }
    }

    pub fn to_bitcoin(self) -> Self {
        match self {
            Self::Secp256k1Sha256(value) => Self::Secp256k1Bitcoin(value),
            Self::Secp256k1Keccak256(value) => Self::Secp256k1Bitcoin(value),
            Self::Secp256k1Bitcoin(value) => Self::Secp256k1Bitcoin(value),
        }
    }

    pub fn from_sk_bytes(
        sk: [u8; SECRET_KEY_SIZE],
    ) -> Result<([u8; PUB_KEY_SIZE], [u8; SECRET_KEY_SIZE])> {
        let secret_key = K256SecretKey::from_slice(&sk).or(Err(KeyPairError::InvalidEntropy))?;
        let pub_key: [u8; PUB_KEY_SIZE] = secret_key
            .public_key()
            .to_sec1_bytes()
            .to_vec()
            .try_into()
            .or(Err(KeyPairError::InvalidSecretKey))?;
        let secret_key: [u8; SECRET_KEY_SIZE] = secret_key.to_bytes().into();

        Ok((pub_key, secret_key))
    }

    pub fn gen_keys_bytes() -> Result<([u8; PUB_KEY_SIZE], [u8; SECRET_KEY_SIZE])> {
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

    pub fn from_secret_key(sk: SecretKey) -> Result<Self> {
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
                Ok(KeyPair::Secp256k1Keccak256((pub_key, sk)))
            }
            SecretKey::Secp256k1Sha256Zilliqa(sk) => Ok(KeyPair::Secp256k1Sha256((pub_key, sk))),
            SecretKey::Secp256k1Bitcoin(sk) => Ok(KeyPair::Secp256k1Bitcoin((pub_key, sk))),
        }
    }

    pub fn from_bip39_seed(seed: &[u8; BIP39_SEED_SIZE], bip49: &DerivationPath) -> Result<Self> {
        let path = bip49.get_path();
        let secret_key =
            derive_private_key(seed, &path).map_err(KeyPairError::ExtendedPrivKeyDeriveError)?;
        let pub_key: [u8; PUB_KEY_SIZE] = secret_key
            .public_key()
            .to_sec1_bytes()
            .to_vec()
            .try_into()
            .or(Err(KeyPairError::InvalidSecretKey))?;
        let secret_key: [u8; SECRET_KEY_SIZE] = secret_key.to_bytes().into();

        match bip49.slip44 {
            slip44::ETHEREUM | slip44::ZILLIQA => {
                Ok(Self::Secp256k1Keccak256((pub_key, secret_key)))
            }
            _ => {
                return Err(KeyPairError::ExtendedPrivKeyDeriveError(
                    Bip329Errors::InvalidSlip44(bip49.slip44),
                ))
            }
        }
    }

    pub fn get_addr(&self) -> Result<Address> {
        let pk = self.get_pubkey()?;
        let addr = Address::from_pubkey(&pk).map_err(KeyPairError::AddressParseError)?;

        Ok(addr)
    }

    pub fn get_secretkey(&self) -> Result<SecretKey> {
        match self {
            KeyPair::Secp256k1Sha256((_, sk)) => Ok(SecretKey::Secp256k1Sha256Zilliqa(*sk)),
            KeyPair::Secp256k1Keccak256((_, sk)) => Ok(SecretKey::Secp256k1Keccak256Ethereum(*sk)),
            KeyPair::Secp256k1Bitcoin((_, sk)) => Ok(SecretKey::Secp256k1Bitcoin(*sk)),
        }
    }

    pub fn get_pubkey(&self) -> Result<PubKey> {
        match self {
            KeyPair::Secp256k1Sha256((pk, _)) => Ok(PubKey::Secp256k1Sha256(*pk)),
            KeyPair::Secp256k1Keccak256((pk, _)) => Ok(PubKey::Secp256k1Keccak256(*pk)),
            KeyPair::Secp256k1Bitcoin((pk, _)) => Ok(PubKey::Secp256k1Bitcoin(*pk)),
        }
    }

    pub fn get_pubkey_bytes(&self) -> &[u8; PUB_KEY_SIZE] {
        match self {
            KeyPair::Secp256k1Sha256((pk, _)) => pk,
            KeyPair::Secp256k1Keccak256((pk, _)) => pk,
            KeyPair::Secp256k1Bitcoin((pk, _)) => pk,
        }
    }

    pub fn get_sk_bytes(&self) -> [u8; SECRET_KEY_SIZE] {
        match self {
            KeyPair::Secp256k1Sha256((_, sk)) => *sk,
            KeyPair::Secp256k1Keccak256((_, sk)) => *sk,
            KeyPair::Secp256k1Bitcoin((_, sk)) => *sk,
        }
    }

    pub fn get_local_eth_siger(&self) -> Result<PrivateKeySigner> {
        let bytes = self.get_sk_bytes();
        PrivateKeySigner::from_slice(&bytes)
            .map_err(|e| KeyPairError::EthersInvalidSecretKey(e.to_string()))
    }

    pub fn get_local_eth_wallet(&self) -> Result<EthereumWallet> {
        let signer: PrivateKeySigner = self.get_local_eth_siger()?;
        let wallet = EthereumWallet::from(signer);
        Ok(wallet)
    }

    pub fn sign_message(&self, msg: &[u8]) -> Result<Signature> {
        match self {
            KeyPair::Secp256k1Keccak256((_, _sk)) => {
                let signer = self.get_local_eth_siger()?;
                let sig = signer
                    .sign_message_sync(msg)
                    .map_err(|e| KeyPairError::EthersInvalidSign(e.to_string()))?
                    .try_into()
                    .map_err(KeyPairError::InvalidSignature)?;

                Ok(sig)
            }
            KeyPair::Secp256k1Sha256((_, sk)) => {
                let secret_key =
                    K256SecretKey::from_slice(sk).or(Err(KeyPairError::InvalidSecretKey))?;
                let sig: Signature = schnorr::sign(&msg, &secret_key)
                    .map_err(KeyPairError::SchorrError)?
                    .try_into()
                    .map_err(KeyPairError::InvalidSignature)?;

                Ok(sig)
            }
            KeyPair::Secp256k1Bitcoin((_, _sk)) => {
                let signer = self.get_local_eth_siger()?;
                let sig = signer
                    .sign_message_sync(msg)
                    .map_err(|e| KeyPairError::EthersInvalidSign(e.to_string()))?
                    .try_into()
                    .map_err(KeyPairError::InvalidSignature)?;

                Ok(sig)
            }
        }
    }

    pub async fn sign_typed_data_eip712(&self, data: TypedData) -> Result<Signature> {
        match self {
            KeyPair::Secp256k1Keccak256((_, _)) => {
                let signer = self.get_local_eth_siger()?;
                let signing_hash = data
                    .eip712_signing_hash()
                    .map_err(|e| KeyPairError::Eip712Error(e.to_string()))?;
                let signature = signer
                    .sign_hash(&signing_hash)
                    .await
                    .map_err(|e| KeyPairError::EthersInvalidSign(e.to_string()))?;
                let sig = signature
                    .try_into()
                    .map_err(KeyPairError::InvalidSignature)?;

                Ok(sig)
            }
            KeyPair::Secp256k1Sha256((_, _)) => Err(KeyPairError::InvalidSecp256k1Sha256),
            KeyPair::Secp256k1Bitcoin((_, _)) => {
                let signer = self.get_local_eth_siger()?;
                let signing_hash = data
                    .eip712_signing_hash()
                    .map_err(|e| KeyPairError::Eip712Error(e.to_string()))?;
                let signature = signer
                    .sign_hash(&signing_hash)
                    .await
                    .map_err(|e| KeyPairError::EthersInvalidSign(e.to_string()))?;
                let sig = signature
                    .try_into()
                    .map_err(KeyPairError::InvalidSignature)?;

                Ok(sig)
            }
        }
    }

    pub fn verify_sig(&self, msg_bytes: &[u8], sig: &Signature) -> Result<bool> {
        let pk = self.get_pubkey()?;
        let is_verify = sig
            .verify(msg_bytes, &pk)
            .map_err(KeyPairError::InvalidSignature)?;

        Ok(is_verify)
    }

    pub async fn sign_tx(&self, tx: TransactionRequest) -> Result<TransactionReceipt> {
        tx.sign(self)
            .await
            .map_err(|e| KeyPairError::TransactionErrors(e.to_string()))
    }

    pub fn to_bytes(&self) -> Result<[u8; KEYPAIR_BYTES_SIZE]> {
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
            KeyPair::Secp256k1Bitcoin((pk, sk)) => {
                result[0] = 2;
                result[1..PUB_KEY_SIZE + 1].copy_from_slice(pk);
                result[PUB_KEY_SIZE + 1..].copy_from_slice(sk);
            }
        };

        Ok(result)
    }

    pub fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Result<Self> {
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
            2 => Ok(KeyPair::Secp256k1Bitcoin((pk, sk))),
            _ => Err(KeyPairError::InvalidKeyType),
        }
    }
}

#[cfg(test)]
mod tests_keypair {
    use super::*;
    use config::bip39::EN_WORDS;
    use pqbip39::mnemonic::Mnemonic;
    use serde_json::json;
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
        bytes[0] = 3;
        let result = KeyPair::from_bytes(Cow::Borrowed(&bytes));
        assert!(matches!(result, Err(KeyPairError::InvalidKeyType)));
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
        let key_pair = KeyPair::gen_keccak256().unwrap();
        let bytes = key_pair.to_bytes().unwrap();
        let restored_key_pair = KeyPair::from_bytes(bytes[..].into()).unwrap();

        assert_eq!(restored_key_pair, key_pair);
    }

    #[test]
    fn test_bip39_derivation() {
        let mnemonic_str =
            "green process gate doctor slide whip priority shrug diamond crumble average help";
        let m = Mnemonic::parse_str(&EN_WORDS, mnemonic_str).unwrap();
        let seed = m.to_seed("").unwrap();

        assert_eq!(
            [
                143, 219, 233, 88, 72, 55, 94, 13, 19, 72, 66, 197, 121, 69, 163, 46, 15, 247, 4,
                104, 60, 132, 106, 5, 135, 186, 182, 62, 54, 56, 209, 5, 182, 104, 244, 78, 184,
                167, 36, 156, 3, 14, 212, 191, 102, 69, 11, 214, 43, 181, 138, 7, 21, 241, 122,
                192, 73, 244, 36, 136, 187, 175, 159, 181,
            ],
            seed
        );

        let zil_path = DerivationPath::new(slip44::ZILLIQA, 0);
        let eth_path = DerivationPath::new(slip44::ETHEREUM, 0);

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
            "0xC315295101461753b838E0BE8688E744cf52Dd6b"
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
            "01e93c035175b08613c4b0251ca92cd007026ca032ba53bafa3c839838f8b52d04"
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
            "0103150a7f37063b134cde30070431a69148d60b252f4c7b38de33d813d329a7b7da"
        );
    }

    #[test]
    fn test_derivation_path_generation() {
        let eth_path = DerivationPath::new(slip44::ETHEREUM, 0);
        let zil_path = DerivationPath::new(slip44::ZILLIQA, 1);

        assert_eq!(eth_path.get_path(), "m/44'/60'/0'/0/0");
        assert_eq!(zil_path.get_path(), "m/44'/313'/0'/0/1");

        assert_eq!(eth_path.get_base_path(), "m/44'/60'/0'/0/");
        assert_eq!(zil_path.get_base_path(), "m/44'/313'/0'/0/");

        assert_eq!(eth_path.get_index(), 0);
        assert_eq!(zil_path.get_index(), 1);
    }

    #[tokio::test]
    async fn test_sign_typed_data_eip712_success() {
        let key_pair = KeyPair::gen_keccak256().unwrap();
        let address = key_pair.get_pubkey().unwrap().get_addr().unwrap();
        let typed_data_json = json!({
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"}
                ],
                "Person": [
                    {"name": "name", "type": "string"},
                    {"name": "wallet", "type": "address"}
                ]
            },
            "primaryType": "Person",
            "domain": {
                "name": "Ether Mail",
                "version": "1",
                "chainId": 1,
                "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
            },
            "message": {
                "name": "Bob",
                "wallet": address.to_eth_checksummed().unwrap()
            }
        });
        let typed_data: TypedData = serde_json::from_str(&typed_data_json.to_string()).unwrap();
        let signature = key_pair.sign_typed_data_eip712(typed_data).await;
        assert!(signature.is_ok());
    }

    #[tokio::test]
    async fn test_sign_typed_data_eip712_invalid_type() {
        let key_pair = KeyPair::gen_sha256().unwrap();
        let typed_data_json = json!({
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"}
                ],
                "Person": [
                    {"name": "name", "type": "string"},
                    {"name": "wallet", "type": "address"}
                ]
            },
            "primaryType": "Person",
            "domain": {
                "name": "Ether Mail",
                "version": "1",
                "chainId": 1,
                "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
            },
            "message": {
                "name": "Bob",
                "wallet": "0xbBbBBBBbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
            }
        });
        let typed_data: TypedData = serde_json::from_str(&typed_data_json.to_string()).unwrap();
        let result = key_pair.sign_typed_data_eip712(typed_data).await;
        assert!(matches!(result, Err(KeyPairError::InvalidSecp256k1Sha256)));
    }

    #[test]
    fn test_gen_bitcoin_keypair() {
        let keypair = KeyPair::gen_bitcoin().unwrap();
        assert!(matches!(keypair, KeyPair::Secp256k1Bitcoin(_)));

        let pubkey = keypair.get_pubkey().unwrap();
        assert!(matches!(pubkey, PubKey::Secp256k1Bitcoin(_)));

        let secret_key = keypair.get_secretkey().unwrap();
        assert!(matches!(secret_key, SecretKey::Secp256k1Bitcoin(_)));
    }

    #[test]
    fn test_bitcoin_keypair_get_addr() {
        let keypair = KeyPair::gen_bitcoin().unwrap();
        let addr = keypair.get_addr().unwrap();

        assert!(matches!(addr, Address::Secp256k1Bitcoin(_)));
    }

    #[test]
    fn test_bitcoin_keypair_to_bytes() {
        let keypair = KeyPair::gen_bitcoin().unwrap();
        let bytes = keypair.to_bytes().unwrap();

        assert_eq!(bytes[0], 2);
        assert_eq!(bytes.len(), KEYPAIR_BYTES_SIZE);
    }

    #[test]
    fn test_bitcoin_keypair_from_bytes() {
        let original = KeyPair::gen_bitcoin().unwrap();
        let bytes = original.to_bytes().unwrap();
        let recovered = KeyPair::from_bytes(std::borrow::Cow::Borrowed(&bytes)).unwrap();

        assert_eq!(original, recovered);
    }

    #[test]
    fn test_bitcoin_keypair_sign_message() {
        let keypair = KeyPair::gen_bitcoin().unwrap();
        let message = b"Hello Bitcoin!";

        let signature = keypair.sign_message(message);
        assert!(signature.is_ok());
    }

    #[test]
    fn test_bitcoin_keypair_conversion() {
        let keypair_zil = KeyPair::gen_sha256().unwrap();
        let keypair_btc = keypair_zil.to_bitcoin();

        assert!(matches!(keypair_btc, KeyPair::Secp256k1Bitcoin(_)));
    }

    #[test]
    fn test_bitcoin_from_secret_key() {
        let sk = SecretKey::Secp256k1Bitcoin([42u8; SECRET_KEY_SIZE]);
        let result = KeyPair::from_secret_key(sk);

        assert!(result.is_ok());
        let keypair = result.unwrap();
        assert!(matches!(keypair, KeyPair::Secp256k1Bitcoin(_)));
    }

    #[test]
    fn test_bitcoin_address_generation() {
        let keypair = KeyPair::gen_bitcoin().unwrap();
        let address = keypair.get_addr().unwrap();

        let p2pkh = address.to_btc_p2pkh().unwrap();
        assert!(p2pkh.starts_with('1'));

        let bech32 = address.to_btc_bech32().unwrap();
        assert!(bech32.starts_with("bc1"));
    }

    #[test]
    fn test_bitcoin_known_key_address_derivation() {
        let public_key_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let expected_address = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";
        let expected_hash160 = "751e76e8199196d454941c45d1b3a323f1433bd6";

        let pk_bytes = hex::decode(public_key_hex).unwrap();
        let pk_array: [u8; PUB_KEY_SIZE] = pk_bytes.try_into().unwrap();
        let pubkey = PubKey::Secp256k1Bitcoin(pk_array);

        let address = Address::from_pubkey(&pubkey).unwrap();

        let hash160_hex = hex::encode(address.addr_bytes());
        assert_eq!(hash160_hex, expected_hash160);

        let btc_address = address.to_btc_p2pkh().unwrap();
        assert_eq!(btc_address, expected_address);
    }

    #[test]
    fn test_bitcoin_derived_addresses_from_csv() {
        let test_cases = vec![
            (
                "024447e68ff4efc6dccac32b60c9af9421654763a93d9573d7284567b70f7993ef",
                "183jY8BqANQctEHNB7z3KfCxbBKav6C2Xb",
            ),
            (
                "0344d7472c77f5400f2671c9e6fc1a167c9fa98d2d0c98c5253dd8a11771b232d4",
                "14WTRqxezCyjJ8bGLMey8FAUeucQyBGvqj",
            ),
            (
                "03ef8ac6029411ae46a2cdb4d15a87a318f3bd68b91aa9d08869bc778b9e8e19cf",
                "1wi5gLfdxVbfmCHrYe9YeV5VrZQiUAuB2",
            ),
            (
                "02edbcf32cbdf36bf161cbf4aa10e5b6704320e6bcd8abdaf4a301adb1acd65150",
                "14X5Y28wnQkYNcHekFjixbVkZjXpScvwvc",
            ),
            (
                "0371f0511f34bd3875bdf0565eb73940fea335caf991fcf09c9a09d5074eaa21c2",
                "1EJpWTHGfoX3azrA5Z8VCBmwp5J8YQ3SA9",
            ),
        ];

        for (pubkey_hex, expected_addr) in test_cases {
            let pk_bytes = hex::decode(pubkey_hex).unwrap();
            let pk_array: [u8; PUB_KEY_SIZE] = pk_bytes.try_into().unwrap();
            let pubkey = PubKey::Secp256k1Bitcoin(pk_array);

            let address = Address::from_pubkey(&pubkey).unwrap();
            let btc_address = address.to_btc_p2pkh().unwrap();

            assert_eq!(
                btc_address, expected_addr,
                "Failed for pubkey: {}",
                pubkey_hex
            );
        }
    }

    #[test]
    fn test_bitcoin_wif_private_key_decode() {
        let wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
        let expected_pubkey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let expected_address = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";

        let decoded = bs58::decode(wif).into_vec().unwrap();

        assert_eq!(decoded[0], 0x80);
        assert_eq!(decoded.len(), 38);

        let private_key_bytes: [u8; SECRET_KEY_SIZE] = decoded[1..33].try_into().unwrap();

        let keypair = KeyPair::from_sk_bytes(private_key_bytes).unwrap();
        let keypair_btc = KeyPair::Secp256k1Bitcoin(keypair);

        let pubkey = keypair_btc.get_pubkey().unwrap();
        let pubkey_hex = hex::encode(pubkey.as_bytes());
        assert_eq!(pubkey_hex, expected_pubkey);

        let address = keypair_btc.get_addr().unwrap();
        let btc_address = address.to_btc_p2pkh().unwrap();
        assert_eq!(btc_address, expected_address);
    }

    #[test]
    fn test_bitcoin_multiple_wif_keys() {
        let test_cases = vec![
            (
                "L1NQXBsdws444VbdxGqztar6nf1GcmZNXZWDYetAUJ9NE47SRWxN",
                "024447e68ff4efc6dccac32b60c9af9421654763a93d9573d7284567b70f7993ef",
                "183jY8BqANQctEHNB7z3KfCxbBKav6C2Xb",
            ),
            (
                "L4PvnB6kR8bmrMvUS86RESUeDFWGNB5UmH6663yJCGgrhEgJdyq3",
                "0344d7472c77f5400f2671c9e6fc1a167c9fa98d2d0c98c5253dd8a11771b232d4",
                "14WTRqxezCyjJ8bGLMey8FAUeucQyBGvqj",
            ),
            (
                "L2NZxVEQmDc4fDrLvX7NDsCMSTugKZxZ6vrX61UJvZLkWgXrACoe",
                "03ef8ac6029411ae46a2cdb4d15a87a318f3bd68b91aa9d08869bc778b9e8e19cf",
                "1wi5gLfdxVbfmCHrYe9YeV5VrZQiUAuB2",
            ),
        ];

        for (wif, expected_pubkey, expected_address) in test_cases {
            let decoded = bs58::decode(wif).into_vec().unwrap();
            let private_key_bytes: [u8; SECRET_KEY_SIZE] = decoded[1..33].try_into().unwrap();

            let keypair = KeyPair::from_sk_bytes(private_key_bytes).unwrap();
            let keypair_btc = KeyPair::Secp256k1Bitcoin(keypair);

            let pubkey = keypair_btc.get_pubkey().unwrap();
            let pubkey_hex = hex::encode(pubkey.as_bytes());
            assert_eq!(pubkey_hex, expected_pubkey, "Failed for WIF: {}", wif);

            let address = keypair_btc.get_addr().unwrap();
            let btc_address = address.to_btc_p2pkh().unwrap();
            assert_eq!(btc_address, expected_address, "Failed for WIF: {}", wif);
        }
    }
}
