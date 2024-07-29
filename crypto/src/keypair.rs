use super::schnorr;

use ethers::{
    core::k256::ecdsa::SigningKey,
    signers::LocalWallet,
    types::{transaction::eip2718::TypedTransaction, Signature as EvmSignature, H256},
    utils::hash_message,
};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use k256::{ecdsa, PublicKey, SecretKey};
use zil_errors::{EvmErrors, ZilliqaErrors};

pub const PUB_KEY_SIZE: usize = 33;
pub const SECRET_KEY_SIZE: usize = 32;

#[derive(Debug)]
pub struct KeyPair {
    pub pub_key: [u8; PUB_KEY_SIZE],
    pub secret_key: [u8; SECRET_KEY_SIZE],
}

impl KeyPair {
    pub fn generate<'a>() -> Result<Self, ZilliqaErrors<'a>> {
        let mut rng = ChaCha20Rng::from_entropy();
        let mut sk_bytes = [0u8; SECRET_KEY_SIZE];

        rng.fill_bytes(&mut sk_bytes);

        let secret_key = SecretKey::from_slice(&sk_bytes).or(Err(ZilliqaErrors::InvalidEntropy))?;
        let pub_key: [u8; PUB_KEY_SIZE] = secret_key
            .public_key()
            .to_sec1_bytes()
            .to_vec()
            .try_into()
            .or(Err(ZilliqaErrors::InvalidSecretKey))?;
        let secret_key: [u8; SECRET_KEY_SIZE] = secret_key.to_bytes().into();

        Ok(Self {
            secret_key,
            pub_key,
        })
    }

    pub fn from_secret_key<'a>(sk: SecretKey) -> Result<Self, ZilliqaErrors<'a>> {
        let pub_key: [u8; PUB_KEY_SIZE] = sk
            .public_key()
            .to_sec1_bytes()
            .to_vec()
            .try_into()
            .or(Err(ZilliqaErrors::InvalidSecretKey))?;
        let secret_key: [u8; SECRET_KEY_SIZE] = sk.to_bytes().into();

        Ok(Self {
            pub_key,
            secret_key,
        })
    }

    pub fn get_zil1_wallet<'a>(&self) -> Result<(SecretKey, PublicKey), ZilliqaErrors<'a>> {
        let secret_key =
            SecretKey::from_slice(&self.secret_key).or(Err(ZilliqaErrors::InvalidSecretKey))?;
        let pub_key =
            PublicKey::from_sec1_bytes(&self.pub_key).or(Err(ZilliqaErrors::InvalidSecretKey))?;

        Ok((secret_key, pub_key))
    }

    pub fn get_evm_wallet(&self) -> Result<LocalWallet, EvmErrors> {
        let signing_key = SigningKey::from_slice(&self.secret_key)
            .map_err(|e| EvmErrors::InvalidSecretKey(e.to_string()))?;

        Ok(LocalWallet::from(signing_key))
    }

    pub fn sign_message_secp256k1(&self, msg: &[u8]) -> Result<ecdsa::Signature, ZilliqaErrors> {
        let secret_key =
            SecretKey::from_slice(&self.secret_key).or(Err(ZilliqaErrors::InvalidSecretKey))?;

        schnorr::sign(msg, &secret_key)
    }

    pub fn sign_ecdsa_hash(&self, hash: H256) -> Result<EvmSignature, EvmErrors> {
        let wallet = self.get_evm_wallet()?;

        wallet
            .sign_hash(hash)
            .map_err(|e| EvmErrors::InvalidSign(e.to_string()))
    }

    pub fn sign_ecdsa_message(&self, msg: &[u8]) -> Result<EvmSignature, EvmErrors> {
        let hash_msg = hash_message(msg);

        self.sign_ecdsa_hash(hash_msg)
    }

    pub fn sign_ecdsa_tx(&self, tx: &TypedTransaction) -> Result<EvmSignature, EvmErrors> {
        let wallet = self.get_evm_wallet()?;

        wallet
            .sign_transaction_sync(tx)
            .map_err(|e| EvmErrors::InvalidSign(e.to_string()))
    }
}

impl std::fmt::Display for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex_sk = hex::encode(self.secret_key);
        let hex_pk = hex::encode(self.pub_key);

        write!(f, "{}:{}", hex_sk, hex_pk)
    }
}

mod tests {
    #[test]
    fn from_secret_key_secp256k1() {
        use crate::keypair::KeyPair;
        use k256::SecretKey;

        let hex_key = "0F494B8312E8D257E51730C78F8FE3B47B6840C59AAAEC7C2EBE404A2DE8B25A";
        let bytes = hex::decode(hex_key).unwrap();
        let secret_key = SecretKey::from_slice(&bytes).unwrap();
        let keypair = KeyPair::from_secret_key(secret_key).unwrap();

        assert_eq!(
            keypair.to_string(),
            "0f494b8312e8d257e51730c78f8fe3b47b6840c59aaaec7c2ebe404a2de8b25a:039e43c9810e6cc09f46aad38e716dae3191629534967dc457d3a687d2e2cddc6a"
        );
    }

    #[test]
    fn test_sign_secp256k1() {
        use super::schnorr;
        use crate::keypair::KeyPair;
        use rand::{RngCore, SeedableRng};
        use rand_chacha::ChaCha20Rng;

        let mut rng = ChaCha20Rng::from_entropy();

        for _ in 0..100 {
            let key_pair = KeyPair::generate().unwrap();
            let mut message_bytes = [0u8; 100];
            let (_, pub_key) = key_pair.get_zil1_wallet().unwrap();

            rng.fill_bytes(&mut message_bytes);

            let signature = key_pair.sign_message_secp256k1(&message_bytes).unwrap();
            let verify = schnorr::verify(&message_bytes, pub_key, signature);

            assert!(verify.is_some());
        }
    }
}
