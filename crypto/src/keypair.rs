use std::str::FromStr;

use super::bip49::Bip49DerivationPath;
use super::schnorr;
use config::key::{BIP39_SEED_SIZE, PUB_KEY_SIZE, SECRET_KEY_SIZE};
use tiny_hderive::bip32::ExtendedPrivKey;

use ethers::{
    core::k256::ecdsa::SigningKey,
    signers::LocalWallet,
    types::{transaction::eip2718::TypedTransaction, Signature as EvmSignature, H256},
    utils::hash_message,
};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use k256::{ecdsa, PublicKey, SecretKey};
use zil_errors::{EvmErrors, KeyPairError};

#[derive(Debug)]
pub enum HDDerivePathes {}

#[derive(Debug, PartialEq, Eq)]
pub struct KeyPair {
    pub pub_key: [u8; PUB_KEY_SIZE],
    pub secret_key: [u8; SECRET_KEY_SIZE],
}

impl KeyPair {
    pub fn generate() -> Result<Self, KeyPairError> {
        let mut rng = ChaCha20Rng::from_entropy();
        let mut sk_bytes = [0u8; SECRET_KEY_SIZE];

        rng.fill_bytes(&mut sk_bytes);

        let secret_key = SecretKey::from_slice(&sk_bytes).or(Err(KeyPairError::InvalidEntropy))?;
        let pub_key: [u8; PUB_KEY_SIZE] = secret_key
            .public_key()
            .to_sec1_bytes()
            .to_vec()
            .try_into()
            .or(Err(KeyPairError::InvalidSecretKey))?;
        let secret_key: [u8; SECRET_KEY_SIZE] = secret_key.to_bytes().into();

        Ok(Self {
            secret_key,
            pub_key,
        })
    }

    pub fn from_bip39_seed(
        seed: &[u8; BIP39_SEED_SIZE],
        bip49: &Bip49DerivationPath,
    ) -> Result<Self, KeyPairError> {
        let path = bip49.get_path();
        let ext = ExtendedPrivKey::derive(seed, path.as_str())
            .map_err(|_| KeyPairError::ExtendedPrivKeyDeriveError)?;
        let secret_key =
            SecretKey::from_slice(&ext.secret()).or(Err(KeyPairError::InvalidEntropy))?;
        let pub_key: [u8; PUB_KEY_SIZE] = secret_key
            .public_key()
            .to_sec1_bytes()
            .to_vec()
            .try_into()
            .or(Err(KeyPairError::InvalidSecretKey))?;
        let secret_key: [u8; SECRET_KEY_SIZE] = secret_key.to_bytes().into();

        Ok(Self {
            secret_key,
            pub_key,
        })
    }

    pub fn from_secret_key_bytes(sk: [u8; SECRET_KEY_SIZE]) -> Result<Self, KeyPairError> {
        let secret_key: SecretKey =
            SecretKey::from_slice(&sk).or(Err(KeyPairError::InvalidSecretKey))?;
        let pub_key: [u8; PUB_KEY_SIZE] = secret_key
            .public_key()
            .to_sec1_bytes()
            .to_vec()
            .try_into()
            .or(Err(KeyPairError::InvalidSecretKey))?;

        Ok(Self {
            pub_key,
            secret_key: sk,
        })
    }

    pub fn from_secret_key(sk: SecretKey) -> Result<Self, KeyPairError> {
        let pub_key: [u8; PUB_KEY_SIZE] = sk
            .public_key()
            .to_sec1_bytes()
            .to_vec()
            .try_into()
            .or(Err(KeyPairError::InvalidSecretKey))?;
        let secret_key: [u8; SECRET_KEY_SIZE] = sk.to_bytes().into();

        Ok(Self {
            pub_key,
            secret_key,
        })
    }
    pub fn from_bytes(bytes: &[u8; PUB_KEY_SIZE + SECRET_KEY_SIZE]) -> Self {
        let mut pub_key = [0u8; PUB_KEY_SIZE];
        let mut secret_key = [0u8; SECRET_KEY_SIZE];

        pub_key.copy_from_slice(&bytes[..PUB_KEY_SIZE]);
        secret_key.copy_from_slice(&bytes[PUB_KEY_SIZE..]);

        KeyPair {
            pub_key,
            secret_key,
        }
    }

    pub fn to_bytes(&self) -> [u8; PUB_KEY_SIZE + SECRET_KEY_SIZE] {
        let mut result = [0u8; PUB_KEY_SIZE + SECRET_KEY_SIZE];

        result[..PUB_KEY_SIZE].copy_from_slice(&self.pub_key);
        result[PUB_KEY_SIZE..].copy_from_slice(&self.secret_key);
        result
    }

    pub fn get_zil1_wallet(&self) -> Result<(SecretKey, PublicKey), KeyPairError> {
        let secret_key =
            SecretKey::from_slice(&self.secret_key).or(Err(KeyPairError::InvalidSecretKey))?;
        let pub_key =
            PublicKey::from_sec1_bytes(&self.pub_key).or(Err(KeyPairError::InvalidSecretKey))?;

        Ok((secret_key, pub_key))
    }

    pub fn get_evm_wallet(&self) -> Result<LocalWallet, EvmErrors> {
        let signing_key = SigningKey::from_slice(&self.secret_key)
            .map_err(|e| EvmErrors::InvalidSecretKey(e.to_string()))?;

        Ok(LocalWallet::from(signing_key))
    }

    pub fn sign_message_secp256k1(&self, msg: &[u8]) -> Result<ecdsa::Signature, KeyPairError> {
        let secret_key =
            SecretKey::from_slice(&self.secret_key).or(Err(KeyPairError::InvalidSecretKey))?;

        schnorr::sign(msg, &secret_key).map_err(KeyPairError::SchorrError)
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
        let bytes_str = hex::encode(self.to_bytes());

        write!(f, "{}", bytes_str)
    }
}

impl FromStr for KeyPair {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes: [u8; PUB_KEY_SIZE + SECRET_KEY_SIZE] = hex::decode(s)
            .or(Err("Invalid string format".to_string()))?
            .try_into()
            .or(Err("Invalid string length".to_string()))?;

        Ok(KeyPair::from_bytes(&bytes))
    }
}

#[cfg(test)]
mod tests {
    use crate::bip49::Bip49DerivationPath;

    use super::KeyPair;
    use bip39::Mnemonic;

    #[test]
    fn from_secret_key_secp256k1() {
        use crate::keypair::KeyPair;
        use k256::SecretKey;
        use std::str::FromStr;

        let hex_key = "0F494B8312E8D257E51730C78F8FE3B47B6840C59AAAEC7C2EBE404A2DE8B25A";
        let bytes = hex::decode(hex_key).unwrap();
        let secret_key = SecretKey::from_slice(&bytes).unwrap();
        let keypair = KeyPair::from_secret_key(secret_key).unwrap();

        assert_eq!(
            keypair.to_string(),
            "039e43c9810e6cc09f46aad38e716dae3191629534967dc457d3a687d2e2cddc6a0f494b8312e8d257e51730c78f8fe3b47b6840c59aaaec7c2ebe404a2de8b25a"
        );
        assert_eq!(KeyPair::from_str(&keypair.to_string()).unwrap(), keypair);
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

    #[test]
    fn from_to_bytes() {
        use crate::keypair::KeyPair;

        let key_pair = KeyPair::generate().unwrap();
        let bytes = key_pair.to_bytes();
        let restored_key_pair = KeyPair::from_bytes(&bytes);

        assert_eq!(restored_key_pair.pub_key, key_pair.pub_key);
        assert_eq!(restored_key_pair.secret_key, key_pair.secret_key);
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

        assert_ne!(zil_key_pair.pub_key, eth_key_pair.pub_key);
        assert_ne!(zil_key_pair.secret_key, eth_key_pair.secret_key);

        assert_eq!(
            hex::encode(zil_key_pair.secret_key),
            "e93c035175b08613c4b0251ca92cd007026ca032ba53bafa3c839838f8b52d04"
        );
        assert_eq!(
            hex::encode(eth_key_pair.secret_key),
            "b8ef60193eec0a55db93ba692035a8b5a388579c8dc58acc62ea470aba529e1c"
        );
        assert_eq!(
            hex::encode(eth_key_pair.pub_key),
            "0315bd7b9301a2cde69ef8092d6fb275a077e3c94e5ed166c915426850cf606600"
        );
        assert_eq!(
            hex::encode(zil_key_pair.pub_key),
            "03150a7f37063b134cde30070431a69148d60b252f4c7b38de33d813d329a7b7da"
        );
    }
}
