use super::schnorr;
use k256::{ecdsa, SecretKey};
use zil_errors::ZilliqaErrors;

pub const PUB_KEY_SIZE: usize = 33;
pub const SECRET_KEY_SIZE: usize = 32;

#[derive(Debug)]
pub struct KeyPair {
    pub pub_key: [u8; PUB_KEY_SIZE],
    pub secret_key: [u8; SECRET_KEY_SIZE],
}

impl KeyPair {
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

    pub fn sign_secp256k1(&self, msg: &[u8]) -> Result<ecdsa::Signature, ZilliqaErrors> {
        let secret_key =
            SecretKey::from_slice(&self.secret_key).or(Err(ZilliqaErrors::InvalidSecretKey))?;

        schnorr::sign(msg, &secret_key)
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
    fn signing() {
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
}
