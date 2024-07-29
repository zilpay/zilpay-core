pub use k256::{ecdsa::Signature, PublicKey, SecretKey};

pub struct KeyPair {
    pub_key: PublicKey,
    secret_key: SecretKey,
}

impl KeyPair {
    pub fn from_secret_key(secret_key: SecretKey) -> Self {
        let pub_key = secret_key.public_key();

        Self {
            pub_key,
            secret_key,
        }
    }
}
