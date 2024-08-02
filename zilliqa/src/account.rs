use crypto::keypair::{KeyPair, SECRET_KEY_SIZE};
use proto::address::Address;

#[derive(Debug)]
pub struct Account {
    pub key_pair: KeyPair,
    pub address: Address,
}

impl Account {
    pub fn from_secret_key(sk: &[u8; SECRET_KEY_SIZE]) {
        Self {}
    }
}
