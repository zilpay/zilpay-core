use crypto::keypair::{KeyPair, SECRET_KEY_SIZE};
use proto::address::Address;
use zil_errors::ZilliqaErrors;

#[derive(Debug)]
pub struct Account {
    pub key_pair: KeyPair,
    pub address: Address,
}

impl Account {
    pub fn from_secret_key<'a>(sk: [u8; SECRET_KEY_SIZE]) -> Result<Self, ZilliqaErrors<'a>> {
        let key_pair = KeyPair::from_secret_key_bytes(sk)?;
        let address = Address::from_zil_pub_key(&key_pair.pub_key)?;

        Ok(Self { key_pair, address })
    }
}
