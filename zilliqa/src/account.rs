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

    pub fn from_key_pair<'a>(key_pair: KeyPair) -> Result<Self, ZilliqaErrors<'a>> {
        let address = Address::from_zil_pub_key(&key_pair.pub_key)?;

        Ok(Self { key_pair, address })
    }
}

impl std::fmt::Display for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let key_pair = self.key_pair.to_string();
        let hex_address = hex::encode(self.address.as_slice());

        write!(f, "{}:{}", key_pair, hex_address)
    }
}
