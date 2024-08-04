use crypto::keypair::{KeyPair, PUB_KEY_SIZE, SECRET_KEY_SIZE};
use proto::address::Address;
use proto::address::ADDR_LEN;
use zil_errors::ZilliqaErrors;

#[derive(Debug)]
pub struct Account {
    pub key_pair: KeyPair,
    pub address: Address,
}

impl Account {
    pub fn generate<'a>() -> Result<Self, ZilliqaErrors<'a>> {
        let key_pair = KeyPair::generate()?;
        let address = Address::from_zil_pub_key(&key_pair.pub_key)?;

        Ok(Self { key_pair, address })
    }

    pub fn from_bytes<'a>(
        bytes: [u8; PUB_KEY_SIZE + SECRET_KEY_SIZE + ADDR_LEN],
    ) -> Result<Self, ZilliqaErrors<'a>> {
        let mut key_pair_bytes: [u8; PUB_KEY_SIZE + SECRET_KEY_SIZE] =
            [0u8; PUB_KEY_SIZE + SECRET_KEY_SIZE];
        let mut address: [u8; ADDR_LEN] = [0u8; ADDR_LEN];

        key_pair_bytes.copy_from_slice(&bytes[..PUB_KEY_SIZE + SECRET_KEY_SIZE]);
        address.copy_from_slice(&bytes[PUB_KEY_SIZE + SECRET_KEY_SIZE..]);

        Ok(Self {
            key_pair: KeyPair::from_bytes(&key_pair_bytes),
            address: Address::from_bytes(address),
        })
    }

    pub fn from_secret_key<'a>(sk: [u8; SECRET_KEY_SIZE]) -> Result<Self, ZilliqaErrors<'a>> {
        let key_pair = KeyPair::from_secret_key_bytes(sk)?;
        let address = Address::from_zil_pub_key(&key_pair.pub_key)?;

        Ok(Self { key_pair, address })
    }

    pub fn from_key_pair<'a>(key_pair: KeyPair) -> Result<Self, ZilliqaErrors<'a>> {
        let address = Address::from_zil_pub_key(&key_pair.pub_key)?;

        Ok(Self { key_pair, address })
    }

    pub fn to_bytes(&self) -> [u8; PUB_KEY_SIZE + SECRET_KEY_SIZE + ADDR_LEN] {
        let mut result = [0u8; PUB_KEY_SIZE + SECRET_KEY_SIZE + ADDR_LEN];

        result[..PUB_KEY_SIZE + SECRET_KEY_SIZE].copy_from_slice(&self.key_pair.to_bytes());
        result[PUB_KEY_SIZE + SECRET_KEY_SIZE..].copy_from_slice(&self.address.to_bytes());

        result
    }
}

impl std::fmt::Display for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex_acc = hex::encode(self.to_bytes());

        write!(f, "{}", hex_acc)
    }
}
