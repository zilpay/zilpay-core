use std::str::FromStr;

use crypto::keypair::{KeyPair, PUB_KEY_SIZE, SECRET_KEY_SIZE};
use proto::address::Address;
use proto::address::ADDR_LEN;
use zil_errors::ZilliqaErrors;

#[derive(Debug, PartialEq, Eq)]
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

        dbg!(&hex_acc);

        write!(f, "{}", hex_acc)
    }
}

impl FromStr for Account {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes: [u8; PUB_KEY_SIZE + SECRET_KEY_SIZE + ADDR_LEN] = hex::decode(s)
            .or(Err("Invalid string format".to_string()))?
            .try_into()
            .or(Err("Invalid string length".to_string()))?;
        let account = Account::from_bytes(bytes).or(Err("Invalid hex".to_string()))?;

        Ok(account)
    }
}

#[cfg(test)]
mod tests {
    use super::{Account, FromStr};

    #[test]
    fn generate() {
        let acc = Account::generate();

        assert!(acc.is_ok());
    }

    #[test]
    fn from_to_bytes() {
        let acc = Account::generate().unwrap();
        let bytes = acc.to_bytes();
        let restored = Account::from_bytes(bytes).unwrap();

        assert_eq!(restored, acc);
    }

    #[test]
    fn test_str() {
        let acc = Account::generate().unwrap();
        let shoudl_be = "02e91c375e5bdb8f99eb6ad70ab2f1004f7e735f4a949df7cd95b72e91e44e9bbde9d2a1c1f95e6a7226afdf56a9217afa44c076d3f16bf6d4ecd61ce3b29ab82dc3832f9b09525c14dca01cd4bd3f9d190762c27e";

        assert_eq!(acc.to_string(), shoudl_be);
        // assert_eq!(acc, shoudl_be.parse::<Account>().unwrap());
    }
}
