use zil_errors::AddressError;

use crate::zil_address::ADDR_LEN;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Address {
    Secp256k1Sha256([u8; ADDR_LEN]),    // ZILLIQA
    Secp256k1Keccak256([u8; ADDR_LEN]), // Ethereum
}

impl Address {
    pub fn to_bytes(&self) -> [u8; ADDR_LEN + 1] {
        let mut result = [0u8; ADDR_LEN + 1];
        result[0] = match self {
            Address::Secp256k1Sha256(_) => 0,
            Address::Secp256k1Keccak256(_) => 1,
        };
        result[1..].copy_from_slice(self.as_ref());
        result
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.to_bytes()))
    }
}

impl From<[u8; ADDR_LEN + 1]> for Address {
    fn from(bytes: [u8; ADDR_LEN + 1]) -> Self {
        let key_type = bytes[0];
        let key_data: [u8; ADDR_LEN] = bytes[1..].try_into().unwrap();

        match key_type {
            0 => Address::Secp256k1Sha256(key_data),
            1 => Address::Secp256k1Keccak256(key_data),
            _ => panic!("Invalid key type"),
        }
    }
}

impl TryFrom<&[u8]> for Address {
    type Error = AddressError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        if slice.len() != ADDR_LEN + 1 {
            return Err(AddressError::InvalidLength);
        }

        let key_type = slice[0];
        let key_data: [u8; ADDR_LEN] = slice[1..]
            .try_into()
            .map_err(|_| AddressError::InvalidLength)?;

        match key_type {
            0 => Ok(Address::Secp256k1Sha256(key_data)),
            1 => Ok(Address::Secp256k1Keccak256(key_data)),
            _ => Err(AddressError::InvalidKeyType),
        }
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        match self {
            Address::Secp256k1Sha256(data) => data,
            Address::Secp256k1Keccak256(data) => data,
        }
    }
}
