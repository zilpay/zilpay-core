use zil_errors::PubKeyError;

pub const PUB_KEY_SIZE: usize = 33;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PubKey {
    Secp256k1Sha256([u8; PUB_KEY_SIZE]),    // ZILLIQA
    Secp256k1Keccak256([u8; PUB_KEY_SIZE]), // Ethereum
}

impl From<[u8; PUB_KEY_SIZE + 1]> for PubKey {
    fn from(bytes: [u8; PUB_KEY_SIZE + 1]) -> Self {
        let key_type = bytes[0];
        let key_data: [u8; PUB_KEY_SIZE] = bytes[1..].try_into().unwrap();

        match key_type {
            0 => PubKey::Secp256k1Sha256(key_data),
            1 => PubKey::Secp256k1Keccak256(key_data),
            _ => panic!("Invalid key type"),
        }
    }
}
impl TryFrom<&[u8]> for PubKey {
    type Error = PubKeyError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        if slice.len() != PUB_KEY_SIZE + 1 {
            return Err(PubKeyError::InvalidLength);
        }

        let key_type = slice[0];
        let key_data: [u8; PUB_KEY_SIZE] = slice[1..]
            .try_into()
            .map_err(|_| PubKeyError::InvalidLength)?;

        match key_type {
            0 => Ok(PubKey::Secp256k1Sha256(key_data)),
            1 => Ok(PubKey::Secp256k1Keccak256(key_data)),
            _ => Err(PubKeyError::InvalidKeyType),
        }
    }
}

impl AsRef<[u8]> for PubKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            PubKey::Secp256k1Sha256(data) => data,
            PubKey::Secp256k1Keccak256(data) => data,
        }
    }
}

impl PubKey {
    pub fn to_bytes(&self) -> [u8; PUB_KEY_SIZE + 1] {
        let mut result = [0u8; PUB_KEY_SIZE + 1];
        result[0] = match self {
            PubKey::Secp256k1Sha256(_) => 0,
            PubKey::Secp256k1Keccak256(_) => 1,
        };
        result[1..].copy_from_slice(self.as_ref());
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_bytes() {
        let zil_bytes = [0u8; PUB_KEY_SIZE + 1];
        let eth_bytes = [1u8; PUB_KEY_SIZE + 1];

        let zil_key = PubKey::from(zil_bytes);
        let eth_key = PubKey::from(eth_bytes);

        assert!(matches!(zil_key, PubKey::Secp256k1Sha256(_)));
        assert!(matches!(eth_key, PubKey::Secp256k1Keccak256(_)));
    }

    #[test]
    fn test_try_from_slice() {
        let zil_slice = &[0u8; PUB_KEY_SIZE + 1][..];
        let eth_slice = &[1u8; PUB_KEY_SIZE + 1][..];
        let invalid_slice = &[2u8; PUB_KEY_SIZE + 1][..];
        let short_slice = &[0u8; PUB_KEY_SIZE][..];

        assert!(matches!(
            PubKey::try_from(zil_slice),
            Ok(PubKey::Secp256k1Sha256(_))
        ));
        assert!(matches!(
            PubKey::try_from(eth_slice),
            Ok(PubKey::Secp256k1Keccak256(_))
        ));
        assert!(matches!(
            PubKey::try_from(invalid_slice),
            Err(PubKeyError::InvalidKeyType)
        ));
        assert!(matches!(
            PubKey::try_from(short_slice),
            Err(PubKeyError::InvalidLength)
        ));
    }

    #[test]
    fn test_as_ref() {
        let data = [42u8; PUB_KEY_SIZE];
        let zil_key = PubKey::Secp256k1Sha256(data);
        let eth_key = PubKey::Secp256k1Keccak256(data);

        assert_eq!(zil_key.as_ref(), &data);
        assert_eq!(eth_key.as_ref(), &data);
    }

    #[test]
    fn test_to_bytes() {
        let data = [42u8; PUB_KEY_SIZE];
        let zil_key = PubKey::Secp256k1Sha256(data);
        let eth_key = PubKey::Secp256k1Keccak256(data);

        let zil_bytes = zil_key.to_bytes();
        let eth_bytes = eth_key.to_bytes();

        assert_eq!(zil_bytes[0], 0);
        assert_eq!(eth_bytes[0], 1);
        assert_eq!(&zil_bytes[1..], &data);
        assert_eq!(&eth_bytes[1..], &data);
    }

    #[test]
    fn test_roundtrip() {
        let original_data = [42u8; PUB_KEY_SIZE];
        let zil_key = PubKey::Secp256k1Sha256(original_data);
        let eth_key = PubKey::Secp256k1Keccak256(original_data);

        let zil_bytes = zil_key.to_bytes();
        let eth_bytes = eth_key.to_bytes();

        let zil_key_roundtrip = PubKey::from(zil_bytes);
        let eth_key_roundtrip = PubKey::from(eth_bytes);

        assert_eq!(zil_key, zil_key_roundtrip);
        assert_eq!(eth_key, eth_key_roundtrip);
    }
}
