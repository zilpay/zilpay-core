use bincode::{FromBytes, ToVecBytes};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::str::FromStr;
use zil_errors::cipher::CipherErrors;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum CipherOrders {
    AESGCM256,
    NTRUP1277,
}

impl CipherOrders {
    pub fn from_code(code: u8) -> Result<Self, CipherErrors> {
        match code {
            0 => Ok(CipherOrders::AESGCM256),
            1 => Ok(CipherOrders::NTRUP1277),
            _ => Err(CipherErrors::InvalidTypeCode),
        }
    }

    pub fn code(&self) -> u8 {
        match self {
            CipherOrders::AESGCM256 => 0,
            CipherOrders::NTRUP1277 => 1,
        }
    }
}

impl ToVecBytes for CipherOrders {
    fn to_bytes(&self) -> Vec<u8> {
        vec![self.code()]
    }
}

impl FromBytes for CipherOrders {
    type Error = CipherErrors;
    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Result<Self, Self::Error> {
        Self::from_code(bytes[0])
    }
}

impl std::fmt::Display for CipherOrders {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex_str = hex::encode(self.to_bytes());
        write!(f, "{}", hex_str)
    }
}

impl FromStr for CipherOrders {
    type Err = CipherErrors;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).or(Err(CipherErrors::InvalidTypeCode))?;

        Self::from_code(bytes[0])
    }
}

impl Serialize for CipherOrders {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for CipherOrders {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        CipherOrders::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests_cipher_orders {
    use super::*;

    #[test]
    fn test_ser() {
        let origin_order_ntru = CipherOrders::NTRUP1277;
        let origin_order_aes = CipherOrders::AESGCM256;

        let bytes_ntru = origin_order_ntru.to_bytes();
        let bytes_aes = origin_order_aes.to_bytes();

        let res_ntru = CipherOrders::from_bytes(bytes_ntru.into()).unwrap();
        let res_aes = CipherOrders::from_bytes(bytes_aes.into()).unwrap();

        assert_eq!(res_ntru, origin_order_ntru);
        assert_eq!(res_aes, origin_order_aes);

        let hex_ntru = origin_order_ntru.to_string();
        let hex_aes = origin_order_aes.to_string();

        let res_ntru = CipherOrders::from_str(&hex_ntru).unwrap();
        let res_aes = CipherOrders::from_str(&hex_aes).unwrap();

        assert_eq!(res_ntru, origin_order_ntru);
        assert_eq!(res_aes, origin_order_aes);
    }

    #[test]
    fn test_convert_invalid() {
        let invalid_bytes = vec![3];
        let res_ntru = CipherOrders::from_bytes(invalid_bytes.into());

        assert_eq!(res_ntru, Err(CipherErrors::InvalidTypeCode));

        let invalid_hex = "FF";

        let res_aes = CipherOrders::from_str(invalid_hex);

        assert_eq!(res_aes, Err(CipherErrors::InvalidTypeCode));
    }
}
