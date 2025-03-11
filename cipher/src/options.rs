use errors::cipher::CipherErrors;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::str::FromStr;

type Result<T> = std::result::Result<T, CipherErrors>;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum CipherOrders {
    AESGCM256,
    KUZNECHIK,
    NTRUP1277,
    CYBER,
}

impl CipherOrders {
    pub fn from_code(code: u8) -> Result<Self> {
        match code {
            0 => Ok(CipherOrders::AESGCM256),
            1 => Ok(CipherOrders::KUZNECHIK),
            2 => Ok(CipherOrders::NTRUP1277),
            3 => Ok(CipherOrders::CYBER),
            _ => Err(CipherErrors::InvalidTypeCode),
        }
    }

    pub fn code(&self) -> u8 {
        match self {
            CipherOrders::AESGCM256 => 0,
            CipherOrders::KUZNECHIK => 1,
            CipherOrders::NTRUP1277 => 2,
            CipherOrders::CYBER => 3,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        vec![self.code()]
    }

    pub fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Result<Self> {
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

    fn from_str(s: &str) -> Result<Self> {
        let bytes = hex::decode(s).or(Err(CipherErrors::InvalidTypeCode))?;

        Self::from_code(bytes[0])
    }
}

impl Serialize for CipherOrders {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<<S as serde::Serializer>::Ok, <S as serde::Serializer>::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for CipherOrders {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
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
        let origin_order_kuz = CipherOrders::KUZNECHIK;
        let origin_order_cyber = CipherOrders::CYBER;

        let bytes_ntru = origin_order_ntru.to_bytes();
        let bytes_aes = origin_order_aes.to_bytes();
        let bytes_kuz = origin_order_kuz.to_bytes();
        let bytes_cyber = origin_order_cyber.to_bytes();

        let res_ntru = CipherOrders::from_bytes(bytes_ntru.into()).unwrap();
        let res_aes = CipherOrders::from_bytes(bytes_aes.into()).unwrap();
        let res_kuz = CipherOrders::from_bytes(bytes_kuz.into()).unwrap();
        let res_cyber = CipherOrders::from_bytes(bytes_cyber.into()).unwrap();

        assert_eq!(res_ntru, origin_order_ntru);
        assert_eq!(res_aes, origin_order_aes);
        assert_eq!(res_kuz, origin_order_kuz);
        assert_eq!(res_cyber, origin_order_cyber);

        let hex_ntru = origin_order_ntru.to_string();
        let hex_aes = origin_order_aes.to_string();
        let hex_kuz = origin_order_kuz.to_string();
        let hex_cyber = origin_order_cyber.to_string();

        let res_ntru = CipherOrders::from_str(&hex_ntru).unwrap();
        let res_aes = CipherOrders::from_str(&hex_aes).unwrap();
        let res_kuz = CipherOrders::from_str(&hex_kuz).unwrap();
        let res_cyber = CipherOrders::from_str(&hex_cyber).unwrap();

        assert_eq!(res_ntru, origin_order_ntru);
        assert_eq!(res_aes, origin_order_aes);
        assert_eq!(res_kuz, origin_order_kuz);
        assert_eq!(res_cyber, origin_order_cyber);
    }

    #[test]
    fn test_convert_invalid() {
        let invalid_bytes = vec![4]; // 4 теперь недопустимый код (было 3)
        let res_ntru = CipherOrders::from_bytes(invalid_bytes.into());

        assert_eq!(res_ntru, Err(CipherErrors::InvalidTypeCode));

        let invalid_hex = "FF";

        let res_aes = CipherOrders::from_str(invalid_hex);

        assert_eq!(res_aes, Err(CipherErrors::InvalidTypeCode));
    }
}
