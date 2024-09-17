use bincode::ToBytes;
use config::SYS_SIZE;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::str::FromStr;
use zil_errors::account::AccountErrors;

pub const ACCOUNT_TYPE_SIZE: usize = SYS_SIZE + 1;

#[derive(Debug, PartialEq, Eq)]
pub enum AccountType {
    Ledger(usize),     // Ledger index
    Bip39HD(usize),    // HD key bip39 index
    PrivateKey(usize), // A storage key for cipher secret key
}

impl AccountType {
    pub fn from_bytes(bytes: &[u8; ACCOUNT_TYPE_SIZE]) -> Result<Self, AccountErrors> {
        let code = bytes[0];
        let bytes_value: [u8; SYS_SIZE] = bytes[1..]
            .try_into()
            .or(Err(AccountErrors::InvalidAccountTypeValue))?;
        let value: usize = usize::from_ne_bytes(bytes_value);

        match code {
            0 => Ok(AccountType::Ledger(value)),
            1 => Ok(AccountType::Bip39HD(value)),
            2 => Ok(AccountType::PrivateKey(value)),
            _ => Err(AccountErrors::InvalidAccountTypeCode),
        }
    }

    pub fn code(&self) -> u8 {
        match self {
            AccountType::Ledger(_) => 0,
            AccountType::Bip39HD(_) => 1,
            AccountType::PrivateKey(_) => 2,
        }
    }

    pub fn value(&self) -> usize {
        match self {
            AccountType::Ledger(v) => *v,
            AccountType::Bip39HD(v) => *v,
            AccountType::PrivateKey(v) => *v,
        }
    }
}

impl std::fmt::Display for AccountType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // TODO: unwrap should call
        let hex_str = hex::encode(self.to_bytes().unwrap());

        write!(f, "{}", hex_str)
    }
}

impl FromStr for AccountType {
    type Err = AccountErrors;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(|_| AccountErrors::InvalidAccountTypeCode)?;
        let bytes: [u8; ACCOUNT_TYPE_SIZE] = bytes
            .try_into()
            .or(Err(AccountErrors::InvalidAccountTypeCode))?;

        AccountType::from_bytes(&bytes)
    }
}

impl TryFrom<[u8; ACCOUNT_TYPE_SIZE]> for AccountType {
    type Error = AccountErrors;
    fn try_from(value: [u8; ACCOUNT_TYPE_SIZE]) -> Result<Self, Self::Error> {
        AccountType::from_bytes(&value)
    }
}

impl TryInto<[u8; ACCOUNT_TYPE_SIZE]> for AccountType {
    type Error = AccountErrors;

    fn try_into(self) -> Result<[u8; ACCOUNT_TYPE_SIZE], Self::Error> {
        Ok(self.to_bytes().unwrap())
    }
}

impl ToBytes<{ ACCOUNT_TYPE_SIZE }> for AccountType {
    type Error = AccountErrors;

    fn to_bytes(&self) -> Result<[u8; ACCOUNT_TYPE_SIZE], Self::Error> {
        let mut res = [0u8; ACCOUNT_TYPE_SIZE];
        let code = self.code();
        let value_bytes = self.value().to_ne_bytes();

        res[0] = code;
        res[1..].copy_from_slice(&value_bytes);
        Ok(res)
    }
}

impl Serialize for AccountType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for AccountType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        AccountType::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests_account_type {
    use super::*;

    #[test]
    fn test_bytes_try_into() {
        let origin_acc_type = AccountType::Ledger(42);
        let bytes = origin_acc_type.to_bytes().unwrap();
        let acc = AccountType::from_bytes(&bytes).unwrap();

        assert_eq!(acc, origin_acc_type);
    }

    #[test]
    fn test_invalid_bytes_try_into() {
        let origin_acc_type = AccountType::Ledger(42);
        let mut bytes = origin_acc_type.to_bytes().unwrap();

        bytes[0] = 69;

        let acc = AccountType::from_bytes(&bytes);

        assert_eq!(acc, Err(AccountErrors::InvalidAccountTypeCode));
    }

    #[test]
    fn test_from_to_str() {
        let origin_acc_type = AccountType::Ledger(42);
        let hex_str = origin_acc_type.to_string();
        let restored: AccountType = hex_str.parse().unwrap();

        assert_eq!(origin_acc_type, restored);
    }
}
