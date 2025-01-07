use serde::{Deserialize, Serialize};
use std::str::FromStr;
use errors::account::AccountErrors;

type Result<T> = std::result::Result<T, AccountErrors>;

#[derive(Debug, PartialEq, Eq, Clone, Deserialize, Serialize)]
pub enum AccountType {
    Ledger(usize),     // Ledger cipher index
    Bip39HD(usize),    // HD key bip39 index
    PrivateKey(usize), // A storage key for cipher secret key
}

impl AccountType {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| AccountErrors::AccountTypeSerdeError(e.to_string()))
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

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(&self).map_err(|e| AccountErrors::AccountTypeSerdeError(e.to_string()))
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

    fn from_str(s: &str) -> Result<Self> {
        let bytes =
            hex::decode(s).map_err(|e| AccountErrors::AccountTypeSerdeError(e.to_string()))?;

        AccountType::from_bytes(&bytes)
    }
}

impl TryFrom<&[u8]> for AccountType {
    type Error = AccountErrors;
    fn try_from(value: &[u8]) -> Result<Self> {
        AccountType::from_bytes(value)
    }
}

impl TryInto<Vec<u8>> for AccountType {
    type Error = AccountErrors;

    fn try_into(self) -> Result<Vec<u8>> {
        self.to_bytes()
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
    fn test_from_to_str() {
        let origin_acc_type = AccountType::Ledger(42);
        let hex_str = origin_acc_type.to_string();
        let restored: AccountType = hex_str.parse().unwrap();

        assert_eq!(origin_acc_type, restored);
    }
}
