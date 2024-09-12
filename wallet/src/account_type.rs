use bincode::ToBytes;
use config::SYS_SIZE;
use zil_errors::AccountErrors;

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
        let bytes_value: [u8; SYS_SIZE] = bytes[1..].try_into().unwrap();
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
}
