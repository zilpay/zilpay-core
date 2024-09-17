use bincode::{FromBytes, ToVecBytes};
use config::SYS_SIZE;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zil_errors::wallet::WalletErrors;

#[derive(Debug, PartialEq, Eq)]
pub enum WalletTypes {
    Ledger(usize), // Ledger product_id
    // Cipher for entropy secret words storage_key / passphrase
    SecretPhrase((usize, bool)),
    SecretKey,
}

impl WalletTypes {
    pub fn code(&self) -> u8 {
        match self {
            Self::Ledger(_) => 0,
            Self::SecretPhrase(_) => 1,
            Self::SecretKey => 2,
        }
    }
}

impl std::fmt::Display for WalletTypes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex_str = hex::encode(self.to_bytes());
        write!(f, "{}", hex_str)
    }
}

impl ToVecBytes for WalletTypes {
    fn to_bytes(&self) -> Vec<u8> {
        let code = self.code();

        match self {
            Self::Ledger(value) => {
                let mut bytes = vec![0u8; SYS_SIZE + 1];

                bytes[0] = code;
                bytes[1..].copy_from_slice(&value.to_ne_bytes());

                bytes
            }
            Self::SecretPhrase((storage_key, passphrase)) => {
                let mut bytes = vec![0u8; SYS_SIZE + 2];

                bytes[0] = code;

                if *passphrase {
                    bytes[1] = 1;
                } else {
                    bytes[1] = 0;
                }

                bytes[2..].copy_from_slice(&storage_key.to_ne_bytes());

                bytes
            }
            Self::SecretKey => {
                vec![code]
            }
        }
    }
}

impl FromBytes for WalletTypes {
    type Error = WalletErrors;

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Result<Self, Self::Error> {
        match bytes[0] {
            0 => {
                let bytes_value: [u8; SYS_SIZE] = bytes[1..]
                    .try_into()
                    .or(Err(WalletErrors::InvalidWalletTypeValue))?;
                let value: usize = usize::from_ne_bytes(bytes_value);

                Ok(Self::Ledger(value))
            }
            1 => {
                let passphrase = if bytes[1] == 1 {
                    true
                } else if bytes[1] == 0 {
                    false
                } else {
                    return Err(WalletErrors::InvalidWalletTypeValue);
                };
                let bytes_value: [u8; SYS_SIZE] = bytes[2..]
                    .try_into()
                    .or(Err(WalletErrors::InvalidWalletTypeValue))?;
                let value: usize = usize::from_ne_bytes(bytes_value);

                Ok(Self::SecretPhrase((value, passphrase)))
            }
            2 => Ok(Self::SecretKey),
            _ => Err(WalletErrors::UnknownWalletType(bytes[0])),
        }
    }
}

#[cfg(test)]
mod tests_wallet_type {
    use super::*;

    #[test]
    fn tests_wallet_type_bytes() {
        let ledger_type = WalletTypes::Ledger(42);
        let secret_phrase_type = WalletTypes::SecretPhrase((69, true));
        let secret_key_type = WalletTypes::SecretKey;

        let ledger_type_bytes = ledger_type.to_bytes();
        let secret_phrase_type_bytes = secret_phrase_type.to_bytes();
        let secret_key_type_bytes = secret_key_type.to_bytes();

        let res_ledger_type = WalletTypes::from_bytes(ledger_type_bytes.into()).unwrap();
        let res_secret_phrase_type =
            WalletTypes::from_bytes(secret_phrase_type_bytes.into()).unwrap();
        let res_secret_key_type = WalletTypes::from_bytes(secret_key_type_bytes.into()).unwrap();

        assert_eq!(res_ledger_type, ledger_type);
        assert_eq!(res_secret_phrase_type, secret_phrase_type);
        assert_eq!(res_secret_key_type, res_secret_key_type);
    }
}
