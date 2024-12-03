use std::str::FromStr;

use bincode::{FromBytes, ToVecBytes};
use config::SYS_SIZE;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zil_errors::wallet::WalletErrors;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum WalletTypes {
    Ledger(Vec<u8>), // Ledger product_id or uuid
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

    pub fn to_str(self) -> String {
        match self {
            Self::Ledger(bytes) => format!("ledger.{:?}", hex::encode(bytes)),
            Self::SecretPhrase((_, pass)) => format!("SecretPhrase.{:?}", pass),
            Self::SecretKey => "SecretKey".to_string(),
        }
    }
}

impl std::fmt::Display for WalletTypes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex_str = hex::encode(self.to_bytes());
        write!(f, "{}", hex_str)
    }
}

impl FromStr for WalletTypes {
    type Err = WalletErrors;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(|_| WalletErrors::InvalidHexToWalletType)?;

        WalletTypes::from_bytes(bytes.into())
    }
}

impl ToVecBytes for WalletTypes {
    fn to_bytes(&self) -> Vec<u8> {
        let code = self.code();

        match self {
            Self::Ledger(value) => {
                let mut bytes = vec![];

                bytes.push(code);
                bytes.extend_from_slice(value);

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

impl Serialize for WalletTypes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for WalletTypes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        WalletTypes::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl FromBytes for WalletTypes {
    type Error = WalletErrors;

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Result<Self, Self::Error> {
        match bytes[0] {
            0 => Ok(Self::Ledger(bytes[1..].to_vec())),
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
    use rand::RngCore;

    use super::*;

    #[test]
    fn tests_wallet_type_convert() {
        let mut rng = rand::thread_rng();
        let mut ledger_uuid = vec![0u8; 128];

        rng.fill_bytes(&mut ledger_uuid);

        let ledger_type = WalletTypes::Ledger(ledger_uuid);
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

        let ledger_type_hex = ledger_type.to_string();
        let secret_phrase_type_hex = secret_phrase_type.to_string();
        let secret_key_type_hex = secret_key_type.to_string();

        let res_ledger_type = WalletTypes::from_str(&ledger_type_hex).unwrap();
        let res_secret_phrase_type = WalletTypes::from_str(&secret_phrase_type_hex).unwrap();
        let res_secret_key_type = WalletTypes::from_str(&secret_key_type_hex).unwrap();

        assert_eq!(res_ledger_type, ledger_type);
        assert_eq!(res_secret_phrase_type, secret_phrase_type);
        assert_eq!(res_secret_key_type, res_secret_key_type);
    }
}
