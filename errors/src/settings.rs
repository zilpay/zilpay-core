use thiserror::Error;

use crate::cipher::CipherErrors;

#[derive(Debug, Error, PartialEq)]
pub enum SettingsErrors {
    #[error("Invalid option for convert from string")]
    InvlidStringOption,

    #[error("Invalid theme code: {0}")]
    InvalidThemeCode(u8),

    #[error("Invalid hex: {0}")]
    InvalidHex(String),

    #[error("Cipher Error: {0}")]
    CipherErrors(CipherErrors),
}

impl From<CipherErrors> for SettingsErrors {
    fn from(value: CipherErrors) -> Self {
        SettingsErrors::CipherErrors(value)
    }
}
