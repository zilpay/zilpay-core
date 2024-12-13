use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SettingsErrors {
    #[error("Invalid option for convert from string")]
    InvlidStringOption,

    #[error("Invalid theme code: {0}")]
    InvalidThemeCode(u8),
}
