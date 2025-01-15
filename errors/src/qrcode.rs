use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum QRCodeError {
    #[error("Invalid address format")]
    InvalidAddress,

    #[error("Invalid amount format")]
    InvalidAmount,

    #[error("Invalid QR code format")]
    InvalidFormat,

    #[error("Invalid Provider")]
    InvalidProvider,

    #[error("Invalid token address")]
    InvalidTokenAddress,
}
