use storage::LocalStorageError;

pub mod account;
pub mod address;
pub mod background;
pub mod cipher;
pub mod crypto;
pub mod keychain;
pub mod keypair;
pub mod ntru;
pub mod session;
pub mod storage;
pub mod wallet;

#[derive(Debug, PartialEq, Eq)]
pub enum ZilliqaNetErrors {
    BadRequest,
    FailToParseResponse,
    NetowrkIsDown,
    InvalidPayload,
    InvalidRPCReq(String),
    InvalidJson(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum EvmErrors {
    InvalidSecretKey(String),
    InvalidSign(String),
}
