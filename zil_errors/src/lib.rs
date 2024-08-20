#[derive(Debug, PartialEq, Eq)]
pub enum ZilliqaErrors<'a> {
    Schnorr(&'a str),
    InvalidPubKey,
    InvalidSecretKey,
    InvalidSignTry,
    InvalidEntropy,
    BadRequest,
    FailToParseResponse,
    NetowrkIsDown,
    InvalidPayload,
    InvalidRPCReq(String),
    InvalidJson(String),
}

#[derive(Debug)]
pub enum EvmErrors {
    InvalidSecretKey(String),
    InvalidSign(String),
}

#[derive(Debug)]
pub enum CipherErrors {
    ArgonKeyDerivingError(String),
}

#[derive(Debug)]
pub enum AesGCMErrors {
    EncryptError(String),
    DecryptError(String),
}
