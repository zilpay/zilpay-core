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
