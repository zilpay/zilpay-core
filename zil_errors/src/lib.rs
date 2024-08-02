#[derive(Debug)]
pub enum ZilliqaErrors<'a> {
    Schnorr(&'a str),
    InvalidPubKey,
    InvalidSecretKey,
    InvalidSignTry,
    InvalidEntropy,
}

#[derive(Debug)]
pub enum EvmErrors {
    InvalidSecretKey(String),
    InvalidSign(String),
}
