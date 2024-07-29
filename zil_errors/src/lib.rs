#[derive(Debug)]
pub enum ZilliqaErrors<'a> {
    Schnorr(&'a str),
    InvalidSecretKey,
    InvalidSignTry,
    InvalidEntropy,
}

#[derive(Debug)]
pub enum EvmErrors {
    InvalidSecretKey(String),
    InvalidSign(String),
}
