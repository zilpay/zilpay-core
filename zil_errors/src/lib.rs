#[derive(Debug)]
pub enum ZilliqaErrors<'a> {
    Schnorr(&'a str),
    InvalidSecretKey,
    InvalidSignTry,
}

#[derive(Debug)]
pub enum EvmErrors {
    InvalidSecretKey(String),
    InvalidSign(String),
}
