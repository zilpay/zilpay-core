#[derive(Debug)]
pub enum ZilliqaErrors<'a> {
    Schnorr(&'a str),
    InvalidSecretKey,
    InvalidSignTry,
}
