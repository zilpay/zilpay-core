use config::sha::{SHA256_SIZE, SHA512_SIZE};

#[derive(Debug)]
pub struct Session {
    key: [u8; SHA512_SIZE],
    nonce: [u8; SHA256_SIZE],
}

#[cfg(test)]
mod tests {}
