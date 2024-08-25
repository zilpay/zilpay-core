use cipher::argon2::{derive_key, KEY_SIZE};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

#[derive(Debug)]
pub struct Session {
    cipher_key: Vec<u8>, // TODO: know how much bytes
    nonce: u64,
}

impl Session {
    pub fn from_password(password: &[u8]) {
        let mut rng = ChaCha20Rng::from_entropy();
        let key = derive_key(password);
        let nonce: u64 = rng.gen();
    }
    pub fn from_key(key: &[u8; KEY_SIZE]) {}
}
