use config::sha::SHA256_SIZE;
use storage::Storage;
use wallet::Wallet;

#[derive(Debug)]
pub struct Background {
    wallets: Vec<Wallet>,
    selected: usize,
    storage: Storage,
    indicators: Vec<[u8; SHA256_SIZE]>,
}

impl Default for Background {
    fn default() -> Self {
        Self::new()
    }
}

impl Background {
    pub fn new() -> Self {
        Self {
            wallets: Vec::new(),
            selected: 0,
            indicators: Vec::new(),
            storage: Storage {},
        }
    }
}
