use cipher::options::CipherOrders;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct CryptoSettings {
    pub cipher_orders: Vec<CipherOrders>,
}

impl Default for CryptoSettings {
    fn default() -> Self {
        Self {
            cipher_orders: [CipherOrders::AESGCM256, CipherOrders::NTRUP1277].into(),
        }
    }
}
