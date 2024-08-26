use config::sha::SHA256_SIZE;
use storage::LocalStorage;
use wallet::Wallet;
use zil_errors::ZilliqaErrors;

pub struct Background {
    storage: LocalStorage,
    wallets: Vec<Wallet>,
    selected: usize,
    indicators: Vec<[u8; SHA256_SIZE]>,
    is_old_storage: bool,
}

impl Background {
    pub fn from_storage_path<'a>(path: &str) -> Result<Self, ZilliqaErrors<'a>> {
        let storage = LocalStorage::from(path).map_err(ZilliqaErrors::TryInitLocalStorageError)?;
        let is_old_storage = false; // TODO: check old storage from first ZilPay version

        Ok(Self {
            storage,
            wallets: Vec::new(),
            selected: 0,
            indicators: Vec::new(),
            is_old_storage,
        })
    }
}
