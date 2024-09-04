use config::sha::SHA256_SIZE;
use settings::common_settings::CommonSettings;
use storage::LocalStorage;
use wallet::Wallet;
use zil_errors::ZilliqaErrors;

pub struct Background<'a> {
    storage: LocalStorage,
    pub wallets: Vec<Wallet<'a>>,
    pub selected: usize,
    pub indicators: Vec<[u8; SHA256_SIZE]>,
    pub is_old_storage: bool,
    pub settings: CommonSettings,
}

impl<'a> Background<'a> {
    pub fn from_storage_path<'b>(path: &str) -> Result<Self, ZilliqaErrors<'b>> {
        let storage = LocalStorage::from(path).map_err(ZilliqaErrors::TryInitLocalStorageError)?;
        let is_old_storage = false; // TODO: check old storage from first ZilPay version

        Ok(Self {
            storage,
            wallets: Vec::new(),
            selected: 0,
            indicators: Vec::new(),
            is_old_storage,
            settings: Default::default(),
        })
    }
}
