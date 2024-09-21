use thiserror::Error;

use crate::{storage::LocalStorageError, wallet::WalletErrors};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BackgroundError {
    #[error("Failt to get indicators of wallet, storage: {0}")]
    FailTogetIndicators(LocalStorageError),
    #[error("Fail to load from storage selected indicator: {0}")]
    FailToLoadSelectedIndicators(LocalStorageError),
    #[error("Failt to init  storage: {0}")]
    TryInitLocalStorageError(LocalStorageError),
    #[error("Fail to laod wallet from storage: {0}")]
    TryLoadWalletError(WalletErrors),
    #[error("Fail to get slice selected indicators")]
    FailTosliceSelectedIndicators,
}
