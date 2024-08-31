pub mod data_warp;

use bincode::{FromBytes, ToVecBytes};
use config::storage::STORAGE_VERSION;
use data_warp::DataWarp;
use directories::ProjectDirs;
use sled::{Db, IVec};
use std::path::Path;
use zil_errors::LocalStorageError;

pub struct LocalStorage {
    tree: Db,
    version: u16,
}

impl LocalStorage {
    pub fn from<P: AsRef<Path>>(path: P) -> Result<Self, LocalStorageError> {
        let tree =
            sled::open(path).map_err(|e| LocalStorageError::StorageAccessError(e.to_string()))?;
        let version = STORAGE_VERSION;

        Ok(LocalStorage { tree, version })
    }

    pub fn new(
        qualifier: &str,
        organization: &str,
        application: &str,
    ) -> Result<Self, LocalStorageError> {
        let path = ProjectDirs::from(qualifier, organization, application)
            .ok_or(LocalStorageError::StoragePathError)?;
        let tree = sled::open(path.data_dir())
            .map_err(|e| LocalStorageError::StorageAccessError(e.to_string()))?;
        let version = STORAGE_VERSION;

        Ok(LocalStorage { tree, version })
    }

    pub fn get_db_size(&self) -> u64 {
        self.tree.size_on_disk().unwrap_or(0)
    }

    pub fn get(&self, key: &[u8]) -> Result<Vec<u8>, LocalStorageError> {
        let some_value = self
            .tree
            .get(key)
            .map_err(|e| LocalStorageError::StorageAccessError(e.to_string()))?;
        let value = some_value
            .ok_or(LocalStorageError::StorageDataNotFound)?
            .to_vec();
        let data = DataWarp::from_bytes(value.into())?;

        Ok(data.payload)
    }

    pub fn set(&self, key: &[u8], payload: Vec<u8>) -> Result<(), LocalStorageError> {
        let data = DataWarp {
            payload,
            version: self.version,
        };
        let vec = IVec::from(data.to_bytes());

        self.tree
            .insert(key, vec)
            .or(Err(LocalStorageError::StorageWriteError))?;

        Ok(())
    }
}

#[cfg(test)]
mod storage_tests {
    use super::*;

    #[test]
    fn test_read_write() {
        const KEY: &[u8] = b"TEST_KEY_FOR_STORAGE";

        let payload = b"Hello, World!".to_vec();
        let db = LocalStorage::new("com.test_write", "WriteTest Corp", "WriteTest App").unwrap();

        db.set(KEY, payload.clone()).unwrap();

        let out = db.get(KEY).unwrap();

        assert_eq!(out, payload);
    }
}
