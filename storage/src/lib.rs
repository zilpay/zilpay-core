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

    pub fn get<ST>(&self, key: &[u8]) -> Result<ST, LocalStorageError>
    where
        ST: FromBytes + ToVecBytes,
    {
        let some_value = self
            .tree
            .get(key)
            .map_err(|e| LocalStorageError::StorageAccessError(e.to_string()))?;
        let value = some_value
            .ok_or(LocalStorageError::StorageDataNotFound)?
            .to_vec();
        let data: DataWarp<ST> = DataWarp::from_bytes(&value)?;

        Ok(data.payload)
    }

    pub fn set<ST>(&self, key: &[u8], payload: ST) -> Result<(), LocalStorageError>
    where
        ST: FromBytes + ToVecBytes,
    {
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

    #[derive(Debug, PartialEq, Clone)]
    struct TestPayload {
        data: String,
    }

    impl bincode::ToVecBytes for TestPayload {
        fn to_bytes(&self) -> Vec<u8> {
            self.data.as_bytes().to_vec()
        }
    }

    impl bincode::FromBytes for TestPayload {
        type Error = LocalStorageError;

        fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
            String::from_utf8(bytes.to_vec())
                .map(|data| TestPayload { data })
                .map_err(|_| LocalStorageError::PayloadParseError)
        }
    }

    #[test]
    fn test_read_write() {
        const KEY: &[u8] = b"TEST_KEY_FOR_STORAGE";

        let payload = TestPayload {
            data: "Hello, World!".to_string(),
        };
        let db = LocalStorage::new("com.test_write", "WriteTest Corp", "WriteTest App").unwrap();

        db.set(KEY, payload.clone()).unwrap();

        let out = db.get::<TestPayload>(KEY).unwrap();

        assert_eq!(out, payload);
    }
}
