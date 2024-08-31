pub mod data_warp;

use bincode::{FromBytes, ToVecBytes};
use config::storage::STORAGE_VERSION;
use data_warp::DataWarp;
use directories::ProjectDirs;
use sha2::{Digest, Sha256};
use sled::{Db, IVec};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use zil_errors::LocalStorageError;

// pub struct LocalStorage {
//     tree: Db,
//     version: u16,
// }
//
// impl LocalStorage {
//     pub fn from<P: AsRef<Path>>(path: P) -> Result<Self, LocalStorageError> {
//         let tree =
//             sled::open(path).map_err(|e| LocalStorageError::StorageAccessError(e.to_string()))?;
//         let version = STORAGE_VERSION;
//
//         Ok(LocalStorage { tree, version })
//     }
//
//     pub fn new(
//         qualifier: &str,
//         organization: &str,
//         application: &str,
//     ) -> Result<Self, LocalStorageError> {
//         let path = ProjectDirs::from(qualifier, organization, application)
//             .ok_or(LocalStorageError::StoragePathError)?;
//         let tree = sled::open(path.data_dir())
//             .map_err(|e| LocalStorageError::StorageAccessError(e.to_string()))?;
//         let version = Self::VERSION;
//
//         Ok(LocalStorage { tree, version })
//     }
//
//     pub fn save_as_file(&self, path: &Path) -> Result<(), LocalStorageError> {
//         let export = self.tree.export();
//
//         for (_, _, collection_iter) in export {
//             for mut kv in collection_iter {
//                 let bytes = kv.pop().ok_or(LocalStorageError::FailToloadBytesTree)?;
//                 let mut file = File::create(path).or(Err(LocalStorageError::FailToCreateFile))?;
//
//                 file.write_all(&bytes)
//                     .or(Err(LocalStorageError::FailToWriteFile))?;
//             }
//         }
//
//         Ok(())
//     }
//
//     pub fn get_db_size(&self) -> u64 {
//         self.tree.size_on_disk().unwrap_or(0)
//     }
//
//     pub fn get<ST>(&self, key: &[u8]) -> Result<ST, LocalStorageError>
//     where
//         ST: FromBytes + ToVecBytes,
//     {
//         let some_value = self
//             .tree
//             .get(key)
//             .map_err(|e| LocalStorageError::StorageAccessError(e.to_string()))?;
//         let value = some_value.ok_or(LocalStorageError::StorageDataNotFound)?;
//         let data: DataWarp<ST> = value.into();
//
//         Ok(data.payload)
//     }
//
//     pub fn set<ST>(&self, key: &[u8], payload: ST) -> Result<(), LocalStorageError>
//     where
//         ST: FromBytes + ToVecBytes,
//     {
//         let last_update = self.get_unix_time()?;
//         let data = DataWarp {
//             payload,
//             version: self.version,
//         };
//         let vec = IVec::from(data.as_bytes());
//
//         self.tree
//             .insert(key, vec)
//             .or(Err(LocalStorageError::StorageWriteError))?;
//
//         Ok(())
//     }
//
//     fn hash(&self, bytes: &[u8]) -> String {
//         let mut hasher = Sha256::new();
//         hasher.update(bytes);
//         let hashsum = hasher.finalize();
//
//         hex::encode(hashsum)
//     }
//
//     fn get_unix_time(&self) -> Result<u64, LocalStorageError> {
//         let now = SystemTime::now();
//         let since_epoch = now
//             .duration_since(UNIX_EPOCH)
//             .or(Err(LocalStorageError::StorageTimeWentBackwards))?;
//         let u64_time = since_epoch.as_secs();
//
//         Ok(u64_time)
//     }
// }
//
// #[cfg(test)]
// mod storage_tests {
//     use super::*;
//
//     #[test]
//     fn test_read_write() {
//         const KEY: &[u8] = b"TEST_KEY_FOR_STORAGE";
//
//         let db = LocalStorage::new("com.test_write", "WriteTest Corp", "WriteTest App").unwrap();
//         let payload = vec!["test1", "test2", "test3"];
//
//         db.set(KEY, &payload).unwrap();
//
//         let out = db.get::<Vec<String>>(KEY).unwrap();
//
//         assert_eq!(out, payload);
//     }
// }
