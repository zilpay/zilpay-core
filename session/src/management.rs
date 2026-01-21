use std::{sync::Arc, time::Duration};

use errors::session::SessionErrors;
use secrecy::SecretSlice;
use storage::LocalStorage;

pub trait SessionManagement {
    fn create_session(&self, words_bytes: SecretSlice<u8>) -> Result<(), SessionErrors>;
    fn unlock_session(&self) -> Result<SecretSlice<u8>, SessionErrors>;
    fn is_session_active(&self) -> bool;
    fn clear_session(&self) -> Result<(), SessionErrors>;
}

pub struct SessionManager {
    storage: Arc<LocalStorage>,
    ttl: Duration,
}

impl SessionManager {
    pub fn new(storage: Arc<LocalStorage>, ttl_secs: u64) -> Self {
        Self {
            storage,
            ttl: Duration::from_secs(ttl_secs),
        }
    }
}

impl SessionManagement for SessionManager {
    fn create_session(&self, words_bytes: SecretSlice<u8>) -> Result<(), SessionErrors> {
        todo!()
    }

    fn unlock_session(&self) -> Result<SecretSlice<u8>, SessionErrors> {
        todo!()
    }

    fn is_session_active(&self) -> bool {
        todo!()
    }

    fn clear_session(&self) -> Result<(), SessionErrors> {
        todo!()
    }
}
