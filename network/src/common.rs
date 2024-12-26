use crate::Result;
use std::{collections::HashSet, sync::Arc};
use storage::LocalStorage;

pub trait Provider: Sized {
    fn get_network_id(&self) -> u64;
    fn load_network_configs(storage: Arc<LocalStorage>) -> HashSet<Self>;
    fn save_network_config(&self, storage: Arc<LocalStorage>) -> Result<()>;
}
