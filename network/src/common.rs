use crate::Result;
use std::sync::Arc;
use storage::LocalStorage;

pub trait Provider: Sized {
    fn load_network_configs(storage: Arc<LocalStorage>) -> Vec<Self>;
    fn save_network_configs(providers: &[Self], storage: Arc<LocalStorage>) -> Result<()>;
}
