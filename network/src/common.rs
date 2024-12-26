use crate::Result;

pub trait Provider {
    fn get_network_id(&self) -> u64;
    fn load_network_configs(storage: Arc<LocalStorage>) -> Vec<Self>;
    fn save_network_configs(&self) -> Result<()>;
}
