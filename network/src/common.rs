pub trait Provider {
    fn get_network_id(&self) -> u64;
}
