use rpc::network_config::NetworkConfig;

/// Network management operations
pub trait NetworkOperations {
    type Error;

    /// Adds a new network provider
    fn add_provider(&mut self, provider: NetworkConfig) -> Result<(), Self::Error>;

    /// Removes an existing network provider
    fn remove_provider(&mut self, id: u64) -> Result<(), Self::Error>;
}
