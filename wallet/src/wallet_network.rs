use network::provider::NetworkProvider;

/// Network management operations
pub trait NetworkOperations {
    type Error;

    /// Adds a new network provider
    fn add_provider(&mut self, provider: NetworkProvider) -> Result<(), Self::Error>;

    /// Removes an existing network provider
    fn remove_provider(&mut self, provider: &NetworkProvider) -> Result<(), Self::Error>;

    /// Sets the active network provider
    fn set_active_provider(&mut self, provider: NetworkProvider) -> Result<(), Self::Error>;
}
