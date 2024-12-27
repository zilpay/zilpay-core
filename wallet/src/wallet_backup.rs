/// Wallet backup operations
pub trait WalletBackup {
    type Error;

    /// Creates an encrypted backup of the wallet
    fn create_backup(&self, password: &str) -> Result<Vec<u8>, Self::Error>;

    /// Restores wallet from an encrypted backup
    fn restore_from_backup(backup: &[u8], password: &str) -> Result<Self, Self::Error>
    where
        Self: Sized;
}
