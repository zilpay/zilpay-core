use crate::{bg_wallet::WalletManagement, Result};

use config::storage::CONNECTIONS_LIST_DB_KEY;
use errors::background::BackgroundError;

use crate::{connections::Connection, Background};

/// Manages connections between wallets and external services
pub trait ConnectionManagement {
    type Error;

    fn get_connections(&self, wallet_index: usize) -> Vec<Connection>;
    fn get_db_key(&self, wallet_index: usize) -> std::result::Result<Vec<u8>, Self::Error>;

    fn add_connection(
        &self,
        wallet_index: usize,
        connection: Connection,
    ) -> std::result::Result<(), Self::Error>;
    fn remove_connection(
        &self,
        wallet_index: usize,
        domain: &str,
    ) -> std::result::Result<(), Self::Error>;
    fn save_connection(
        &self,
        wallet_index: usize,
        connections: Vec<Connection>,
    ) -> std::result::Result<(), Self::Error>;
}

impl ConnectionManagement for Background {
    type Error = BackgroundError;

    fn get_db_key(&self, wallet_index: usize) -> std::result::Result<Vec<u8>, Self::Error> {
        let wallet = self.get_wallet_by_index(wallet_index)?;

        Ok([&wallet.wallet_address, CONNECTIONS_LIST_DB_KEY].concat())
    }

    fn save_connection(&self, wallet_index: usize, connections: Vec<Connection>) -> Result<()> {
        let key = self.get_db_key(wallet_index)?;
        let bytes = bincode::serialize(&connections)
            .map_err(|e| BackgroundError::FailToSerializeConnections(e.to_string()))?;

        self.storage.set(&key, &bytes)?;
        self.storage.flush()?;

        Ok(())
    }

    fn get_connections(&self, wallet_index: usize) -> Vec<Connection> {
        if let Some(key) = self.get_db_key(wallet_index).ok() {
            let bytes = self.storage.get(&key).unwrap_or_default();

            if bytes.is_empty() {
                return Vec::with_capacity(1);
            }

            bincode::deserialize(&bytes).unwrap_or(Vec::with_capacity(1))
        } else {
            Vec::with_capacity(1)
        }
    }

    fn remove_connection(
        &self,
        wallet_index: usize,
        domain: &str,
    ) -> std::result::Result<(), Self::Error> {
        let mut connections = self.get_connections(wallet_index);
        let initial_len = connections.len();
        connections.retain(|c| !c.domain.contains(domain));

        if connections.len() == initial_len {
            return Err(BackgroundError::ConnectionNotFound(domain.to_string()));
        }

        self.save_connection(wallet_index, connections)?;

        Ok(())
    }

    fn add_connection(&self, wallet_index: usize, connection: Connection) -> Result<()> {
        let mut connections = self.get_connections(wallet_index);

        if connections.iter().any(|c| c.domain == connection.domain) {
            return Err(BackgroundError::ConnectionAlreadyExists(connection.domain));
        }

        connections.push(connection);
        self.save_connection(wallet_index, connections)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests_background_connections {}
