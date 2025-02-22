use crate::Result;

use config::storage::CONNECTIONS_LIST_DB_KEY;
use errors::background::BackgroundError;

use crate::{connections::Connection, Background};

/// Manages connections between wallets and external services
pub trait ConnectionManagement {
    type Error;

    /// Retrieves all active connections
    fn get_connections(&self) -> Vec<Connection>;

    /// Associates a wallet with a domain
    fn add_wallet_to_connection(
        &self,
        domain: String,
        wallet_index: usize,
    ) -> std::result::Result<(), Self::Error>;

    /// Adds a new connection
    fn add_connection(&self, connection: Connection) -> std::result::Result<(), Self::Error>;
    fn remove_connection(&self, domain: &str) -> std::result::Result<(), Self::Error>;
}

impl ConnectionManagement for Background {
    type Error = BackgroundError;

    fn get_connections(&self) -> Vec<Connection> {
        let bytes = self
            .storage
            .get(CONNECTIONS_LIST_DB_KEY)
            .unwrap_or_default();

        if bytes.is_empty() {
            return Vec::with_capacity(1);
        }

        bincode::deserialize(&bytes).unwrap_or(Vec::with_capacity(1))
    }

    fn remove_connection(&self, domain: &str) -> std::result::Result<(), Self::Error> {
        let mut connections = self.get_connections();
        let initial_len = connections.len();
        connections.retain(|c| !c.domain.contains(domain));

        if connections.len() == initial_len {
            return Err(BackgroundError::ConnectionNotFound(domain.to_string()));
        }

        let bytes = bincode::serialize(&connections)
            .map_err(|e| BackgroundError::FailToSerializeConnections(e.to_string()))?;

        self.storage.set(CONNECTIONS_LIST_DB_KEY, &bytes)?;
        self.storage.flush()?;

        Ok(())
    }

    fn add_wallet_to_connection(&self, domain: String, wallet_index: usize) -> Result<()> {
        let mut connections = self.get_connections();

        let connection = connections
            .iter_mut()
            .find(|c| c.domain == domain)
            .ok_or_else(|| BackgroundError::ConnectionNotFound(domain.clone()))?;

        if self.wallets.get(wallet_index).is_none() {
            return Err(BackgroundError::WalletNotExists(wallet_index));
        }

        connection.add_wallet(wallet_index);
        connection.update_last_connected();

        let bytes = bincode::serialize(&connections)
            .map_err(|e| BackgroundError::FailToSerializeConnections(e.to_string()))?;

        self.storage.set(CONNECTIONS_LIST_DB_KEY, &bytes)?;
        self.storage.flush()?;

        Ok(())
    }

    fn add_connection(&self, connection: Connection) -> Result<()> {
        let mut connections = self.get_connections();

        if connections.iter().any(|c| c.domain == connection.domain) {
            return Err(BackgroundError::ConnectionAlreadyExists(connection.domain));
        }

        connections.push(connection);

        let bytes = bincode::serialize(&connections)
            .map_err(|e| BackgroundError::FailToSerializeConnections(e.to_string()))?;

        self.storage.set(CONNECTIONS_LIST_DB_KEY, &bytes)?;
        self.storage.flush()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests_background_connections {
    use errors::background::BackgroundError;
    use rand::Rng;

    use crate::bg_connections::ConnectionManagement;
    use crate::bg_storage::StorageManagement;
    use crate::connections::{Connection, DAppColors};
    use crate::Background;

    fn setup_test_background() -> (Background, String) {
        let mut rng = rand::thread_rng();
        let dir = format!("/tmp/{}", rng.gen::<usize>());
        let bg = Background::from_storage_path(&dir).unwrap();
        (bg, dir)
    }

    #[test]
    fn test_connections_storage() {
        let (bg, dir) = setup_test_background();

        let connections = bg.get_connections();
        assert!(connections.is_empty());

        let colors = DAppColors {
            primary: "#000000".to_string(),
            secondary: Some("#FFFFFF".to_string()),
            background: None,
            text: None,
        };

        let connection = Connection::new(
            "example.com".to_string(),
            0,
            "Example DApp".to_string(),
            Some(colors),
        );

        bg.add_connection(connection.clone()).unwrap();

        assert_eq!(
            bg.add_connection(connection.clone()),
            Err(BackgroundError::ConnectionAlreadyExists(
                "example.com".to_string()
            ))
        );

        let connections = bg.get_connections();
        assert_eq!(connections.len(), 1);
        let first_conn = &connections[0];
        assert_eq!(first_conn.domain, "example.com");
        assert_eq!(first_conn.title, "Example DApp");

        drop(bg);
        let bg2 = Background::from_storage_path(&dir).unwrap();
        let loaded_connections = bg2.get_connections();

        assert_eq!(loaded_connections.len(), 1);
        let loaded_conn = &loaded_connections[0];
        assert_eq!(loaded_conn.domain, "example.com");
        assert_eq!(loaded_conn.title, "Example DApp");
        assert!(loaded_conn.colors.is_some());
        assert!(loaded_conn.is_wallet_connected(0));
    }

    #[test]
    fn test_remove_connection() {
        let (bg, _dir) = setup_test_background();

        let connection1 = Connection::new(
            "example.com".to_string(),
            0,
            "Example DApp".to_string(),
            None,
        );
        let connection2 =
            Connection::new("sub.test.com".to_string(), 0, "Test DApp".to_string(), None);

        bg.add_connection(connection1).unwrap();
        bg.add_connection(connection2).unwrap();

        let connections = bg.get_connections();
        assert_eq!(connections.len(), 2);

        // Test removing existing connection
        bg.remove_connection("example").unwrap();
        let connections = bg.get_connections();
        assert_eq!(connections.len(), 1);
        assert_eq!(connections[0].domain, "sub.test.com");

        // Test removing with substring match
        bg.remove_connection("test").unwrap();
        let connections = bg.get_connections();
        assert_eq!(connections.len(), 0);

        // Test removing non-existent connection
        assert_eq!(
            bg.remove_connection("nonexistent"),
            Err(BackgroundError::ConnectionNotFound(
                "nonexistent".to_string()
            ))
        );
    }
}
