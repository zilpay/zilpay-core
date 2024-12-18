use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DAppColors {
    pub primary: String,
    pub secondary: Option<String>,
    pub background: Option<String>,
    pub text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    // Base fields
    pub domain: String,
    pub wallet_indexes: HashSet<usize>,
    pub favicon: Option<String>,
    pub title: String,
    pub description: Option<String>,
    pub colors: Option<DAppColors>,

    // Additional Web3-specific fields
    pub last_connected: u64, // Unix timestamp
    pub permissions: ConnectionPermissions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionPermissions {
    pub can_read_accounts: bool,
    pub can_request_signatures: bool,
    pub can_suggest_tokens: bool,
    pub can_suggest_transactions: bool,
}

impl Connection {
    pub fn new(
        domain: String,
        wallet_index: usize,
        title: String,
        colors: Option<DAppColors>,
    ) -> Self {
        let mut wallet_indexes = HashSet::new();
        wallet_indexes.insert(wallet_index);

        Self {
            domain,
            wallet_indexes,
            favicon: None,
            title,
            description: None,
            colors,
            last_connected: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            permissions: ConnectionPermissions::default(),
        }
    }

    pub fn add_wallet(&mut self, wallet_index: usize) {
        self.wallet_indexes.insert(wallet_index);
    }

    pub fn remove_wallet(&mut self, wallet_index: usize) {
        self.wallet_indexes.remove(&wallet_index);
    }

    pub fn is_wallet_connected(&self, wallet_index: usize) -> bool {
        self.wallet_indexes.contains(&wallet_index)
    }

    pub fn update_last_connected(&mut self) {
        self.last_connected = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }
}

impl Default for ConnectionPermissions {
    fn default() -> Self {
        Self {
            can_read_accounts: true,
            can_request_signatures: true,
            can_suggest_tokens: true,
            can_suggest_transactions: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_creation() {
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
            Some(colors.clone()),
        );

        assert_eq!(connection.domain, "example.com");
        assert!(connection.wallet_indexes.contains(&0));
        assert_eq!(connection.title, "Example DApp");
        assert_eq!(connection.colors.unwrap().primary, colors.primary);
    }

    #[test]
    fn test_wallet_management() {
        let mut connection = Connection::new(
            "example.com".to_string(),
            0,
            "Example DApp".to_string(),
            Some(DAppColors {
                primary: "#000000".to_string(),
                secondary: None,
                background: None,
                text: None,
            }),
        );

        assert!(connection.is_wallet_connected(0));

        connection.add_wallet(1);
        assert!(connection.is_wallet_connected(1));

        connection.remove_wallet(0);
        assert!(!connection.is_wallet_connected(0));
    }
}
