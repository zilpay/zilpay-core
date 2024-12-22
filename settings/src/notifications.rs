use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotificationState {
    pub transactions: bool,
    pub price: bool,
    pub security: bool,
    pub balance: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Notifications {
    /// HashMap mapping wallet index to notification states
    pub wallet_states: HashMap<usize, NotificationState>,
    /// Global notification state that affects all wallets
    #[serde(default)]
    pub global_enabled: bool,
}

impl NotificationState {
    pub fn all_enabled() -> Self {
        Self {
            transactions: true,
            price: true,
            security: true,
            balance: true,
        }
    }

    pub fn all_disabled() -> Self {
        Self {
            transactions: false,
            price: false,
            security: false,
            balance: false,
        }
    }
}

impl Notifications {
    pub fn new() -> Self {
        Self {
            wallet_states: HashMap::new(),
            global_enabled: true,
        }
    }

    pub fn set_state(&mut self, wallet_index: usize, state: NotificationState) {
        self.wallet_states.insert(wallet_index, state);
    }

    pub fn get_state(&self, wallet_index: usize) -> Option<NotificationState> {
        self.wallet_states.get(&wallet_index).cloned()
    }

    pub fn remove_state(&mut self, wallet_index: usize) -> Option<NotificationState> {
        self.wallet_states.remove(&wallet_index)
    }

    pub fn set_global_enabled(&mut self, enabled: bool) {
        self.global_enabled = enabled;
    }

    pub fn is_globally_enabled(&self) -> bool {
        self.global_enabled
    }

    pub fn clear_all(&mut self) {
        self.wallet_states.clear();
    }

    pub fn len(&self) -> usize {
        self.wallet_states.len()
    }

    pub fn is_empty(&self) -> bool {
        self.wallet_states.is_empty()
    }

    pub fn wallet_indices(&self) -> Vec<usize> {
        self.wallet_states.keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_and_get_state() {
        let mut notifications = Notifications::new();
        let state = NotificationState {
            transactions: true,
            price: false,
            security: true,
            balance: false,
        };

        notifications.set_state(0, state.clone());
        assert_eq!(notifications.get_state(0), Some(state));
        assert_eq!(notifications.get_state(1), None);
    }

    #[test]
    fn test_remove_state() {
        let mut notifications = Notifications::new();
        let state = NotificationState::all_enabled();

        notifications.set_state(0, state.clone());
        assert_eq!(notifications.remove_state(0), Some(state));
        assert_eq!(notifications.get_state(0), None);
    }

    #[test]
    fn test_global_enable() {
        let mut notifications = Notifications::new();
        assert!(notifications.is_globally_enabled());

        notifications.set_global_enabled(false);
        assert!(!notifications.is_globally_enabled());
    }

    #[test]
    fn test_clear_all() {
        let mut notifications = Notifications::new();
        notifications.set_state(0, NotificationState::all_enabled());
        notifications.set_state(1, NotificationState::all_enabled());

        notifications.clear_all();
        assert!(notifications.is_empty());
    }

    #[test]
    fn test_wallet_indices() {
        let mut notifications = Notifications::new();
        notifications.set_state(0, NotificationState::all_enabled());
        notifications.set_state(2, NotificationState::all_disabled());

        let indices = notifications.wallet_indices();
        assert_eq!(indices.len(), 2);
        assert!(indices.contains(&0));
        assert!(indices.contains(&2));
    }
}
