use crate::{bg_storage::StorageManagement, Result};

use errors::background::BackgroundError;
use settings::{
    locale::Locale,
    notifications::{NotificationState, Notifications},
    theme::Theme,
};

use crate::Background;

/// Manages application settings and preferences
pub trait SettingsManagement {
    type Error;

    /// Enables or disables global notifications
    fn set_global_notifications(
        &mut self,
        global_enabled: bool,
    ) -> std::result::Result<(), Self::Error>;

    /// Updates notification settings for a specific wallet
    fn set_wallet_notifications(
        &mut self,
        wallet_index: usize,
        notification: NotificationState,
    ) -> std::result::Result<(), Self::Error>;

    /// Updates application locale
    fn set_locale(&mut self, new_locale: Locale) -> std::result::Result<(), Self::Error>;

    /// Updates application theme
    fn set_theme(&mut self, new_theme: Theme) -> std::result::Result<(), Self::Error>;

    /// Updates notification settings
    fn set_notifications(
        &mut self,
        new_notifications: Notifications,
    ) -> std::result::Result<(), Self::Error>;
}

impl SettingsManagement for Background {
    type Error = BackgroundError;

    fn set_global_notifications(&mut self, global_enabled: bool) -> Result<()> {
        self.settings.notifications.global_enabled = global_enabled;
        self.save_settings()?;

        Ok(())
    }

    fn set_wallet_notifications(
        &mut self,
        wallet_index: usize,
        notification: NotificationState,
    ) -> Result<()> {
        self.settings
            .notifications
            .wallet_states
            .insert(wallet_index, notification);
        self.save_settings()?;

        Ok(())
    }

    fn set_locale(&mut self, new_locale: Locale) -> Result<()> {
        self.settings.locale = new_locale;
        self.save_settings()?;

        Ok(())
    }

    fn set_theme(&mut self, new_theme: Theme) -> Result<()> {
        self.settings.theme = new_theme;
        self.save_settings()?;

        Ok(())
    }

    fn set_notifications(&mut self, new_notifications: Notifications) -> Result<()> {
        self.settings.notifications = new_notifications;
        self.save_settings()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests_background {
    use super::*;
    use rand::Rng;

    fn setup_test_background() -> (Background, String) {
        let mut rng = rand::thread_rng();
        let dir = format!("/tmp/{}", rng.gen::<usize>());
        let bg = Background::from_storage_path(&dir).unwrap();
        (bg, dir)
    }

    #[test]
    fn test_set_global_notifications() {
        let (mut bg, dir) = setup_test_background();

        // Test enabling notifications
        assert!(bg.set_global_notifications(true).is_ok());
        assert!(bg.settings.notifications.global_enabled);

        // Test disabling notifications
        assert!(bg.set_global_notifications(false).is_ok());
        assert!(!bg.settings.notifications.global_enabled);

        drop(bg);

        // Test persistence after reload
        let bg_reloaded = Background::from_storage_path(&dir).unwrap();
        assert!(!bg_reloaded.settings.notifications.global_enabled);
    }

    #[test]
    fn test_set_wallet_notifications() {
        let (mut bg, dir) = setup_test_background();
        let test_state = NotificationState::all_enabled();
        let wallet_index = 1;

        // Test setting notification state
        assert!(bg
            .set_wallet_notifications(wallet_index, test_state.clone())
            .is_ok());
        assert_eq!(
            bg.settings.notifications.wallet_states.get(&wallet_index),
            Some(&test_state)
        );

        drop(bg);

        // Test persistence after reload
        let bg_reloaded = Background::from_storage_path(&dir).unwrap();
        assert_eq!(
            bg_reloaded
                .settings
                .notifications
                .wallet_states
                .get(&wallet_index),
            Some(&test_state)
        );
    }

    #[test]
    fn test_set_locale() {
        let (mut bg, dir) = setup_test_background();
        let test_locale = Locale::System;

        // Test setting locale
        assert!(bg.set_locale(test_locale.clone()).is_ok());
        assert_eq!(bg.settings.locale, test_locale);

        drop(bg);

        // Test persistence after reload
        let bg_reloaded = Background::from_storage_path(&dir).unwrap();
        assert_eq!(bg_reloaded.settings.locale, test_locale);
    }

    #[test]
    fn test_set_theme() {
        let (mut bg, dir) = setup_test_background();
        let test_theme = Theme {
            appearances: settings::theme::Appearances::Light,
            compact_numbers: true,
        };

        // Test setting theme
        assert!(bg.set_theme(test_theme.clone()).is_ok());
        assert_eq!(bg.settings.theme, test_theme);

        drop(bg);

        // Test persistence after reload
        let bg_reloaded = Background::from_storage_path(&dir).unwrap();
        assert_eq!(bg_reloaded.settings.theme, test_theme);
    }

    #[test]
    fn test_set_notifications() {
        let (mut bg, dir) = setup_test_background();
        let mut test_notifications = Notifications::default();

        test_notifications
            .wallet_states
            .insert(0, NotificationState::all_enabled());

        // Test setting notifications
        assert!(bg.set_notifications(test_notifications.clone()).is_ok());
        assert_eq!(bg.settings.notifications, test_notifications);

        drop(bg);

        // Test persistence after reload
        let bg_reloaded = Background::from_storage_path(&dir).unwrap();
        assert_eq!(bg_reloaded.settings.notifications, test_notifications);
    }

    #[test]
    fn test_settings_persistence() {
        let (mut bg, dir) = setup_test_background();

        // Make multiple settings changes
        assert!(bg.set_global_notifications(true).is_ok());
        assert!(bg
            .set_theme(Theme {
                compact_numbers: true,
                appearances: settings::theme::Appearances::System
            })
            .is_ok());
        assert!(bg.set_locale(Locale::System).is_ok());
        assert!(bg
            .set_wallet_notifications(1, NotificationState::all_enabled())
            .is_ok());

        drop(bg);

        // Verify all changes persist after reload
        let bg_reloaded = Background::from_storage_path(&dir).unwrap();
        assert!(bg_reloaded.settings.notifications.global_enabled);
        assert_eq!(
            bg_reloaded.settings.theme,
            Theme {
                compact_numbers: true,
                appearances: settings::theme::Appearances::System
            }
        );
        assert_eq!(bg_reloaded.settings.locale, Locale::System);
        assert_eq!(
            bg_reloaded.settings.notifications.wallet_states.get(&1),
            Some(&NotificationState::all_enabled())
        );
    }
}
