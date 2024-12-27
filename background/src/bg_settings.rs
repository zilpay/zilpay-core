use crate::{bg_storage::StorageManagement, Result};

use settings::{
    locale::Locale,
    notifications::{NotificationState, Notifications},
    theme::Theme,
};
use zil_errors::background::BackgroundError;

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
}
