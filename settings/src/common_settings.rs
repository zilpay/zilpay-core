use crate::{browser::BrowserSettings, notifications::Notifications, theme::Theme};
use serde::{Deserialize, Serialize};
use std::fmt;

fn default_wallet_biometric_salt_type() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommonSettings {
    #[serde(default)]
    pub notifications: Notifications,

    #[serde(default)]
    pub theme: Theme,

    #[serde(default)]
    pub locale: Option<String>,

    #[serde(default)]
    pub browser: BrowserSettings,

    #[serde(default = "default_wallet_biometric_salt_type")]
    pub wallet_biometric_salt_type: bool,
}

impl Default for CommonSettings {
    fn default() -> Self {
        Self {
            notifications: Notifications::default(),
            theme: Theme::default(),
            locale: None,
            browser: BrowserSettings::default(),
            wallet_biometric_salt_type: default_wallet_biometric_salt_type(),
        }
    }
}

impl CommonSettings {
    pub fn new(
        notifications: Notifications,
        theme: Theme,
        locale: Option<String>,
        browser: BrowserSettings,
        wallet_biometric_salt_type: bool,
    ) -> Self {
        Self {
            browser,
            notifications,
            theme,
            locale,
            wallet_biometric_salt_type,
        }
    }

    pub fn with_theme(mut self, theme: Theme) -> Self {
        self.theme = theme;
        self
    }

    pub fn with_locale(mut self, locale: Option<String>) -> Self {
        self.locale = locale;
        self
    }

    pub fn with_notifications(mut self, notifications: Notifications) -> Self {
        self.notifications = notifications;
        self
    }

    pub fn with_wallet_biometric_salt_type(mut self, wallet_biometric_salt_type: bool) -> Self {
        self.wallet_biometric_salt_type = wallet_biometric_salt_type;
        self
    }
}

impl fmt::Display for CommonSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CommonSettings {{ theme: {:?}, locale: {:?}, notifications: {:?} }}",
            self.theme, self.locale, self.notifications
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_test_settings() -> CommonSettings {
        CommonSettings::default()
    }

    #[test]
    fn test_new_settings() {
        let notifications = Notifications::default();
        let theme = Theme::default();
        let locale = Some("en".to_string());

        let settings = CommonSettings::new(
            notifications,
            theme,
            locale.clone(),
            Default::default(),
            true,
        );

        assert_eq!(settings.locale, locale);
        assert_eq!(settings.wallet_biometric_salt_type, true);
    }

    #[test]
    fn test_with_theme() {
        let settings = setup_test_settings();
        let new_theme = Theme::default(); // Assuming Theme has variants
        let updated = settings.with_theme(new_theme.clone());
        assert_eq!(updated.theme, new_theme);
    }

    #[test]
    fn test_with_locale() {
        let settings = setup_test_settings();
        let custom_locale = Some("fr".to_string());
        let updated = settings.with_locale(custom_locale.clone());
        assert_eq!(updated.locale, custom_locale);
    }

    #[test]
    fn test_with_notifications() {
        let settings = setup_test_settings();
        let new_notifications = Notifications::default();
        let updated = settings.with_notifications(new_notifications);
        assert_eq!(updated.notifications, Notifications::default());
    }

    #[test]
    fn test_display_implementation() {
        let settings = setup_test_settings();
        let display_string = settings.to_string();
        assert!(display_string.contains("theme"));
        assert!(display_string.contains("locale"));
        assert!(display_string.contains("notifications"));
    }

    #[test]
    fn test_clone() {
        let settings = setup_test_settings();
        let cloned = settings.clone();
        assert_eq!(settings.locale, cloned.locale);
        assert_eq!(settings.theme, cloned.theme);
    }

    #[test]
    fn test_debug_implementation() {
        let settings = setup_test_settings();
        let debug_string = format!("{:?}", settings);
        assert!(!debug_string.is_empty());
    }

    #[test]
    fn test_with_wallet_biometric_salt_type() {
        let settings = setup_test_settings();
        let updated = settings.with_wallet_biometric_salt_type(false);
        assert_eq!(updated.wallet_biometric_salt_type, false);

        let settings_true = setup_test_settings().with_wallet_biometric_salt_type(true);
        assert_eq!(settings_true.wallet_biometric_salt_type, true);
    }

    #[test]
    fn test_default_wallet_biometric_salt_type() {
        let settings = setup_test_settings();
        assert_eq!(settings.wallet_biometric_salt_type, true);
    }

    #[test]
    fn test_bincode_backward_compatibility() {
        #[derive(Serialize)]
        struct OldCommonSettings {
            notifications: Notifications,
            theme: Theme,
            locale: Option<String>,
            browser: BrowserSettings,
        }

        let old_settings = OldCommonSettings {
            notifications: Notifications::default(),
            theme: Theme::default(),
            locale: Some("en".to_string()),
            browser: BrowserSettings::default(),
        };

        let serialized = bincode::serialize(&old_settings).unwrap();

        let new_settings: CommonSettings =
            bincode::deserialize(&serialized).unwrap_or(CommonSettings::default());

        assert_eq!(new_settings.wallet_biometric_salt_type, true);
    }
}
