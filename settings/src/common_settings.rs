use crate::{browser::BrowserSettings, notifications::Notifications, theme::Theme};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Common application settings for UI preferences and behavior
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CommonSettings {
    /// Notification configuration and preferences
    #[serde(default)]
    pub notifications: Notifications,

    /// User interface theme settings
    #[serde(default)]
    pub theme: Theme,

    /// Language and regional settings
    #[serde(default)]
    pub locale: Option<String>,

    #[serde(default)]
    pub browser: BrowserSettings,
}

impl CommonSettings {
    pub fn new(
        notifications: Notifications,
        theme: Theme,
        locale: Option<String>,
        browser: BrowserSettings,
    ) -> Self {
        Self {
            browser,
            notifications,
            theme,
            locale,
        }
    }

    /// Returns a new instance with the specified theme
    pub fn with_theme(mut self, theme: Theme) -> Self {
        self.theme = theme;
        self
    }

    /// Returns a new instance with the specified locale
    pub fn with_locale(mut self, locale: Option<String>) -> Self {
        self.locale = locale;
        self
    }

    /// Returns a new instance with the specified notifications settings
    pub fn with_notifications(mut self, notifications: Notifications) -> Self {
        self.notifications = notifications;
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

        let settings =
            CommonSettings::new(notifications, theme, locale.clone(), Default::default());

        assert_eq!(settings.locale, locale);
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
}
