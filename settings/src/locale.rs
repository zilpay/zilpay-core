use errors::settings::SettingsErrors;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub enum Locale {
    #[default]
    System,
    Custom(String),
}

impl Locale {
    pub fn new_custom(value: String) -> Result<Self, SettingsErrors> {
        if value.trim().is_empty() {
            return Err(SettingsErrors::InvlidStringOption);
        }

        Ok(Self::Custom(value))
    }

    #[inline]
    pub fn code(&self) -> u8 {
        match &self {
            Self::System => 0,
            Self::Custom(_) => 1,
        }
    }

    #[inline]
    pub fn name(&self) -> &str {
        match self {
            Self::System => "system",
            Self::Custom(value) => value,
        }
    }

    #[inline]
    pub fn is_system(&self) -> bool {
        matches!(self, Self::System)
    }

    #[inline]
    pub fn is_custom(&self) -> bool {
        matches!(self, Self::Custom(_))
    }
}

impl FromStr for Locale {
    type Err = SettingsErrors;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().trim() {
            "" => Err(SettingsErrors::InvlidStringOption),
            "system" => Ok(Self::System),
            value => Ok(Self::Custom(value.to_string())),
        }
    }
}

impl std::fmt::Display for Locale {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[cfg(test)]
mod tests_locales {
    use super::*;

    #[test]
    fn test_locale_from_str() {
        assert!(matches!(Locale::from_str("system"), Ok(Locale::System)));
        assert!(matches!(Locale::from_str("SYSTEM"), Ok(Locale::System)));
        assert!(matches!(
            Locale::from_str("en-US"),
            Ok(Locale::Custom(s)) if s == "en-us"
        ));
        assert!(Locale::from_str("").is_err());
        assert!(Locale::from_str("  ").is_err());
    }

    #[test]
    fn test_locale_display() {
        assert_eq!(Locale::System.to_string(), "system");
        assert_eq!(Locale::Custom("en-US".to_string()).to_string(), "en-US");
    }

    #[test]
    fn test_locale_code() {
        assert_eq!(Locale::System.code(), 0);
        assert_eq!(Locale::Custom("en-US".to_string()).code(), 1);
    }

    #[test]
    fn test_locale_is_methods() {
        let system = Locale::System;
        let custom = Locale::Custom("en-US".to_string());

        assert!(system.is_system());
        assert!(!system.is_custom());
        assert!(!custom.is_system());
        assert!(custom.is_custom());
    }

    #[test]
    fn test_new_custom() {
        assert!(Locale::new_custom("en-US".to_string()).is_ok());
        assert!(Locale::new_custom("".to_string()).is_err());
        assert!(Locale::new_custom("  ".to_string()).is_err());
    }
}
