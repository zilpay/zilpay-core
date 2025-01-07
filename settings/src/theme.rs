use serde::{Deserialize, Serialize};
use std::str::FromStr;
use errors::settings::SettingsErrors;

#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub enum Appearances {
    #[default]
    System,
    Light,
    Dark,
}

impl Appearances {
    pub fn from_code(code: u8) -> Result<Self, SettingsErrors> {
        match code {
            0 => Ok(Self::System),
            1 => Ok(Self::Light),
            2 => Ok(Self::Dark),
            _ => Err(SettingsErrors::InvalidThemeCode(code)),
        }
    }

    pub fn code(&self) -> u8 {
        match &self {
            Self::System => 0,
            Self::Light => 1,
            Self::Dark => 2,
        }
    }

    pub fn name(&self) -> String {
        match self {
            Self::System => "system".to_string(),
            Self::Light => "light".to_string(),
            Self::Dark => "dark".to_string(),
        }
    }
}

impl FromStr for Appearances {
    type Err = SettingsErrors;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "system" => Ok(Self::System),
            "light" => Ok(Self::Light),
            "dark" => Ok(Self::Dark),
            _ => Err(SettingsErrors::InvlidStringOption),
        }
    }
}

impl std::fmt::Display for Appearances {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Theme {
    pub appearances: Appearances,
}
