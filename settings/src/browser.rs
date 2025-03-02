use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub enum ContentBlockingLevel {
    None,
    Moderate,
    #[default]
    Strict,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BrowserSettings {
    pub search_engine_index: u8,

    pub cache_enabled: bool,
    pub cookies_enabled: bool,
    pub content_blocking: ContentBlockingLevel,

    pub do_not_track: bool,
    pub incognito_mode: bool,
    pub text_scaling_factor: f32,

    pub allow_geolocation: bool,
    pub allow_camera: bool,
    pub allow_microphone: bool,
    pub allow_auto_play: bool,
}

impl Default for BrowserSettings {
    fn default() -> Self {
        BrowserSettings {
            search_engine_index: 0,
            cache_enabled: true,
            cookies_enabled: true,
            content_blocking: ContentBlockingLevel::Moderate,
            do_not_track: false,
            incognito_mode: false,
            text_scaling_factor: 1.0,
            allow_geolocation: false,
            allow_camera: false,
            allow_microphone: false,
            allow_auto_play: false,
        }
    }
}

impl ContentBlockingLevel {
    pub fn code(&self) -> u8 {
        match self {
            Self::None => 0,
            Self::Moderate => 1,
            Self::Strict => 2,
        }
    }

    pub fn from_code(code: u8) -> Self {
        match code {
            0 => Self::None,
            1 => Self::Moderate,
            2 => Self::Strict,
            _ => Self::None,
        }
    }
}
