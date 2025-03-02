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
    pub search_engine: String,

    pub javascript_enabled: bool,
    pub cache_enabled: bool,
    pub cookies_enabled: bool,
    pub form_data_save_enabled: bool,
    pub content_blocking: ContentBlockingLevel,

    pub do_not_track: bool,
    pub incognito_mode: bool,
    pub clear_cache_on_exit: bool,
    pub user_agent_override: String,

    pub prefetch_enabled: bool,
    pub preload_links: bool,
    pub hardware_acceleration: bool,

    pub text_scaling_factor: f32,

    pub allow_geolocation: bool,
    pub allow_camera: bool,
    pub allow_microphone: bool,
    pub allow_auto_play: bool,
}

impl Default for BrowserSettings {
    fn default() -> Self {
        BrowserSettings {
            search_engine: "https://duckduckgo.com/?q=".to_string(),
            javascript_enabled: true,
            cache_enabled: true,
            cookies_enabled: true,
            form_data_save_enabled: false,
            content_blocking: ContentBlockingLevel::Moderate,
            do_not_track: false,
            incognito_mode: false,
            clear_cache_on_exit: false,
            user_agent_override: String::with_capacity(0),
            prefetch_enabled: true,
            preload_links: true,
            hardware_acceleration: true,
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
}
