use crate::{notificcations::Notificcations, theme::Theme};

#[derive(Debug, Clone)]
pub struct CommonSettings {
    pub notificcations: Notificcations,
    pub theme: Theme,
    pub locale: String,
}

impl Default for CommonSettings {
    fn default() -> Self {
        Self {
            notificcations: Notificcations {},
            theme: Theme::default(),
            locale: String::default(),
        }
    }
}
