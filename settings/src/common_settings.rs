use crate::{language::Language, notificcations::Notificcations, storage::Storage, theme::Theme};

#[derive(Debug, Clone)]
pub struct CommonSettings {
    pub language: Language,
    pub notificcations: Notificcations,
    pub storage: Storage,
    pub theme: Theme,
}

impl Default for CommonSettings {
    fn default() -> Self {
        Self {
            language: Language {},
            notificcations: Notificcations {},
            storage: Storage {},
            theme: Theme {},
        }
    }
}
