#[derive(Debug, Clone, Copy)]
pub struct ArgonParams {
    /// Количество памяти в KB
    pub memory: u32,
    /// Количество итераций
    pub iterations: u32,
    /// Количество потоков
    pub threads: u32,
}

impl ArgonParams {
    /// Создает новые параметры
    pub fn new(memory: u32, iterations: u32, threads: u32) -> Self {
        Self {
            memory,
            iterations,
            threads,
        }
    }

    /// Конвертирует в Config для Argon2
    pub fn into_config(&self) -> Config<'static> {
        Config {
            ad: &[],
            hash_length: 32,
            lanes: self.threads,
            mem_cost: self.memory,
            secret: &[],
            time_cost: self.iterations,
            variant: Variant::Argon2id,
            version: Version::Version13,
        }
    }

    /// Стандартные параметры OWASP (19 MB RAM, 2 итерации)
    pub fn owasp_default() -> Self {
        Self {
            memory: 19 * 1024, // 19 MB
            iterations: 2,
            threads: 1,
        }
    }

    /// Параметры для слабых устройств (64 MB RAM, 3 итерации)
    pub fn low_memory() -> Self {
        Self {
            memory: 64 * 1024, // 64 MB
            iterations: 3,
            threads: 1,
        }
    }

    /// Параметры повышенной безопасности (256 MB RAM, 4 итерации, 4 потока)
    pub fn secure() -> Self {
        Self {
            memory: 256 * 1024, // 256 MB
            iterations: 4,
            threads: 4,
        }
    }
}

impl Default for ArgonParams {
    fn default() -> Self {
        Self::owasp_default()
    }
}
