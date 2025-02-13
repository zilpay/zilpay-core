use crate::{Background, Result};
use errors::background::BackgroundError;

pub enum JobMessage {
    Block,
}

pub trait WorkerManager {
    type Error;

    fn start_worker(&self, cb_job: impl Fn(JobMessage)) -> std::result::Result<(), Self::Error>;
}

impl WorkerManager for Background {
    type Error = BackgroundError;

    fn start_worker(&self, cb_job: impl Fn(JobMessage)) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests_background_worker {}
