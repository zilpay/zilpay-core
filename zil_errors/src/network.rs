use crate::zilliqa::ZilliqaNetErrors;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NetworkErrors {
    #[error("Fail to fetch nodes error: {0}")]
    FailToFetchNodes(ZilliqaNetErrors),
}
