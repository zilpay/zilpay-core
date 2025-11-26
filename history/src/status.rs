use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransactionStatus {
    #[default]
    Pending,
    Success,
    Failed,
}
