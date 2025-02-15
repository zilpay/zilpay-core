use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub enum TransactionStatus {
    #[default]
    Pending,
    Confirmed,
    Rejected,
}
