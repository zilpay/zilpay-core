pub enum ZilMethods {
    GetSmartContractInit,
    GetBalance,
    GetSmartContractSubState,
    GetNetworkId,
    GetPendingTxn,
    GetTransaction,
    CreateTransaction,
    GetTransactionStatus,
    GetLatestTxBlock,
    GetRecentTransactions,
    GetMinimumGasPrice,
}

impl std::fmt::Display for ZilMethods {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ZilMethods::GetSmartContractInit => write!(f, "GetSmartContractInit"),
            ZilMethods::GetBalance => write!(f, "GetBalance"),
            ZilMethods::GetSmartContractSubState => write!(f, "GetSmartContractSubState"),
            ZilMethods::GetNetworkId => write!(f, "GetNetworkId"),
            ZilMethods::GetPendingTxn => write!(f, "GetPendingTxn"),
            ZilMethods::GetTransaction => write!(f, "GetTransaction"),
            ZilMethods::CreateTransaction => write!(f, "CreateTransaction"),
            ZilMethods::GetTransactionStatus => write!(f, "GetTransactionStatus"),
            ZilMethods::GetLatestTxBlock => write!(f, "GetLatestTxBlock"),
            ZilMethods::GetRecentTransactions => write!(f, "GetRecentTransactions"),
            ZilMethods::GetMinimumGasPrice => write!(f, "GetMinimumGasPrice"),
        }
    }
}
