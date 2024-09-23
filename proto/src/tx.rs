use crate::zil_tx::ZILTransactionRequest;
use ethers::types::TransactionRequest as ETHTransactionRequest;

#[derive(Debug, PartialEq, Eq)]
pub enum TransactionRequest {
    Zilliqa(ZILTransactionRequest),  // ZILLIQA
    Ethereum(ETHTransactionRequest), // Ethereum
}

#[cfg(test)]
mod tests_transaction_request {
    use super::*;

    #[test]
    fn test_sign() {}
}
