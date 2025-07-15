use async_trait::async_trait;
use config::contracts::{SCILLA_STAKE_PROXY, ST_ZIL_CONTRACT};
use errors::network::NetworkErrors;
use proto::{
    address::Address,
    tx::{TransactionMetadata, TransactionRequest},
    zil_tx::ZILTransactionRequest,
};
use serde_json::json;

use crate::{provider::NetworkProvider, stake::FinalOutput};

#[async_trait]
pub trait ZilliqaScillaStakeing {
    fn build_tx_scilla_claim(
        &self,
        stake: &FinalOutput,
    ) -> Result<TransactionRequest, NetworkErrors>;
    fn build_tx_scilla_init_unstake(
        &self,
        stake: &FinalOutput,
    ) -> Result<TransactionRequest, NetworkErrors>;
    fn build_tx_scilla_complete_withdrawal(
        &self,
        contract: Address,
    ) -> Result<TransactionRequest, NetworkErrors>;
    fn build_tx_scilla_withdraw_stake_avely(
        &self,
        stake: &FinalOutput,
    ) -> Result<TransactionRequest, NetworkErrors>;
}

#[async_trait]
impl ZilliqaScillaStakeing for NetworkProvider {
    fn build_tx_scilla_withdraw_stake_avely(
        &self,
        stake: &FinalOutput,
    ) -> Result<TransactionRequest, NetworkErrors> {
        let params = json!({
          "_tag": "WithdrawTokensAmt",
          "params": [
            {
              "vname": "amount",
              "type": "Uint128",
              "value": stake.deleg_amt.to_string()
            }
          ]
        });
        let contract = Address::from_zil_base16(ST_ZIL_CONTRACT)?;
        let zil_tx = ZILTransactionRequest {
            chain_id: self.config.chain_ids[1] as u16,
            nonce: 0,
            gas_price: 2000000050,
            gas_limit: 5000,
            to_addr: contract,
            amount: 0,
            code: vec![],
            data: params.to_string().into_bytes(),
        };
        let metdata = TransactionMetadata {
            chain_hash: self.config.hash(),
            ..Default::default()
        };
        let req_tx = TransactionRequest::Zilliqa((zil_tx, metdata));

        Ok(req_tx)
    }

    fn build_tx_scilla_complete_withdrawal(
        &self,
        contract: Address,
    ) -> Result<TransactionRequest, NetworkErrors> {
        let params = json!({
            "_tag": "CompleteWithdrawal",
            "params": []
        });
        let zil_tx = ZILTransactionRequest {
            chain_id: self.config.chain_ids[1] as u16,
            nonce: 0,
            gas_price: 2000000050,
            gas_limit: 100000,
            to_addr: contract,
            amount: 0,
            code: vec![],
            data: params.to_string().into_bytes(),
        };
        let metdata = TransactionMetadata {
            chain_hash: self.config.hash(),
            ..Default::default()
        };
        let req_tx = TransactionRequest::Zilliqa((zil_tx, metdata));

        Ok(req_tx)
    }

    fn build_tx_scilla_init_unstake(
        &self,
        stake: &FinalOutput,
    ) -> Result<TransactionRequest, NetworkErrors> {
        let params = json!({
          "_tag": "WithdrawStakeAmt",
          "params": [
            {
              "vname": "ssnaddr",
              "type": "ByStr20",
              "value": stake.address
            },
            {
              "vname": "amt",
              "type": "Uint128",
              "value": stake.deleg_amt.to_string()
            }
          ]
        });
        let contract = Address::from_zil_base16(SCILLA_STAKE_PROXY)?;
        let zil_tx = ZILTransactionRequest {
            chain_id: self.config.chain_ids[1] as u16,
            nonce: 0,
            gas_price: 2000000050,
            gas_limit: 5000,
            to_addr: contract,
            amount: 0,
            code: vec![],
            data: params.to_string().into_bytes(),
        };
        let metdata = TransactionMetadata {
            chain_hash: self.config.hash(),
            ..Default::default()
        };
        let req_tx = TransactionRequest::Zilliqa((zil_tx, metdata));

        Ok(req_tx)
    }

    fn build_tx_scilla_claim(
        &self,
        stake: &FinalOutput,
    ) -> Result<TransactionRequest, NetworkErrors> {
        let params = json!({
            "_tag": "WithdrawStakeRewards",
            "params": [
                {
                    "vname": "ssnaddr",
                    "type": "ByStr20",
                    "value": stake.address
                }
            ]
        });
        let contract = Address::from_zil_base16(SCILLA_STAKE_PROXY)?;
        let zil_tx = ZILTransactionRequest {
            chain_id: self.config.chain_ids[1] as u16,
            nonce: 0,
            gas_price: 2000000050,
            gas_limit: 100000,
            to_addr: contract,
            amount: 0,
            code: vec![],
            data: params.to_string().into_bytes(),
        };
        let metdata = TransactionMetadata {
            chain_hash: self.config.hash(),
            ..Default::default()
        };
        let req_tx = TransactionRequest::Zilliqa((zil_tx, metdata));

        Ok(req_tx)
    }
}
