use crate::Result;
use proto::tx::TransactionReceipt;
use rpc::{
    methods::ZilMethods, network_config::NetworkConfig, provider::RpcProvider,
    zil_interfaces::ResultRes,
};
use serde_json::{json, Value};
use zil_errors::{network::NetworkErrors, tx::TransactionErrors};

pub fn build_tx_request(tx: &TransactionReceipt) -> Value {
    match tx {
        TransactionReceipt::Zilliqa(zil) => {
            RpcProvider::<NetworkConfig>::build_payload(json!([zil]), ZilMethods::CreateTransaction)
        }
        TransactionReceipt::Ethereum(_eth) => {
            todo!()
        }
    }
}

pub fn process_tx_response(response: &ResultRes<Value>, tx: &mut TransactionReceipt) -> Result<()> {
    if let Some(error) = &response.error {
        let error_msg = format!(
            "JSON-RPC error (code: {}): {}{}",
            error.code,
            error.message,
            error
                .data
                .as_ref()
                .map(|d| format!(", data: {}", d))
                .unwrap_or_default()
        );

        return Err(NetworkErrors::RPCError(error_msg));
    }

    match tx {
        TransactionReceipt::Zilliqa(zil) => {
            if let Some(result) = &response.result {
                let info = result
                    .get("Info")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let tx_id = result
                    .get("TranID")
                    .and_then(|v| v.as_str())
                    .ok_or(TransactionErrors::InvalidTxHash)?;

                zil.metadata.hash = Some(tx_id.to_string());
                zil.metadata.info = Some(info.to_string());

                Ok(())
            } else {
                Err(NetworkErrors::RPCError("Invlid response".to_string()))
            }
        }
        TransactionReceipt::Ethereum(_eth) => {
            todo!()
        }
    }
}
