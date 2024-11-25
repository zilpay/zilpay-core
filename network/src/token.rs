use alloy::{
    dyn_abi::{DynSolValue, FunctionExt, JsonAbiExt},
    json_abi::{Function, JsonAbi},
    primitives::U256,
};
use config::abi::ERC20_ABI;
use proto::address::Address;
use serde_json::{json, Value};
use zil_errors::network::NetworkErrors;
use zilliqa::json_rpc::{
    zil::ZilliqaJsonRPC,
    zil_interfaces::{GetTokenInitItem, ResultRes},
    zil_methods::ZilMethods,
};

trait ResponseValidator {
    fn validate(&self) -> Result<&Self, NetworkErrors>;
}

impl<T> ResponseValidator for ResultRes<T> {
    fn validate(&self) -> Result<&Self, NetworkErrors> {
        if let Some(error) = &self.error {
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
            Err(NetworkErrors::RPCError(error_msg))
        } else {
            Ok(self)
        }
    }
}

// Type alias for clarity
type RequestResult = Result<Vec<(Value, RequestType)>, NetworkErrors>;

#[derive(Debug)]
pub enum RequestType {
    Metadata(MetadataField),
    Balance(Address),
}

#[derive(Debug, Clone)]
pub enum MetadataField {
    Name,
    Symbol,
    Decimals,
}

impl std::fmt::Display for MetadataField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MetadataField::Name => write!(f, "name"),
            MetadataField::Symbol => write!(f, "symbol"),
            MetadataField::Decimals => write!(f, "decimals"),
        }
    }
}

// Helper struct to encapsulate ERC20 functionality
struct ERC20Helper {
    abi: JsonAbi,
}

impl ERC20Helper {
    fn new() -> Result<Self, NetworkErrors> {
        Ok(Self {
            abi: serde_json::from_str(ERC20_ABI).map_err(|e| {
                NetworkErrors::ABIError(format!("Failed to parse ERC20 ABI: {}", e))
            })?,
        })
    }

    fn get_function(&self, name: &str) -> Result<&Function, NetworkErrors> {
        self.abi
            .function(name)
            .and_then(|f| f.first())
            .ok_or_else(|| {
                NetworkErrors::ABIError(format!("Function {} not found or no overloads", name))
            })
    }

    fn encode_function_call(
        &self,
        name: &str,
        inputs: &[DynSolValue],
    ) -> Result<String, NetworkErrors> {
        let func = self.get_function(name)?;
        Ok(format!(
            "0x{}",
            hex::encode(
                &func
                    .abi_encode_input(inputs)
                    .map_err(|e| NetworkErrors::ABIError(e.to_string()))?
            )
        ))
    }
}

pub fn build_token_requests(
    contract: &Address,
    accounts: &[Address],
    native: bool,
) -> RequestResult {
    let mut requests = Vec::new();

    match contract {
        Address::Secp256k1Sha256Zilliqa(_) => {
            build_zil_requests(contract, accounts, native, &mut requests)?;
        }
        Address::Secp256k1Keccak256Ethereum(_) => {
            build_eth_requests(contract, accounts, native, &mut requests)?;
        }
    }

    Ok(requests)
}

fn build_zil_requests(
    contract: &Address,
    accounts: &[Address],
    native: bool,
    requests: &mut Vec<(Value, RequestType)>,
) -> Result<(), NetworkErrors> {
    let base16_contract = contract
        .get_zil_base16()
        .map_err(NetworkErrors::InvalidZilAddress)?;

    // Add metadata request
    requests.push((
        ZilliqaJsonRPC::build_payload(json!([base16_contract]), ZilMethods::GetSmartContractInit),
        RequestType::Metadata(MetadataField::Name),
    ));

    // Build balance requests
    for account in accounts {
        let base16_account = account
            .get_zil_check_sum_addr()
            .map_err(NetworkErrors::InvalidZilAddress)?
            .to_lowercase();

        let request = if native {
            ZilliqaJsonRPC::build_payload(json!([base16_account]), ZilMethods::GetBalance)
        } else {
            ZilliqaJsonRPC::build_payload(
                json!([base16_contract, "balances", [base16_account]]),
                ZilMethods::GetSmartContractSubState,
            )
        };

        requests.push((request, RequestType::Balance(account.clone())));
    }

    Ok(())
}

fn build_eth_requests(
    contract: &Address,
    accounts: &[Address],
    native: bool,
    requests: &mut Vec<(Value, RequestType)>,
) -> Result<(), NetworkErrors> {
    let token_addr = contract
        .to_eth_checksummed()
        .map_err(NetworkErrors::InvalidETHAddress)?;
    let erc20 = ERC20Helper::new()?;

    // Create a closure for building ETH call payloads
    let build_eth_call = |data: String| -> Value {
        ZilliqaJsonRPC::build_payload(
            json!([{
                "to": &token_addr,
                "data": data
            }, "latest"]),
            ZilMethods::ETHCall,
        )
    };

    // Add metadata requests
    for field in [
        MetadataField::Name,
        MetadataField::Symbol,
        MetadataField::Decimals,
    ] {
        let data = erc20.encode_function_call(&field.to_string(), &[])?;
        requests.push((build_eth_call(data), RequestType::Metadata(field)));
    }

    // Build balance requests
    for account in accounts {
        let request = if native {
            let owner = account
                .to_eth_checksummed()
                .map_err(NetworkErrors::InvalidETHAddress)?;
            ZilliqaJsonRPC::build_payload(json!([owner, "latest"]), ZilMethods::ETHgetBalance)
        } else {
            let call_data = erc20.encode_function_call(
                "balanceOf",
                &[DynSolValue::Address(account.clone().to_alloy_addr())],
            )?;
            build_eth_call(call_data)
        };

        requests.push((request, RequestType::Balance(account.clone())));
    }

    Ok(())
}

pub fn process_eth_metadata_response(
    response: &ResultRes<Value>,
    field_type: &MetadataField,
    field_name: &str,
) -> Result<String, NetworkErrors> {
    if let Some(error) = &response.error {
        return Err(NetworkErrors::RPCError(format!(
            "JSON-RPC error (code: {}): {}{}",
            error.code,
            error.message,
            error
                .data
                .as_ref()
                .map(|d| format!(", data: {}", d))
                .unwrap_or_default()
        )));
    }

    let erc20 = ERC20Helper::new()?;
    let func = erc20.get_function(field_name)?;
    let hex_str = response
        .result
        .as_ref()
        .and_then(|r| r.as_str())
        .ok_or_else(|| NetworkErrors::ABIError("Invalid response format".to_string()))?;

    let bytes = hex::decode(hex_str.trim_start_matches("0x"))
        .map_err(|e| NetworkErrors::ABIError(format!("Failed to decode hex: {}", e)))?;

    let values = func
        .abi_decode_output(&bytes, false)
        .map_err(|e| NetworkErrors::ABIError(e.to_string()))?;

    let value = values
        .first()
        .ok_or_else(|| NetworkErrors::ABIError("No values decoded".to_string()))?;

    match field_type {
        MetadataField::Decimals => value
            .as_uint()
            .ok_or_else(|| NetworkErrors::ABIError("Invalid decimals format".to_string()))
            .map(|u| u.0.to_string()),
        _ => value
            .as_str()
            .ok_or_else(|| NetworkErrors::ABIError("Invalid string format".to_string()))
            .map(|s| s.to_string()),
    }
}

pub fn process_zil_metadata_response(
    init_res: &Value,
) -> Result<(String, String, u8), NetworkErrors> {
    let res_init: Vec<GetTokenInitItem> = init_res
        .as_array()
        .ok_or(NetworkErrors::InvalidContractInit)?
        .iter()
        .map(|v| v.try_into())
        .collect::<Result<_, _>>()
        .map_err(NetworkErrors::TokenParseError)?;

    let get_field = |field: &str| -> Result<String, NetworkErrors> {
        res_init
            .iter()
            .find(|v| v.vname == field)
            .map(|v| v.value.clone())
            .ok_or(NetworkErrors::InvalidContractInit)
    };

    let name = get_field(&MetadataField::Name.to_string())?;
    let symbol = get_field(&MetadataField::Symbol.to_string())?;
    let decimals = get_field(&MetadataField::Decimals.to_string())?
        .parse()
        .map_err(|_| NetworkErrors::InvalidContractInit)?;

    Ok((name, symbol, decimals))
}

pub fn process_eth_balance_response(response: &ResultRes<Value>) -> Result<U256, NetworkErrors> {
    let response = response.validate()?;

    response
        .result
        .as_ref()
        .and_then(|v| v.as_str())
        .ok_or_else(|| NetworkErrors::ABIError("Invalid response format".to_string()))?
        .parse()
        .map_err(|_| NetworkErrors::ABIError("Invalid balance format".to_string()))
}

pub fn process_zil_balance_response(
    response: &ResultRes<Value>,
    account: &Address,
    is_native: bool,
) -> Result<U256, NetworkErrors> {
    let response = response.validate()?;

    if is_native {
        response
            .result
            .as_ref()
            .and_then(|v| v.get("balance"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| NetworkErrors::ABIError("Invalid native balance format".to_string()))?
            .parse()
            .map_err(|_| NetworkErrors::ABIError("Invalid native balance value".to_string()))
    } else {
        let base16_account = account
            .get_zil_check_sum_addr()
            .map_err(NetworkErrors::InvalidZilAddress)?
            .to_lowercase();

        response
            .result
            .as_ref()
            .and_then(|v| v.get("balances"))
            .and_then(|v| v.get(base16_account))
            .and_then(|v| v.as_str())
            .ok_or_else(|| NetworkErrors::ABIError("Invalid token balance format".to_string()))?
            .parse()
            .map_err(|_| NetworkErrors::ABIError("Invalid token balance value".to_string()))
    }
}
