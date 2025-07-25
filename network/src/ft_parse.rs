use alloy::{
    dyn_abi::{DynSolValue, FunctionExt, JsonAbiExt},
    hex,
    json_abi::{Function, JsonAbi},
    primitives::U256,
};
use config::abi::ERC20_ABI;
use errors::{network::NetworkErrors, token::TokenError};
use proto::address::Address;
use rpc::{
    methods::{EvmMethods, ZilMethods},
    network_config::ChainConfig,
    provider::RpcProvider,
    zil_interfaces::{GetTokenInitItem, ResultRes},
};
use serde_json::{json, Value};
use token::Result;

type RequestResult<'a> = std::result::Result<Vec<(Value, RequestType<'a>)>, TokenError>;

trait ResponseValidator {
    fn validate(&self) -> Result<&Self>;
}

impl<T> ResponseValidator for ResultRes<T> {
    fn validate(&self) -> Result<&Self> {
        if let Some(error) = &self.error {
            Err(TokenError::NetworkError(error.to_string()))
        } else {
            Ok(self)
        }
    }
}

#[derive(Debug)]
pub enum RequestType<'a> {
    Metadata(MetadataField),
    Balance(&'a Address),
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

struct ERC20Helper {
    abi: JsonAbi,
}

impl ERC20Helper {
    fn new() -> Result<Self> {
        Ok(Self {
            abi: serde_json::from_str(ERC20_ABI)
                .map_err(|e| TokenError::ABIError(format!("Failed to parse ERC20 ABI: {}", e)))?,
        })
    }

    fn get_function(&self, name: &str) -> Result<&Function> {
        self.abi
            .function(name)
            .and_then(|f| f.first())
            .ok_or_else(|| {
                TokenError::ABIError(format!("Function {} not found or no overloads", name))
            })
    }

    fn encode_function_call(&self, name: &str, inputs: &[DynSolValue]) -> Result<Vec<u8>> {
        let func = self.get_function(name)?;
        let bytes = &func
            .abi_encode_input(inputs)
            .map_err(|e| TokenError::ABIError(e.to_string()))?;

        Ok(bytes.to_owned())
    }

    pub fn generate_transfer_input(&self, to: &Address, amount: U256) -> Result<Vec<u8>> {
        let inputs = vec![
            DynSolValue::Address(to.to_alloy_addr()),
            DynSolValue::Uint(amount, 256),
        ];

        self.encode_function_call("transfer", &inputs)
    }
}

pub fn generate_erc20_transfer_data(to: &Address, amount: U256) -> Result<Vec<u8>> {
    let erc20 = ERC20Helper::new()?;

    erc20.generate_transfer_input(to, amount)
}

pub fn build_token_requests<'a>(
    contract: &Address,
    accounts: &[&'a Address],
    native: bool,
) -> RequestResult<'a> {
    let size = match contract {
        Address::Secp256k1Sha256(_) => 1 + accounts.len(),
        Address::Secp256k1Keccak256(_) => 3 + accounts.len(),
    };
    let mut requests = Vec::with_capacity(size);

    match contract {
        Address::Secp256k1Sha256(_) => {
            build_zil_requests(contract, accounts, native, &mut requests)?;
        }
        Address::Secp256k1Keccak256(_) => {
            build_eth_requests(contract, accounts, native, &mut requests)?;
        }
    }

    Ok(requests)
}

fn build_zil_requests<'a>(
    contract: &Address,
    accounts: &[&'a Address],
    native: bool,
    requests: &mut Vec<(Value, RequestType<'a>)>,
) -> Result<()> {
    let base16_contract = contract
        .get_zil_base16()
        .map_err(TokenError::InvalidContractAddress)?;
    requests.push((
        RpcProvider::<ChainConfig>::build_payload(
            json!([base16_contract]),
            ZilMethods::GetSmartContractInit,
        ),
        RequestType::Metadata(MetadataField::Name),
    ));

    for account in accounts {
        let base16_account = match &account {
            Address::Secp256k1Sha256(_) => &account
                .get_zil_check_sum_addr()
                .map_err(TokenError::InvalidContractAddress)?
                .to_lowercase(),
            Address::Secp256k1Keccak256(_) => &account
                .to_eth_checksummed()
                .map_err(TokenError::InvalidContractAddress)?,
        };

        let request = if native {
            RpcProvider::<ChainConfig>::build_payload(
                json!([base16_account]),
                ZilMethods::GetBalance,
            )
        } else {
            RpcProvider::<ChainConfig>::build_payload(
                json!([base16_contract, "balances", [base16_account]]),
                ZilMethods::GetSmartContractSubState,
            )
        };

        requests.push((request, RequestType::Balance(account)));
    }

    Ok(())
}

fn build_eth_requests<'a>(
    contract: &Address,
    accounts: &[&'a Address],
    native: bool,
    requests: &mut Vec<(Value, RequestType<'a>)>,
) -> Result<()> {
    let build_payload = RpcProvider::<ChainConfig>::build_payload;
    let token_addr = contract
        .to_eth_checksummed()
        .map_err(TokenError::InvalidContractAddress)?;
    let erc20 = ERC20Helper::new()?;

    let build_eth_call = |data: Vec<u8>| -> Value {
        build_payload(
            json!([{
                "to": &token_addr,
                "data": alloy::hex::encode_prefixed(data)
            }, "latest"]),
            EvmMethods::Call,
        )
    };

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
                .map_err(TokenError::InvalidContractAddress)?;
            build_payload(json!([owner, "latest"]), EvmMethods::GetBalance)
        } else {
            let call_data = erc20.encode_function_call(
                "balanceOf",
                &[DynSolValue::Address(account.to_alloy_addr())],
            )?;
            build_eth_call(call_data)
        };

        requests.push((request, RequestType::Balance(account)));
    }

    Ok(())
}

pub fn process_eth_metadata_response(
    response: &ResultRes<Value>,
    field_type: &MetadataField,
) -> Result<String> {
    if let Some(error) = &response.error {
        let rpc_err = NetworkErrors::RPCError(format!(
            "JSON-RPC error (code: {}): {}{}",
            error.code,
            error.message,
            error
                .data
                .as_ref()
                .map(|d| format!(", data: {}", d))
                .unwrap_or_default()
        ))
        .to_string();
        return Err(TokenError::NetworkError(rpc_err));
    }

    let erc20 = ERC20Helper::new()?;
    let func = erc20.get_function(&field_type.to_string())?;
    let hex_str = response
        .result
        .as_ref()
        .and_then(|r| r.as_str())
        .ok_or_else(|| TokenError::ABIError("Invalid response format".to_string()))?;

    let bytes = hex::decode(hex_str.trim_start_matches("0x"))
        .map_err(|e| TokenError::ABIError(format!("Failed to decode hex: {}", e)))?;

    let values = func
        .abi_decode_output(&bytes)
        .map_err(|e| TokenError::ABIError(e.to_string()))?;

    let value = values
        .first()
        .ok_or_else(|| TokenError::ABIError("No values decoded".to_string()))?;

    match field_type {
        MetadataField::Decimals => value
            .as_uint()
            .ok_or_else(|| TokenError::ABIError("Invalid decimals format".to_string()))
            .map(|u| u.0.to_string()),
        _ => value
            .as_str()
            .ok_or_else(|| TokenError::ABIError("Invalid string format".to_string()))
            .map(|s| s.to_string()),
    }
}

pub fn process_zil_metadata_response(init_res: &Value) -> Result<(String, String, u8)> {
    let res_init: Vec<GetTokenInitItem> = init_res
        .as_array()
        .ok_or(TokenError::InvalidContractInit)?
        .iter()
        .map(|v| v.try_into())
        .collect::<std::result::Result<Vec<GetTokenInitItem>, TokenError>>()
        .map_err(|_| TokenError::TokenParseError)?;

    let get_field = |field: &str| -> Result<String> {
        res_init
            .iter()
            .find(|v| v.vname == field)
            .map(|v| v.value.clone())
            .ok_or(TokenError::InvalidContractInit)
    };

    let name = get_field(&MetadataField::Name.to_string())?;
    let symbol = get_field(&MetadataField::Symbol.to_string())?;
    let decimals = get_field(&MetadataField::Decimals.to_string())?
        .parse()
        .map_err(|_| TokenError::InvalidContractInit)?;

    Ok((name, symbol, decimals))
}

pub fn process_eth_balance_response(response: &ResultRes<Value>) -> Result<U256> {
    let response = response.validate()?;

    response
        .result
        .as_ref()
        .and_then(|v| v.as_str())
        .ok_or_else(|| TokenError::ABIError("Invalid response format".to_string()))?
        .parse()
        .map_err(|_| TokenError::ABIError("Invalid balance format".to_string()))
}

pub fn process_zil_balance_response(
    response: &ResultRes<Value>,
    account: &Address,
    is_native: bool,
) -> u128 {
    if response.error.is_some() {
        return 0;
    }

    if is_native {
        let balance = response
            .result
            .as_ref()
            .and_then(|v| v.get("balance"))
            .and_then(|v| v.as_str())
            .and_then(|v| v.parse::<u128>().ok())
            .unwrap_or_default();

        balance
    } else {
        let addr = match account.get_zil_check_sum_addr() {
            Ok(v) => v.to_lowercase(),
            Err(_) => {
                return 0;
            }
        };

        let balance = response
            .result
            .as_ref()
            .and_then(|v| v.get("balances"))
            .and_then(|v| v.get(addr))
            .and_then(|v| v.as_str())
            .and_then(|v| v.parse::<u128>().ok())
            .unwrap_or_default();

        balance
    }
}

#[cfg(test)]
mod ftoken_tests {
    use super::*;
    use config::address::ADDR_LEN;
    use rpc::zil_interfaces::ErrorRes;
    use serde_json::json;

    fn create_mock_eth_address() -> Address {
        Address::Secp256k1Keccak256([0u8; ADDR_LEN])
    }

    fn create_mock_zil_address() -> Address {
        Address::from_zil_bech32("zil1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq9yf6pz").unwrap()
    }

    fn create_mock_error_response<T>(code: i16, message: &str) -> ResultRes<T> {
        ResultRes {
            id: 1,
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(ErrorRes {
                code,
                message: message.to_string(),
                data: None,
            }),
        }
    }

    mod response_validator_tests {
        use super::*;

        #[test]
        fn test_validate_success() {
            let response: ResultRes<Value> = ResultRes {
                id: 1,
                jsonrpc: "2.0".to_string(),
                result: Some(json!("0x123")),
                error: None,
            };
            assert!(response.validate().is_ok());
        }

        #[test]
        fn test_validate_error() {
            let response = create_mock_error_response::<Value>(1, "Test error");
            let err = response.validate().unwrap_err();
            match err {
                TokenError::NetworkError(msg) => {
                    assert!(msg.contains("Test error"));
                    assert!(msg.contains("code: 1"));
                }
                _ => panic!("Expected RPCError"),
            }
        }
    }

    mod build_token_requests_tests {
        use super::*;

        #[test]
        fn test_build_eth_token_requests() {
            let contract = create_mock_eth_address();
            let account = create_mock_eth_address();
            let accounts = vec![&account];
            let requests = build_token_requests(&contract, &accounts, false).unwrap();

            // Should have 4 requests: name, symbol, decimals, and balance
            assert_eq!(requests.len(), 4);

            // Verify metadata requests
            let metadata_requests: Vec<_> = requests
                .iter()
                .filter_map(|(_, req_type)| match req_type {
                    RequestType::Metadata(field) => Some(field),
                    _ => None,
                })
                .collect();
            assert_eq!(metadata_requests.len(), 3);

            // Verify balance request
            let balance_requests: Vec<_> = requests
                .iter()
                .filter_map(|(_, req_type)| match req_type {
                    RequestType::Balance(_) => Some(true),
                    _ => None,
                })
                .collect();
            assert_eq!(balance_requests.len(), 1);
        }

        #[test]
        fn test_build_zil_token_requests() {
            let contract = create_mock_zil_address();
            let account = create_mock_zil_address();
            let accounts = vec![&account];
            let requests = build_token_requests(&contract, &accounts, false).unwrap();

            // Should have 2 requests: init (metadata) and balance
            assert_eq!(requests.len(), 2);
        }
    }

    mod process_eth_metadata_response_tests {
        use super::*;

        #[test]
        fn test_process_name_success() {
            let hex_string = "0x000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000047465737400000000000000000000000000000000000000000000000000000000";
            let response = ResultRes {
                id: 1,
                jsonrpc: "2.0".to_string(),
                result: Some(json!(hex_string)),
                error: None,
            };

            let result = process_eth_metadata_response(&response, &MetadataField::Name).unwrap();
            assert_eq!(result, "test");
        }

        #[test]
        fn test_process_decimals_success() {
            let hex_string = "0x0000000000000000000000000000000000000000000000000000000000000012"; // 18 in hex
            let response = ResultRes {
                id: 1,
                jsonrpc: "2.0".to_string(),
                result: Some(json!(hex_string)),
                error: None,
            };

            let result =
                process_eth_metadata_response(&response, &MetadataField::Decimals).unwrap();
            assert_eq!(result, "18");
        }

        #[test]
        fn test_process_rpc_error() {
            let response = create_mock_error_response::<Value>(1, "Test error");
            let result = process_eth_metadata_response(&response, &MetadataField::Name);
            assert!(matches!(result, Err(TokenError::NetworkError(_))));
        }
    }

    mod process_eth_balance_response_tests {
        use super::*;

        #[test]
        fn test_process_balance_success() {
            let response = ResultRes {
                id: 1,
                jsonrpc: "2.0".to_string(),
                result: Some(json!(
                    "0x0000000000000000000000000000000000000000000000000000000000000064"
                )), // 100 in hex
                error: None,
            };

            let balance = process_eth_balance_response(&response).unwrap();
            assert_eq!(balance, U256::from(100));
        }

        #[test]
        fn test_process_balance_invalid_format() {
            let response = ResultRes {
                id: 1,
                jsonrpc: "2.0".to_string(),
                result: Some(json!("invalid_hex")),
                error: None,
            };

            let result = process_eth_balance_response(&response);
            assert!(matches!(result, Err(TokenError::ABIError(_))));
        }
    }

    mod process_zil_balance_response_tests {
        use proto::keypair::KeyPair;

        use super::*;

        #[test]
        fn test_process_native_balance_success() {
            let response = ResultRes {
                id: 1,
                jsonrpc: "2.0".to_string(),
                result: Some(json!({
                    "balance": "100"
                })),
                error: None,
            };

            let balance = process_zil_balance_response(&response, &create_mock_zil_address(), true);
            assert_eq!(balance, 100);
        }

        #[test]
        fn test_process_token_balance_success() {
            let keypair = KeyPair::gen_sha256().unwrap();
            let account = keypair.get_addr().unwrap();
            let base16_account = account.get_zil_check_sum_addr().unwrap().to_lowercase();

            dbg!(&base16_account);

            let mut balances = serde_json::Map::new();
            balances.insert(base16_account, json!("200"));

            let response = ResultRes {
                id: 1,
                jsonrpc: "2.0".to_string(),
                result: Some(json!({
                    "balances": balances
                })),
                error: None,
            };

            let balance = process_zil_balance_response(&response, &account, false);
            assert_eq!(balance, 200);
        }
    }

    mod process_zil_metadata_response_tests {
        use super::*;

        #[test]
        fn test_process_metadata_success() {
            let init_data = json!([
                {
                    "vname": "name",
                    "type": "String",
                    "value": "Test Token"
                },
                {
                    "vname": "symbol",
                    "type": "String",
                    "value": "TEST"
                },
                {
                    "vname": "decimals",
                    "value": "18",
                    "type": "Uint32",
                }
            ]);

            let (name, symbol, decimals) = process_zil_metadata_response(&init_data).unwrap();
            assert_eq!(name, "Test Token");
            assert_eq!(symbol, "TEST");
            assert_eq!(decimals, 18);
        }

        #[test]
        fn test_process_metadata_missing_field() {
            let init_data = json!([
                {
                    "type": "String",
                    "vname": "name",
                    "value": "Test Token"
                }
            ]);

            let result = process_zil_metadata_response(&init_data);

            assert!(matches!(result, Err(TokenError::InvalidContractInit)));
        }
    }

    #[test]
    fn test_generate_transfer_input() {
        let to_address = Address::Secp256k1Keccak256([1u8; ADDR_LEN]);
        let amount = U256::from(1000000000000000000u64);
        let result = generate_erc20_transfer_data(&to_address, amount);

        assert!(result.is_ok());
        let input_data = result.unwrap();

        assert_eq!(alloy::hex::encode_prefixed(input_data), "0xa9059cbb00000000000000000000000001010101010101010101010101010101010101010000000000000000000000000000000000000000000000000de0b6b3a7640000");
    }
}
