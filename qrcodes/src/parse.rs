use alloy::primitives::U256;
use errors::qrcode::QRCodeError;
use std::{collections::HashMap, str::FromStr};

#[derive(Debug, Clone, PartialEq)]
pub struct QRcodeScanResult {
    pub recipient: String,
    pub provider: Option<String>,
    pub token_address: Option<String>,
    pub amount: Option<String>,
}

impl FromStr for QRcodeScanResult {
    type Err = QRCodeError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let clean_input = input.trim();

        if !clean_input.contains(':') {
            return Ok(QRcodeScanResult {
                recipient: clean_input.to_string(),
                provider: None,
                token_address: None,
                amount: None,
            });
        }

        let (uri, params) = clean_input.split_once('?').unwrap_or((clean_input, ""));
        let parts: Vec<&str> = uri
            .split(|c| c == ':' || c == '/')
            .filter(|s| !s.is_empty())
            .collect();
        let network = parts
            .first()
            .ok_or(QRCodeError::InvalidProvider)?
            .to_string();
        let recipient = parts.get(1).ok_or(QRCodeError::InvalidAddress)?.to_string();
        let params: HashMap<&str, &str> = params
            .split('&')
            .filter(|s| !s.is_empty())
            .filter_map(|param| param.split_once('='))
            .collect();

        let amount = params.get("amount").map(|&s| s.to_string());
        if let Some(ref amt) = amount {
            if !validate_amount(amt) {
                return Err(QRCodeError::InvalidAmount);
            }
        }

        Ok(QRcodeScanResult {
            recipient,
            provider: Some(network),
            token_address: params.get("token").map(|&s| s.to_string()),
            amount,
        })
    }
}

pub fn validate_amount(amount: &str) -> bool {
    if amount.is_empty() {
        return false;
    }

    U256::from_str(amount).is_ok()
}

#[cfg(test)]
mod tests_qrcode_parse {
    use super::*;

    #[test]
    fn test_valid_amount() {
        assert!(validate_amount("0"));
        assert!(validate_amount(
            "115792089237316195423570985008687907853269984665640564039457584007913129639935"
        )); // max U256
    }

    #[test]
    fn test_invalid_amount() {
        assert!(!validate_amount(""));
        assert!(!validate_amount("-1"));
        assert!(!validate_amount("abc"));
        assert!(!validate_amount(
            "115792089237316195423570985008687907853269984665640564039457584007913129639936"
        )); // U256 overflow
        assert!(!validate_amount("1.23"));
        assert!(!validate_amount(" 123"));
    }

    #[test]
    fn test_from_str() {
        let result = "zilliqa://zil1sctmwt3zpy8scyck0pj3glky3fkm0z8lxa4ga7"
            .parse::<QRcodeScanResult>()
            .unwrap();
        assert_eq!(
            result.recipient,
            "zil1sctmwt3zpy8scyck0pj3glky3fkm0z8lxa4ga7"
        );
        assert_eq!(result.provider, Some("zilliqa".to_string()));

        let result = "zilliqa:zil1sctmwt3zpy8scyck0pj3glky3fkm0z8lxa4ga7"
            .parse::<QRcodeScanResult>()
            .unwrap();
        assert_eq!(
            result.recipient,
            "zil1sctmwt3zpy8scyck0pj3glky3fkm0z8lxa4ga7"
        );
        assert_eq!(result.provider, Some("zilliqa".to_string()));

        let result = "ethereum:0x246C5881E3F109B2aF170F5C773EF969d3da581B"
            .parse::<QRcodeScanResult>()
            .unwrap();
        assert_eq!(
            result.recipient,
            "0x246C5881E3F109B2aF170F5C773EF969d3da581B"
        );
        assert_eq!(result.provider, Some("ethereum".to_string()));

        assert!(
            "ethereum:0x246C5881E3F109B2aF170F5C773EF969d3da581B?amount=abc"
                .parse::<QRcodeScanResult>()
                .is_err()
        );
        assert!(
            "ethereum:0x246C5881E3F109B2aF170F5C773EF969d3da581B?amount=-1"
                .parse::<QRcodeScanResult>()
                .is_err()
        );
        assert!(
            "ethereum:0x246C5881E3F109B2aF170F5C773EF969d3da581B?amount=1.2"
                .parse::<QRcodeScanResult>()
                .is_err()
        );

        assert!(
            "ethereum:0x246C5881E3F109B2aF170F5C773EF969d3da581B?amount=42"
                .parse::<QRcodeScanResult>()
                .is_ok()
        );

        let result = "ethereum:0x246C5881E3F109B2aF170F5C773EF969d3da581B?token=0xdac17f958d2ee523a2206206994597c13d831ec7&amount=1000000"
            .parse::<QRcodeScanResult>()
            .unwrap();
        assert_eq!(
            result.recipient,
            "0x246C5881E3F109B2aF170F5C773EF969d3da581B"
        );
        assert_eq!(result.provider, Some("ethereum".to_string()));
        assert_eq!(
            result.token_address,
            Some("0xdac17f958d2ee523a2206206994597c13d831ec7".to_string())
        );
        assert_eq!(result.amount, Some("1000000".to_string()));

        let result = "0x246C5881E3F109B2aF170F5C773EF969d3da581B"
            .parse::<QRcodeScanResult>()
            .unwrap();
        assert_eq!(
            result.recipient,
            "0x246C5881E3F109B2aF170F5C773EF969d3da581B"
        );
    }
}
