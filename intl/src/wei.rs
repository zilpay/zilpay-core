use bigdecimal::{BigDecimal, num_bigint::BigInt};
use errors::intl::IntlErrors;
use std::str::FromStr;

pub fn to_wei(value: String) -> Result<(BigInt, u8), IntlErrors> {
    let decimals_value = BigDecimal::from_str(&value)
        .map_err(|e| IntlErrors::BigDecimalParseError(value, e.to_string()))?;
    let (big_value, decimals) = decimals_value.as_bigint_and_exponent();

    if decimals > u8::MAX as i64 {
        return Err(IntlErrors::InvalidDecimals(decimals));
    }

    Ok((big_value, decimals as u8))
}

pub fn from_wei(value: String, decimals: u8) -> Result<String, IntlErrors> {
    let big_value = BigInt::from_str(&value)
        .map_err(|e| IntlErrors::BigDecimalParseError(value, e.to_string()))?;
    let big_decimal = BigDecimal::new(big_value, decimals as i64);

    Ok(big_decimal.normalized().to_plain_string())
}

#[cfg(test)]
mod tests_wei {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_to_wei_integer() {
        let value = "100".to_string();
        let expected_bigint = BigInt::from(100);
        let expected_decimals = 0u8;
        let result = to_wei(value);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), (expected_bigint, expected_decimals));
    }

    #[test]
    fn test_to_wei_decimal() {
        let value = "123.45".to_string();
        let expected_bigint = BigInt::from(12345);
        let expected_decimals = 2u8;
        let result = to_wei(value);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), (expected_bigint, expected_decimals));
    }

    #[test]
    fn test_to_wei_small_decimal() {
        let value = "0.000000000000000001".to_string();
        let expected_bigint = BigInt::from(1);
        let expected_decimals = 18u8;
        let result = to_wei(value);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), (expected_bigint, expected_decimals));
    }

    #[test]
    fn test_to_wei_leading_zero_decimal() {
        let value = "0.5".to_string();
        let expected_bigint = BigInt::from(5);
        let expected_decimals = 1u8;
        let result = to_wei(value);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), (expected_bigint, expected_decimals));
    }

    #[test]
    fn test_to_wei_large_number() {
        let value = "1000000000000000000000000000000".to_string();
        let expected_bigint = BigInt::from_str("1000000000000000000000000000000").unwrap();
        let expected_decimals = 0u8;
        let result = to_wei(value);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), (expected_bigint, expected_decimals));
    }

    #[test]
    fn test_to_wei_invalid_input() {
        let value = "not_a_number".to_string();
        let result = to_wei(value.clone());
        assert!(result.is_err());
        match result.err().unwrap() {
            IntlErrors::BigDecimalParseError(val, _) => assert_eq!(val, value),
            _ => panic!("Expected BigDecimalParseError"),
        }
    }

    #[test]
    fn test_from_wei_zero_decimals() {
        let value = String::from("12345");
        let decimals = 0u8;
        let expected_string = "12345".to_string();
        let result = from_wei(value, decimals).unwrap();

        assert_eq!(result, expected_string);
    }

    #[test]
    fn test_from_wei_with_decimals() {
        let value = String::from("12345");
        let decimals = 2u8;
        let expected_string = "123.45".to_string();
        let result = from_wei(value, decimals).unwrap();
        assert_eq!(result, expected_string);
    }

    #[test]
    fn test_from_wei_less_than_one() {
        let value = String::from("1");
        let decimals = 18u8;
        let expected_string = "0.000000000000000001".to_string();
        let result = from_wei(value, decimals).unwrap();
        assert_eq!(result, expected_string);
    }

    #[test]
    fn test_from_wei_leading_zeros_in_bigint() {
        let value = String::from("500");
        let decimals = 3u8;
        let expected_string = "0.5".to_string();
        let result = from_wei(value, decimals).unwrap();
        assert_eq!(result, expected_string);
    }

    #[test]
    fn test_from_wei_large_number() {
        let value = String::from_str("100000000000000000000").unwrap();
        let decimals = 18u8;
        let expected_string = "100".to_string();
        let result = from_wei(value, decimals).unwrap();
        assert_eq!(result, expected_string);
    }

    #[test]
    fn test_from_wei_large_number_with_decimals() {
        let value = String::from_str("123456789000000000000").unwrap();
        let decimals = 18u8;
        let expected_string = "123.456789".to_string();
        let result = from_wei(value, decimals).unwrap();
        assert_eq!(result, expected_string);
    }
}
