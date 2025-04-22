use bigdecimal::{BigDecimal, num_bigint::BigInt};
use errors::intl::IntlErrors;
use std::str::FromStr;

pub fn to_wei(value: String, target_decimals: u8) -> Result<BigInt, IntlErrors> {
    let decimals_value = BigDecimal::from_str(&value)
        .map_err(|e| IntlErrors::BigDecimalParseError(value, e.to_string()))?;
    let (big_value, exponent) = decimals_value.as_bigint_and_exponent();

    if exponent < 0 {
        return Err(IntlErrors::InvalidDecimals(exponent));
    }
    if exponent > u8::MAX as i64 {
        return Err(IntlErrors::InvalidDecimals(exponent));
    }

    let current_decimals = exponent as u8;

    if current_decimals < target_decimals {
        let multiplier = BigInt::from(10).pow((target_decimals - current_decimals) as u32);
        Ok(big_value * multiplier)
    } else if current_decimals > target_decimals {
        let divisor = BigInt::from(10).pow((current_decimals - target_decimals) as u32);
        Ok(big_value / divisor)
    } else {
        Ok(big_value)
    }
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
        let target_decimals = 18u8;
        let expected_bigint = BigInt::from_str("100000000000000000000").unwrap();
        let result = to_wei(value, target_decimals);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected_bigint);
    }

    #[test]
    fn test_to_wei_specific_high_precision_decimal() {
        let value = "99.63999999715".to_string();
        let target_decimals = 18u8;
        let expected_bigint = BigInt::from_str("99639999997150000000").unwrap();
        let result = to_wei(value, target_decimals);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected_bigint);
    }

    #[test]
    fn test_to_wei_decimal() {
        let value = "123.45".to_string();
        let target_decimals = 18u8;
        let expected_bigint = BigInt::from_str("123450000000000000000").unwrap();
        let result = to_wei(value, target_decimals);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected_bigint);
    }

    #[test]
    fn test_to_wei_small_decimal() {
        let value = "0.000000000000000001".to_string();
        let target_decimals = 18u8;
        let expected_bigint = BigInt::from(1);
        let result = to_wei(value, target_decimals);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected_bigint);
    }

    #[test]
    fn test_to_wei_leading_zero_decimal() {
        let value = "0.5".to_string();
        let target_decimals = 18u8;
        let expected_bigint = BigInt::from_str("500000000000000000").unwrap();
        let result = to_wei(value, target_decimals);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected_bigint);
    }

    #[test]
    fn test_to_wei_large_number() {
        let value = "1000000000000000000000000000000".to_string();
        let target_decimals = 18u8;
        let expected_bigint =
            BigInt::from_str("1000000000000000000000000000000000000000000000000").unwrap();
        let result = to_wei(value, target_decimals);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected_bigint);
    }

    #[test]
    fn test_to_wei_invalid_input() {
        let value = "not_a_number".to_string();
        let target_decimals = 18u8;
        let result = to_wei(value.clone(), target_decimals);
        assert!(result.is_err());
        match result.err().unwrap() {
            IntlErrors::BigDecimalParseError(val, _) => assert_eq!(val, value),
            _ => panic!("Expected BigDecimalParseError"),
        }
    }

    #[test]
    fn test_to_wei_custom_decimals() {
        let value = "123.45".to_string();
        let target_decimals = 8u8;
        let expected_bigint = BigInt::from_str("12345000000").unwrap();
        let result = to_wei(value, target_decimals);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected_bigint);
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

    #[test]
    fn test_from_wei_and_from_wei() {
        let value = String::from_str("123456789000000000000").unwrap();
        let decimals = 18u8;
        let result = from_wei(value.clone(), decimals).unwrap();
        let res = to_wei(result, decimals).unwrap();
        assert_eq!(res.to_string(), value);
    }
}
