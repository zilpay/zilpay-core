use alloy::primitives::U256;
use num_format::{Grouping, Locale};

const CURRENCY_SYMBOLS: &[(&str, &str)] = &[
    ("RUB", "₽"),
    ("USD", "$"),
    ("EUR", "€"),
    ("JPY", "¥"),
    ("GBP", "£"),
    ("CNY", "¥"),
    ("INR", "₹"),
    ("KRW", "₩"),
    ("CHF", "₣"),
    ("BRL", "R$"),
    ("AUD", "A$"),
    ("CAD", "C$"),
    ("MXN", "$"),
    ("BTC", "₿"),
    ("ETH", "Ξ"),
    ("LTC", "Ł"),
    ("XRP", "✕"),
    ("BCH", "Ƀ"),
    ("ADA", "₳"),
    ("DOT", "●"),
    ("SOL", "◎"),
    ("USDT", "₮"),
    ("DOGE", "Ð"),
    ("GOLD", "Au"),
    ("SILVER", "Ag"),
    ("OIL", "🛢️"),
    ("GAS", "⛽"),
    ("PLAT", "Pt"),
];

const DISPLAY_DECIMALS: usize = 6;

pub fn format_u256(
    value: U256,
    decimals: u8,
    locale_str: &str,
    symbol_str: &str,
    threshold: f64,
    compact: bool,
) -> String {
    let locale = Locale::from_name(locale_str).unwrap_or(Locale::en);
    let currency_symbol = CURRENCY_SYMBOLS
        .iter()
        .find(|&&(key, _)| key == symbol_str)
        .map(|&(_, symbol)| symbol)
        .unwrap_or(symbol_str);

    let value_str = value.to_string();
    let decimals_usize = decimals as usize;
    let padded_value_str = if value_str.len() < decimals_usize {
        "0".repeat(decimals_usize - value_str.len()) + &value_str
    } else {
        value_str
    };

    let len = padded_value_str.len();
    let integer_part = if len <= decimals_usize {
        "0"
    } else {
        &padded_value_str[..len - decimals_usize]
    };
    let decimal_part = if decimals == 0 {
        ""
    } else if len <= decimals_usize {
        padded_value_str.trim_end_matches('0')
    } else {
        padded_value_str[len - decimals_usize..].trim_end_matches('0')
    };

    let threshold_scaled = (threshold * 10.0f64.powi(decimals as i32)).ceil() as u128;
    let threshold_u256 = U256::from(threshold_scaled);
    if value < threshold_u256 && !value.is_zero() {
        return format!(">{} {}", threshold, currency_symbol);
    }

    if compact && integer_part.len() > 3 {
        let integer_len = integer_part.len();
        let magnitude = ((integer_len - 1) / 3) * 3;

        let suffix = match magnitude {
            3 => "K",
            6 => "M",
            9 => "B",
            12 => "T",
            15 => "Q",
            _ => "",
        };

        let significant = &integer_part[..integer_part.len() - magnitude];
        let rest = &integer_part[integer_part.len() - magnitude..];

        let formatted = if rest.chars().all(|c| c == '0') {
            significant.to_string()
        } else {
            let rest_formatted = rest.trim_end_matches('0');
            if rest_formatted.is_empty() {
                significant.to_string()
            } else if rest_formatted.len() > DISPLAY_DECIMALS {
                format!("{}.{}..", significant, &rest_formatted[..DISPLAY_DECIMALS])
            } else {
                format!("{}.{}", significant, rest_formatted)
            }
        };

        return format!("{}{} {}", formatted, suffix, currency_symbol);
    } else {
        let integer_formatted = format_integer_part(integer_part, &locale);
        let decimal_display = if decimal_part.len() > DISPLAY_DECIMALS {
            &decimal_part[..DISPLAY_DECIMALS]
        } else {
            decimal_part
        };
        let ellipsis = if decimal_part.len() > DISPLAY_DECIMALS {
            ".."
        } else {
            ""
        };
        let result = if decimal_display.is_empty() {
            format!("{} {}", integer_formatted, currency_symbol)
        } else {
            format!(
                "{}.{}{} {}",
                integer_formatted, decimal_display, ellipsis, currency_symbol
            )
        };
        return result.replace('\u{a0}', " ");
    }
}

#[inline]
fn format_integer_part(integer_part: &str, locale: &Locale) -> String {
    let grouping = locale.grouping();
    let separator = locale.separator();
    match grouping {
        Grouping::Standard => {
            let mut result = String::new();
            let len = integer_part.len();
            for (i, c) in integer_part.chars().enumerate() {
                if i > 0 && (len - i) % 3 == 0 {
                    result.push_str(separator);
                }
                result.push(c);
            }
            result
        }
        Grouping::Indian => format_indian_grouping(integer_part, separator),
        _ => integer_part.to_string(),
    }
}

#[inline]
fn format_indian_grouping(s: &str, separator: &str) -> String {
    let len = s.len();
    if len <= 3 {
        return s.to_string();
    }
    let last_three = &s[len - 3..];
    let remaining = &s[..len - 3];
    let mut result = String::new();
    let mut count = 0;
    for c in remaining.chars().rev() {
        if count > 0 && count % 2 == 0 {
            result.push_str(separator);
        }
        result.push(c);
        count += 1;
    }
    let formatted_remaining = result.chars().rev().collect::<String>();
    formatted_remaining + separator + last_three
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_traditional_currency() {
        let value = U256::from(123456789);
        let result = format_u256(value, 2, "ru", "RUB", 0.0000001, false);
        assert_eq!(result, "1 234 567.89 ₽");
    }

    #[test]
    fn test_crypto_currency() {
        let value = U256::from(123456789);
        let result = format_u256(value, 2, "en", "BTC", 0.0000001, false);
        assert_eq!(result, "1,234,567.89 ₿");
    }

    #[test]
    fn test_commodity() {
        let value = U256::from(500000);
        let result = format_u256(value, 2, "en", "GOLD", 0.0000001, false);
        assert_eq!(result, "5,000 Au");
    }

    #[test]
    fn test_zero_decimals() {
        let value = U256::from(1234567);
        let result = format_u256(value, 0, "en", "USD", 0.0000001, false);
        assert_eq!(result, "1,234,567 $");
    }

    #[test]
    fn test_small_number() {
        let value = U256::from(42);
        let result = format_u256(value, 3, "fr", "EUR", 0.0000001, false);
        assert_eq!(result, "0.042 €");
    }

    #[test]
    fn test_threshold() {
        let value = U256::from(5);
        let result = format_u256(value, 6, "en", "ETH", 0.00001, false);
        assert_eq!(result, ">0.00001 Ξ");
    }

    #[test]
    fn test_compact() {
        let value = U256::from(123456789);
        let result = format_u256(value, 2, "en", "USD", 0.0000001, true);
        assert_eq!(result, "1.234567M $");
    }

    #[test]
    fn test_unknown_symbol() {
        let value = U256::from(12345);
        let result = format_u256(value, 2, "en", "ZIL", 0.0000001, false);
        assert_eq!(result, "123.45 ZIL");
    }

    #[test]
    fn test_indian_grouping() {
        let value = U256::from(12345678);
        let result = format_u256(value, 2, "hi", "INR", 0.0000001, false);
        assert_eq!(result, "1,23,456.78 ₹");
    }

    #[test]
    fn test_symbol() {
        let value = U256::from(10000000u128);
        let result = format_u256(value, 18, "", "BNB", 0.0000001, true);
        assert_eq!(result, ">0.0000001 BNB");
    }

    #[test]
    fn test_compact_with_long_decimal() {
        let value = U256::from(233555435453454354u128);
        let result = format_u256(value, 18, "en", "USD", 0.000001, true);
        assert_eq!(result, "0.233555.. $");
    }

    #[test]
    fn test_compact_with_exact_six_decimals() {
        let value = U256::from(123456789123456789u128);
        let result = format_u256(value, 18, "en", "ETH", 0.000001, true);
        assert_eq!(result, "0.123456.. Ξ");
    }

    #[test]
    fn test_k_values() {
        let value = U256::from(20000000000000000000000u128);
        let result = format_u256(value, 18, "", "ETH", 0.000001, true);
        assert_eq!(result, "20K Ξ");
    }

    #[test]
    fn test_none_k_values() {
        let value = U256::from(20000000000000000000000u128);
        let result = format_u256(value, 18, "", "ETH", 0.000001, false);
        assert_eq!(result, "20,000 Ξ");
    }
}
