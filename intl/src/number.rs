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
        return format!(">{}", threshold);
    }

    if compact && integer_part.len() > 3 {
        let float_value =
            value.to_string().parse::<f64>().unwrap_or(0.0) / 10f64.powi(decimals as i32);
        let log = float_value.log10().floor();
        let magnitude = if log >= 3.0 {
            (log / 3.0).floor() * 3.0
        } else {
            0.0
        };
        let divisor = 10f64.powf(magnitude);
        let compact_value = float_value / divisor;
        let suffix = match magnitude as u32 {
            3 => "K",
            6 => "M",
            9 => "B",
            12 => "T",
            15 => "Q",
            _ => "",
        };
        if suffix.is_empty() {
            return format!("{:.6} {}", compact_value, currency_symbol);
        } else {
            return format!("{:.6}{} {}", compact_value, suffix, currency_symbol);
        }
    }

    let integer_formatted = format_integer_part(integer_part, &locale);

    let result = if decimal_part.is_empty() {
        format!("{} {}", integer_formatted, currency_symbol)
    } else {
        format!("{}.{} {}", integer_formatted, decimal_part, currency_symbol)
    };

    result.replace('\u{a0}', " ")
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
        assert_eq!(result, ">0.00001");
    }

    #[test]
    fn test_compact() {
        let value = U256::from(123456789);
        let result = format_u256(value, 2, "en", "USD", 0.0000001, true);
        assert_eq!(result, "1.234568M $");
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
}
