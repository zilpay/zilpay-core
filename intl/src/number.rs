use alloy::primitives::U256;
use num_format::{Grouping, Locale};

pub const CURRENCY_SYMBOLS: &[(&str, &str)] = &[
    ("BTC", "₿"),
    ("ETH", "Ξ"),
    ("LTC", "Ł"),
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
    ("SOL", "◎"),
    ("USDT", "₮"),
    ("DOGE", "Ð"),
    ("XAUT", "🟡"),
    ("SILVER", "Ag"),
    ("OIL", "🛢️"),
    ("GAS", "⛽"),
    ("PLAT", "Pt"),
    ("KHR", "៛"),
    ("ILS", "₪"),
    ("TRY", "₺"),
    ("NGN", "₦"),
    ("UAH", "₴"),
    ("ZAR", "R"),
    ("PHP", "₱"),
    ("THB", "฿"),
    ("VND", "₫"),
    ("HKD", "HK$"),
    ("SGD", "S$"),
    ("NZD", "NZ$"),
    ("XMR", "ɱ"),
    ("AED", "د.إ"),
    ("EGP", "£"),
    ("ETB", "Br"),
    ("IRR", "﷼"),
    ("SAR", "﷼"),
];

const DISPLAY_DECIMALS: usize = 6;

struct FormatConfig<'a> {
    locale_str: &'a str,
    symbol_str: &'a str,
    threshold: f64,
    compact: bool,
}

pub fn format_u256(
    value: U256,
    decimals: u8,
    locale_str: &str,
    native_symbol_str: &str,
    converted_symbol_str: &str,
    threshold: f64,
    compact: bool,
    converted: f64,
) -> (String, String) {
    let native_config = FormatConfig {
        locale_str,
        symbol_str: native_symbol_str,
        threshold,
        compact,
    };

    let converted_config = FormatConfig {
        locale_str,
        symbol_str: converted_symbol_str,
        threshold,
        compact,
    };

    let native_formatted = format_value(value, decimals, &native_config, None);

    let converted_formatted = if converted > 0.0 {
        format_value(value, decimals, &converted_config, Some(converted))
    } else {
        "-".to_string()
    };

    (native_formatted, converted_formatted)
}

fn format_value(value: U256, decimals: u8, config: &FormatConfig, rate_opt: Option<f64>) -> String {
    let locale = Locale::from_name(config.locale_str).unwrap_or(Locale::en);
    let currency_symbol = get_currency_symbol(config.symbol_str);

    if let Some(rate) = rate_opt {
        let value_f64 = convert_u256_to_f64(value, decimals);
        let converted_value = value_f64 * rate;

        if converted_value < config.threshold && converted_value > 0.0 {
            return format!(">{}  {}", config.threshold, currency_symbol);
        }

        if config.compact && converted_value >= 1000.0 {
            return format_number_compact(converted_value, currency_symbol, config.threshold);
        }

        return format_f64(converted_value, &locale, currency_symbol);
    }

    let value_parts = extract_integer_decimal_parts(value, decimals);

    let threshold_scaled = (config.threshold * 10.0f64.powi(decimals as i32)).ceil() as u128;
    let threshold_u256 = U256::from(threshold_scaled);
    if value < threshold_u256 && !value.is_zero() {
        return format!(">{} {}", config.threshold, currency_symbol);
    }

    if config.compact && value_parts.0.len() > 3 {
        format_number_compact_parts(&value_parts.0, currency_symbol)
    } else {
        format_number_standard(&value_parts.0, &value_parts.1, &locale, currency_symbol)
    }
}

fn extract_integer_decimal_parts(value: U256, decimals: u8) -> (String, String) {
    let value_str = value.to_string();
    let decimals_usize = decimals as usize;

    let padded_value_str = if value_str.len() < decimals_usize {
        "0".repeat(decimals_usize - value_str.len()) + &value_str
    } else {
        value_str
    };

    let len = padded_value_str.len();
    let integer_part = if len <= decimals_usize {
        "0".to_string()
    } else {
        padded_value_str[..len - decimals_usize].to_string()
    };

    let decimal_part = if decimals == 0 {
        "".to_string()
    } else if len <= decimals_usize {
        padded_value_str.trim_end_matches('0').to_string()
    } else {
        padded_value_str[len - decimals_usize..]
            .trim_end_matches('0')
            .to_string()
    };

    (integer_part, decimal_part)
}

fn convert_u256_to_f64(value: U256, decimals: u8) -> f64 {
    let divisor = 10.0f64.powi(decimals as i32);

    let value_str = value.to_string();
    if let Ok(value_u128) = value_str.parse::<u128>() {
        return value_u128 as f64 / divisor;
    }

    let value_str = value.to_string();
    let len = value_str.len();
    let decimal_position = if len <= decimals as usize {
        0
    } else {
        len - decimals as usize
    };

    let mut result_str = String::new();
    if decimal_position == 0 {
        result_str.push_str("0.");
        result_str.push_str(&"0".repeat(decimals as usize - len));
        result_str.push_str(&value_str);
    } else {
        result_str.push_str(&value_str[..decimal_position]);
        if decimals > 0 {
            result_str.push('.');
            result_str.push_str(&value_str[decimal_position..]);
        }
    }

    result_str.parse::<f64>().unwrap_or(0.0)
}

fn format_number_compact(value: f64, currency_symbol: &str, threshold: f64) -> String {
    let magnitude = value.log10().floor() as usize / 3 * 3;

    if magnitude == 3 {
        let locale = Locale::en;
        return format_f64(value, &locale, currency_symbol);
    }

    let suffix = get_magnitude_suffix(magnitude);

    let scaled_value = value / 10.0f64.powi(magnitude as i32);

    let precision = if threshold > 0.0 {
        (-threshold.log10().ceil() as i32).max(0) as usize
    } else {
        DISPLAY_DECIMALS
    };

    let value_str = format!("{:.*}", precision, scaled_value);
    let formatted = value_str.trim_end_matches('0').trim_end_matches('.');

    format!("{}{} {}", formatted, suffix, currency_symbol)
}

fn format_number_compact_parts(integer_part: &str, currency_symbol: &str) -> String {
    let integer_len = integer_part.len();
    let magnitude = ((integer_len - 1) / 3) * 3;

    if magnitude == 3 {
        let locale = Locale::en;
        return format_number_standard(integer_part, "", &locale, currency_symbol);
    }

    let suffix = get_magnitude_suffix(magnitude);

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

    format!("{}{} {}", formatted, suffix, currency_symbol)
}

fn get_magnitude_suffix(magnitude: usize) -> &'static str {
    match magnitude {
        6 => "M",
        9 => "B",
        12 => "T",
        15 => "Q",
        _ => "",
    }
}

fn format_f64(value: f64, locale: &Locale, currency_symbol: &str) -> String {
    let value_str = format!("{:.8}", value);
    let decimal_pos = value_str.find('.').unwrap_or(value_str.len());

    let integer_part = &value_str[..decimal_pos];
    let decimal_part = if decimal_pos < value_str.len() - 1 {
        value_str[decimal_pos + 1..].trim_end_matches('0')
    } else {
        ""
    };

    format_number_standard(integer_part, decimal_part, locale, currency_symbol)
}

fn format_number_standard(
    integer_part: &str,
    decimal_part: &str,
    locale: &Locale,
    currency_symbol: &str,
) -> String {
    let integer_formatted = format_integer_part(integer_part, locale);
    let (decimal_display, ellipsis) = format_decimal_part(decimal_part);

    let result = if decimal_display.is_empty() {
        format!("{} {}", integer_formatted, currency_symbol)
    } else {
        format!(
            "{}.{}{} {}",
            integer_formatted, decimal_display, ellipsis, currency_symbol
        )
    };

    result.replace('\u{a0}', " ")
}

fn format_decimal_part(decimal_part: &str) -> (String, String) {
    let decimal_display = if decimal_part.len() > DISPLAY_DECIMALS {
        decimal_part[..DISPLAY_DECIMALS].to_string()
    } else {
        decimal_part.to_string()
    };

    let ellipsis = if decimal_part.len() > DISPLAY_DECIMALS {
        ".."
    } else {
        ""
    };

    (decimal_display, ellipsis.to_string())
}

#[inline]
fn get_currency_symbol(symbol_str: &str) -> &str {
    CURRENCY_SYMBOLS
        .iter()
        .find(|&&(key, _)| key == symbol_str)
        .map(|&(_, symbol)| symbol)
        .unwrap_or(symbol_str)
}

#[inline]
fn format_integer_part(integer_part: &str, locale: &Locale) -> String {
    let grouping = locale.grouping();
    let separator = locale.separator();
    match grouping {
        Grouping::Standard => {
            let mut result = String::with_capacity(integer_part.len() * 4 / 3);
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

    let mut result = String::with_capacity(len + len / 2);
    let mut count = 0;

    for c in remaining.chars().rev() {
        if count > 0 && count % 2 == 0 {
            result.push_str(separator);
        }
        result.push(c);
        count += 1;
    }

    format!(
        "{}{}{}",
        result.chars().rev().collect::<String>(),
        separator,
        last_three
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_traditional_currency() {
        let value = U256::from(123456789);
        let (native, _) = format_u256(value, 2, "ru", "RUB", "USD", 0.0000001, false, 0.0);
        assert_eq!(native, "1 234 567.89 ₽");
    }

    #[test]
    fn test_crypto_currency() {
        let value = U256::from(123456789);
        let (native, _) = format_u256(value, 2, "en", "BTC", "USD", 0.0000001, false, 0.0);
        assert_eq!(native, "1,234,567.89 ₿");
    }

    #[test]
    fn test_commodity() {
        let value = U256::from(500000);
        let (native, _) = format_u256(value, 2, "en", "GOLD", "USD", 0.0000001, false, 0.0);
        assert_eq!(native, "5,000 Au");
    }

    #[test]
    fn test_zero_decimals() {
        let value = U256::from(1234567);
        let (native, _) = format_u256(value, 0, "en", "USD", "EUR", 0.0000001, false, 0.0);
        assert_eq!(native, "1,234,567 $");
    }

    #[test]
    fn test_small_number() {
        let value = U256::from(42);
        let (native, _) = format_u256(value, 3, "fr", "EUR", "USD", 0.0000001, false, 0.0);
        assert_eq!(native, "0.042 €");
    }

    #[test]
    fn test_threshold() {
        let value = U256::from(5);
        let (native, _) = format_u256(value, 6, "en", "ETH", "USD", 0.00001, false, 0.0);
        assert_eq!(native, ">0.00001 Ξ");
    }

    #[test]
    fn test_compact() {
        let value = U256::from(123456789);
        let (native, _) = format_u256(value, 2, "en", "USD", "EUR", 0.0000001, true, 0.0);
        assert_eq!(native, "1.234567M $");
    }

    #[test]
    fn test_unknown_symbol() {
        let value = U256::from(12345);
        let (native, _) = format_u256(value, 2, "en", "ZIL", "USD", 0.0000001, false, 0.0);
        assert_eq!(native, "123.45 ZIL");
    }

    #[test]
    fn test_indian_grouping() {
        let value = U256::from(12345678);
        let (native, _) = format_u256(value, 2, "hi", "INR", "USD", 0.0000001, false, 0.0);
        assert_eq!(native, "1,23,456.78 ₹");
    }

    #[test]
    fn test_symbol() {
        let value = U256::from(10000000u128);
        let (native, _) = format_u256(value, 18, "", "BNB", "USD", 0.0000001, true, 0.0);
        assert_eq!(native, ">0.0000001 BNB");
    }

    #[test]
    fn test_compact_with_long_decimal() {
        let value = U256::from(233555435453454354u128);
        let (native, _) = format_u256(value, 18, "en", "USD", "EUR", 0.000001, true, 0.0);
        assert_eq!(native, "0.233555.. $");
    }

    #[test]
    fn test_compact_with_exact_six_decimals() {
        let value = U256::from(123456789123456789u128);
        let (native, _) = format_u256(value, 18, "en", "ETH", "USD", 0.000001, true, 0.0);
        assert_eq!(native, "0.123456.. Ξ");
    }

    #[test]
    fn test_k_values() {
        let value = U256::from(20000000000000000000000u128);
        let (native, _) = format_u256(value, 18, "", "ETH", "USD", 0.000001, true, 0.0);
        assert_eq!(native, "20,000 Ξ");
    }

    #[test]
    fn test_none_k_values() {
        let value = U256::from(20000000000000000000000u128);
        let (native, _) = format_u256(value, 18, "", "ETH", "USD", 0.000001, false, 0.0);
        assert_eq!(native, "20,000 Ξ");
    }

    #[test]
    fn test_values_converted() {
        let value = U256::from(2000000000000000000u128);
        let (native, converted) =
            format_u256(value, 18, "", "ETH", "BTC", 0.000001, false, 0.02536244);
        assert_eq!(native, "2 Ξ");
        assert_eq!(converted, "0.050724.. ₿");
    }

    #[test]
    fn test_both_values() {
        let value = U256::from(1000000000000000000u128);
        let (native, converted) =
            format_u256(value, 18, "en", "ETH", "USD", 0.000001, false, 1500.0);
        assert_eq!(native, "1 Ξ");
        assert_eq!(converted, "1,500 $");
    }

    #[test]
    fn test_compact_converted() {
        let value = U256::from(5000000000000000000u128);
        let (native, converted) =
            format_u256(value, 18, "en", "ETH", "USD", 0.000001, true, 1500.0);
        assert_eq!(native, "5 Ξ");
        assert_eq!(converted, "7,500 $");
    }
}
