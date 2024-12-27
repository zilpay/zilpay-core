use config::sha::SHA256_SIZE;

pub fn create_wallet_device_indicator(
    wallet_address: &[u8; SHA256_SIZE],
    device_indicators: &[String],
) -> Vec<u8> {
    let total_size = wallet_address.len()
        + device_indicators
            .iter()
            .map(|s| s.as_bytes().len())
            .sum::<usize>()
        + device_indicators.len();
    let mut result = Vec::with_capacity(total_size);

    result.extend_from_slice(wallet_address);

    for indicator in device_indicators {
        result.push(b':');
        result.extend_from_slice(indicator.as_bytes());
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_wallet_device_indicator() {
        // Prepare test data
        let mut wallet_address = [0u8; SHA256_SIZE];
        wallet_address[0] = 0x12;
        wallet_address[1] = 0x34;

        let device_indicators = vec![String::from("device1"), String::from("device2")];

        // Execute tested function
        let result = create_wallet_device_indicator(&wallet_address, &device_indicators);

        // Prepare expected result
        let mut expected = Vec::new();
        expected.extend_from_slice(&wallet_address);
        expected.push(b':');
        expected.extend_from_slice(b"device1");
        expected.push(b':');
        expected.extend_from_slice(b"device2");

        // Verify result
        assert_eq!(result, expected);
    }

    #[test]
    fn test_empty_device_indicators() {
        let wallet_address = [0u8; SHA256_SIZE];
        let device_indicators: Vec<String> = vec![];

        let result = create_wallet_device_indicator(&wallet_address, &device_indicators);

        // Should contain only wallet_address without delimiters
        assert_eq!(result, wallet_address);
    }

    #[test]
    fn test_single_device_indicator() {
        let mut wallet_address = [0u8; SHA256_SIZE];
        wallet_address[0] = 0xFF;

        let device_indicators = vec![String::from("single_device")];

        let result = create_wallet_device_indicator(&wallet_address, &device_indicators);

        let mut expected = Vec::new();
        expected.extend_from_slice(&wallet_address);
        expected.push(b':');
        expected.extend_from_slice(b"single_device");

        assert_eq!(result, expected);
    }

    #[test]
    fn test_capacity_allocation() {
        let wallet_address = [0u8; SHA256_SIZE];
        let device_indicators = vec![String::from("dev1"), String::from("dev2")];

        let result = create_wallet_device_indicator(&wallet_address, &device_indicators);

        // Check if capacity equals length (no extra allocation)
        assert_eq!(result.capacity(), result.len());
    }
}
