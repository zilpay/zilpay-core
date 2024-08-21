use argon2::Argon2;
use zil_errors::CipherErrors;

pub const KEY_SIZE: usize = 64;
pub const WALLET_SALT: &[u8] = b"ZILPAY:54040c2f-1ec1-4eb1-9595-6e4294d14fd6";

pub fn derive_key(password: &[u8]) -> Result<[u8; KEY_SIZE], CipherErrors> {
    let mut output_key_material = [0u8; KEY_SIZE];
    let argon2 = Argon2::default();

    argon2
        .hash_password_into(password, WALLET_SALT, &mut output_key_material)
        .map_err(|e| CipherErrors::ArgonKeyDerivingError(e.to_string()))?;

    Ok(output_key_material)
}

#[cfg(test)]
mod tests {
    use super::derive_key;

    #[test]
    fn test_derive_key() {
        let password = b"test_password";
        let key = derive_key(password).unwrap();

        assert_eq!(
            key,
            [
                105, 163, 39, 110, 187, 108, 209, 71, 192, 27, 68, 241, 118, 214, 246, 178, 29,
                104, 200, 155, 198, 86, 120, 219, 16, 9, 228, 81, 190, 208, 236, 153, 9, 88, 58,
                136, 123, 69, 67, 37, 202, 217, 182, 51, 253, 254, 173, 77, 100, 61, 52, 130, 148,
                76, 1, 67, 38, 172, 203, 49, 163, 201, 103, 178,
            ]
        )
    }
}
