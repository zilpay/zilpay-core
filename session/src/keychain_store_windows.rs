use errors::session::SessionErrors;

pub fn store_key_in_secure_enclave(key: &[u8], service: &str) -> Result<(), SessionErrors> {
    let entry = keyring::Entry::new(service, "session_key")
        .map_err(|e| SessionErrors::KeychainError(errors::keychain::KeyChainErrors::KeyringError(e.to_string())))?;
        
    let encoded = hex::encode(key);
    entry.set_password(&encoded)
         .map_err(|e| SessionErrors::KeychainError(errors::keychain::KeyChainErrors::KeyringError(e.to_string())))?;
         
    Ok(())
}

pub fn retrieve_key_from_secure_enclave(service: &str) -> Result<Vec<u8>, SessionErrors> {
     let entry = keyring::Entry::new(service, "session_key")
        .map_err(|e| SessionErrors::KeychainError(errors::keychain::KeyChainErrors::KeyringError(e.to_string())))?;
         
    let encoded = entry.get_password()
         .map_err(|e| SessionErrors::KeychainError(errors::keychain::KeyChainErrors::KeyringError(e.to_string())))?;
         
    hex::decode(encoded)
        .map_err(|_| SessionErrors::InvalidDecryptSession)
}

pub fn delete_key_from_secure_enclave(service: &str) -> Result<(), SessionErrors> {
    let entry = keyring::Entry::new(service, "session_key")
        .map_err(|e| SessionErrors::KeychainError(errors::keychain::KeyChainErrors::KeyringError(e.to_string())))?;
         
    entry.delete_password()
         .map_err(|e| SessionErrors::KeychainError(errors::keychain::KeyChainErrors::KeyringError(e.to_string())))?;
    Ok(())
}
