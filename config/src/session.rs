use serde::{Deserialize, Serialize};

pub const KEYCHAIN_SERVICE: &str = "com.bearby.session";
pub const ANDROID_KEYSTORE: &str = "AndroidKeyStore";
pub const TRANSFORMATION: &str = "AES/GCM/NoPadding";
pub const KEY_ALIAS: &str = KEYCHAIN_SERVICE;
pub const PREFS_NAME: &str = "secure_session_storage";

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub enum AuthMethod {
    FaceId,
    Fingerprint,
    Biometric,
    PinCode,
    #[default]
    None,
    TouchID,
    OpticID,
    Password,
}

impl From<AuthMethod> for String {
    fn from(method: AuthMethod) -> Self {
        match method {
            AuthMethod::TouchID => "touchId".to_string(),
            AuthMethod::FaceId => "faceId".to_string(),
            AuthMethod::OpticID => "opticId".to_string(),
            AuthMethod::Fingerprint => "fingerprint".to_string(),
            AuthMethod::Biometric => "biometric".to_string(),
            AuthMethod::Password | AuthMethod::PinCode => "password".to_string(),
            AuthMethod::None => "none".to_string(),
        }
    }
}

impl From<String> for AuthMethod {
    fn from(s: String) -> Self {
        match s.as_str() {
            "touchId" => AuthMethod::TouchID,
            "faceId" => AuthMethod::FaceId,
            "faceid" => AuthMethod::FaceId,
            "opticId" => AuthMethod::OpticID,
            "fingerprint" => AuthMethod::Fingerprint,
            "biometric" => AuthMethod::Biometric,
            "password" | "pinCode" => AuthMethod::Password,
            _ => AuthMethod::None,
        }
    }
}
