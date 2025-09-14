use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct HandshakeRequest {
    pub public_key: String,
    pub salt: String,
    pub info: String,
}

#[derive(Serialize, Deserialize)]
pub struct HandshakeResponse {
    pub session_id: String,
    pub public_key: String,
    pub attestation: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct AttestationUserData {
    pub salt: String,
}

#[derive(Serialize, Deserialize)]
pub struct DecryptRequest {
    pub session_id: String,
    pub ciphertext: String,
    pub initialization_vector: String,
}

#[derive(Serialize, Deserialize)]
pub struct DecryptResponse {
    pub plaintext: String,
}

/// Known agreed-upon info string
pub const INFO_STRING: &str = "nitro-key-exchange-v1";
