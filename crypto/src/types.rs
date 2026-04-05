use serde::{Deserialize, Serialize};

pub const INVITE_SECRET_LEN: usize = 32;
pub const SESSION_ID_LEN: usize = 32;
pub const KEM_SEED_LEN: usize = 64;
pub const X25519_KEY_LEN: usize = 32;
pub const SHARED_SECRET_LEN: usize = 32;
pub const XCHACHA_NONCE_LEN: usize = 24;
pub const TRAFFIC_KEY_LEN: usize = 32;
pub const HANDSHAKE_KEY_LEN: usize = 32;
pub const FINGERPRINT_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionRole {
    Alice,
    Bob,
}

impl SessionRole {
    pub fn label(self) -> &'static str {
        match self {
            Self::Alice => "alice",
            Self::Bob => "bob",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageEnvelopeHeader {
    pub protocol_version: String,
    pub session_id: String,
    pub sender_role: SessionRole,
    pub sequence_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlKemKeypair {
    pub secret_seed: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X25519Keypair {
    pub secret_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KemEncapsulation {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSecrets {
    pub send_key: Vec<u8>,
    pub recv_key: Vec<u8>,
    pub handshake_key: Vec<u8>,
    pub fingerprint: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}
