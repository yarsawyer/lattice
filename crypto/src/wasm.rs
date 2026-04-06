#![cfg(target_arch = "wasm32")]

use crate::{
    aead, envelope, hash, kem,
    session::{self, SessionDerivationInputs},
    types::{EncryptedMessage, SessionRole},
    x25519,
};
use serde_wasm_bindgen::{from_value, to_value};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn generate_invite_secret() -> Result<Vec<u8>, JsValue> {
    session::generate_invite_secret()
        .map(|secret| secret.to_vec())
        .map_err(|err| JsValue::from_str(&err.to_string()))
}

#[wasm_bindgen]
pub fn generate_nonce() -> Result<Vec<u8>, JsValue> {
    session::generate_nonce()
        .map(|nonce| nonce.to_vec())
        .map_err(|err| JsValue::from_str(&err.to_string()))
}

#[wasm_bindgen]
pub fn derive_session_id(invite_secret: &[u8]) -> Result<Vec<u8>, JsValue> {
    session::derive_session_id(invite_secret)
        .map(|id| id.to_vec())
        .map_err(|err| JsValue::from_str(&err.to_string()))
}

#[wasm_bindgen]
pub fn build_message_aad(
    session_id: &str,
    role: &str,
    sequence_number: u64,
) -> Result<Vec<u8>, JsValue> {
    let role = match role {
        "alice" => SessionRole::Alice,
        "bob" => SessionRole::Bob,
        _ => return Err(JsValue::from_str("invalid role")),
    };

    envelope::build_message_aad(session_id, role, sequence_number)
        .map_err(|err| JsValue::from_str(&err.to_string()))
}

#[wasm_bindgen]
pub fn build_file_chunk_aad(
    session_id: &str,
    role: &str,
    transfer_id: &str,
    chunk_index: u32,
    declared_size: u64,
    total_chunks: u32,
    file_sha256: &str,
) -> Result<Vec<u8>, JsValue> {
    let role = match role {
        "alice" => SessionRole::Alice,
        "bob" => SessionRole::Bob,
        _ => return Err(JsValue::from_str("invalid role")),
    };

    envelope::build_file_chunk_aad(
        session_id,
        role,
        transfer_id,
        chunk_index,
        declared_size,
        total_chunks,
        file_sha256,
    )
    .map_err(|err| JsValue::from_str(&err.to_string()))
}

#[wasm_bindgen]
pub fn generate_mlkem_keypair() -> Result<JsValue, JsValue> {
    to_value(&kem::generate_keypair()).map_err(Into::into)
}

#[wasm_bindgen]
pub fn generate_x25519_keypair() -> Result<JsValue, JsValue> {
    to_value(&x25519::generate_keypair()).map_err(Into::into)
}

#[wasm_bindgen]
pub fn encapsulate_mlkem(public_key: &[u8]) -> Result<JsValue, JsValue> {
    kem::encapsulate(public_key)
        .and_then(|value| {
            to_value(&value).map_err(|_| crate::errors::CryptoError::InvalidKemPublicKey)
        })
        .map_err(|err| JsValue::from_str(&err.to_string()))
}

#[wasm_bindgen]
pub fn decapsulate_mlkem(seed: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, JsValue> {
    kem::decapsulate(seed, ciphertext).map_err(|err| JsValue::from_str(&err.to_string()))
}

#[wasm_bindgen]
pub fn x25519_shared_secret(secret_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    x25519::shared_secret(secret_key, public_key).map_err(|err| JsValue::from_str(&err.to_string()))
}

#[wasm_bindgen]
pub fn hash_transcript(parts: JsValue) -> Result<Vec<u8>, JsValue> {
    let parts: Vec<Vec<u8>> = from_value(parts)?;
    let refs = parts.iter().map(Vec::as_slice).collect::<Vec<_>>();
    Ok(session::hash_transcript(&refs).to_vec())
}

#[wasm_bindgen]
pub fn derive_session_secrets(
    role: &str,
    session_id: &[u8],
    invite_secret: &[u8],
    alice_nonce: &[u8],
    bob_nonce: &[u8],
    mlkem_shared_secret: &[u8],
    x25519_shared_secret: &[u8],
    transcript_hash: &[u8],
) -> Result<JsValue, JsValue> {
    let role = match role {
        "alice" => SessionRole::Alice,
        "bob" => SessionRole::Bob,
        _ => return Err(JsValue::from_str("invalid role")),
    };

    session::derive_session_secrets(
        role,
        SessionDerivationInputs {
            session_id,
            invite_secret,
            alice_nonce,
            bob_nonce,
            mlkem_shared_secret,
            x25519_shared_secret,
            transcript_hash,
        },
    )
    .and_then(|secrets| {
        to_value(&secrets).map_err(|_| crate::errors::CryptoError::InvalidKeyLength)
    })
    .map_err(|err| JsValue::from_str(&err.to_string()))
}

#[wasm_bindgen]
pub fn handshake_mac(
    handshake_key: &[u8],
    transcript_hash: &[u8],
    role: &str,
) -> Result<Vec<u8>, JsValue> {
    let role = match role {
        "alice" => SessionRole::Alice,
        "bob" => SessionRole::Bob,
        _ => return Err(JsValue::from_str("invalid role")),
    };

    session::handshake_mac(handshake_key, transcript_hash, role)
        .map_err(|err| JsValue::from_str(&err.to_string()))
}

#[wasm_bindgen]
pub fn resume_verifier(resume_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    session::resume_verifier(resume_key)
        .map(|verifier| verifier.to_vec())
        .map_err(|err| JsValue::from_str(&err.to_string()))
}

#[wasm_bindgen]
pub fn resume_mac(
    resume_key: &[u8],
    challenge_nonce: &[u8],
    session_id_hex: &str,
    role: &str,
) -> Result<Vec<u8>, JsValue> {
    let role = match role {
        "alice" => SessionRole::Alice,
        "bob" => SessionRole::Bob,
        _ => return Err(JsValue::from_str("invalid role")),
    };

    session::resume_mac(resume_key, challenge_nonce, session_id_hex, role)
        .map_err(|err| JsValue::from_str(&err.to_string()))
}

#[wasm_bindgen]
pub fn encrypt_message(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<JsValue, JsValue> {
    let message: EncryptedMessage =
        aead::encrypt(key, plaintext, aad).map_err(|err| JsValue::from_str(&err.to_string()))?;
    to_value(&message).map_err(Into::into)
}

#[wasm_bindgen]
pub fn decrypt_message(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, JsValue> {
    aead::decrypt(key, nonce, ciphertext, aad).map_err(|err| JsValue::from_str(&err.to_string()))
}

#[wasm_bindgen]
pub struct Sha256Hasher {
    inner: hash::Sha256Hasher,
}

#[wasm_bindgen]
impl Sha256Hasher {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: hash::Sha256Hasher::new(),
        }
    }

    pub fn update(&mut self, bytes: &[u8]) -> Result<(), JsValue> {
        self.inner
            .update(bytes)
            .map_err(|err| JsValue::from_str(&err.to_string()))
    }

    pub fn finalize_hex(&mut self) -> Result<String, JsValue> {
        self.inner
            .finalize_hex()
            .map_err(|err| JsValue::from_str(&err.to_string()))
    }
}
