#![cfg(target_arch = "wasm32")]

use crate::{
    aead, envelope, kem, session, x25519,
    types::{EncryptedMessage, SessionRole},
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
        .and_then(|value| to_value(&value).map_err(|_| crate::errors::CryptoError::InvalidKemPublicKey))
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
        session_id,
        invite_secret,
        alice_nonce,
        bob_nonce,
        mlkem_shared_secret,
        x25519_shared_secret,
        transcript_hash,
    )
    .and_then(|secrets| {
        to_value(&secrets).map_err(|_| crate::errors::CryptoError::InvalidKeyLength)
    })
    .map_err(|err| JsValue::from_str(&err.to_string()))
}

#[wasm_bindgen]
pub fn handshake_mac(handshake_key: &[u8], transcript_hash: &[u8], role: &str) -> Result<Vec<u8>, JsValue> {
    let role = match role {
        "alice" => SessionRole::Alice,
        "bob" => SessionRole::Bob,
        _ => return Err(JsValue::from_str("invalid role")),
    };

    session::handshake_mac(handshake_key, transcript_hash, role)
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
