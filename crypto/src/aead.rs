use crate::{
    errors::CryptoError,
    session::ensure_nonce_length,
    types::{EncryptedMessage, TRAFFIC_KEY_LEN},
};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, OsRng, rand_core::RngCore},
};

pub fn encrypt(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<EncryptedMessage, CryptoError> {
    if key.len() != TRAFFIC_KEY_LEN {
        return Err(CryptoError::InvalidKeyLength);
    }

    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength)?;
    let mut nonce = [0_u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Aead)?;

    Ok(EncryptedMessage {
        nonce: nonce.to_vec(),
        ciphertext,
    })
}

pub fn decrypt(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if key.len() != TRAFFIC_KEY_LEN {
        return Err(CryptoError::InvalidKeyLength);
    }

    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength)?;
    let nonce = ensure_nonce_length(nonce)?;
    cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Aead)
}
