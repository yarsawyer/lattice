use crate::{
    errors::CryptoError,
    types::{SHARED_SECRET_LEN, X25519_KEY_LEN, X25519Keypair},
};
use x25519_dalek::{PublicKey, StaticSecret};

pub fn generate_keypair() -> X25519Keypair {
    let secret = StaticSecret::random();
    let public = PublicKey::from(&secret);
    X25519Keypair {
        secret_key: secret.to_bytes().to_vec(),
        public_key: public.as_bytes().to_vec(),
    }
}

pub fn shared_secret(secret_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let secret_key: [u8; X25519_KEY_LEN] = secret_key
        .try_into()
        .map_err(|_| CryptoError::InvalidX25519KeyLength)?;
    let public_key: [u8; X25519_KEY_LEN] = public_key
        .try_into()
        .map_err(|_| CryptoError::InvalidX25519KeyLength)?;

    let secret = StaticSecret::from(secret_key);
    let public = PublicKey::from(public_key);
    let shared = secret.diffie_hellman(&public);
    let bytes = shared.as_bytes();
    if bytes.len() != SHARED_SECRET_LEN {
        return Err(CryptoError::InvalidKeyLength);
    }
    Ok(bytes.to_vec())
}
