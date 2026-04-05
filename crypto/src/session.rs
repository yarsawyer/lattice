use crate::{
    errors::CryptoError,
    types::{
        FINGERPRINT_LEN, HANDSHAKE_KEY_LEN, INVITE_SECRET_LEN, SESSION_ID_LEN, SHARED_SECRET_LEN,
        SessionRole, TRAFFIC_KEY_LEN, XCHACHA_NONCE_LEN,
    },
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, TryRngCore};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

const PROTOCOL_VERSION: &[u8] = b"lattice-ephemeral-v1";
const TRAFFIC_INFO: &[u8] = b"lattice-traffic-v1";

pub fn protocol_version() -> &'static [u8] {
    PROTOCOL_VERSION
}

pub fn generate_invite_secret() -> Result<[u8; INVITE_SECRET_LEN], CryptoError> {
    generate_random_32()
}

pub fn generate_nonce() -> Result<[u8; 32], CryptoError> {
    generate_random_32()
}

fn generate_random_32() -> Result<[u8; 32], CryptoError> {
    let mut secret = [0_u8; INVITE_SECRET_LEN];
    OsRng
        .try_fill_bytes(&mut secret)
        .map_err(|_| CryptoError::InvalidInviteSecretLength)?;
    Ok(secret)
}

pub fn derive_session_id(invite_secret: &[u8]) -> Result<[u8; SESSION_ID_LEN], CryptoError> {
    if invite_secret.len() != INVITE_SECRET_LEN {
        return Err(CryptoError::InvalidInviteSecretLength);
    }

    let mut hasher = Sha256::new();
    hasher.update(invite_secret);
    hasher.update(PROTOCOL_VERSION);
    Ok(hasher.finalize().into())
}

pub fn hash_transcript(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u32).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

pub fn derive_session_secrets(
    role: SessionRole,
    session_id: &[u8],
    invite_secret: &[u8],
    alice_nonce: &[u8],
    bob_nonce: &[u8],
    mlkem_shared_secret: &[u8],
    x25519_shared_secret: &[u8],
    transcript_hash: &[u8],
) -> Result<crate::types::SessionSecrets, CryptoError> {
    if session_id.len() != SESSION_ID_LEN {
        return Err(CryptoError::InvalidSessionIdLength);
    }
    if invite_secret.len() != INVITE_SECRET_LEN {
        return Err(CryptoError::InvalidInviteSecretLength);
    }
    if mlkem_shared_secret.len() != SHARED_SECRET_LEN || x25519_shared_secret.len() != SHARED_SECRET_LEN
    {
        return Err(CryptoError::InvalidKeyLength);
    }

    let mut salt_hasher = Sha256::new();
    salt_hasher.update(session_id);
    salt_hasher.update(invite_secret);
    let salt = salt_hasher.finalize();

    let mut ikm = Vec::with_capacity(
        mlkem_shared_secret.len()
            + x25519_shared_secret.len()
            + alice_nonce.len()
            + bob_nonce.len()
            + transcript_hash.len(),
    );
    ikm.extend_from_slice(mlkem_shared_secret);
    ikm.extend_from_slice(x25519_shared_secret);
    ikm.extend_from_slice(alice_nonce);
    ikm.extend_from_slice(bob_nonce);
    ikm.extend_from_slice(transcript_hash);

    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut okm = [0_u8; 2 * TRAFFIC_KEY_LEN + HANDSHAKE_KEY_LEN + FINGERPRINT_LEN];
    hk.expand(TRAFFIC_INFO, &mut okm)
        .map_err(|_| CryptoError::HkdfExpand)?;

    let alice_send = okm[0..TRAFFIC_KEY_LEN].to_vec();
    let bob_send = okm[TRAFFIC_KEY_LEN..2 * TRAFFIC_KEY_LEN].to_vec();
    let handshake_key =
        okm[2 * TRAFFIC_KEY_LEN..2 * TRAFFIC_KEY_LEN + HANDSHAKE_KEY_LEN].to_vec();
    let fingerprint = okm[2 * TRAFFIC_KEY_LEN + HANDSHAKE_KEY_LEN..].to_vec();

    let (send_key, recv_key) = match role {
        SessionRole::Alice => (alice_send, bob_send),
        SessionRole::Bob => (bob_send, alice_send),
    };

    Ok(crate::types::SessionSecrets {
        send_key,
        recv_key,
        handshake_key,
        fingerprint,
    })
}

pub fn handshake_mac(
    handshake_key: &[u8],
    transcript_hash: &[u8],
    role: SessionRole,
) -> Result<Vec<u8>, CryptoError> {
    let mut mac = HmacSha256::new_from_slice(handshake_key).map_err(|_| CryptoError::InvalidKeyLength)?;
    mac.update(PROTOCOL_VERSION);
    mac.update(role.label().as_bytes());
    mac.update(transcript_hash);
    Ok(mac.finalize().into_bytes().to_vec())
}

pub fn verify_handshake_mac(
    handshake_key: &[u8],
    transcript_hash: &[u8],
    role: SessionRole,
    expected: &[u8],
) -> Result<(), CryptoError> {
    let mut mac =
        HmacSha256::new_from_slice(handshake_key).map_err(|_| CryptoError::InvalidKeyLength)?;
    mac.update(PROTOCOL_VERSION);
    mac.update(role.label().as_bytes());
    mac.update(transcript_hash);
    mac.verify_slice(expected).map_err(|_| CryptoError::Aead)
}

pub fn ensure_nonce_length(nonce: &[u8]) -> Result<[u8; XCHACHA_NONCE_LEN], CryptoError> {
    nonce
        .try_into()
        .map_err(|_| CryptoError::InvalidNonceLength)
}
