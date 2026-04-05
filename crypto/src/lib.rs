pub mod aead;
pub mod envelope;
pub mod errors;
pub mod kem;
pub mod session;
pub mod types;
pub mod x25519;

#[cfg(target_arch = "wasm32")]
pub mod wasm;

pub use errors::CryptoError;
pub use envelope::build_message_aad;
pub use session::{derive_session_id, derive_session_secrets, generate_invite_secret, handshake_mac};
pub use types::{
    EncryptedMessage, KemEncapsulation, MlKemKeypair, SessionRole, SessionSecrets, X25519Keypair,
};

#[cfg(test)]
mod tests {
    use super::{
        aead, build_message_aad, derive_session_id, derive_session_secrets, generate_invite_secret, handshake_mac,
        kem, session::hash_transcript, types::SessionRole, x25519,
    };

    #[test]
    fn derives_stable_session_id() {
        let invite_secret = generate_invite_secret().unwrap();
        let session_id_1 = derive_session_id(&invite_secret).unwrap();
        let session_id_2 = derive_session_id(&invite_secret).unwrap();
        assert_eq!(session_id_1, session_id_2);
    }

    #[test]
    fn mlkem_round_trip() {
        let bob = kem::generate_keypair();
        let encapsulated = kem::encapsulate(&bob.public_key).unwrap();
        let decapsulated = kem::decapsulate(&bob.secret_seed, &encapsulated.ciphertext).unwrap();
        assert_eq!(encapsulated.shared_secret, decapsulated);
    }

    #[test]
    fn x25519_round_trip() {
        let alice = x25519::generate_keypair();
        let bob = x25519::generate_keypair();
        let alice_ss = x25519::shared_secret(&alice.secret_key, &bob.public_key).unwrap();
        let bob_ss = x25519::shared_secret(&bob.secret_key, &alice.public_key).unwrap();
        assert_eq!(alice_ss, bob_ss);
    }

    #[test]
    fn derives_matching_session_keys() {
        let invite_secret = generate_invite_secret().unwrap();
        let session_id = derive_session_id(&invite_secret).unwrap();
        let alice_nonce = [1_u8; 32];
        let bob_nonce = [2_u8; 32];

        let bob_kem = kem::generate_keypair();
        let kem_ss = kem::encapsulate(&bob_kem.public_key).unwrap();
        let bob_kem_ss = kem::decapsulate(&bob_kem.secret_seed, &kem_ss.ciphertext).unwrap();
        assert_eq!(kem_ss.shared_secret, bob_kem_ss);

        let alice_x = x25519::generate_keypair();
        let bob_x = x25519::generate_keypair();
        let alice_x_ss = x25519::shared_secret(&alice_x.secret_key, &bob_x.public_key).unwrap();
        let bob_x_ss = x25519::shared_secret(&bob_x.secret_key, &alice_x.public_key).unwrap();

        let transcript_hash =
            hash_transcript(&[b"offer", alice_x.public_key.as_slice(), bob_x.public_key.as_slice()]);

        let alice = derive_session_secrets(
            SessionRole::Alice,
            &session_id,
            &invite_secret,
            &alice_nonce,
            &bob_nonce,
            &kem_ss.shared_secret,
            &alice_x_ss,
            &transcript_hash,
        )
        .unwrap();
        let bob = derive_session_secrets(
            SessionRole::Bob,
            &session_id,
            &invite_secret,
            &alice_nonce,
            &bob_nonce,
            &bob_kem_ss,
            &bob_x_ss,
            &transcript_hash,
        )
        .unwrap();

        assert_eq!(alice.send_key, bob.recv_key);
        assert_eq!(alice.recv_key, bob.send_key);

        let alice_mac = handshake_mac(&alice.handshake_key, &transcript_hash, SessionRole::Alice).unwrap();
        let bob_mac = handshake_mac(&bob.handshake_key, &transcript_hash, SessionRole::Alice).unwrap();
        assert_eq!(alice_mac, bob_mac);
    }

    #[test]
    fn encrypts_and_decrypts() {
        let key = [7_u8; 32];
        let aad = build_message_aad(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            SessionRole::Alice,
            1,
        )
        .unwrap();
        let message = aead::encrypt(&key, b"hello", &aad).unwrap();
        let plaintext = aead::decrypt(&key, &message.nonce, &message.ciphertext, &aad).unwrap();
        assert_eq!(plaintext, b"hello");
    }
}
