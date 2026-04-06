pub mod aead;
pub mod envelope;
pub mod errors;
pub mod hash;
pub mod kem;
pub mod session;
pub mod types;
pub mod x25519;

#[cfg(target_arch = "wasm32")]
pub mod wasm;

pub use envelope::{build_file_chunk_aad, build_message_aad};
pub use errors::CryptoError;
pub use hash::{Sha256Hasher, sha256, sha256_hex};
pub use session::{
    SessionDerivationInputs, derive_session_id, derive_session_secrets,
    generate_invite_secret, handshake_mac, resume_mac, resume_verifier,
};
pub use types::{
    EncryptedMessage, KemEncapsulation, MlKemKeypair, SessionRole, SessionSecrets, X25519Keypair,
};

#[cfg(test)]
mod tests {
    use super::{
        aead, build_file_chunk_aad, build_message_aad, derive_session_id, derive_session_secrets,
        generate_invite_secret, handshake_mac, kem, resume_mac, resume_verifier, sha256_hex,
        SessionDerivationInputs, Sha256Hasher,
        session::hash_transcript, types::SessionRole, x25519,
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

        let transcript_hash = hash_transcript(&[
            b"offer",
            alice_x.public_key.as_slice(),
            bob_x.public_key.as_slice(),
        ]);

        let alice = derive_session_secrets(
            SessionRole::Alice,
            SessionDerivationInputs {
                session_id: &session_id,
                invite_secret: &invite_secret,
                alice_nonce: &alice_nonce,
                bob_nonce: &bob_nonce,
                mlkem_shared_secret: &kem_ss.shared_secret,
                x25519_shared_secret: &alice_x_ss,
                transcript_hash: &transcript_hash,
            },
        )
        .unwrap();
        let bob = derive_session_secrets(
            SessionRole::Bob,
            SessionDerivationInputs {
                session_id: &session_id,
                invite_secret: &invite_secret,
                alice_nonce: &alice_nonce,
                bob_nonce: &bob_nonce,
                mlkem_shared_secret: &bob_kem_ss,
                x25519_shared_secret: &bob_x_ss,
                transcript_hash: &transcript_hash,
            },
        )
        .unwrap();

        assert_eq!(alice.send_key, bob.recv_key);
        assert_eq!(alice.recv_key, bob.send_key);
        assert_eq!(alice.resume_key, bob.resume_key);

        let alice_mac =
            handshake_mac(&alice.handshake_key, &transcript_hash, SessionRole::Alice).unwrap();
        let bob_mac =
            handshake_mac(&bob.handshake_key, &transcript_hash, SessionRole::Alice).unwrap();
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

    #[test]
    fn encrypts_and_decrypts_file_chunk() {
        let key = [9_u8; 32];
        let aad = build_file_chunk_aad(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            SessionRole::Bob,
            "00112233445566778899aabbccddeeff",
            3,
            8192,
            8,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap();

        let message = aead::encrypt(&key, b"chunk-bytes", &aad).unwrap();
        let plaintext = aead::decrypt(&key, &message.nonce, &message.ciphertext, &aad).unwrap();
        assert_eq!(plaintext, b"chunk-bytes");
    }

    #[test]
    fn derives_matching_resume_proofs() {
        let resume_key = [3_u8; 32];
        let verifier = resume_verifier(&resume_key).unwrap();
        let mac = resume_mac(
            &resume_key,
            b"challenge-nonce",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            SessionRole::Alice,
        )
        .unwrap();

        assert_eq!(verifier, resume_verifier(&resume_key).unwrap());
        assert_eq!(
            mac,
            resume_mac(
                &resume_key,
                b"challenge-nonce",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                SessionRole::Alice,
            )
            .unwrap()
        );
    }

    #[test]
    fn rejects_invalid_file_chunk_metadata() {
        let invalid_transfer = build_file_chunk_aad(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            SessionRole::Alice,
            "abcd",
            0,
            1,
            1,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        assert!(invalid_transfer.is_err());

        let invalid_digest = build_file_chunk_aad(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            SessionRole::Alice,
            "00112233445566778899aabbccddeeff",
            0,
            1,
            1,
            "deadbeef",
        );
        assert!(invalid_digest.is_err());
    }

    #[test]
    fn rejects_file_chunk_with_wrong_manifest_metadata() {
        let key = [5_u8; 32];
        let aad = build_file_chunk_aad(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            SessionRole::Alice,
            "00112233445566778899aabbccddeeff",
            4,
            4096,
            4,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap();
        let encrypted = aead::encrypt(&key, b"payload", &aad).unwrap();

        let wrong_digest_aad = build_file_chunk_aad(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            SessionRole::Alice,
            "00112233445566778899aabbccddeeff",
            4,
            4096,
            4,
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        )
        .unwrap();

        assert!(
            aead::decrypt(
                &key,
                &encrypted.nonce,
                &encrypted.ciphertext,
                &wrong_digest_aad
            )
            .is_err()
        );
    }

    #[test]
    fn incremental_sha256_matches_one_shot() {
        let mut hasher = Sha256Hasher::new();
        hasher.update(b"hello ").unwrap();
        hasher.update(b"world").unwrap();

        assert_eq!(hasher.finalize_hex().unwrap(), sha256_hex(b"hello world"));
    }
}
