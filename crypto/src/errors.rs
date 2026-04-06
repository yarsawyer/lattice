use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid invite secret length")]
    InvalidInviteSecretLength,
    #[error("invalid ML-KEM seed length")]
    InvalidKemSeedLength,
    #[error("invalid ML-KEM public key")]
    InvalidKemPublicKey,
    #[error("invalid ML-KEM ciphertext")]
    InvalidKemCiphertext,
    #[error("invalid X25519 key length")]
    InvalidX25519KeyLength,
    #[error("invalid session id length")]
    InvalidSessionIdLength,
    #[error("invalid transfer id length")]
    InvalidTransferIdLength,
    #[error("invalid file digest length")]
    InvalidFileDigestLength,
    #[error("invalid nonce length")]
    InvalidNonceLength,
    #[error("invalid key length")]
    InvalidKeyLength,
    #[error("hasher already finalized")]
    HasherFinalized,
    #[error("hkdf expand failed")]
    HkdfExpand,
    #[error("aead error")]
    Aead,
}
