use crate::errors::CryptoError;
use sha2::{Digest, Sha256};

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(sha256(bytes))
}

#[derive(Default)]
pub struct Sha256Hasher {
    state: Option<Sha256>,
}

impl Sha256Hasher {
    pub fn new() -> Self {
        Self {
            state: Some(Sha256::new()),
        }
    }

    pub fn update(&mut self, bytes: &[u8]) -> Result<(), CryptoError> {
        let Some(state) = self.state.as_mut() else {
            return Err(CryptoError::HasherFinalized);
        };
        state.update(bytes);
        Ok(())
    }

    pub fn finalize(&mut self) -> Result<[u8; 32], CryptoError> {
        let Some(state) = self.state.take() else {
            return Err(CryptoError::HasherFinalized);
        };
        Ok(state.finalize().into())
    }

    pub fn finalize_hex(&mut self) -> Result<String, CryptoError> {
        self.finalize().map(hex::encode)
    }
}
