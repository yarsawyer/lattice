use crate::{
    errors::CryptoError,
    types::{KEM_SEED_LEN, MlKemKeypair},
};
use ml_kem::{
    Ciphertext, Decapsulate, Encapsulate, EncapsulationKey768, Kem, MlKem768, Seed,
    kem::KeyExport,
};

pub fn generate_keypair() -> MlKemKeypair {
    let (dk, ek): (ml_kem::DecapsulationKey768, ml_kem::EncapsulationKey768) =
        MlKem768::generate_keypair();
    MlKemKeypair {
        secret_seed: dk.to_bytes().as_slice().to_vec(),
        public_key: ek.to_bytes().as_slice().to_vec(),
    }
}

pub fn encapsulate(public_key: &[u8]) -> Result<crate::types::KemEncapsulation, CryptoError> {
    let key = EncapsulationKey768::new(
        &public_key
            .try_into()
            .map_err(|_| CryptoError::InvalidKemPublicKey)?,
    )
    .map_err(|_| CryptoError::InvalidKemPublicKey)?;
    let (ciphertext, shared_secret) = key.encapsulate();
    Ok(crate::types::KemEncapsulation {
        ciphertext: ciphertext.as_slice().to_vec(),
        shared_secret: shared_secret.as_slice().to_vec(),
    })
}

pub fn decapsulate(seed: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let seed = Seed::try_from(seed).map_err(|_| CryptoError::InvalidKemSeedLength)?;
    if seed.len() != KEM_SEED_LEN {
        return Err(CryptoError::InvalidKemSeedLength);
    }
    let dk = ml_kem::DecapsulationKey768::from_seed(seed);
    let ciphertext = Ciphertext::<MlKem768>::try_from(ciphertext)
        .map_err(|_| CryptoError::InvalidKemCiphertext)?;
    Ok(dk.decapsulate(&ciphertext).as_slice().to_vec())
}
