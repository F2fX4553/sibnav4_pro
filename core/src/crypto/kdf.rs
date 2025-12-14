use hkdf::Hkdf;
use sha2::Sha256;
use super::{CryptoError, CryptoResult};

/// HKDF Helper
pub fn hkdf_expand(prk: &[u8], info: &[u8], length: usize) -> CryptoResult<Vec<u8>> {
    let hkdf = Hkdf::<Sha256>::from_prk(prk)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
        
    let mut okm = vec![0u8; length];
    hkdf.expand(info, &mut okm)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
        
    Ok(okm)
}

pub fn hkdf_extract(salt: Option<&[u8]>, ikm: &[u8]) -> (Vec<u8>, Hkdf<Sha256>) {
    Hkdf::<Sha256>::extract(salt, ikm)
}
