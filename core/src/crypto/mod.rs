//! Secure Crypto Module
//! Safe implementation of cryptographic algorithms.

pub mod encryptor;
pub mod random;
pub mod kdf;

pub use encryptor::*;
pub use random::*;
pub use kdf::*;

use zeroize::Zeroizing;
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, AeadInPlace},
};
use thiserror::Error;

/// Crypto Errors
#[derive(Error, Debug, Clone, PartialEq)]
pub enum CryptoError {
    #[error("Invalid key length")]
    InvalidKeyLength,
    #[error("Invalid nonce length")]
    InvalidNonceLength,
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Authentication failed")]
    AuthenticationFailed,
    #[error("Random generation failed")]
    RandomFailed,
    #[error("Key derivation failed")]
    KeyDerivationFailed,
    #[error("Invalid ciphertext")]
    InvalidCiphertext,
}

/// Result type for crypto operations
pub type CryptoResult<T> = std::result::Result<T, CryptoError>;

/// Constants
pub const KEY_LENGTH: usize = 32;
pub const NONCE_LENGTH: usize = 12;
pub const TAG_LENGTH: usize = 16;
pub const CHACHA20_NONCE_LENGTH: usize = 12;

/// General Encryption Handler
pub struct CryptoHandler {
    cipher: ChaCha20Poly1305,
    key: Zeroizing<[u8; KEY_LENGTH]>,
}

impl CryptoHandler {
    /// Create new crypto handler
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        if key.len() != KEY_LENGTH {
            return Err(CryptoError::InvalidKeyLength);
        }
        
        let mut key_array = [0u8; KEY_LENGTH];
        key_array.copy_from_slice(key);
        
        let cipher = ChaCha20Poly1305::new(&key_array.into());
        
        Ok(Self {
            cipher,
            key: Zeroizing::new(key_array),
        })
    }
    
    /// Encrypt data
    pub fn encrypt(&self, plaintext: &[u8], associated_data: &[u8]) -> CryptoResult<Vec<u8>> {
        let mut rng = SecureRandom::new()?;
        let mut nonce = [0u8; NONCE_LENGTH];
        rng.fill_bytes(&mut nonce);
        
        self.encrypt_with_nonce(plaintext, associated_data, &nonce)
    }
    
    /// Encrypt with specific nonce
    pub fn encrypt_with_nonce(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
        nonce: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        if nonce.len() != NONCE_LENGTH {
            return Err(CryptoError::InvalidNonceLength);
        }
        
        let ciphertext = self.cipher
            .encrypt(nonce.into(), plaintext)
            .map_err(|_| CryptoError::EncryptionFailed)?;
        
        // Result: nonce + ciphertext
        let mut result = Vec::with_capacity(NONCE_LENGTH + ciphertext.len());
        result.extend_from_slice(nonce);
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }
    
    /// Decrypt data
    pub fn decrypt(&self, ciphertext: &[u8], associated_data: &[u8]) -> CryptoResult<Vec<u8>> {
        if ciphertext.len() < NONCE_LENGTH {
            return Err(CryptoError::DecryptionFailed);
        }
        
        let nonce = &ciphertext[..NONCE_LENGTH];
        let encrypted_data = &ciphertext[NONCE_LENGTH..];
        
        self.cipher
            .decrypt(nonce.into(), encrypted_data)
            .map_err(|_| CryptoError::DecryptionFailed)
    }
}
