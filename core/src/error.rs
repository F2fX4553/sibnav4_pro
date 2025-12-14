use thiserror::Error;

/// Protocol Error Type
#[derive(Error, Debug, Clone, PartialEq)]
pub enum ProtocolError {
    #[error("Invalid key length")]
    InvalidKeyLength,
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed, 
    #[error("Authentication failed")]
    AuthenticationFailed,
    #[error("Invalid nonce")]
    InvalidNonce,
    #[error("Session not found")]
    SessionNotFound,
    #[error("Invalid state")]
    InvalidState,
    #[error("Key derivation failed")]
    KeyDerivationFailed,
    #[error("Invalid message")]
    InvalidMessage,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Handshake failed")]
    HandshakeFailed,
    #[error("Out of memory")]
    OutOfMemory,
    #[error("Internal error: {0}")]
    InternalError(String),
    #[error("Invalid ciphertext")]
    InvalidCiphertext,
    #[error("Invalid nonce length")]
    InvalidNonceLength,
    #[error("Random generation failed")]
    RandomFailed,
}

pub type ProtocolResult<T> = Result<T, ProtocolError>;

impl From<crate::crypto::CryptoError> for ProtocolError {
    fn from(err: crate::crypto::CryptoError) -> Self {
        match err {
            crate::crypto::CryptoError::InvalidKeyLength => ProtocolError::InvalidKeyLength,
            crate::crypto::CryptoError::EncryptionFailed => ProtocolError::EncryptionFailed,
            crate::crypto::CryptoError::DecryptionFailed => ProtocolError::DecryptionFailed,
            crate::crypto::CryptoError::AuthenticationFailed => ProtocolError::AuthenticationFailed,
            crate::crypto::CryptoError::InvalidNonceLength => ProtocolError::InvalidNonceLength,
            crate::crypto::CryptoError::RandomFailed => ProtocolError::RandomFailed,
            crate::crypto::CryptoError::KeyDerivationFailed => ProtocolError::KeyDerivationFailed,
            crate::crypto::CryptoError::InvalidCiphertext => ProtocolError::InvalidCiphertext,
        }
    }
}
