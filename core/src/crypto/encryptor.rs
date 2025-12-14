use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

/// Encryptor with message counter tracking
pub struct Encryptor {
    handler: CryptoHandler,
    message_counter: AtomicU64,
    max_message_count: u64,
}

impl Encryptor {
    /// Create new encryptor
    pub fn new(key: &[u8], max_message_count: u64) -> CryptoResult<Self> {
        let handler = CryptoHandler::new(key)?;
        
        Ok(Self {
            handler,
            message_counter: AtomicU64::new(0),
            max_message_count,
        })
    }
    
    /// Encrypt message with counter
    pub fn encrypt_message(&self, plaintext: &[u8], context: &[u8]) -> CryptoResult<Vec<u8>> {
        let message_num = self.message_counter.fetch_add(1, Ordering::SeqCst);
        
        if message_num >= self.max_message_count {
            return Err(CryptoError::EncryptionFailed);
        }
        
        // Build associated data: context + message number + timestamp
        let mut associated_data = Vec::with_capacity(context.len() + 16);
        associated_data.extend_from_slice(context);
        associated_data.extend_from_slice(&message_num.to_le_bytes());
        
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| CryptoError::EncryptionFailed)?
            .as_secs();
        associated_data.extend_from_slice(&timestamp.to_le_bytes());
        
        self.handler.encrypt(plaintext, &associated_data)
    }
    
    /// Decrypt message
    pub fn decrypt_message(&self, ciphertext: &[u8], context: &[u8]) -> CryptoResult<Vec<u8>> {
        if ciphertext.len() < NONCE_LENGTH {
            return Err(CryptoError::InvalidCiphertext);
        }
        
        self.handler.decrypt(ciphertext, context)
    }
    
    pub fn message_count(&self) -> u64 {
        self.message_counter.load(Ordering::SeqCst)
    }
    
    pub fn reset_counter(&self) {
        self.message_counter.store(0, Ordering::SeqCst);
    }
}
