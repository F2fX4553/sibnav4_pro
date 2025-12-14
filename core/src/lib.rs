//! Secure Protocol Core - Secure Communication Protocol Kernel
//! Modular and secure implementation of Noise and Double Ratchet protocols.

#![warn(missing_docs)]
#![allow(unsafe_code)] // FFI requires unsafe
#![allow(clippy::needless_return)]
#![allow(clippy::redundant_clone)]

// System Modules
pub mod crypto;
pub mod ratchet;
pub mod handshake;
pub mod keystore;
pub mod error;

// FFI Modules
#[cfg(feature = "ffi")]
pub mod ffi;

// Re-exports
pub use crypto::*;
pub use ratchet::*;
pub use handshake::*;
pub use keystore::*;
pub use error::{ProtocolError, ProtocolResult};

use std::sync::Arc;
use parking_lot::RwLock;
use sled;
use std::path::PathBuf;

/// Main System Context
pub struct SecureContext {
    keystore: Arc<RwLock<KeyStore>>,
    sessions: Arc<RwLock<SessionManager>>,
    config: Config,
    random: Arc<RwLock<SecureRandom>>,
}

/// System Configuration
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Config {
    /// Enable Forward Secrecy
    pub enable_forward_secrecy: bool,
    /// Enable Post-Compromise Security
    pub enable_post_compromise_security: bool,
    /// Max skipped messages
    pub max_skipped_messages: usize,
    /// Key rotation interval (seconds)
    pub key_rotation_interval: u64,
    /// Handshake timeout (seconds)
    pub handshake_timeout: u64,
    /// Message buffer size
    pub message_buffer_size: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enable_forward_secrecy: true,
            enable_post_compromise_security: true,
            max_skipped_messages: 2000,
            key_rotation_interval: 86400, // 24 hours
            handshake_timeout: 30,
            message_buffer_size: 1024,
        }
    }
}

impl SecureContext {
    /// Create a new context
    pub fn new(config: Config) -> ProtocolResult<Self> {
        // Open a sled database for persistence (sessions + keystore)
        let db_path = PathBuf::from("secure_core_db");
        let db = sled::open(&db_path).map_err(|e| ProtocolError::InternalError(format!("DB open error: {}", e)))?;

        let keystore = KeyStore::new(Arc::new(db.clone()))?;
        let sessions = SessionManager::new(config.clone(), Arc::new(db));
        let random = SecureRandom::new()?;
        
        Ok(Self {
            keystore: Arc::new(RwLock::new(keystore)),
            sessions: Arc::new(RwLock::new(sessions)),
            config,
            random: Arc::new(RwLock::new(random)),
        })
    }
    
    /// Create a new session
    pub fn create_session(&self, peer_id: &[u8]) -> ProtocolResult<SessionHandle> {
        let mut sessions = self.sessions.write();
        sessions.create_session(peer_id, self.config.clone())
    }
    
    /// Load an identity key pair into the keystore.
    pub fn load_identity(&mut self, public: &[u8], private: &[u8]) {
        let keypair = crate::keystore::IdentityKeyPair::from_bytes(public, private);
        self.keystore.write().set_identity(keypair);
    }
    
    /// Perform handshake with peer
    pub fn perform_handshake(
        &self,
        session_id: &[u8],
        initiator: bool,
        peer_public_key: Option<&[u8]>,
        prologue: Option<&[u8]>,
    ) -> ProtocolResult<Vec<u8>> {
        let sessions = self.sessions.read();
        let session = sessions.get_session(session_id)?;
        
        let keystore = self.keystore.read();
        let random = self.random.read();
        
        let handshake = HandshakeBuilder::new()
            .with_config(self.config.clone())
            .with_keystore(&*keystore)
            .with_random(&*random)
            .with_initiator(initiator);
        
        // Convert Option<&[u8]> to Option key
        let handshake = if let Some(peer_key) = peer_public_key {
            handshake.with_peer_public_key(peer_key)?
        } else {
            handshake
        };
        
        let handshake = if let Some(prologue_data) = prologue {
            handshake.with_prologue(prologue_data)
        } else {
            handshake
        };
        
        let handshake = handshake.build()?;
        
        // In a real implementation, you would update the session with the handshake result
        // Here we just return the handshake message
        handshake.perform()
    }
    
    /// Encrypt a message
    pub fn encrypt_message(
        &self,
        session_id: &[u8],
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> ProtocolResult<Vec<u8>> {
        let sessions = self.sessions.read();
        let session = sessions.get_session(session_id)?;
        
        let mut session = session.write();
        let ad = associated_data.unwrap_or_default();
        
        let res = session.encrypt(plaintext, ad)?;
        
        // Persist state
        drop(session); // release write lock before saving (though not strictly necessary as save_session takes &self)
        let session_read = sessions.get_session(session_id)?.read().clone(); // Need to re-acquire or just use what we had?
        // Actually, we can just use the session we have. But session is RwLockWriteGuard.
        // We need to pass &DoubleRatchetSession.
        // Let's re-acquire read lock or clearer: just deref the write guard.
        // Sled is thread safe.
        // self.sessions.read() is held in `sessions` variable.
        self.sessions.read().save_session(session_id, &*sessions.get_session(session_id)?.read())?;
        
        Ok(res)
    }
    
    /// Decrypt a message
    pub fn decrypt_message(
        &self,
        session_id: &[u8],
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> ProtocolResult<Vec<u8>> {
        let sessions = self.sessions.read();
        let session = sessions.get_session(session_id)?;
        
        let mut session = session.write();
        let ad = associated_data.unwrap_or_default();
        
        let res = session.decrypt(ciphertext, ad)?;
        
        // Persist state
        self.sessions.read().save_session(session_id, &*session)?;
        
        Ok(res)
    }
    
    /// Deserialize session state
    pub fn deserialize_session_state(
        &self,
        session_id: &[u8],
        state: &[u8],
    ) -> ProtocolResult<()> {
        let sessions = self.sessions.read();
        let session = sessions.get_session(session_id)?;
        
        let mut session = session.write();
        session.deserialize_state(state) // Ensure this method exists in DoubleRatchetSession
    }
}

/// Session Manager
pub struct SessionManager {
    sessions: parking_lot::RwLock<std::collections::HashMap<Vec<u8>, Arc<RwLock<DoubleRatchetSession>>>>,
    db: sled::Tree,
    config: Config,
}

impl SessionManager {
    /// Create new session manager
    pub fn new(config: Config, db: Arc<sled::Db>) -> Self {
        let tree = db.open_tree("sessions").expect("failed to open sessions tree");
        Self {
            sessions: parking_lot::RwLock::new(std::collections::HashMap::new()),
            db: tree,
            config,
        }
    }
    
    /// Create a new session
    pub fn create_session(
        &mut self,
        peer_id: &[u8],
        config: Config,
    ) -> ProtocolResult<SessionHandle> {
        let session = DoubleRatchetSession::new(config)?;
        let session = Arc::new(RwLock::new(session));
        // Persist initial session state
        let state_bytes = session.read().serialize_state()?;
        self.db.insert(peer_id, state_bytes).map_err(|e| ProtocolError::InternalError(format!("DB insert error: {}", e)))?;

        // Cache in-memory
        let mut sessions = self.sessions.write();
        sessions.insert(peer_id.to_vec(), session.clone());
        
        Ok(SessionHandle {
            peer_id: peer_id.to_vec(),
            session,
        })
    }
    
    /// Get existing session
    pub fn get_session(
        &self,
        session_id: &[u8],
    ) -> ProtocolResult<Arc<RwLock<DoubleRatchetSession>>> {
        // Try in-memory cache first
        {
            let sessions = self.sessions.read();
            if let Some(s) = sessions.get(session_id) {
                return Ok(s.clone());
            }
        }

        // Try loading from persistent store
        match self.db.get(session_id).map_err(|e| ProtocolError::InternalError(format!("DB read error: {}", e)))? {
            Some(ivec) => {
                // Reconstruct a session and deserialize state
                let mut session = DoubleRatchetSession::new(self.config.clone())?;
                session.deserialize_state(&ivec)?;
                let arc_s = Arc::new(RwLock::new(session));
                // Insert into cache
                let mut sessions = self.sessions.write();
                sessions.insert(session_id.to_vec(), arc_s.clone());
                Ok(arc_s)
            }
            None => Err(ProtocolError::SessionNotFound),
        }
    }
    
    /// Save session state to persistence
    pub fn save_session(&self, peer_id: &[u8], session: &DoubleRatchetSession) -> ProtocolResult<()> {
        let state_bytes = session.serialize_state()?;
        self.db.insert(peer_id, state_bytes).map_err(|e| ProtocolError::InternalError(format!("DB insert error: {}", e)))?;
        // Ensure data is flushed to disk (optional but safer for critical steps)
        self.db.flush().map_err(|e| ProtocolError::InternalError(format!("DB flush error: {}", e)))?;
        Ok(())
    }

    /// Remove session
    pub fn remove_session(&mut self, session_id: &[u8]) -> bool {
        let mut sessions = self.sessions.write();
        let removed = sessions.remove(session_id).is_some();
        let _ = self.db.remove(session_id);
        removed
    }
}

/// Session Handle
#[derive(Clone)]
pub struct SessionHandle {
    peer_id: Vec<u8>,
    session: Arc<RwLock<DoubleRatchetSession>>,
}

impl SessionHandle {
    /// Get peer ID
    pub fn peer_id(&self) -> &[u8] {
        &self.peer_id
    }
    
    /// Get session
    pub fn session(&self) -> Arc<RwLock<DoubleRatchetSession>> {
        self.session.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_persistence_roundtrip() {
        let cfg = Config::default();

        // Create context and session
        let ctx = SecureContext::new(cfg.clone()).expect("create ctx");
        let peer = b"peer-persist-1";
        let _handle = ctx.create_session(peer).expect("create session");

        // Serialize current state
        let sessions_read = ctx.sessions.read();
        let s = sessions_read.get_session(peer).expect("get session");
        let state_before = s.read().serialize_state().expect("serialize");

        // Drop context to simulate shutdown
        drop(ctx);

        // Re-open context
        let ctx2 = SecureContext::new(cfg).expect("reopen ctx");
        let sessions_read2 = ctx2.sessions.read();
        let s2 = sessions_read2.get_session(peer).expect("load session");
        let state_after = s2.read().serialize_state().expect("serialize after");

        assert_eq!(state_before, state_after);
    }
}
