use super::*;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
use rand_core::OsRng;
use parking_lot::RwLock;
use sled;
use std::sync::Arc;

/// Identity Key Pair
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct IdentityKeyPair {
    #[serde(with = "serde_bytes")]
    pub private: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub public: Vec<u8>,
}

impl IdentityKeyPair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(&mut OsRng);
        let public = PublicKey::from(&secret);
        
        Self {
            private: secret.to_bytes().to_vec(),
            public: public.as_bytes().to_vec(),
        }
    }

    pub fn from_bytes(public: &[u8], secret: &[u8]) -> Self {
        let mut secret_arr = [0u8; 32];
        secret_arr.copy_from_slice(secret);
        let secret = StaticSecret::from(secret_arr);
        
        let mut public_arr = [0u8; 32];
        public_arr.copy_from_slice(public);
        let public = PublicKey::from(public_arr);
        
        Self {
            private: secret.to_bytes().to_vec(),
            public: public.as_bytes().to_vec(),
        }
    }
}

mod serde_bytes {
    use serde::{Serializer, Deserializer};
    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        serializer.serialize_bytes(bytes)
    }
    
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where D: Deserializer<'de> {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        Ok(bytes)
    }
}

/// Secure Key Store
#[derive(Default)]
pub struct KeyStore {
    identity_key: RwLock<Option<IdentityKeyPair>>, 
    db: sled::Tree,
}

impl KeyStore {
    pub fn new(db: Arc<sled::Db>) -> ProtocolResult<Self> {
        // Use a dedicated tree for keystore
        let tree = db.open_tree("keystore").map_err(|e| ProtocolError::InternalError(format!("DB open tree error: {}", e)))?;

        // Try to load existing identity key
        if let Ok(Some(ivec)) = tree.get(b"identity") {
            if let Ok(loaded) = serde_json::from_slice::<IdentityKeyPair>(&ivec) {
                return Ok(Self {
                    identity_key: RwLock::new(Some(loaded)),
                    db: tree,
                });
            }
        }

        // Auto-generate identity key on new store for simplicity in this blueprint
        let identity = IdentityKeyPair::generate();
        let bytes = serde_json::to_vec(&identity).map_err(|_| ProtocolError::InternalError("Serialization failed".into()))?;
        tree.insert(b"identity", bytes).map_err(|e| ProtocolError::InternalError(format!("DB insert error: {}", e)))?;

        Ok(Self {
            identity_key: RwLock::new(Some(identity)),
            db: tree,
        })
    }
    
    pub fn get_identity_keypair(&self) -> ProtocolResult<IdentityKeyPair> {
        let guard = self.identity_key.read();
        if let Some(key) = &*guard {
            // Manual clone because ZeroizeOnDrop prevents auto-derive clone sometimes or we want explicit copy
             Ok(IdentityKeyPair {
                 private: key.private.clone(),
                 public: key.public.clone(),
             })
        } else {
            Err(ProtocolError::InvalidState)
        }
    }
    /// Save a One-Time PreKey
    pub fn save_prekey(&self, id: u32, keypair: &PreKeyPair) -> ProtocolResult<()> {
        let bytes = serde_json::to_vec(keypair).map_err(|_| ProtocolError::InternalError("Serialization failed".into()))?;
        let key = format!("prekey:{}", id);
        self.db.insert(key.as_bytes(), bytes).map_err(|e| ProtocolError::InternalError(format!("DB insert error: {}", e)))?;
        Ok(())
    }

    /// Get a One-Time PreKey
    pub fn get_prekey(&self, id: u32) -> ProtocolResult<PreKeyPair> {
        let key = format!("prekey:{}", id);
        match self.db.get(key.as_bytes()).map_err(|e| ProtocolError::InternalError(format!("DB read error: {}", e)))? {
            Some(ivec) => serde_json::from_slice(&ivec).map_err(|_| ProtocolError::InternalError("Deserialization failed".into())),
            None => Err(ProtocolError::KeyNotFound),
        }
    }

    /// Remove a One-Time PreKey
    pub fn remove_prekey(&self, id: u32) -> ProtocolResult<()> {
        let key = format!("prekey:{}", id);
        self.db.remove(key.as_bytes()).map_err(|e| ProtocolError::InternalError(format!("DB remove error: {}", e)))?;
        Ok(())
    }

    /// Save a Signed PreKey
    pub fn save_signed_prekey(&self, id: u32, keypair: &SignedPreKeyPair) -> ProtocolResult<()> {
        let bytes = serde_json::to_vec(keypair).map_err(|_| ProtocolError::InternalError("Serialization failed".into()))?;
        let key = format!("signed_prekey:{}", id);
        self.db.insert(key.as_bytes(), bytes).map_err(|e| ProtocolError::InternalError(format!("DB insert error: {}", e)))?;
        Ok(())
    }

    /// Get a Signed PreKey
    pub fn get_signed_prekey(&self, id: u32) -> ProtocolResult<SignedPreKeyPair> {
        let key = format!("signed_prekey:{}", id);
        match self.db.get(key.as_bytes()).map_err(|e| ProtocolError::InternalError(format!("DB read error: {}", e)))? {
            Some(ivec) => serde_json::from_slice(&ivec).map_err(|_| ProtocolError::InternalError("Deserialization failed".into())),
            None => Err(ProtocolError::KeyNotFound),
        }
    }
}

/// PreKey Pair
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PreKeyPair {
    #[serde(with = "serde_bytes")]
    pub private: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub public: Vec<u8>,
}

/// Signed PreKey Pair
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SignedPreKeyPair {
    #[serde(with = "serde_bytes")]
    pub private: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub public: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}
