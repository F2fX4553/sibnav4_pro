use crate::Config;
use crate::keystore::KeyStore;
use crate::crypto::SecureRandom;
use crate::error::{ProtocolResult, ProtocolError};

pub struct HandshakeBuilder<'a> {
    config: Option<Config>,
    keystore: Option<&'a KeyStore>,
    random: Option<&'a SecureRandom>,
    initiator: bool,
    peer_public_key: Option<Vec<u8>>,
    prologue: Option<Vec<u8>>,
}

impl<'a> HandshakeBuilder<'a> {
    pub fn new() -> Self {
        Self {
            config: None,
            keystore: None,
            random: None,
            initiator: false,
            peer_public_key: None,
            prologue: None,
        }
    }
    
    pub fn with_config(mut self, config: Config) -> Self {
        self.config = Some(config);
        self
    }
    
    pub fn with_keystore(mut self, keystore: &'a KeyStore) -> Self {
        self.keystore = Some(keystore);
        self
    }
    
    pub fn with_random(mut self, random: &'a SecureRandom) -> Self {
        self.random = Some(random);
        self
    }
    
    pub fn with_initiator(mut self, initiator: bool) -> Self {
        self.initiator = initiator;
        self
    }
    
    pub fn with_peer_public_key(mut self, key: &[u8]) -> ProtocolResult<Self> {
        if key.len() != 32 {
            return Err(ProtocolError::InvalidKeyLength);
        }
        self.peer_public_key = Some(key.to_vec());
        Ok(self)
    }
    
    pub fn with_prologue(mut self, prologue: &[u8]) -> Self {
        self.prologue = Some(prologue.to_vec());
        self
    }
    
    pub fn build(self) -> ProtocolResult<Handshake> {
        Ok(Handshake {
            config: self.config.ok_or(ProtocolError::InvalidState)?,
            initiator: self.initiator,
            peer_public_key: self.peer_public_key,
            prologue: self.prologue,
        })
    }
}

pub struct Handshake {
    config: Config,
    initiator: bool,
    peer_public_key: Option<Vec<u8>>,
    prologue: Option<Vec<u8>>,
}

impl Handshake {
    pub fn perform(&self) -> ProtocolResult<Vec<u8>> {
        // Mock handshake logic for blueprint
        // Real logic would follow Noise protocol patterns (e.g. IK, XX) using x25519-dalek and maybe snow or manual implementation
        // For this blueprint, we'll return a mock handshake message
        
        let mut message = Vec::new();
        message.extend_from_slice(b"HANDSHAKE_V1");
        if self.initiator {
             message.extend_from_slice(b"_INIT");
             if let Some(pk) = &self.peer_public_key {
                 message.extend_from_slice(pk);
             }
        } else {
             message.extend_from_slice(b"_RESP");
        }
        
        Ok(message)
    }
}
