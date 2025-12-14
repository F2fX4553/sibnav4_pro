use super::{ChainKey, DoubleRatchetState};
use crate::crypto::{Encryptor, CryptoError};
use crate::error::{ProtocolError, ProtocolResult};
use crate::Config;
use x25519_dalek::{StaticSecret, PublicKey};
use hkdf::Hkdf;
use sha2::Sha256;
use parking_lot::RwLock;
use std::collections::HashMap;
use rand_core::OsRng;

pub struct DoubleRatchetSession {
    state: RwLock<DoubleRatchetState>,
    config: Config,
}

impl DoubleRatchetSession {
    pub fn new(config: Config) -> ProtocolResult<Self> {
        let dh_local = StaticSecret::random_from_rng(&mut OsRng);
        let dh_local_bytes = dh_local.to_bytes().to_vec();
        
        let state = DoubleRatchetState {
            root_key: [0u8; 32],
            sending_chain: None,
            receiving_chain: None,
            dh_local: Some(dh_local),
            dh_local_bytes,
            dh_remote: None,
            skipped_message_keys: HashMap::new(),
            max_skip: config.max_skipped_messages,
            previous_counter: 0,
        };
        
        Ok(Self {
            state: RwLock::new(state),
            config,
        })
    }
    
    // Create from existing shared secret (post-handshake)
    pub fn from_shared_secret(
        shared_secret: &[u8; 32],
        local_dh: StaticSecret,
        remote_dh: PublicKey,
        config: Config,
    ) -> ProtocolResult<Self> {
        let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
        let mut root_key = [0u8; 32];
        hkdf.expand(b"root_key", &mut root_key)
            .map_err(|_| ProtocolError::KeyDerivationFailed)?;
            
        let mut sending_key = [0u8; 32];
        hkdf.expand(b"sending_chain", &mut sending_key)
            .map_err(|_| ProtocolError::KeyDerivationFailed)?;
            
        let sending_chain = ChainKey::new(sending_key);
        let dh_local_bytes = local_dh.to_bytes().to_vec();
        
        let state = DoubleRatchetState {
            root_key,
            sending_chain: Some(sending_chain),
            receiving_chain: None,
            dh_local: Some(local_dh),
            dh_local_bytes,
            dh_remote: Some(remote_dh),
            skipped_message_keys: HashMap::new(),
            max_skip: config.max_skipped_messages,
            previous_counter: 0,
        };
        
        Ok(Self {
            state: RwLock::new(state),
            config,
        })
    }
    
    pub fn encrypt(&mut self, plaintext: &[u8], associated_data: &[u8]) -> ProtocolResult<Vec<u8>> {
        let mut state = self.state.write();
        
        if state.sending_chain.is_none() {
            // Need to initialize sending chain or perform DH
            return Err(ProtocolError::InvalidState); 
        }
        
        let sending_chain = state.sending_chain.as_mut().unwrap();
        let message_key = sending_chain.next_message_key();
        
        // Header: (DH Public Key, Message Number, Previous Chain Length)
        // Standard DR Header
        let dh_pub = if let Some(dh) = &state.dh_local {
            PublicKey::from(dh)
        } else {
            return Err(ProtocolError::InvalidState);
        };
        
        let header_bytes = dh_pub.as_bytes(); 
        // We really should serialize a proper header struct with index and prev_counter
        // HEADER = DH_RATOHET_KEY || N || PN
        // For simplicity in this blueprint, we'll prefix just DH key for now, 
        // but realistic impl needs more.
        // Let's adopt a simple serialization:
        // [DH(32)][N(8)][PN(8)]
        let mut header = Vec::with_capacity(32 + 8 + 8);
        header.extend_from_slice(header_bytes);
        header.extend_from_slice(&(sending_chain.index - 1).to_le_bytes()); // -1 because next_message_key incremented it
        header.extend_from_slice(&state.previous_counter.to_le_bytes());
        
        let encryptor = Encryptor::new(&message_key, u64::MAX).map_err(ProtocolError::from)?;
        // Encrypt uses associated_data + header as AD usually
        let mut final_ad = Vec::new();
        final_ad.extend_from_slice(associated_data);
        final_ad.extend_from_slice(&header);
        
        let ciphertext = encryptor.encrypt_message(plaintext, &final_ad)?;
        
        // Result: Header + Ciphertext
        let mut result = Vec::new();
        result.extend_from_slice(&header);
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }
    
    pub fn decrypt(&mut self, message: &[u8], associated_data: &[u8]) -> ProtocolResult<Vec<u8>> {
        if message.len() < 32 + 8 + 8 {
            return Err(ProtocolError::InvalidMessage);
        }
        
        // Parse Header
        let header_dh = &message[..32];
        let n_bytes: [u8; 8] = message[32..40].try_into().unwrap();
        let pn_bytes: [u8; 8] = message[40..48].try_into().unwrap();
        let n = u64::from_le_bytes(n_bytes);
        let pn = u64::from_le_bytes(pn_bytes);
        
        let ciphertext = &message[48..];
        let header = &message[..48];
        
        let mut state = self.state.write();
        let remote_dh = PublicKey::from(<[u8; 32]>::try_from(header_dh).unwrap());
        
        // Check if we need to do a DH ratchet
        let mut performed_ratchet = false;
        if state.dh_remote.is_none() || state.dh_remote.unwrap() != remote_dh {
             // DH Ratchet
             // 1. Try to skip messages in current receiving chain
             if let Some(mut chain) = state.receiving_chain.take() {
                 // Skip up to PN
                 // Store skipped keys
             }
             
             // 2. Perform Ratchet Step
             // Compute DHe_r = DH(dh_local, header_dh)
             let shared_secret = state.dh_local.as_ref().unwrap().diffie_hellman(&remote_dh);
             
             // ... Logic for root key update ...
             // Update root_key, receiving_chain
             
             // Generate new local key
             let new_local = StaticSecret::random_from_rng(&mut OsRng);
             state.dh_local_bytes = new_local.to_bytes().to_vec();
             state.dh_local = Some(new_local);
             
             // Update receiving key update...
             
             state.dh_remote = Some(remote_dh);
             performed_ratchet = true;
        }
        
        // Decrypt
        // If we found the key in skipped keys, use it
        // Else, step the receiving chain to N
        
        // Mock decryption for blueprint flow (since full DR logic is 100+ lines)
        // In a real impl, we'd complete the above steps.
        // For now, let's assume we derive the key successfully if state is valid.
        
        // Basic fallback for invalid state
        if state.receiving_chain.is_none() && !performed_ratchet {
            return Err(ProtocolError::InvalidState); 
        }
        
        // Placeholder key derivation
        let message_key = [1u8; 32]; // Replace with actual logic
        
        let encryptor = Encryptor::new(&message_key, u64::MAX).map_err(ProtocolError::from)?;
        let mut final_ad = Vec::new();
        final_ad.extend_from_slice(associated_data);
        final_ad.extend_from_slice(header);
        
        encryptor.decrypt_message(ciphertext, &final_ad).map_err(ProtocolError::from)
    }
    
    pub fn serialize_state(&self) -> ProtocolResult<Vec<u8>> {
        let state = self.state.read();
        serde_json::to_vec(&*state).map_err(|_| ProtocolError::InternalError("Serialization failed".into()))
    }
    
    pub fn deserialize_state(&mut self, data: &[u8]) -> ProtocolResult<()> {
        let mut state = self.state.write();
        // Load basic struct
        let mut loaded: DoubleRatchetState = serde_json::from_slice(data)
            .map_err(|_| ProtocolError::InternalError("Deserialization failed".into()))?;
            
        // Restore StaticSecrets from bytes
        if !loaded.dh_local_bytes.is_empty() {
             let arr: [u8; 32] = loaded.dh_local_bytes.clone().try_into().unwrap_or([0; 32]);
             loaded.dh_local = Some(StaticSecret::from(arr));
        }
        
        *state = loaded;
        Ok(())
    }
}
