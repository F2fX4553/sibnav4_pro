use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};
use serde::{Serialize, Deserialize};

/// Chain Key for Double Ratchet
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ChainKey {
    pub key: [u8; 32],
    pub index: u64,
    #[zeroize(skip)]
    #[serde(skip)]
    hmac: Option<Hmac<Sha256>>, // Option to allow serialization
}

impl Clone for ChainKey {
    fn clone(&self) -> Self {
        // Re-create HMAC on clone
        let hmac = Hmac::<Sha256>::new_from_slice(&self.key)
            .expect("HMAC key length is valid");
            
        Self {
            key: self.key,
            index: self.index,
            hmac: Some(hmac),
        }
    }
}

impl ChainKey {
    pub fn new(key: [u8; 32]) -> Self {
        let hmac = Hmac::<Sha256>::new_from_slice(&key)
            .expect("HMAC key length is valid");
        
        Self {
            key,
            index: 0,
            hmac: Some(hmac),
        }
    }
    
    pub fn next_message_key(&mut self) -> [u8; 32] {
        let mut input = vec![0x01]; // Message Key Seed
        input.extend_from_slice(&self.index.to_le_bytes()); // Although standard DR uses constants
        // Actually, standard says: 
        // MK = HMAC(CK, "1")
        // CK = HMAC(CK, "2")
        // But the blueprint used:
        // input = index + "message_key"
        
        // Let's stick to a robust derivation
        // Message Key
        let mut hmac = self.hmac.clone().expect("HMAC initialized");
        hmac.update(&[0x01]);
        let result = hmac.finalize();
        let mut message_key = [0u8; 32];
        message_key.copy_from_slice(&result.into_bytes()[..32]);
        
        // Next Chain Key
        let mut hmac_next = self.hmac.clone().expect("HMAC initialized");
        hmac_next.update(&[0x02]);
        let next_result = hmac_next.finalize();
        let mut next_key = [0u8; 32];
        next_key.copy_from_slice(&next_result.into_bytes()[..32]);
        
        // Update self
        self.key = next_key;
        self.hmac = Some(Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC valid"));
        self.index += 1;
        
        message_key
    }
}
