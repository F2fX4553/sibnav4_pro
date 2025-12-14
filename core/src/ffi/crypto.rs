use super::*;
use std::slice;

#[no_mangle]
pub extern "C" fn secure_generate_keypair(
    public_key: *mut uint8_t,
    private_key: *mut uint8_t,
) -> FFIError {
    if public_key.is_null() || private_key.is_null() {
        return FFIError::NullPointer;
    }
    
    let result = panic::catch_unwind(|| {
        use x25519_dalek::{StaticSecret, PublicKey};
        use rand_core::OsRng;
        
        // Using x25519-dalek for key generation
        let secret = StaticSecret::random_from_rng(&mut OsRng);
        let public = PublicKey::from(&secret);
        
        unsafe {
            std::ptr::copy_nonoverlapping(secret.to_bytes().as_ptr(), private_key, 32);
            std::ptr::copy_nonoverlapping(public.as_bytes().as_ptr(), public_key, 32);
        }
        
        FFIError::Success
    });
    
    result.unwrap_or(FFIError::UnknownError)
}
