use super::*;
use std::slice;
use std::sync::Arc;
use parking_lot::RwLock;

// Note: SecureSessionHandle.session is effectively *const RwLock<DoubleRatchetSession>
// We cheated a bit in context.rs casting Arc::into_raw result to *mut DoubleRatchetSession
// But Arc::into_raw returns *const T.
// Let's stay consistent.

#[no_mangle]
pub extern "C" fn secure_session_free(handle: *mut SecureSessionHandle) -> FFIError {
    if handle.is_null() {
        return FFIError::NullPointer;
    }
    
    unsafe {
        let handle = Box::from_raw(handle);
        if !handle.session.is_null() {
            // Reconstruct Arc to drop ref count
            let _ = Arc::from_raw(handle.session as *const RwLock<DoubleRatchetSession>);
        }
    }
    
    FFIError::Success
}

#[no_mangle]
pub extern "C" fn secure_session_encrypt(
    session: *mut SecureSessionHandle,
    plaintext: *const uint8_t,
    plaintext_len: size_t,
    ciphertext: *mut *mut uint8_t,
    ciphertext_len: *mut size_t,
) -> FFIError {
    if session.is_null() || plaintext.is_null() || ciphertext.is_null() || ciphertext_len.is_null() {
        return FFIError::NullPointer;
    }
    
    let result = panic::catch_unwind(|| {
        unsafe {
            let session_handle = &*session;
            let session_ptr = session_handle.session as *const RwLock<DoubleRatchetSession>;
            
            let plaintext_slice = slice::from_raw_parts(plaintext, plaintext_len);
            
            // We need to access the Arc without consuming it
            // Manually increment ref count? No, just reference it if we know it's valid.
            // But Arc::from_raw takes ownership.
            // We should use ManuallyDrop or just reference the raw pointer if we are careful.
            // Safest: Arc::increment_strong_count? No, that's for when we clone.
            // Typical FFI pattern with Arc:
            // let arc = Arc::from_raw(ptr);
            // ... use arc ...
            // let ptr = Arc::into_raw(arc);
            
            let arc = Arc::from_raw(session_ptr);
            let mut guard = arc.write();
            let result = guard.encrypt(plaintext_slice, &[]); // Empty AD for now
            
            // Release lock and don't drop Arc
            drop(guard);
            let _ = Arc::into_raw(arc);
            
            match result {
                Ok(encrypted) => {
                    let mut boxed = encrypted.into_boxed_slice();
                    let len = boxed.len();
                    let ptr = boxed.as_mut_ptr();
                    
                    *ciphertext = ptr;
                    *ciphertext_len = len;
                    
                    std::mem::forget(boxed);
                    
                    FFIError::Success
                }
                Err(err) => err.into(),
            }
        }
    });
    
    result.unwrap_or(FFIError::UnknownError)
}

#[no_mangle]
pub extern "C" fn secure_session_decrypt(
    session: *mut SecureSessionHandle,
    ciphertext: *const uint8_t,
    ciphertext_len: size_t,
    plaintext: *mut *mut uint8_t,
    plaintext_len: *mut size_t,
) -> FFIError {
    if session.is_null() || ciphertext.is_null() || plaintext.is_null() || plaintext_len.is_null() {
        return FFIError::NullPointer;
    }
    
    let result = panic::catch_unwind(|| {
        unsafe {
            let session_handle = &*session;
            let session_ptr = session_handle.session as *const RwLock<DoubleRatchetSession>;
            
            let ciphertext_slice = slice::from_raw_parts(ciphertext, ciphertext_len);
            
            let arc = Arc::from_raw(session_ptr);
            let mut guard = arc.write();
            let result = guard.decrypt(ciphertext_slice, &[]);
            
            drop(guard);
            let _ = Arc::into_raw(arc);
            
            match result {
                Ok(decrypted) => {
                    let mut boxed = decrypted.into_boxed_slice();
                    let len = boxed.len();
                    let ptr = boxed.as_mut_ptr();
                    
                    *plaintext = ptr;
                    *plaintext_len = len;
                    
                    std::mem::forget(boxed);
                    
                    FFIError::Success
                }
                Err(err) => err.into(),
            }
        }
    });
    
    result.unwrap_or(FFIError::UnknownError)
}
