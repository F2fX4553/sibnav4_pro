//! Foreign Function Interface
//! Bridges Rust core with C ABI.

pub mod context;
pub mod session;
pub mod crypto;

use std::ffi::CStr;
use std::os::raw::{c_char, c_void};
use std::ptr;
use std::panic;
use libc::{size_t, uint8_t};

use crate::{SecureContext, Config, ProtocolError};
use crate::ratchet::DoubleRatchetSession;
use crate::keystore::KeyStore;
use crate::crypto::{SecureRandom, Encryptor};

// Opaque Types
#[repr(C)]
pub struct SecureContextHandle {
    context: *mut SecureContext,
}

#[repr(C)]
pub struct SecureSessionHandle {
    session: *mut DoubleRatchetSession,
}

#[repr(C)]
pub struct SecureKeyStoreHandle {
    keystore: *mut KeyStore,
}

// FFI Errors
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum FFIError {
    Success = 0,
    NullPointer = 1,
    InvalidArgument = 2,
    EncryptionFailed = 3,
    DecryptionFailed = 4,
    SessionNotFound = 5,
    OutOfMemory = 6,
    UnknownError = 255,
}

impl From<ProtocolError> for FFIError {
    fn from(err: ProtocolError) -> Self {
        match err {
            ProtocolError::InvalidKeyLength => FFIError::InvalidArgument,
            ProtocolError::EncryptionFailed => FFIError::EncryptionFailed,
            ProtocolError::DecryptionFailed => FFIError::DecryptionFailed,
            ProtocolError::SessionNotFound => FFIError::SessionNotFound,
            ProtocolError::OutOfMemory => FFIError::OutOfMemory,
            _ => FFIError::UnknownError,
        }
    }
}

// Global initialization
#[no_mangle]
pub extern "C" fn secure_protocol_init() -> FFIError {
    // Set panic hook to avoid aborting the process on Rust panics if possible,
    // though across FFI boundaries unwinding is UB. We should catch unwind.
    panic::set_hook(Box::new(|info| {
        eprintln!("PANIC in secure_protocol: {}", info);
    }));
    
    FFIError::Success
}

// Helper to free buffers allocated by Rust
#[no_mangle]
pub extern "C" fn secure_free_buffer(ptr: *mut uint8_t, len: size_t) -> FFIError {
    if ptr.is_null() {
        return FFIError::NullPointer;
    }
    
    unsafe {
        let slice = std::slice::from_raw_parts_mut(ptr, len);
        let _ = Box::from_raw(slice);
    }
    
    FFIError::Success
}
