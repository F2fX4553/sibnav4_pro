#include "secure_protocol.hpp"
#include <stdexcept>
#include <vector>
#include <cstring>

namespace secure {

// SecureContext Implementation

std::unique_ptr<SecureContext> SecureContext::Create(const Config& config) {
    ConfigFFI ffi_config;
    ffi_config.enable_forward_secrecy = config.enable_forward_secrecy ? 1 : 0;
    ffi_config.enable_post_compromise_security = config.enable_post_compromise_security ? 1 : 0;
    ffi_config.max_skipped_messages = config.max_skipped_messages;
    ffi_config.key_rotation_interval = config.key_rotation_interval;
    ffi_config.handshake_timeout = config.handshake_timeout;
    ffi_config.message_buffer_size = config.message_buffer_size;

    SecureContextHandle* handle = secure_context_create(&ffi_config);
    if (!handle) {
        throw std::runtime_error("Failed to create secure context");
    }

    return std::unique_ptr<SecureContext>(new SecureContext(handle));
}

SecureContext::SecureContext(SecureContextHandle* handle) : handle_(handle) {}

SecureContext::~SecureContext() {
    if (handle_) {
        secure_context_free(handle_);
    }
}

std::unique_ptr<SecureSession> SecureContext::CreateSession(const std::vector<uint8_t>& peer_id) {
    SecureSessionHandle* session_handle = secure_session_create(
        handle_,
        peer_id.data(),
        peer_id.size()
    );

    if (!session_handle) {
        throw std::runtime_error("Failed to create session");
    }

    return std::unique_ptr<SecureSession>(new SecureSession(session_handle)); // Using raw pointer constructor usually bad practice, make friend or public
}

// SecureSession Implementation

SecureSession::SecureSession(SecureSessionHandle* handle) : handle_(handle) {}

SecureSession::~SecureSession() {
    if (handle_) {
        secure_session_free(handle_);
    }
}

std::vector<uint8_t> SecureSession::Encrypt(const std::vector<uint8_t>& plaintext) {
    uint8_t* ciphertext_ptr = nullptr;
    size_t ciphertext_len = 0;

    FFIError result = secure_session_encrypt(
        handle_,
        plaintext.data(),
        plaintext.size(),
        &ciphertext_ptr,
        &ciphertext_len
    );

    if (result != FFIError::Success) {
        throw std::runtime_error("Encryption failed with error code: " + std::to_string(static_cast<int>(result)));
    }

    std::vector<uint8_t> ciphertext(ciphertext_ptr, ciphertext_ptr + ciphertext_len);
    
    // We must free the memory allocated by Rust
    // Wait, `secure_session_encrypt` uses `Box::into_raw` which hands over ownership.
    // Does Rust free it? No, Rust forgot it. C++ must free it?
    // BUT we don't have a `secure_box_free`. We have `secure_free_buffer`.
    // Yes, `secure_free_buffer` takes ptr and len and reconstructs the slice to drop it.
    secure_free_buffer(ciphertext_ptr, ciphertext_len);

    return ciphertext;
}

std::vector<uint8_t> SecureSession::Decrypt(const std::vector<uint8_t>& ciphertext) {
    uint8_t* plaintext_ptr = nullptr;
    size_t plaintext_len = 0;

    FFIError result = secure_session_decrypt(
        handle_,
        ciphertext.data(),
        ciphertext.size(),
        &plaintext_ptr,
        &plaintext_len
    );

    if (result != FFIError::Success) {
        throw std::runtime_error("Decryption failed");
    }

    std::vector<uint8_t> plaintext(plaintext_ptr, plaintext_ptr + plaintext_len);
    secure_free_buffer(plaintext_ptr, plaintext_len);

    return plaintext;
}

KeyPair GenerateKeyPair() {
    KeyPair kp;
    kp.public_key.resize(32);
    kp.private_key.resize(32);

    FFIError result = secure_generate_keypair(kp.public_key.data(), kp.private_key.data());
    if (result != FFIError::Success) {
        throw std::runtime_error("Key generation failed");
    }
    return kp;
}

} // namespace secure
