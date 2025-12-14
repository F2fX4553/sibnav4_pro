from ._native import *
import ctypes

class ProtocolError(Exception):
    pass

class SecureContext:
    def __init__(self, **kwargs):
        if not lib:
            raise RuntimeError("Native library not loaded")
            
        config = ConfigFFI()
        config.enable_forward_secrecy = kwargs.get("enable_forward_secrecy", True)
        config.enable_post_compromise_security = kwargs.get("enable_post_compromise_security", True)
        config.max_skipped_messages = kwargs.get("max_skipped_messages", 2000)
        config.key_rotation_interval = kwargs.get("key_rotation_interval", 86400)
        config.handshake_timeout = kwargs.get("handshake_timeout", 30)
        config.message_buffer_size = kwargs.get("message_buffer_size", 1024)
        
        self._handle = lib.secure_context_create(ctypes.byref(config))
        if not self._handle:
            raise ProtocolError("Failed to create context")
            
    def __del__(self):
        if hasattr(self, "_handle") and self._handle and lib:
            lib.secure_context_free(self._handle)

    def create_session(self, peer_id: bytes) -> "SecureSession":
        if not isinstance(peer_id, bytes):
            raise TypeError("peer_id must be bytes")
            
        handle = lib.secure_session_create(
            self._handle,
            (c_uint8 * len(peer_id)).from_buffer_copy(peer_id),
            len(peer_id)
        )
        
        if not handle:
            raise ProtocolError("Failed to create session")
            
        return SecureSession(handle)
        
    def load_identity(self, public_key: bytes, private_key: bytes):
        if len(public_key) != 32 or len(private_key) != 32:
            raise ValueError("Keys must be 32 bytes")
            
        res = lib.secure_context_load_identity(
            self._handle,
            (c_uint8 * 32).from_buffer_copy(private_key),
            (c_uint8 * 32).from_buffer_copy(public_key)
        )
        
        if res != FFI_SUCCESS:
            raise ProtocolError("Failed to load identity")

class SecureSession:
    def __init__(self, handle):
        self._handle = handle
        
    def encrypt(self, plaintext: bytes) -> bytes:
        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes")
            
        out_ptr = POINTER(c_uint8)()
        out_len = c_size_t(0)
        
        res = lib.secure_session_encrypt(
            self._handle,
            (c_uint8 * len(plaintext)).from_buffer_copy(plaintext),
            len(plaintext),
            ctypes.byref(out_ptr),
            ctypes.byref(out_len)
        )
        
        if res != FFI_SUCCESS:
            raise ProtocolError(f"Encryption failed: {res}")
            
        try:
            return ctypes.string_at(out_ptr, out_len.value)
        finally:
            lib.secure_free_buffer(out_ptr, out_len)
            
    def decrypt(self, ciphertext: bytes) -> bytes:
        if not isinstance(ciphertext, bytes):
            raise TypeError("ciphertext must be bytes")
            
        out_ptr = POINTER(c_uint8)()
        out_len = c_size_t(0)
        
        res = lib.secure_session_decrypt(
            self._handle,
            (c_uint8 * len(ciphertext)).from_buffer_copy(ciphertext),
            len(ciphertext),
            ctypes.byref(out_ptr),
            ctypes.byref(out_len)
        )
        
        if res != FFI_SUCCESS:
            raise ProtocolError(f"Decryption failed: {res}")
            
        try:
            return ctypes.string_at(out_ptr, out_len.value)
        finally:
            lib.secure_free_buffer(out_ptr, out_len)

def generate_keypair():
    public = (c_uint8 * 32)()
    private = (c_uint8 * 32)()
    
    res = lib.secure_generate_keypair(public, private)
    if res != FFI_SUCCESS:
        raise ProtocolError("Key generation failed")
        
    return bytes(public), bytes(private)

# Generic Secure Networking
import socket
import struct

class SecureSocket:
    """
    A wrapper around a standard python socket that transparently 
    encrypts and decrypts data using a SecureSession.
    """
    def __init__(self, sock: socket.socket, session: SecureSession):
        self.sock = sock
        self.session = session
        
    def send(self, data: bytes):
        """Encrypts and sends data with length prefixing."""
        if not isinstance(data, bytes):
            raise TypeError("Data must be bytes")
            
        encrypted = self.session.encrypt(data)
        # 4-byte Big Endian Length Prefix
        length_prefix = len(encrypted).to_bytes(4, 'big')
        self.sock.sendall(length_prefix + encrypted)
        
    def recv(self) -> bytes:
        """Receives a frame, decrypts it, and returns plaintext."""
        # Read length prefix
        len_bytes = self._recv_exact(4)
        if not len_bytes:
            return b""
            
        msg_len = int.from_bytes(len_bytes, 'big')
        if msg_len == 0:
            return b""
            
        # Read encrypted payload
        encrypted = self._recv_exact(msg_len)
        if len(encrypted) != msg_len:
            raise ProtocolError("Incomplete message received")
            
        return self.session.decrypt(encrypted)
        
    def _recv_exact(self, n: int) -> bytes:
        """Helper to receive exactly n bytes."""
        data = b""
        while len(data) < n:
            packet = self.sock.recv(n - len(data))
            if not packet:
                return data # Connection closed
            data += packet
        return data

    def close(self):
        self.sock.close()

# Relay Client (Signal-Style)
class RelayClient:
    def __init__(self, host, port, identity_pub_key):
        self.host = host
        self.port = port
        self.pub_key_bytes = identity_pub_key
        self.sock = None
        
    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            # Auto-register on connect
            self._register()
        except Exception as e:
            self.sock = None
            raise ProtocolError(f"Connection failed: {e}")

    def _register(self):
        # CMD 1 (Register) + PubKey (32)
        self.sock.sendall(b'\x01' + self.pub_key_bytes)
        resp = self.sock.recv(1)
        if resp != b'\x00':
            raise ProtocolError("Registration failed")

    def send_message(self, recipient_pub_key: bytes, encrypted_blob: bytes):
        if not self.sock: raise ProtocolError("Not connected")
        
        # CMD 2 (Send) + Recipient (32) + Len (4) + Blob
        msg_len = len(encrypted_blob)
        payload = (b'\x02' + 
                   recipient_pub_key + 
                   struct.pack('>I', msg_len) + 
                   encrypted_blob)
        
        self.sock.sendall(payload)
        resp = self.sock.recv(1)
        if resp != b'\x00':
            raise ProtocolError("Send failed (Server rejected)")

    def fetch_messages(self):
        """Returns list of (sender_pub_key, blob)"""
        if not self.sock: raise ProtocolError("Not connected")
        
        # CMD 3 (Fetch)
        self.sock.sendall(b'\x03')
        
        # Read count
        count_bytes = self._recv_exact(4)
        if not count_bytes: return []
        
        count = struct.unpack('>I', count_bytes)[0]
        messages = []
        
        for _ in range(count):
            sender = self._recv_exact(32)
            len_bytes = self._recv_exact(4)
            msg_len = struct.unpack('>I', len_bytes)[0]
            blob = self._recv_exact(msg_len)
            messages.append((sender, blob))
            
        return messages

    def _recv_exact(self, n):
        data = b''
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk: raise ProtocolError("Connection lost")
            data += chunk
        return data

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None
