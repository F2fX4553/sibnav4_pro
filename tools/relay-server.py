import socket
import threading
import struct
import sys

# In-memory storage: { public_key_bytes : [ (sender_key, message_bytes), ... ] }
MAILBOX = {}
MAILBOX_LOCK = threading.Lock()

# Registered clients map (optional, for online status check)
ONLINE_CLIENTS = {}

def handle_client(conn, addr):
    print(f"[+] New connection from {addr}")
    client_pub_key = None
    
    try:
        while True:
            # Read Command (1 byte)
            cmd_byte = conn.recv(1)
            if not cmd_byte:
                break
                
            cmd = cmd_byte[0]
            
            if cmd == 1: # REGISTER
                # Expect 32 bytes public key
                pub_key = recv_exact(conn, 32)
                if len(pub_key) != 32: break
                
                client_pub_key = pub_key
                with MAILBOX_LOCK:
                    ONLINE_CLIENTS[client_pub_key] = conn
                    if client_pub_key not in MAILBOX:
                        MAILBOX[client_pub_key] = []
                
                conn.sendall(b'\x00') # OK
                print(f"[*] Registered user: {pub_key.hex()[:8]}...")
                
            elif cmd == 2: # SEND
                # Recipient (32) + Len (4) + Msg (Len)
                recipient = recv_exact(conn, 32)
                len_bytes = recv_exact(conn, 4)
                msg_len = struct.unpack('>I', len_bytes)[0]
                msg = recv_exact(conn, msg_len)
                
                # Store message
                with MAILBOX_LOCK:
                    if recipient not in MAILBOX:
                        MAILBOX[recipient] = []
                    # We assume the sender is the current authenticated client (client_pub_key)
                    # Ideally we verify signature, but for demo we trust the socket connection after Register.
                    sender = client_pub_key if client_pub_key else b'\x00'*32
                    MAILBOX[recipient].append((sender, msg))
                
                conn.sendall(b'\x00') # OK
                print(f"[*] Stored message for {recipient.hex()[:8]}...")
                
            elif cmd == 3: # FETCH
                # Return all messages for current user
                if not client_pub_key:
                    conn.sendall(b'\xFF') # Error: Not registered
                    continue
                    
                with MAILBOX_LOCK:
                    messages = MAILBOX.get(client_pub_key, [])
                    # Clear mailbox after fetch (POP3 style)
                    MAILBOX[client_pub_key] = []
                    
                # Response: Count (4)
                conn.sendall(struct.pack('>I', len(messages)))
                
                for sender, payload in messages:
                    # Sender (32) + Len (4) + Payload
                    conn.sendall(sender)
                    conn.sendall(struct.pack('>I', len(payload)))
                    conn.sendall(payload)
                    
                print(f"[*] Delivered {len(messages)} messages to {client_pub_key.hex()[:8]}...")
                
            else:
                print(f"[!] Unknown command: {cmd}")
                break
                
    except Exception as e:
        print(f"[!] Error handling client {addr}: {e}")
    finally:
        if client_pub_key:
            with MAILBOX_LOCK:
                if client_pub_key in ONLINE_CLIENTS:
                    del ONLINE_CLIENTS[client_pub_key]
        conn.close()
        print(f"[-] Connection closed {addr}")

def recv_exact(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet: return data
        data += packet
    return data

def main():
    port = 5000
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', port))
    server.listen(5)
    print(f"[*] Relay Server listening on port {port}")
    
    while True:
        conn, addr = server.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr))
        t.daemon = True
        t.start()

if __name__ == "__main__":
    main()
