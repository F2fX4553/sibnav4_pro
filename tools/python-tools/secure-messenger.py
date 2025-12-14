import sys
import os
import threading
import time
import base64
import argparse

# Add bindings Path
sys.path.append(os.path.join(os.path.dirname(__file__), '../../bindings/python'))

from secure_protocol import SecureContext, RelayClient, generate_keypair
from secure_protocol.storage import IdentityStore

RELAY_HOST = "127.0.0.1"
RELAY_PORT = 5000

def poll_messages(relay, ctx, my_priv):
    """Background thread to fetch new messages."""
    while True:
        try:
            messages = relay.fetch_messages()
            for sender_pub, blob in messages:
                # Decrypt
                # In this v1, we do not have a full Double Ratchet session map for every user yet.
                # So we simulate "Single Message" decryption or establish session on fly.
                # For demo simplicity: We create a session using the sender's public key as the shared secret key.
                # In real Signal: PreKey Bundles.
                
                print(f"\n[*] Received message from {base64.b64encode(sender_pub).decode()[:8]}...")
                
                session = ctx.create_session(sender_pub) # Derived from peer_id (sender_pub)
                plaintext = session.decrypt(blob).decode()
                print(f"    > {plaintext}")
                print("Command (send <pubkey> <msg> / exit): ", end="", flush=True)
                
        except Exception as e:
            # print(f"Poll error: {e}")
            pass
        time.sleep(2.0)

def main():
    print("Secure Messenger v1.0 (Relay Mode)")
    print("----------------------------------")
    
    # 1. Identity
    store = IdentityStore("messenger.db")
    identity = store.load_identity()
    if not identity:
        print("[!] No identity found. Generating...")
        pub, priv = generate_keypair()
        store.save_identity(pub, priv)
    else:
        pub, priv = identity
        
    print(f"My Public ID: {base64.b64encode(pub).decode()}")
    
    # 2. Connect to Relay
    try:
        relay = RelayClient(RELAY_HOST, RELAY_PORT, pub)
        relay.connect()
        print("[*] Connected and Registered to Relay Server.")
    except Exception as e:
        print(f"[!] Could not connect to relay: {e}")
        return

    # 3. Start Polling
    ctx = SecureContext()
    ctx.load_identity(pub, priv)
    
    t = threading.Thread(target=poll_messages, args=(relay, ctx, priv))
    t.daemon = True
    t.start()
    
    # 4. Input Loop
    print("\nCommands:")
    print("  send <recipient_b64> <message>")
    print("  exit")
    
    while True:
        try:
            line = input("Command: ").strip()
            if not line: continue
            
            parts = line.split(' ', 2)
            cmd = parts[0].lower()
            
            if cmd == "exit":
                break
                
            if cmd == "send":
                if len(parts) < 3:
                    print("Usage: send <recipient_b64> <message>")
                    continue
                    
                target_b64 = parts[1]
                text = parts[2]
                
                try:
                    target_pub = base64.b64decode(target_b64)
                    if len(target_pub) != 32: raise ValueError("Invalid Key Length")
                except:
                    print("[!] Invalid Recipient Public Key B64")
                    continue
                    
                # Encrypt
                session = ctx.create_session(target_pub)
                ciphertext = session.encrypt(text.encode())
                
                # Send
                relay.send_message(target_pub, ciphertext)
                print("[*] Sent.")
                
        except KeyboardInterrupt:
            break
            
    relay.close()

if __name__ == "__main__":
    main()
