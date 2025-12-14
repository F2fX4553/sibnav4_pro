import sys
import os
import asyncio
import base64

# Ensure we can find the bindings
sys.path.append(os.path.join(os.path.dirname(__file__), '../../bindings/python'))

from secure_protocol import SecureContext, generate_keypair, ProtocolError
from secure_protocol.storage import IdentityStore

def main():
    print("Secure Chat Client v2.0 (Persistent Identity)")
    print("-----------------------")
    
    try:
        # 1. Load or Generate Identity
        store = IdentityStore("my_identity.db")
        identity = store.load_identity()
        
        if identity:
            public, private = identity
            print("Identity loaded from disk.")
        else:
            print("No identity found. Generating new keypair...")
            public, private = generate_keypair()
            store.save_identity(public, private)
        
        ctx = SecureContext()
        ctx.load_identity(public, private)
        
        print(f"My Public Key: {base64.b64encode(public).decode()}")
            
            # In a real app, we would exchange keys and establish sessions here
            # This demonstrates the Python bindings are working
            
    except Exception as e:
        print(f"Error: {e}")
        return

if __name__ == "__main__":
    main()
