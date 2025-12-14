import sys
import os
import threading
import time
import base64
import socket

# Add bindings Path
sys.path.append(os.path.join(os.path.dirname(__file__), '../bindings/python'))

from secure_protocol import RelayClient

# Use a specific port for test to match server
RELAY_PORT = 5000

def run_server():
    # Execute the server script in this thread (or we could use subprocess)
    # But importing it is easier if designed well.
    # Let's verify we can import it.
    sys.path.append(os.path.join(os.path.dirname(__file__), '../tools'))
    import importlib.util
    spec = importlib.util.spec_from_file_location("relay_server", os.path.join(os.path.dirname(__file__), '../tools/relay-server.py'))
    relay_server = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(relay_server)
    
    # We need to run main() but main() blocks.
    # So we run it in a thread? 
    # Or just use subprocess to be clean.
    pass

import subprocess

def main():
    print("Starting Relay Server...")
    # Start server process
    server_proc = subprocess.Popen([sys.executable, "tools/relay-server.py"])
    time.sleep(2) # Wait for start
    
    try:
        print("Starting Client A...")
        pub_a = b'A'*32
        client_a = RelayClient("127.0.0.1", RELAY_PORT, pub_a)
        client_a.connect()
        
        print("Starting Client B...")
        pub_b = b'B'*32
        client_b = RelayClient("127.0.0.1", RELAY_PORT, pub_b)
        client_b.connect()
        
        msg = b"Hello from A to B"
        print(f"A sending to B: {msg}")
        # Note: We are sending RAW bytes here for simplicity of testing Relay Logic 
        # (Relay doesn't care if it's encrypted or not, it treats blob as opaque)
        client_a.send_message(pub_b, msg)
        
        print("B fetching messages...")
        # Polling/Fetching
        messages = client_b.fetch_messages()
        
        if len(messages) == 1:
            sender, content = messages[0]
            if sender == pub_a and content == msg:
                print("[TEST SUCCESS] Message delivered correctly.")
            else:
                print(f"[TEST FAILED] Content mismatch. Got {sender}:{content}")
                sys.exit(1)
        else:
            print(f"[TEST FAILED] Expected 1 message, got {len(messages)}")
            sys.exit(1)
            
    finally:
        server_proc.terminate()
        
if __name__ == "__main__":
    main()
