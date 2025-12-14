import sys
import os
import argparse
import socket
import threading

# Add bindings to path
sys.path.append(os.path.join(os.path.dirname(__file__), '../../bindings/python'))

from secure_protocol import SecureContext, SecureSocket
from secure_protocol.storage import IdentityStore

def handle_receive(secure_sock, label):
    """Thread function to continuously receive and print data."""
    try:
        while True:
            data = secure_sock.recv()
            if not data:
                print(f"\n[{label}] Connection Closed.")
                os._exit(0)
            print(f"\n[{label}] Received: {data.decode()}")
            print(f"[{label}] > ", end="", flush=True)
    except Exception as e:
        print(f"\nError receiving: {e}")
        os._exit(1)

def run_server(port, peer_id_bytes):
    print(f"Listening on port {port}...")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', port))
    server.listen(1)
    
    conn, addr = server.accept()
    print(f"Accepted connection from {addr}")
    
    # Setup Secure Session
    ctx = SecureContext()
    # In this simplified demo, we assume the peer_id acts as the shared secret derivation key
    # (Simulating a PSK or previously exchanged identity)
    session = ctx.create_session(peer_id_bytes)
    
    secure_socket = SecureSocket(conn, session)
    
    # Start receive thread
    t = threading.Thread(target=handle_receive, args=(secure_socket, "Server"))
    t.daemon = True
    t.start()
    
    # Send loop
    print("Type message and press Enter (Ctrl+C to quit):")
    print("Server > ", end="", flush=True)
    try:
        while True:
            msg = input()
            secure_socket.send(msg.encode())
            print("Server > ", end="", flush=True)
    except KeyboardInterrupt:
        print("\nClosing...")
        secure_socket.close()

def run_client(host, port, peer_id_bytes):
    print(f"Connecting to {host}:{port}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    print("Connected!")
    
    ctx = SecureContext()
    session = ctx.create_session(peer_id_bytes)
    
    secure_socket = SecureSocket(sock, session)
    
    t = threading.Thread(target=handle_receive, args=(secure_socket, "Client"))
    t.daemon = True
    t.start()
    
    print("Type message and press Enter (Ctrl+C to quit):")
    print("Client > ", end="", flush=True)
    try:
        while True:
            msg = input()
            secure_socket.send(msg.encode())
            print("Client > ", end="", flush=True)
    except KeyboardInterrupt:
        print("\nClosing...")
        secure_socket.close()

def main():
    parser = argparse.ArgumentParser(description="Secure Netcat - Generic Encrypted Pipe")
    parser.add_argument("mode", choices=["listen", "connect"])
    parser.add_argument("--host", default="127.0.0.1", help="Target host (for connect)")
    parser.add_argument("--port", type=int, default=1337, help="Port to use")
    parser.add_argument("--secret", default="shared-channel-key", help="Shared ID for key derivation (Demo)")
    
    args = parser.parse_args()
    
    if args.mode == "listen":
        run_server(args.port, args.secret.encode())
    else:
        run_client(args.host, args.port, args.secret.encode())

if __name__ == "__main__":
    main()
