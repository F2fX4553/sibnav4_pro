import sys
import os
import threading
import time
import socket

# Add bindings path
sys.path.append(os.path.join(os.path.dirname(__file__), '../bindings/python'))

from secure_protocol import SecureContext, SecureSocket

SERVER_PORT = 9999
SECRET = b"test-secret"

def server_thread_func(ready_event):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', SERVER_PORT))
    s.listen(1)
    
    ready_event.set()
    conn, addr = s.accept()
    
    ctx = SecureContext()
    session = ctx.create_session(SECRET)
    secure_sock = SecureSocket(conn, session)
    
    # Receive message
    print("[Server] Waiting for data...")
    data = secure_sock.recv()
    print(f"[Server] Received: {data}")
    
    # Send response
    response = b"Echo: " + data
    secure_sock.send(response)
    print("[Server] Sent response")
    
    secure_sock.close()
    s.close()

def client_thread_func():
    # Wait for server to start
    time.sleep(1)
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('127.0.0.1', SERVER_PORT))
    
    ctx = SecureContext()
    session = ctx.create_session(SECRET)
    secure_sock = SecureSocket(s, session)
    
    # Send message
    msg = b"Hello Secure Net"
    print(f"[Client] Sending: {msg}")
    secure_sock.send(msg)
    
    # Receive response
    response = secure_sock.recv()
    print(f"[Client] Received: {response}")
    
    if response == b"Echo: Hello Secure Net":
        print("[TEST SUCCESS] Data integrity verified.")
    else:
        print("[TEST FAILED] Mismatch.")
        sys.exit(1)
        
    secure_sock.close()

def main():
    ready = threading.Event()
    server = threading.Thread(target=server_thread_func, args=(ready,))
    server.start()
    
    ready.wait()
    client_thread_func()
    
    server.join()

if __name__ == "__main__":
    main()
