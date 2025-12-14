import sys
import os
import argparse
sys.path.append(os.path.join(os.path.dirname(__file__), '../../bindings/python'))

from secure_protocol import SecureContext, ProtocolError

def encrypt_file(input_path, output_path, peer_id_bytes):
    ctx = SecureContext()
    try:
        session = ctx.create_session(peer_id_bytes)
    except Exception as e:
        print(f"Session error: {e}")
        return

    try:
        with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            while chunk := f_in.read(1024):
                encrypted = session.encrypt(chunk)
                # Write length prefix to handle streaming decryption
                f_out.write(len(encrypted).to_bytes(4, 'big'))
                f_out.write(encrypted)
        print(f"Encrypted {input_path} -> {output_path}")
    except Exception as e:
        print(f"Error during file transfer: {e}")

def decrypt_file(input_path, output_path, peer_id_bytes):
    ctx = SecureContext()
    try:
        session = ctx.create_session(peer_id_bytes)
    except Exception as e:
        print(f"Session error: {e}")
        return

    try:
        with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            while True:
                # Read 4 bytes length
                len_bytes = f_in.read(4)
                if not len_bytes:
                    break
                
                chunk_len = int.from_bytes(len_bytes, 'big')
                if chunk_len == 0:
                    break
                    
                encrypted_chunk = f_in.read(chunk_len)
                if len(encrypted_chunk) != chunk_len:
                    print("Error: Encrypted file corrupted (short read)")
                    break
                    
                decrypted = session.decrypt(encrypted_chunk)
                f_out.write(decrypted)
                
        print(f"Decrypted {input_path} -> {output_path}")
    except Exception as e:
        print(f"Error during file decryption: {e}")

def main():
    parser = argparse.ArgumentParser(description="Secure File Transfer")
    parser.add_argument("mode", choices=["encrypt", "decrypt"])
    parser.add_argument("input", help="Input file")
    parser.add_argument("output", help="Output file")
    parser.add_argument("--peer", default="default_peer", help="Peer ID")
    
    args = parser.parse_args()
    
    if args.mode == "encrypt":
        encrypt_file(args.input, args.output, args.peer.encode())
    else:
        decrypt_file(args.input, args.output, args.peer.encode())

if __name__ == "__main__":
    main()
