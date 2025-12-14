import requests
import json
import argparse
import sys

SERVER_URL = "http://localhost:8000"

def upload_keys(user_id, identity_key, signed_pre_key, signed_pre_key_sig, one_time_pre_keys):
    payload = {
        "user_id": user_id,
        "identity_key": identity_key.hex(),
        "signed_pre_key": signed_pre_key.hex(),
        "signed_pre_key_sig": signed_pre_key_sig.hex(),
        "one_time_pre_keys": [k.hex() for k in one_time_pre_keys]
    }
    try:
        response = requests.post(f"{SERVER_URL}/keys/upload", json=payload)
        response.raise_for_status()
        print(f"Successfully uploaded keys for {user_id}")
    except requests.exceptions.RequestException as e:
        print(f"Error uploading keys: {e}")
        sys.exit(1)

def get_bundle(user_id):
    try:
        response = requests.get(f"{SERVER_URL}/keys/{user_id}")
        response.raise_for_status()
        data = response.json()
        print(json.dumps(data, indent=2))
        return data
    except requests.exceptions.RequestException as e:
        print(f"Error fetching keys for {user_id}: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="X3DH Key Client")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # Upload command
    upload_parser = subparsers.add_parser("upload", help="Upload keys")
    upload_parser.add_argument("--user-id", required=True, help="User ID")
    # For simulation, we generate dummy keys if not provided or accept them as args
    # simplified for this task
    
    # Get command
    get_parser = subparsers.add_parser("get", help="Get key bundle")
    get_parser.add_argument("--user-id", required=True, help="Target User ID")
    
    args = parser.parse_args()
    
    if args.command == "upload":
        # In a real app, these would come from the Rust FFI
        # Here we simulate valid hex strings (32 bytes = 64 hex chars)
        print("Simulating key generation...")
        dummy_ik = b'\x01' * 32
        dummy_spk = b'\x02' * 32
        dummy_sig = b'\x03' * 64
        dummy_opks = [b'\x04' * 32, b'\x05' * 32]
        
        upload_keys(args.user_id, dummy_ik, dummy_spk, dummy_sig, dummy_opks)
        
    elif args.command == "get":
        get_bundle(args.user_id)
