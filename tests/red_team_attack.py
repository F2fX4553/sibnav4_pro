import requests
import time
import sys
import json
import threading

SERVER_URL = "http://localhost:8000"

def red_print(msg):
    print(f"[\033[91mATTACK \033[0m] {msg}")

def green_print(msg):
    print(f"[\033[92mSHIELD\033[0m] {msg}")

def attack_enumeration():
    red_print("Launching Privacy Check (Try GET /users)...")
    r = requests.get(f"{SERVER_URL}/users")
    if r.status_code == 404:
        green_print("Privacy Leak Sealed! /users endpoint is GONE (404).")
    else:
        red_print(f"Privacy Leak! /users still active? Code: {r.status_code}")

def attack_dos():
    red_print("Launching Rate Limit DoS (70 reqs/sec)...")
    success = 0
    blocked = 0
    # Use a cheap endpoint verify 404s also trigger rate limit, OR use keys/eve
    # Using a 404 endpoint is actually computationally cheaper for server, 
    # but middleware hits BEFORE routing usually? 
    # FastAPI middleware hits before routing? Yes.
    for _ in range(70):
        try:
            r = requests.get(f"{SERVER_URL}/keys/eve") # Valid endpoint
            if r.status_code == 200 or r.status_code == 404: success += 1
            elif r.status_code == 429: blocked += 1
        except: pass
    
    if blocked > 0:
        green_print(f"DoS Mitigated! Blocked {blocked} requests. (Success: {success})")
    else:
        red_print("DoS FAILED! Server did not block requests.")

def attack_payload_overflow():
    red_print("Launching 10MB Payload Attack (Memory Exhaustion)...")
    data = {"user_id": "overflow", "garbage": "A" * (10 * 1024 * 1024)} # 10MB
    try:
        r = requests.post(f"{SERVER_URL}/keys/upload", json=data, headers={"Content-Type": "application/json"})
        if r.status_code == 413:
            green_print("Overflow Mitigated! Server rejected large payload (413).")
        else:
            red_print(f"Overflow FAILED! Server accepted payload? Code: {r.status_code}")
    except Exception as e:
        green_print(f"Overflow Mitigated! Connection likely dropped: {e}")

def attack_sql_injection():
    red_print("Launching SQL Injection Attack (' OR 1=1 --)...")
    # Try to inject via user_id
    payload = {
        "user_id": "' OR 1=1 --", 
        "identity_key": "0" * 64, 
        "signed_pre_key": "0" * 64,
        "signed_pre_key_sig": "0" * 128,
        "one_time_pre_keys": []
    }
    r = requests.post(f"{SERVER_URL}/keys/upload", json=payload)
    # The validation regex should catch this before SQL
    if r.status_code == 422: # Validation Error
        green_print("Injection Mitigated! Input Validation blocked payload.")
    else:
        red_print(f"Injection Result: Code {r.status_code}. If 500, might have hit DB.")

def attack_spoofing():
    red_print("Launching Identity Spoofing Attack (Overwrite 'eve')...")
    # Eve should already exist from previous step. Try to overwrite her key.
    # New fake key
    payload = {
        "user_id": "eve",
        "identity_key": "BAD" * 21 + "1", # 64 hex chars
        "signed_pre_key": "0" * 64,
        "signed_pre_key_sig": "0" * 128,
        "one_time_pre_keys": []
    }
    r = requests.post(f"{SERVER_URL}/keys/upload", json=payload)
    if r.status_code == 409:
        green_print("Spoofing Mitigated! Server rejected key overwrite (TOFU).")
    elif r.json().get('detail') and 'Signature' in str(r.json()):
        green_print("Spoofing Mitigated! Signature verification blocked it.")
    else:
        red_print(f"Spoofing Result: Code {r.status_code}. {(r.text[:50])}...")

def attack_content_type():
    red_print("Launching MIME Sniffing Attack (Wrong Content-Type)...")
    payload = {"foo": "bar"}
    r = requests.post(f"{SERVER_URL}/keys/upload", data=json.dumps(payload), headers={"Content-Type": "text/plain"})
    if r.status_code == 415:
        green_print("MIME Attack Mitigated! Server rejected text/plain.")
    else:
        red_print(f"MIME Attack FAILED! Server accepted it? Code: {r.status_code}")

if __name__ == "__main__":
    print("=== STARTING RED TEAM ATTACK SUITE ===")
    time.sleep(1)
    
    attack_input_validation = threading.Thread(target=attack_sql_injection)
    attack_input_validation.start()
    attack_input_validation.join()
    
    attack_mime = threading.Thread(target=attack_content_type)
    attack_mime.start()
    attack_mime.join()

    attack_overflow = threading.Thread(target=attack_payload_overflow)
    attack_overflow.start()
    attack_overflow.join()
    
    attack_spoof = threading.Thread(target=attack_spoofing)
    attack_spoof.start()
    attack_spoof.join()
    
    # Check Privacy
    attack_enumeration()
    
    # DoS last because it might ban us for a minute
    attack_dos()
    
    print("=== ATTACK SUITE COMPLETE ===")
