from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Optional
import uvicorn

app = FastAPI()

# In-memory storage for simplicity (as requested "Simple API").
# In production, this should use a database (SQLite/Postgres).
# Format: user_id -> {identity_key, signed_prekey, one_time_prekeys}
keys_storage = {}

class PreKeyBundle(BaseModel):
    user_id: str
    identity_key: str  # Hex encoded
    signed_pre_key: str # Hex encoded
    signed_pre_key_sig: str # Hex encoded
    one_time_pre_keys: List[str] # List of Hex encoded keys

class PreKeyResponse(BaseModel):
    identity_key: str
    signed_pre_key: str
    signed_pre_key_sig: str
    one_time_pre_key: Optional[str] = None

@app.post("/keys/upload")
def upload_keys(bundle: PreKeyBundle):
    keys_storage[bundle.user_id] = {
        "identity_key": bundle.identity_key,
        "signed_pre_key": bundle.signed_pre_key,
        "signed_pre_key_sig": bundle.signed_pre_key_sig,
        "one_time_pre_keys": bundle.one_time_pre_keys
    }
    return {"status": "ok", "message": f"Keys stored for {bundle.user_id}"}

@app.get("/keys/{user_id}", response_model=PreKeyResponse)
def get_key(user_id: str):
    if user_id not in keys_storage:
        raise HTTPException(status_code=404, detail="User not found")
    
    user_data = keys_storage[user_id]
    
    # Pop one one-time key if available
    otp_key = None
    if user_data["one_time_pre_keys"]:
        otp_key = user_data["one_time_pre_keys"].pop(0) 
        # In a real DB, we would delete it transactionally
    
    return PreKeyResponse(
        identity_key=user_data["identity_key"],
        signed_pre_key=user_data["signed_pre_key"],
        signed_pre_key_sig=user_data["signed_pre_key_sig"],
        one_time_pre_key=otp_key
    )

@app.get("/users")
def list_users():
    return list(keys_storage.keys())

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
