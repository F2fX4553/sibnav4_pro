import sqlite3
import os
from . import ProtocolError

class IdentityStore:
    def __init__(self, db_path="identity.db"):
        self.db_path = db_path
        self._init_db()
        
    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        # Create table for Identity Key
        # We store just one identity for "Process/User" in this simple model
        c.execute('''CREATE TABLE IF NOT EXISTS identity
                     (id INTEGER PRIMARY KEY CHECK (id = 1),
                      public_key BLOB,
                      private_key BLOB)''')
        conn.commit()
        conn.close()
        
    def save_identity(self, public_key: bytes, private_key: bytes):
        if len(public_key) != 32 or len(private_key) != 32:
            raise ValueError("Invalid key length")
            
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO identity (id, public_key, private_key) VALUES (1, ?, ?)",
                  (public_key, private_key))
        conn.commit()
        conn.close()
        
    def load_identity(self):
        """Returns (public_key, private_key) or None if not found"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT public_key, private_key FROM identity WHERE id = 1")
        row = c.fetchone()
        conn.close()
        
        if row:
            return (row[0], row[1])
        return None

    def clear(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("DELETE FROM identity")
        conn.commit()
        conn.close()
