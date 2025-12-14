import sqlite3
import time
import random
import sys
import os
import argparse

# Try to import bindings, mock if unavailable
try:
    sys.path.append(os.path.join(os.path.dirname(__file__), '../../bindings/python'))
    from secure_protocol import SecureContext
    BINDINGS_AVAILABLE = True
except ImportError:
    print("Warning: secure_protocol bindings not found. Running in simulation mode.")
    BINDINGS_AVAILABLE = False

DB_PATH = "messages.db"

class MessageQueue:
    def __init__(self):
        self.conn = sqlite3.connect(DB_PATH)
        self.create_table()

    def create_table(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                peer_id TEXT,
                message BLOB,
                status TEXT DEFAULT 'pending', 
                attempts INTEGER DEFAULT 0,
                last_attempt REAL DEFAULT 0
            )
        ''')
        self.conn.commit()

    def enqueue(self, peer_id, message):
        cursor = self.conn.cursor()
        cursor.execute('INSERT INTO queue (peer_id, message) VALUES (?, ?)', (peer_id, message))
        self.conn.commit()
        print(f"Message queued for {peer_id}")

    def get_pending(self):
        cursor = self.conn.cursor()
        # Simple exponential backoff check: now > last_attempt + 2^attempts
        now = time.time()
        cursor.execute('''
            SELECT id, peer_id, message, attempts, last_attempt 
            FROM queue 
            WHERE status = 'pending'
        ''')
        rows = cursor.fetchall()
        
        pending = []
        for row in rows:
            mid, peer, msg, attempts, last = row
            backoff = min(60, 2 ** attempts) # Max 60s backoff
            if now > last + backoff:
                pending.append(row)
        return pending

    def mark_success(self, msg_id):
        cursor = self.conn.cursor()
        cursor.execute("UPDATE queue SET status = 'sent' WHERE id = ?", (msg_id,))
        self.conn.commit()
        print(f"Message {msg_id} marked as sent")
    
    def mark_failed_attempt(self, msg_id, attempts):
        cursor = self.conn.cursor()
        cursor.execute("UPDATE queue SET attempts = ?, last_attempt = ? WHERE id = ?", (attempts + 1, time.time(), msg_id))
        self.conn.commit()

class ResilientMessenger:
    def __init__(self):
        self.queue = MessageQueue()
        if BINDINGS_AVAILABLE:
            self.ctx = SecureContext()
        
    def send_message(self, peer_id, plaintext):
        # 1. Encrypt (if possible) - In real app, we might encrypt before queuing or after.
        # Ideally encrypt immediately to secure data at rest in queue.
        # But for this demo we queue plaintext/blobs and simulate encryption or use it.
        
        # In a real signal app, we queue the ciphertext.
        ciphertext = plaintext.encode() # Placeholder
        if BINDINGS_AVAILABLE:
            try:
                # session = self.ctx.create_session(peer_id.encode())
                # ciphertext = session.encrypt(plaintext.encode(), b"")
                pass
            except Exception as e:
                print(f"Encryption failed: {e}")
                return

        self.queue.enqueue(peer_id, ciphertext)
        self.process_queue()

    def process_queue(self):
        pending = self.queue.get_pending()
        if not pending:
            return

        print(f"Processing {len(pending)} pending messages...")
        for row in pending:
            mid, peer, msg, attempts, last = row
            
            success = self._attempt_send(peer, msg)
            
            if success:
                self.queue.mark_success(mid)
            else:
                self.queue.mark_failed_attempt(mid, attempts)
                print(f"Message {mid} failed completely (attempt {attempts+1}). Retrying later.")

    def _attempt_send(self, peer, msg):
        # Simulate network or actual send
        # Here we simulate random network failure
        print(f"Attempting to send to {peer}...")
        
        # Simulation: 30% chance of failure
        if random.random() < 0.3:
            print("Network Error!")
            return False
        
        print("Network Send OK.")
        return True

    def run_daemon(self):
        print("Starting resilient messenger daemon...")
        while True:
            self.process_queue()
            time.sleep(1) # check every second

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["send", "daemon"])
    parser.add_argument("--peer", help="Peer ID")
    parser.add_argument("--msg", help="Message content")
    
    args = parser.parse_args()
    
    messenger = ResilientMessenger()
    
    if args.mode == "send":
        if not args.peer or not args.msg:
            print("Error: --peer and --msg required for send")
            sys.exit(1)
        messenger.send_message(args.peer, args.msg)
    elif args.mode == "daemon":
        messenger.run_daemon()
