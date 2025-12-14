# Relay Server Protocol Design

## Overview
A simple Store-and-Forward server to enable asynchronous messaging. Uses a binary protocol over TCP.

## Protocol Commands
All commands are length-prefixed (4 bytes, Big Endian).

### 1. REGISTER
Client announces presence and public key.
- Command: `0x01` (1 byte)
- PublicKey: 32 bytes
- Response: `0x00` (OK) or `0xFF` (Error)

### 2. SEND
Client sends a message to a recipient.
- Command: `0x02` (1 byte)
- RecipientPubKey: 32 bytes
- MessageLength: 4 bytes (BE)
- MessageBlob: <bytes>
- Response: `0x00` (OK) or `0xFF` (Error/User Not Found - Store anyway?)
*Note: For this v1, if user is not connected, we store it in memory/disk.*

### 3. FETCH
Client asks for pending messages.
- Command: `0x03` (1 byte)
- Response: 
    - Count: 4 bytes (BE)
    - For each message:
        - SenderPubKey: 32 bytes
        - Length: 4 bytes
        - Blob: <bytes>

## Storage
Volatile dictionary `Map<RecipientKey, List<Message>>` for V1 demo. 
Persisted SQLite for V2.

## Security
- The Relay Server sees **metadata** (who is talking to whom).
- The Relay Server **cannot read** the message content (End-to-End Encrypted).
