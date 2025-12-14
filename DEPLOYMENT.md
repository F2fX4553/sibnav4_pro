# Deployment Guide: The Beast Unleashed

This guide details how to deploy the hardened Secure Protocol Server in a production environment.

## 1. Prerequisites
- **Server OS**: Linux (Recommended: Ubuntu 22.04 LTS) or Windows Server.
- **Runtime**: Docker (Preferred) OR Python 3.9+.
- **Network**: Public IP with Port 8000 exposed (and 443 for HTTPS later).

## 2. Quick Start (Docker)
This is the most secure and robust way to run the server.

### Build the Image
```bash
docker build -t secure-server:latest .
```

### Run the Container
```bash
# Run in background, map port 8000, and persist the database
docker run -d \
  --name sibna-server \
  -p 8000:8000 \
  --restart always \
  -v $(pwd)/data:/app/server_keys.db \
  secure-server:latest
```

### Verify Status
```bash
docker ps
# Check logs
docker logs sibna-server
```

## 3. Manual Deployment (Linux/Systemd)
If you cannot use Docker, follow these steps.

### Install Dependencies
```bash
sudo apt update && sudo apt install python3-pip python3-venv sqlite3
cd /path/to/sibnaprotocolv2
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Create Service File
Create `/etc/systemd/system/sibna.service`:
```ini
[Unit]
Description=Sibna Secure Protocol Server
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/path/to/sibnaprotocolv2
ExecStart=/path/to/sibnaprotocolv2/venv/bin/uvicorn server.main:app --host 0.0.0.0 --port 8000 --workers 4
Restart=always

[Install]
WantedBy=multi-user.target
```

### Start Service
```bash
sudo systemctl enable sibna
sudo systemctl start sibna
```

## 4. Security Checklist (Go-Live)
- [ ] **Firewall**: Allow ONLY port 8000 (and 22 for SSH).
- [ ] **HTTPS**: Put `Nginx` or `Caddy` in front of Uvicorn to handle SSL/TLS.
    - *The server enforces HSTS, so HTTPS is mandatory for browsers!*
- [ ] **Backups**: Periodically backup `server_keys.db`.
- [ ] **Monitoring**: Watch logs for `429` (DoS attempts) and `409` (Spoofing attempts).

## 5. Client Configuration
Ensure all clients (`secure-messenger.py`, etc.) point to your new IP:
```python
SERVER_URL = "http://YOUR_PUBLIC_IP:8000"
```
