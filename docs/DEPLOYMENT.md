# Deployment Guide

The Network Anomaly Detection (NAD) platform supports flexible deployment topologies ranging from single-machine developer setups to distributed university computer labs, physical switch SPAN/mirror taps, and enterprise cloud deployments.

---

## 1. Quick Local Deployment (Development)

Run the backend and frontend dev server on the host:

```bash
# 1. Setup virtualenv and dependencies
make setup

# 2. Train baseline detection model
make train

# 3. Start backend API & Ingestion Engine (Port 8000)
make run &

# 4. Start React SOC Dashboard (Port 5174)
make run-frontend
```

- **Dashboard UI**: `http://localhost:5174`
- **REST API & Swagger Docs**: `http://127.0.0.1:8000/docs`

---

## 2. Docker & Containerized Production

The platform includes an optimized [`docker-compose.yml`](file:///home/dereje/project/NAD/docker-compose.yml) configured with **host networking** and Linux network capabilities:

```bash
docker-compose up -d
```

### Why Host Networking & Capabilities?
- `network_mode: "host"`: Allows the application to bind directly to host interfaces without container NAT translation, ensuring real source IPs and MAC addresses are inspected.
- `cap_add: [NET_RAW, NET_ADMIN]`: Grants raw packet capture capability to Scapy and `af_packet` without running the entire container as root.
- Persistent volumes mount `./data` (SQLite database) and `./models` (trained ML weights) to survive reboots.

To stop the stack:
```bash
docker-compose down
```

---

## 3. Physical Host Capture (Without Full Root)

To sniff physical traffic on host NICs (e.g. `eth0`, `enp3s0`, `wlan0`) securely without running the entire web application as root:

```bash
# Grant packet capture capabilities to Python binary
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))

# Launch on physical interface
AEGIS_MODE=live AEGIS_IFACE=eth0 python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

Alternatively, use `make live IFACE=eth0 PORT=8000`.

---

## 4. Hardware Switch Port Mirroring (SPAN)

To monitor an entire department, server rack, or office building passively:
1. Connect a dedicated network cable from the Managed Switch's **Mirror / SPAN** port to a secondary NIC on the monitoring server (e.g. `eth1`).
2. Put the interface into promiscuous mode:
   ```bash
   sudo ip link set eth1 promisc on
   sudo ip link set eth1 up
   ```
3. Configure the switch:

### Cisco Catalyst Switch SPAN Configuration:
```cisco
configure terminal
monitor session 1 source interface GigabitEthernet0/1 - 24 both
monitor session 1 destination interface GigabitEthernet0/48
end
```

### HP / Aruba Switch Mirroring:
```cli
monitor-port 48
interface 1-24 monitor
```

### MikroTik RouterOS:
```routeros
/interface ethernet switch
set switch1 mirror-source=ether1 mirror-target=ether5
```

4. In the Dashboard, go to **Connect Source** → **Switch SPAN / Mirror Port**, select interface `eth1`, and click **Start Monitoring**.

---

## 5. Distributed Multi-Computer Agent Deployment

The system can ingest live telemetry from tens or hundreds of remote computers across different subnets.

### Step 1: Generate an Agent Token
From the dashboard (**Connected Computers** → **Add Computer**) or via API:
```bash
curl -s -X POST http://<SERVER_IP>:8000/api/agents/tokens \
  -H "Content-Type: application/json" \
  -d '{"name": "University-PC-01", "site": "Computer Lab A"}'
```

### Step 2: Deploy to Remote Linux Clients
Run the automated installer on the remote Linux machine (no root required, installs to `~/.nad-agent`):
```bash
curl -sSL http://<SERVER_IP>:8000/api/agents/install.sh | bash -s -- <TOKEN> "Computer Lab A" "University-PC-01"
```

### Step 3: Deploy to Remote Windows Clients
Open PowerShell as Administrator or regular user:
```powershell
curl.exe -sSL http://<SERVER_IP>:8000/api/agents/script -o "$env:TEMP\agent.py"; python "$env:TEMP\agent.py" --server "http://<SERVER_IP>:8000" --token "<TOKEN>" --site "Computer Lab A" --name "University-PC-01"
```

The agent streams encrypted or authenticated telemetry to `/api/agents/ingest` and connects to `/ws/agent`.

---

## 6. Reverse Proxy & Production Hardening

When deploying behind Nginx or Caddy:
- Forward standard HTTP endpoints to `http://127.0.0.1:8000`.
- Enable WebSocket upgrades for `/ws` and `/ws/agent`.
- Set client upload size to at least 100MB to allow large PCAP file uploads (`client_max_body_size 100M;`).

### Nginx Example Configuration:
```nginx
server {
    listen 80;
    server_name nad.university.edu;

    client_max_body_size 100M;

    # Frontend Static UI or Dev Proxy
    location / {
        proxy_pass http://127.0.0.1:5174;
        proxy_set_header Host $host;
    }

    # Backend API
    location /api/ {
        proxy_pass http://127.0.0.1:8000/api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # WebSockets (Live Dashboard & Remote Agents)
    location ~* ^/ws {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_read_timeout 86400s;
    }
}
```

---

## 7. Backups and State Management

The platform is intentionally designed to be lightweight and portable:
- **Alerts, Assets, and Agents**: Stored in `data/alerts.db` (SQLite). Simply snapshot or backup this file.
- **Machine Learning Models**: Stored in `models/*.pkl`.
- **Database Backup Command**:
  ```bash
  sqlite3 data/alerts.db ".backup 'data/alerts-backup-$(date +%F).db'"
  ```
