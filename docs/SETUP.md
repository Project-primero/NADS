# 🛠️ Network Anomaly Detection (NAD) — Complete Setup & Deployment Guide

This comprehensive guide walks you through setting up, configuring, and running the **Network Anomaly Detection (NAD)** platform on local environments, multi-node lab setups, and Docker containers.

---

## 📋 Table of Contents
1. [Prerequisites & System Requirements](#1-prerequisites--system-requirements)
2. [Quick Start (Makefile)](#2-quick-start-makefile)
3. [Manual Step-by-Step Installation](#3-manual-step-by-step-installation)
4. [Environment Configuration (.env)](#4-environment-configuration-env)
5. [Running Modes & Launch Commands](#5-running-modes--launch-commands)
6. [Multi-Node Setup: Connecting PC 1 (Server) and PC 2 (Agent)](#6-multi-node-setup-connecting-pc-1-server-and-pc-2-agent)
7. [Docker Deployment](#7-docker-deployment)
8. [Testing & Verification](#8-testing--verification)
9. [Troubleshooting & Common Issues](#9-troubleshooting--common-issues)

---

## 1. Prerequisites & System Requirements

Ensure your host machine satisfies the following minimum requirements:

### Operating System
- **Linux**: Ubuntu 20.04+, Debian 11+, Fedora 36+, Arch Linux. *(Recommended for live raw socket capture)*
- **macOS**: Monterey (12+) or newer.
- **Windows**: Windows 10/11 using **WSL2** (Windows Subsystem for Linux, Ubuntu recommended).

### Software Dependencies
| Tool | Minimum Version | Verification Command | Installation (Ubuntu/Debian) |
|---|---|---|---|
| **Python** | 3.10+ (up to 3.12) | `python3 --version` | `sudo apt install python3 python3-venv python3-pip` |
| **Node.js** | v18.0.0+ | `node -v` | `sudo apt install nodejs npm` *(or via nvm)* |
| **npm** | v9.0.0+ | `npm -v` | Included with Node.js |
| **Git** | v2.25+ | `git --version` | `sudo apt install git` |
| **libpcap** | Development libs | `dpkg -l | grep libpcap` | `sudo apt install libpcap-dev tcpdump` |

---

## 2. Quick Start (Makefile)

If you have `make` installed on a Linux/macOS or WSL2 system, the fastest way to get started is:

```bash
# 1. Clone the repository
git clone https://github.com/Project-primero/NADS.git
cd NADS

# 2. Automated setup (creates Python venv + installs frontend packages)
make setup

# 3. Train baseline machine learning weights
make train

# 4. Launch Backend API (Terminal 1)
make run

# 5. Launch SOC Dashboard (Terminal 2)
make run-frontend
```

Once running:
- **SOC Web Dashboard**: Open [http://localhost:5174](http://localhost:5174) in your browser.
- **Interactive REST API (Swagger)**: Open [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).

---

## 3. Manual Step-by-Step Installation

If you prefer installing dependencies without `make` or on customized paths:

### Step 3.1: Clone Repository
```bash
git clone https://github.com/Project-primero/NADS.git
cd NADS
```

### Step 3.2: Configure Python Virtual Environment
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On Linux / macOS / WSL2:
source venv/bin/activate
# On Windows (PowerShell):
# .\venv\Scripts\Activate.ps1

# Upgrade pip and install backend packages
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 3.3: Install Frontend Dependencies
```bash
cd frontend
npm install
cd ..
```

### Step 3.4: Train Baseline Machine Learning Model
Train the Isolation Forest and statistical scoring models using synthetic or baseline dataset features:
```bash
# Using active venv:
python3 train_model.py --model hybrid

# Model weights and scaler will be saved into models/ directory:
# models/hybrid_model.pkl
# models/scaler.pkl
```

---

## 4. Environment Configuration (.env)

NAD provides a complete configuration template in `.env.example`. Create your local environment file:

```bash
cp .env.example .env
```

### Key Parameters:
```dotenv
# ── Capture Settings ──────────────────────────────────────
NAD_CAPTURE_MODE=simulate       # Options: simulate, live, pcap, agent
NAD_INTERFACE=lo                # Live NIC: eth0, wlan0, lo, etc.
NAD_FLOW_TIMEOUT=60             # Seconds before idle 5-tuple flow expires

# ── Storage & Machine Learning ───────────────────────────
NAD_DB_PATH=data/alerts.db      # SQLite persistence filepath
NAD_MODEL_TYPE=hybrid           # Detection engine: hybrid, isolation_forest
NAD_ANOMALY_THRESHOLD=0.7       # Sensitivity threshold (0.0 - 1.0)
NAD_WS_BROADCAST_INTERVAL=1.0   # WebSocket broadcast interval in seconds

# ── Heuristic Alert Thresholds ────────────────────────────
NAD_PORT_SCAN_PORTS=15          # Distinct destination ports / 60s
NAD_SYN_FLOOD_COUNT=50          # SYN packets without ACK / 10s
NAD_UDP_FLOOD_COUNT=200         # UDP packets / 10s
NAD_ICMP_FLOOD_COUNT=100        # ICMP packets / 10s
NAD_DDOS_PPS=1000               # Global packets-per-second threshold
NAD_BRUTE_FORCE_FAILS=10        # Failed auth attempts / 300s
NAD_DNS_TUNNEL_LEN=53           # Subdomain character length threshold
NAD_EXFIL_BYTES=10000000        # Data transfer size threshold (10 MB)
```

---

## 5. Running Modes & Launch Commands

NAD supports 4 flexible operating modes depending on your objective:

### Mode A: Simulator Mode (Default, Safe, No Root Required)
Generates benign network traffic alongside simulated cyber attacks (port scans, floods, brute force, SQL injection). Ideal for demonstrations and testing without needing root privileges.
```bash
# Using Makefile:
make run

# Or manually:
python3 -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

### Mode B: Physical Live NIC Sniffing (Requires Root / sudo)
Sniffs real raw network frames arriving at your physical Ethernet or Wi-Fi network interface card.
```bash
# Find active network interface (e.g. eth0, wlan0, enp3s0):
ip route get 1.1.1.1 | awk '{print $5}'

# Launch with sudo:
sudo AEGIS_MODE=live AEGIS_IFACE=eth0 python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8000

# Or using Makefile:
sudo make live IFACE=eth0
```

### Mode C: PCAP / PCAPNG File Replay
Replays recorded `.pcap` capture files through the detection engine at simulated speeds (`instant`, `1x`, `5x`, `10x`).
```bash
# Using Makefile:
make run MODE=pcap FILE=/path/to/capture.pcap

# Or upload via SOC Web UI in the "Connect" tab
```

### Mode D: Starting the Frontend SOC Dashboard
In a separate terminal window:
```bash
# Using Makefile:
make run-frontend

# Or manually:
cd frontend
npm run dev
```

---

## 6. Multi-Node Setup: Connecting PC 1 (Server) and PC 2 (Agent)

NAD supports distributed monitoring where a central server (PC 1) monitors multiple remote machines (PC 2, PC 3) over LAN or Wi-Fi.

```
  ┌────────────────────────────────────────┐           ┌────────────────────────────────────────┐
  │                 PC 1                   │           │                 PC 2                   │
  │        [NAD Server & Console]          │           │          [Remote Client/Agent]         │
  │                                        │   LAN     │                                        │
  │  • Backend API (Port 8000)             │◄─────────►│  • Telemetry Agent (aegis-agent.py)    │
  │  • React SOC Dashboard (Port 5174)     │           │    OR                                  │
  │  • IP Address: 192.168.1.50            │           │  • Penetration Testing (nmap/hping3)   │
  └────────────────────────────────────────┘           └────────────────────────────────────────┘
```

### Step 6.1: Start NAD Server on PC 1
1. Find PC 1's local IP address:
   ```bash
   hostname -I
   # Example: 192.168.1.50
   ```
2. Start server bound to `0.0.0.0`:
   ```bash
   HOST=0.0.0.0 make run
   ```
3. In another terminal on PC 1, start the frontend:
   ```bash
   make run-frontend
   ```

### Step 6.2: Generate Agent Registration Token on PC 1
Generate an authorized token for PC 2:
```bash
curl -X POST http://127.0.0.1:8000/api/agents/tokens \
  -H "Content-Type: application/json" \
  -d '{"name": "Lab-PC-2", "site": "Computer Lab"}'
```
Response will return a token, e.g.:
```json
{"token": "agent_sec_a8f9b2c3d4e5", "name": "Lab-PC-2", "status": "active"}
```

### Step 6.3: Install and Run Agent on PC 2

#### On Linux or macOS:
Run the one-line dynamic installer:
```bash
curl -sSL http://192.168.1.50:8000/api/agents/install.sh | bash -s -- <YOUR_TOKEN> "Computer Lab" "Lab-PC-2"
```

#### On Windows (PowerShell Administrator):
```powershell
irm http://192.168.1.50:8000/api/agents/install.ps1 | iex
```

#### Manual Python Execution:
```bash
python3 scripts/aegis-agent.py \
  --server http://192.168.1.50:8000 \
  --token <YOUR_TOKEN> \
  --site "Computer Lab" \
  --name "Lab-PC-2"
```

### Step 6.4: Verify Telemetry
Open the SOC Dashboard on PC 1 (`http://localhost:5174`). Navigate to the **Agents / Assets** tab to observe incoming real-time packets, PPS, and system metrics from PC 2.

---

## 7. Docker Deployment

Deploy the entire stack with Docker Compose:

```bash
# Build and run containers in background
docker-compose up -d

# View live container logs
docker-compose logs -f

# Stop containers
docker-compose down
```

The `docker-compose.yml` mounts:
- `./data` for persistent SQLite alerts database.
- `./models` for trained machine learning model weights.
- Host networking mode enabled with `NET_RAW` and `NET_ADMIN` capabilities for packet capture.

---

## 8. Testing & Verification

### Run Unit and Integration Tests
```bash
# Run full pytest suite:
pytest tests/ -v

# Or using Makefile:
make test
```

### Run API Smoke Test
Verify all REST endpoints and health checks:
```bash
make smoke
# Or:
bash scripts/smoke.sh 127.0.0.1:8000
```

### Simulate Attack Traffic for Alert Validation
To verify signature rules and ML detection from PC 2 or localhost:
```bash
# 1. Port scan test
nmap -sS -p 1-1000 127.0.0.1

# 2. SYN flood simulation
sudo hping3 -S -p 80 --flood 127.0.0.1

# 3. Web exploit simulation (SQL Injection)
curl "http://127.0.0.1:8000/api/search?q=' OR 1=1--"

# 4. Command Injection attempt
curl "http://127.0.0.1:8000/api/search?q=;cat /etc/passwd"
```
Check the SOC Dashboard to see instantaneous alert notifications, severity levels, and generated firewall blocking commands.

---

## 9. Troubleshooting & Common Issues

| Problem | Cause | Solution |
|---|---|---|
| `PermissionError: [Errno 1] Operation not permitted` | Sniffing raw NIC packets without root privileges | Run using `sudo make live IFACE=eth0` or use `simulate` mode without sudo. |
| `Port 8000 already in use` | Another process is holding backend port | Find PID with `lsof -i :8000` or `netstat -tlpn \| grep 8000`, then terminate with `kill -9 <PID>`. |
| `Port 5174 / 5173 in use` | Vite frontend server conflict | Vite will automatically switch to the next port (e.g. 5174 or 5175). Check terminal output for exact URL. |
| `scapy.error.Scapy_Exception: libpcap missing` | System libpcap shared libraries not installed | Run `sudo apt install libpcap-dev` (Ubuntu/Debian) or `brew install libpcap` (macOS). |
| `FileNotFoundError: models/hybrid_model.pkl` | ML engine model has not been trained yet | Run `make train` or `python3 train_model.py --model hybrid`. |
| Agent connection fails (`ConnectionRefused`) | PC 1 backend bound to `127.0.0.1` instead of `0.0.0.0` | Launch PC 1 backend with `HOST=0.0.0.0 make run` and verify firewall allows port 8000 (`sudo ufw allow 8000/tcp`). |

---

## 📚 Related Documentation
- 📖 [**Project Information & Features**](PROJECT_INFO.md)
- 📑 [**Technical Reference Manual**](REFERENCE.md)
- 📄 [**Presentation Slide Deck (PDF)**](NAD_Presentation.pdf)
