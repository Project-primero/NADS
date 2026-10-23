# 🛡️ Network Anomaly Detection (NAD) — Enterprise Telemetry & Monitoring Platform

## Network Anomaly Detection Dashboard

Real-time network monitoring, automated threat detection, and machine learning anomaly inference.

<img width="1920" height="1080" alt="Screenshot From 2026-10-23 19-17-24" src="https://github.com/user-attachments/assets/9ecab80a-bb75-419a-98c9-288e2b516743" />

[![Backend](https://img.shields.io/badge/Backend-FastAPI-009688)](file:///home/dereje/project/NAD/backend/main.py)
[![ML Engine](https://img.shields.io/badge/ML-IsolationForest%20%2B%20Statistical-orange)](file:///home/dereje/project/NAD/backend/detection/models/hybrid_model.py)
[![UI](https://img.shields.io/badge/UI-React%2018%20%2B%20Tailwind-61dafb)](file:///home/dereje/project/NAD/frontend/src/components/Dashboard.tsx)
[![Tests](https://img.shields.io/badge/Tests-Passing-brightgreen)](file:///home/dereje/project/NAD/tests/test_connect.py)
[![License](https://img.shields.io/badge/License-MIT-blue)](LICENSE)

---

## 👥 Team Members & Contributors

| # | Full Name | CTC ID | Role / Contribution |
|:---:|---|:---:|---|
| 1 | **Dereje Tesfaye** | `CTC-2483-26` | Architecture, Ingestion Pipelines & Team Lead |
| 2 | **Natnael Mamaru** | `CTC-1449-26` | ML Detection Engine & Threat Scoring Fusion |
| 3 | **Esmael Shikur** | `CTC-6394-26` | SOC Frontend Dashboard & WebSec Platform |
| 4 | **Yerosan Kena** | `CTC-2859-26` | Heuristic Signature Rules & Attack Detectors |
| 5 | **Eyosias Dawit** | `CTC-7812-26` | Agent Telemetry & Database Persistence |
| 6 | **Bona Tenu** | `CTC-1793-26` | Network Simulation, Testing & Operations |

---

## 📖 Introduction

**Network Anomaly Detection (NAD)** is an enterprise-grade Cyber Attack Monitoring, Telemetry Ingestion, and Security Operations Center (SOC) platform designed for modern campus, enterprise, and laboratory networks.

Modern networks face a mix of known exploits and novel zero-day behavioral anomalies. NAD tackles this with a **Two-Engine Threat Fusion Pipeline**:
1. **Deterministic Heuristic Signature Engine**: Evaluates traffic against **30 stateful behavioral rules** covering Port Scans, SYN/UDP/ICMP Floods, Brute Force, C2 Beaconing, DNS Exfiltration, and Web Exploits (SQLi, XSS, Log4Shell).
2. **Unsupervised Machine Learning Engine**: An ensemble of **Isolation Forest** and statistical scoring models that baseline benign traffic flow patterns and identify unknown or zero-day anomalies without requiring prior attack labels.

Every detected threat is correlated into a unified **0–100 Threat Score**, mapped to an official **MITRE ATT&CK technique**, and delivered with step-by-step remediation commands and multi-OS firewall block rules (`iptables`, `nftables`, `windows-netsh`, and `cisco-acl`).

---

## ⚙️ Installation & Prerequisites

### 📋 Prerequisites
- **Operating System**: Linux (Ubuntu 20.04+, Debian 11+, Fedora, Arch) or macOS. (Windows supported via WSL2).
- **Python**: Python 3.10, 3.11, or 3.12 (`python3 --version`).
- **Node.js & npm**: Node.js v18+ and npm v9+ (`node -v` & `npm -v`).
- **Permissions**: Root/`sudo` required only for physical raw NIC sniffing (`make live`).

### 📦 Step-by-Step Installation

#### 1. Clone Repository & Setup Virtualenv
```bash
git clone https://github.com/Project-primero/NADS.git
cd NADS

# Automatically create Python virtualenv and install frontend dependencies:
make setup
```

*Or manually:*
```bash
# Backend virtualenv setup
python3 -m venv /tmp/nadvenv
/tmp/nadvenv/bin/pip install --upgrade pip
/tmp/nadvenv/bin/pip install -r requirements.txt

# Frontend dependencies setup
cd frontend && npm install && cd ..
```

#### 2. Train Baseline Machine Learning Weights
```bash
make train
# Generates baseline detection weights in backend/detection/models/
```

#### 3. Launch Services
```bash
# Start backend API (Port 8000)
make run &

# Start React SOC Dashboard (Port 5174 or 5173)
make run-frontend
```

Access the platforms:
- **SOC Web Dashboard**: `http://localhost:5174` (or `http://localhost:5173`)
- **Interactive REST API Documentation**: `http://127.0.0.1:8000/docs`

#### 4. (Optional) Run with Docker Compose
```bash
docker-compose up -d
```

---

## 🖥️ How to Connect PC 1 and PC 2

NAD supports connecting multiple physical or virtual computers across your local network (LAN / Wi-Fi).

```
 ┌─────────────────────────────────────────┐          ┌─────────────────────────────────────────┐
 │               PC 1                      │          │               PC 2                      │
 │     [NAD Server & SOC Console]          │          │      [Monitored Client / Agent]         │
 │                                         │  LAN/Wi-Fi  [or Penetration Testing Machine]       │
 │  • Backend API (Port 8000)              │◄────────►│                                         │
 │  • React SOC Dashboard (Port 5174)      │          │  • aegis-agent.py Telemetry Client      │
 │  • SQLite & Threat Correlation Engine   │          │    OR                                   │
 │  • IP: e.g., 192.168.1.50               │          │  • nmap / hping3 (Attack Simulation)    │
 └─────────────────────────────────────────┘          └─────────────────────────────────────────┘
```

### Scenario A: Monitoring PC 2 using the Lightweight Remote Agent

In this setup, **PC 1** hosts the central SOC server, and **PC 2** runs the background telemetry agent that streams live traffic metrics to PC 1.

#### Step 1: Connect Both PCs to the Same Network
Ensure PC 1 and PC 2 can communicate over your router, switch, or Wi-Fi hotspot.
- On **PC 1**, find its local IP address:
  ```bash
  hostname -I
  # Example output: 192.168.1.50
  ```
- On **PC 2**, verify connectivity to PC 1:
  ```bash
  ping 192.168.1.50
  ```

#### Step 2: Start the NAD Server on PC 1
Make sure PC 1 listens on `0.0.0.0` so external machines can reach it:
```bash
# On PC 1:
AEGIS_HOST=0.0.0.0 make run &
make run-frontend
```

#### Step 3: Generate an Agent Token on PC 1
You can generate a cryptographic agent token via the web UI or via curl on PC 1:
```bash
curl -X POST http://127.0.0.1:8000/api/agents/tokens \
  -H "Content-Type: application/json" \
  -d '{"name": "Lab-PC-2", "site": "Computer Lab"}'
```
Response will return a token such as: `"token": "agt_a1b2c3d4e5f6..."`.

#### Step 4: Install and Run the Agent on PC 2
On **PC 2**, run either the automated one-line installer or the Python script directly:

- **Linux / macOS (One-line installer):**
  ```bash
  curl -sSL http://192.168.1.50:8000/api/agents/install.sh | bash -s -- <YOUR_TOKEN> "Computer Lab" "Lab-PC-2"
  ```

- **Manual Python execution:**
  ```bash
  python3 scripts/aegis-agent.py \
    --server http://192.168.1.50:8000 \
    --token <YOUR_TOKEN> \
    --site "Computer Lab"
  ```

- **Windows (PowerShell):**
  ```powershell
  irm http://192.168.1.50:8000/api/agents/install.ps1 | iex
  ```

#### Step 5: Verify on PC 1 Dashboard
Open the SOC Dashboard on **PC 1** (`http://localhost:5174`), navigate to the **Connected Computers** tab, and observe:
- **PC 2** listed with status `ONLINE`.
- Real-time packets-per-second (PPS), IP address, MAC address, and OS metrics updating live every second!

---

### Scenario B: Testing Live Attack Detection (PC 2 Attacks PC 1)

In this scenario, **PC 1** actively sniffs the network while **PC 2** runs penetration tests against PC 1 to verify the detection engines.

#### Step 1: Start Live Packet Sniffing on PC 1
On **PC 1**, identify your network interface (e.g., `eth0` or `wlan0`) and start in live mode with root capabilities:
```bash
# On PC 1:
sudo make live IFACE=wlan0
```

#### Step 2: Launch Test Attacks from PC 2 Targetting PC 1
From **PC 2**, run security tools pointing to PC 1's IP (`192.168.1.50`):

1. **Port Scan Simulation:**
   ```bash
   nmap -sS -p 1-1000 192.168.1.50
   ```
2. **SYN Flood Simulation:**
   ```bash
   sudo hping3 -S -p 80 --flood 192.168.1.50
   ```
3. **Web Vulnerability Probe:**
   ```bash
   curl "http://192.168.1.50:8000/api/search?q=' OR 1=1--"
   curl "http://192.168.1.50:8000/api/search?q=<script>alert(1)</script>"
   ```

#### Step 3: Observe Instant Detections on PC 1
On **PC 1**'s SOC Dashboard, watch the alerts appear in sub-second time:
- Severity level (`CRITICAL` / `HIGH`), MITRE ATT&CK technique code (e.g. `T1046`, `T1498`), threat score (0–100), and auto-generated firewall mitigation rule.

---

## 🌐 5 Universal Ingestion Modes

The system connects to any network environment via the interactive **Connect Source** dashboard:

1. **Synthetic Attack Simulator:** Generates realistic benign background traffic alongside 14 attack types with adjustable intensity (*Low, Medium, High, Stress*).
2. **Physical Host NIC:** Sniffs live packets directly from physical adapters (`eth0`, `wlan0`, `enp3s0`) with Berkeley Packet Filter (BPF) support.
3. **Switch SPAN / Mirror Port:** Connects to managed network switches to passively monitor entire departmental or office subnets.
4. **PCAP / PCAPNG Replay:** Streams recorded network captures (*Wireshark / tcpdump*) with speed multiplier controls (*Instant, 1x, 5x, 10x*).
5. **Distributed Remote PC Agents:** Lightweight endpoint clients for remote Windows and Linux computers, streaming telemetry over secure WebSockets.

---

## 🚀 Key Platform Capabilities

- **Two-Engine Threat Fusion:** Combines deterministic signature matching with unsupervised Isolation Forest ML anomaly scoring.
- **Real-Time SOC Dashboard:** Live packets-per-second (PPS) charts, protocol breakdowns, active threat matrices, and sub-second alert feeds.
- **Fleet Computer Management:** One-click deployment script generator for remote Linux (`install.sh`) and Windows (`install.ps1`) machines.
- **Automated Network Asset Inventory:** Auto-discovers and indexes IP addresses, MAC addresses, hostnames, and operating systems across your network.
- **CIDR / IP Allowlist Engine:** Eliminates alert fatigue by suppressing false positives from authorized vulnerability scanners and administrative hosts.
- **Multi-OS Firewall Rule Generator:** Generates instant block rules for `iptables`, `nftables`, `windows-netsh`, and `cisco-acl`.
- **WebSec Site Monitor:** Periodic synthetic HTTP audits, TLS certificate expiration tracking, and security header compliance ratings (HSTS, CSP, X-Frame-Options).

---

## 🛡️ Detection Capabilities at a Glance

| Threat Category | Detected Attack Patterns |
|---|---|
| **Reconnaissance & Scans** | TCP SYN Port Scan, Horizontal Scan, Ping Sweep, Null/Xmas Scan |
| **Floods & Denial of Service** | TCP SYN Flood, UDP Flood, ICMP Flood, Slowloris, UDP Amplification, Volumetric DDoS |
| **Brute Force & Credential Access** | SSH, FTP, RDP, Telnet, HTTP Brute Force, Distributed Password Spraying |
| **Command & Control (C2)** | Known Malicious C2 Domains, Periodic Egress C2 Beaconing, Cryptomining Pools |
| **Lateral Movement & Exfiltration** | SMB Lateral Movement (Port 445), DNS Tunneling & Subdomain Exfiltration, Bulk Data Exfiltration |
| **Web Exploitation** | SQL Injection, Cross-Site Scripting (XSS), Log4Shell (`${jndi:`), Path Traversal, Command Injection, SSRF |
| **Anomalous Traffic** | Machine Learning Isolation Forest Anomaly Detection for Zero-Day Threats |

---

## 📚 Documentation Directory

| Document | Description |
|---|---|
| [**DASHBOARD**](docs/DASHBOARD.md) | 🖥️ Detailed visual guide to the Network Anomaly Detection SOC Console & WebSec Platform |
| [**STEP_BY_STEP_GUIDE**](docs/STEP_BY_STEP_GUIDE.md) | 📘 Comprehensive operations manual, switch wiring, and agent deployment guide |
| [**HOW_IT_WORKS**](docs/HOW_IT_WORKS.md) | ⭐ Core pipeline walkthrough, threat correlation formula, and testing levels |
| [**UNDERSTANDING**](docs/UNDERSTANDING.md) | 💡 Plain-language guide: mental models, architecture, and why each layer matters |
| [**PRESENTATION**](docs/PRESENTATION.md) | 🎯 Complete 16-slide Marp-compatible presentation deck with speaker notes |
| [**ARCHITECTURE**](docs/ARCHITECTURE.md) | 🏛️ Detailed pipeline diagrams, database schemas, and WebSocket protocols |
| [**DETECTION_CATALOG**](docs/DETECTION_CATALOG.md) | 🔍 Exhaustive catalog of all 30 detectors, trigger thresholds, and MITRE codes |
| [**API**](docs/API.md) | 🔌 Complete REST endpoint reference and WebSocket telemetry specifications |
| [**CONFIGURATION**](docs/CONFIGURATION.md) | ⚙️ Reference of all `AEGIS_*` and `NAD_*` environment variables and tuning |
| [**TESTING**](docs/TESTING.md) | 🧪 Testing manual, automated test suites, and penetration simulation protocols |
| [**DEPLOYMENT**](docs/DEPLOYMENT.md) | 🚀 Production deployment: Docker host-mode, Linux capabilities, and Nginx proxy |
| [**RUNNING**](docs/RUNNING.md) | 🛠️ Makefile target reference, CLI flags, and operational troubleshooting |
| [**DATASET**](docs/DATASET.md) | 📊 Synthetic flow dataset reference and public benchmark integration (CIC-IDS) |

---

## 🗂️ Project Structure

```
.
├── backend/
│   ├── main.py                    # Application orchestration & WebSocket dispatch
│   ├── config.py                  # System settings (AEGIS_* & NAD_* variables)
│   ├── capture/
│   │   ├── packet_capture.py      # Universal packet capture & mode switching
│   │   ├── packet_parser.py       # L2–L7 protocol dissection
│   │   └── pcap_replayer.py       # Streaming PCAP/PCAPNG playback engine
│   ├── flow/
│   │   ├── flow_manager.py        # 5-tuple flow lifecycle & expiration
│   │   └── feature_extractor.py   # 41 CIC-IDS style flow features
│   ├── detection/
│   │   ├── signature_engine.py    # 30 heuristic and behavioral detectors
│   │   ├── correlation.py         # Signature ⊕ ML threat score fusion (0–100)
│   │   ├── inference.py           # Real-time ML inference engine
│   │   ├── trainer.py             # Model training pipeline
│   │   └── models/                # Hybrid, Isolation Forest, LSTM, Transformer
│   ├── alerts/
│   │   └── alert_manager.py       # Alert deduplication, history, & metrics
│   ├── database/
│   │   ├── db.py                  # SQLite database interface & migrations
│   │   └── models.py              # Schema: alerts, agents, assets, allowlist
│   └── api/
│       ├── routes.py              # REST API endpoints (Connect, Agents, Assets)
│       └── websocket.py           # Real-time WebSocket connection manager
├── frontend/
│   ├── src/
│   │   ├── components/            # SOC Dashboard, TrafficChart, ThreatMatrix
│   │   │   ├── connect/           # Universal Connect, Agents & Assets pages
│   │   │   └── websec/            # WebSec Site Health & TLS monitor
│   │   ├── hooks/useWebSocket.ts  # Live WebSocket snapshot synchronization
│   │   └── types/                 # TypeScript interfaces for alerts & telemetry
│   ├── vite.config.ts             # Dev proxy configuration
│   └── package.json
├── scripts/
│   ├── aegis-agent.py             # Remote computer telemetry client (Linux/Windows)
│   ├── generate_dataset.py        # Synthetic dataset generator
│   └── smoke.sh                   # API health probe script
├── tests/
│   ├── test_connect.py            # Connect system & agent authentication tests
│   └── test_smoke.py              # REST API & detection engine tests
├── Makefile                       # Operations & execution targets
└── docker-compose.yml             # Host-mode container definition
```

---

## 🔒 Security & Authorized Usage

Network Anomaly Detection is engineered for defensive security operations, educational laboratories, and authorized network monitoring. Always adhere to legal and institutional compliance:
- Only capture network packets on hardware, switches, or networks you own or have explicit authorization to monitor.
- Run penetration testing tools only against designated, isolated laboratory target machines.
