# 🛡️ Network Anomaly Detection (NAD) — Enterprise Telemetry & Monitoring Platform

Real-time network monitoring, automated threat detection, and machine learning anomaly inference.

<img width="1920" height="1080" alt="Network Anomaly Detection Dashboard" src="https://github.com/user-attachments/assets/9ecab80a-bb75-419a-98c9-288e2b516743" />

[![Backend](https://img.shields.io/badge/Backend-FastAPI-009688)](file:///home/dereje/project/NAD/backend/main.py)
[![ML Engine](https://img.shields.io/badge/ML-IsolationForest%20%2B%20Statistical-orange)](file:///home/dereje/project/NAD/backend/detection/models/hybrid_model.py)
[![UI](https://img.shields.io/badge/UI-React%2018%20%2B%20Tailwind-61dafb)](file:///home/dereje/project/NAD/frontend/src/components/Dashboard.tsx)
[![Tests](https://img.shields.io/badge/Tests-Passing-brightgreen)](file:///home/dereje/project/NAD/tests/test_connect.py)
[![License](https://img.shields.io/badge/License-MIT-blue)](LICENSE)

---

## 👥 Team Members & Contributors

| # | Full Name | CTC ID |
|:---:|---|:---:|
| 1 | **Dereje Tesfaye** | `CTC-2483-26` |
| 2 | **Natnael Mamaru** | `CTC-1449-26` |
| 3 | **Esmael Shikur** | `CTC-6394-26` |
| 4 | **Yerosan Kena** | `CTC-2859-26` |
| 5 | **Eyosias Dawit** | `CTC-7812-26` |
| 6 | **Bona Tenu** | `CTC-1793-26` |

---

## 🎥 Group Presentation Video & Slides

Watch the comprehensive project presentation and system walkthrough:

<video src="docs/Group%20presentation%20video%201080p.mp4" controls="controls" width="100%" style="max-height: 500px;"></video>

> 🎬 **Direct Video Link / Download**: [Group presentation video 1080p.mp4](docs/Group%20presentation%20video%201080p.mp4)  
> 📄 **Presentation Slides (PDF)**: [NAD_Presentation.pdf](docs/NAD_Presentation.pdf)

---

## 3. Project Information

### 📋 Brief Project Description
**Network Anomaly Detection (NAD)** is an enterprise-grade Cyber Attack Monitoring, Telemetry Ingestion, and Security Operations Center (SOC) platform engineered to protect modern enterprise, academic, and lab networks. It delivers continuous, full-visibility network security monitoring through a hybrid detection model combining rule-based heuristics and unsupervised machine learning.

### 🎯 Purpose
Traditional Intrusion Detection Systems (IDS) often produce excessive false positives, rely solely on static signatures that miss zero-day anomalies, or lack integrated remediation mechanisms. NAD solves these challenges by providing:
1. **Holistic Visibility**: Real-time packet capture and flow analytics across local network interfaces, PCAP packet traces, and distributed endpoints.
2. **Dual-Engine Threat Fusion**: Concurrent analysis by a deterministic signature catalog and an unsupervised Isolation Forest model to detect both known exploit patterns and novel anomalous behavior.
3. **Immediate Operational Response**: Instant generation of copy-paste firewall rules (`iptables`, `nftables`, Windows Firewall `netsh`, Cisco ACLs) to empower security analysts to rapidly isolate malicious actors.
4. **Holistic Perimeter Assessment**: Integrated website security auditing (WebSec) measuring TLS certificate validity, cryptographic cipher suites, and essential HTTP security headers.

---

## 🚀 Key Features

| Category | Capability | Details |
|---|---|---|
| **Threat Detection** | Deterministic + Machine Learning | 30 stateful heuristic rules + Isolation Forest anomaly baseline scoring |
| **Ingestion Modes** | 4 Capture Engines | Live NIC sniffing (Scapy), built-in attack simulator, PCAP replay, and remote telemetry agent |
| **Interactive SOC UI** | Real-time Observability | Low-latency WebSocket streaming (`/ws`) at 1 Hz with flow visualizers and alert triage |
| **Active Mitigation** | Multi-Platform Firewall Export | 1-click rule generation for Linux `iptables`/`nftables`, Windows Firewall, and Cisco ACLs |
| **Web Security** | WebSec Scanner | Automated TLS certificate validity, cryptographic cipher audit, and HTTP security header grades |
| **Distributed Monitoring**| PC-to-PC Agent Telemetry | Secure token-authenticated client agents for multi-host and lab network topologies |
| **Forensic Export** | SQLite Persistence & Reports | Historical alert persistence with search, filtering, and CSV/JSON export |

---

## ⚙️ How It Works (System Architecture)

NAD operates using a three-tier **"Eyes • Brain • Voice"** pipeline:

```
  ┌────────────────────────────────────────────────────────────────────────┐
  │                           1. EYES (Data Ingestion)                      │
  │   • Live NIC Sniffing (Scapy / raw socket)                            │
  │   • PCAP Packet Replay (streaming at 1x-10x speed)                     │
  │   • Attack Traffic Simulator (20+ attack profiles)                     │
  │   • Distributed Remote Agents (aegis-agent.py via REST)                │
  └───────────────────────────────────┬────────────────────────────────────┘
                                      │ Packets / 5-Tuple Flows
                                      ▼
  ┌────────────────────────────────────────────────────────────────────────┐
  │                           2. BRAIN (Fusion Analysis)                   │
  │   ┌───────────────────────────────────┬────────────────────────────┐   │
  │   │ Signature Engine (30 Rules)       │ ML Engine (Hybrid IF)      │   │
  │   │ • Port Scans (T1046)              │ • 41 flow features extracted│  │
  │   │ • Floods (SYN, UDP, ICMP - T1498) │ • Unsupervised Isolation   │   │
  │   │ • Brute Force (T1110)             │   Forest baseline scoring  │   │
  │   │ • DNS Exfiltration (T1048)        │ • Zero-day anomaly scores  │   │
  │   │ • Web Exploits (SQLi, XSS, Log4j) │   (Threshold ≥ 0.7)        │   │
  │   └───────────────────────────────────┴────────────────────────────┘   │
  │                     Threat Correlation & Scoring                       │
  └───────────────────────────────────┬────────────────────────────────────┘
                                      │ Correlated Security Alerts
                                      ▼
  ┌────────────────────────────────────────────────────────────────────────┐
  │                           3. VOICE (Interface & Action)                │
  │   • React SOC Dashboard (Real-time WebSocket telemetry)                │
  │   • FastAPI REST Endpoints (/docs Swagger UI)                          │
  │   • SQLite Alert Persistence & CSV/JSON Export                         │
  │   • Instant Mitigation Playbooks (iptables, nftables, netsh)           │
  └────────────────────────────────────────────────────────────────────────┘
```

1. **Eyes (Telemetry Ingestion)**: Ingests raw Ethernet frames and IP packets from physical NICs, synthetic traffic generators, PCAP capture replays, or remote agent endpoints, transforming raw packets into structured 5-tuple bidirectional flows (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`).
2. **Brain (Dual-Engine Threat Fusion)**:
   - **Signature Engine**: Tracks connection state and packet frequencies across sliding time windows against 30 behavioral threat definitions mapped to MITRE ATT&CK tactics.
   - **Machine Learning Engine**: Computes 41 statistical features per flow (packet size variance, inter-arrival timing, flag ratios) and evaluates them against an Isolation Forest model to detect novel zero-day anomalies.
   - **Correlation & Scoring**: Merges heuristic alerts and ML anomaly scores into prioritized severity levels (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
3. **Voice (Presentation & Active Response)**: Broadcasts telemetry snapshots via WebSockets every second to the React SOC dashboard, persists incidents to SQLite, and renders actionable defense playbooks including copy-ready firewall syntax.

---

## 📖 Introduction

**Network Anomaly Detection (NAD)** is an enterprise-grade Cyber Attack Monitoring, Telemetry Ingestion, and Security Operations Center (SOC) platform designed for modern campus, enterprise, and laboratory networks.

It features a **Two-Engine Threat Fusion Pipeline**:
1. **Deterministic Heuristic Signature Engine**: Evaluates traffic against **30 stateful behavioral rules** covering Port Scans, SYN/UDP/ICMP Floods, Brute Force, C2 Beaconing, DNS Exfiltration, and Web Exploits (SQLi, XSS, Log4Shell).
2. **Unsupervised Machine Learning Engine**: An ensemble of **Isolation Forest** and statistical scoring models that baseline benign traffic flow patterns and identify unknown or zero-day anomalies without requiring prior attack labels.

---

## ⚙️ How to Set Up This System

### 📋 Prerequisites
- **Operating System**: Linux (Ubuntu 20.04+, Debian, Fedora, Arch) or macOS / Windows WSL2.
- **Python**: Python 3.10, 3.11, or 3.12 (`python3 --version`).
- **Node.js & npm**: Node.js v18+ and npm v9+ (`node -v` & `npm -v`).
- **Permissions**: Root/`sudo` required only for physical raw NIC sniffing (`make live`).

### 📦 Step-by-Step Installation

#### 1. Clone Repository & Install Dependencies
```bash
git clone https://github.com/Project-primero/NADS.git
cd NADS

# Automatically creates Python virtual environment and installs frontend packages:
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

#### 2. Train Machine Learning Baseline
```bash
make train
# Generates baseline detection weights in backend/detection/models/
```

#### 3. Launch Services
```bash
# Terminal 1: Start backend API (Port 8000)
make run

# Terminal 2: Start React SOC Dashboard (Port 5174 or 5173)
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

### Scenario A: Monitoring PC 2 using the Remote Agent

1. **Find PC 1's IP**:
   ```bash
   hostname -I
   # Example: 192.168.1.50
   ```
2. **Start NAD Server on PC 1**:
   ```bash
   AEGIS_HOST=0.0.0.0 make run &
   make run-frontend
   ```
3. **Generate an Agent Token on PC 1**:
   ```bash
   curl -X POST http://127.0.0.1:8000/api/agents/tokens \
     -H "Content-Type: application/json" \
     -d '{"name": "Lab-PC-2", "site": "Computer Lab"}'
   ```
4. **Run Agent on PC 2**:
   - **Linux / macOS**:
     ```bash
     curl -sSL http://192.168.1.50:8000/api/agents/install.sh | bash -s -- <YOUR_TOKEN> "Computer Lab" "Lab-PC-2"
     ```
   - **Windows (PowerShell)**:
     ```powershell
     irm http://192.168.1.50:8000/api/agents/install.ps1 | iex
     ```
5. **Verify on PC 1 Dashboard**: Open `http://localhost:5174` and see PC 2 listed with real-time PPS and OS telemetry.

### Scenario B: Attack Simulation Testing (PC 2 Attacks PC 1)

1. **Start live capture on PC 1**:
   ```bash
   sudo make live IFACE=wlan0
   ```
2. **Launch test probes from PC 2 against PC 1**:
   ```bash
   # Port scan simulation
   nmap -sS -p 1-1000 192.168.1.50

   # SYN flood simulation
   sudo hping3 -S -p 80 --flood 192.168.1.50

   # Web vulnerability simulation
   curl "http://192.168.1.50:8000/api/search?q=' OR 1=1--"
   ```
3. **Observe Detections**: The alerts appear instantly on the SOC dashboard with severity, MITRE ATT&CK code, and firewall mitigation commands.

---

## 📚 Technical Documentation & Resources

For detailed project architecture, API endpoint specifications, and configuration:
- [**Project Information & Architecture**](docs/PROJECT_INFO.md) — Detailed purpose, system overview, key capabilities, and architecture breakdown.
- [**Technical Reference Manual**](docs/REFERENCE.md) — Complete REST/WebSocket API endpoints, `NAD_*`/`AEGIS_*` settings, and detection catalog.
- [**Project Presentation Slides (PDF)**](docs/NAD_Presentation.pdf) — Slide deck covering threat detection, architecture, and value proposition.

---

## 🔒 Security & Authorized Usage

Network Anomaly Detection is engineered for defensive security operations, educational laboratories, and authorized network monitoring. Always adhere to legal and institutional compliance:
- Only capture network packets on hardware, switches, or networks you own or have explicit authorization to monitor.
- Run penetration testing tools only against designated, isolated laboratory target machines.
