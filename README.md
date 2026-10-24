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

## 📚 Technical Documentation Reference

For full API endpoint specifications, environment configurations, and the 30-rule detection catalog:
- [**Technical Reference Manual**](docs/REFERENCE.md) — Complete REST/WebSocket API endpoints, `NAD_*`/`AEGIS_*` settings, and detection catalog.

---

## 🔒 Security & Authorized Usage

Network Anomaly Detection is engineered for defensive security operations, educational laboratories, and authorized network monitoring. Always adhere to legal and institutional compliance:
- Only capture network packets on hardware, switches, or networks you own or have explicit authorization to monitor.
- Run penetration testing tools only against designated, isolated laboratory target machines.
