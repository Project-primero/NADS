# 🛡️ Network Anomaly Detection (NAD) — Enterprise Telemetry & Monitoring Platform

## Network Anomaly Detection Dashboard

Real-time network monitoring and threat detection.

<img width="1920" height="1080" alt="Screenshot From 2026-10-23 19-17-24" src="https://github.com/user-attachments/assets/9ecab80a-bb75-419a-98c9-288e2b516743" />

[![Backend](https://img.shields.io/badge/Backend-FastAPI-009688)](file:///home/dereje/project/NAD/backend/main.py)
[![ML Engine](https://img.shields.io/badge/ML-IsolationForest%20%2B%20Statistical-orange)](file:///home/dereje/project/NAD/backend/detection/models/hybrid_model.py)
[![UI](https://img.shields.io/badge/UI-React%2018%20%2B%20Tailwind-61dafb)](file:///home/dereje/project/NAD/frontend/src/components/Dashboard.tsx)
[![Tests](https://img.shields.io/badge/Tests-Passing-brightgreen)](file:///home/dereje/project/NAD/tests/test_connect.py)
[![License](https://img.shields.io/badge/License-MIT-blue)](LICENSE)

**Network Anomaly Detection (NAD)** is a high-performance Telemetry Ingestion, Cyber Attack Monitoring, and Security Operations Center (SOC) platform. It provides sub-second visibility into network traffic by unifying **30 stateful heuristic signature detectors** with **unsupervised machine learning anomaly inference**.

Every detected threat is enriched with an actionable **0–100 Threat Score**, an official **MITRE ATT&CK technique mapping**, and step-by-step remediation instructions.

---

## ⚡ Quickstart

### 1. Launch with Local Environment
```bash
# Install Python virtualenv and frontend dependencies
make setup

# Train baseline ML detection weights
make train

# Start backend API server (Port 8000)
make run &

# Start React SOC Dashboard (Port 5174)
make run-frontend
```

- **SOC Web Dashboard**: `http://localhost:5174` (or `5173`)
- **Interactive REST API**: `http://127.0.0.1:8000/docs`

### 2. Launch with Docker Compose (Host Networking)
```bash
docker-compose up -d
```

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

## 👥 Team Members

| # | Full Name | CTC ID |
|:---:|---|:---:|
| 1 | **Dereje Tesfaye** | `CTC-2483-26` |
| 2 | **Natnael Mamaru** | `CTC-1449-26` |
| 3 | **Esmael Shikur** | `CTC-6394-26` |
| 4 | **Yerosan Kena** | `CTC-2859-26` |
| 5 | **Eyosias Dawit** | `CTC-7812-26` |
| 6 | **Bona Tenu** | `CTC-1793-26` |

---

## 🔒 Security & Authorized Usage

Network Anomaly Detection is engineered for defensive security operations, educational laboratories, and authorized network monitoring. Always adhere to legal and institutional compliance:
- Only capture network packets on hardware, switches, or networks you own or have explicit authorization to monitor.
- Run penetration testing tools only against designated, isolated laboratory target machines.
