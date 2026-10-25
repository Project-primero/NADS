# 🛡️ Network Anomaly Detection (NAD) — Project Information & Architecture

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

### 1. Ingestion & Capture Engine ("Eyes")
- **Live Physical Interface Capture**: Real-time packet sniffing using raw sockets and Scapy across any network interface (`eth0`, `wlan0`, loopback `lo`).
- **Traffic Simulator**: Built-in engine simulating benign traffic and 20+ real-world cyberattack patterns for offline training, demonstrations, and stress testing.
- **PCAP / PCAPNG Replay Engine**: Upload and stream historical network capture files at variable replay speeds (`instant`, `1x`, `5x`, `10x`).
- **Remote Telemetry Agent**: Distributed Python client (`aegis-agent.py`) deployable on endpoints with dynamic 1-line installation scripts (`install.sh` for Linux/macOS, `install.ps1` for Windows).

### 2. Dual-Engine Threat Fusion ("Brain")
- **Deterministic Heuristic Signature Engine**: Evaluates stateful behavioral patterns against **30 documented detection rules** mapped to MITRE ATT&CK tactics (Port Scans, SYN/UDP/ICMP Floods, Brute Force attacks across SSH/FTP/RDP/HTTP, DNS Tunneling/Exfiltration, C2 Beaconing, ARP Spoofing, SQLi, XSS, Path Traversal, Log4Shell, and SSRF).
- **Unsupervised Machine Learning Engine**: An ensemble of **Isolation Forest** and statistical anomaly models trained on 41 flow features (packet size variance, inter-arrival timing, TCP flag ratios, bidirectional volume) to flag zero-day threats without pre-labeled data.
- **Correlated Scoring & Triage**: Merges signature triggers and ML anomaly scores into standardized severity tiers (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) with MITRE ATT&CK technique IDs.

### 3. Real-Time SOC Dashboard ("Voice")
- **Low-Latency Streaming Telemetry**: Broadcasts live flow updates and metrics over WebSockets (`/ws`) at 1-second intervals.
- **Interactive SOC Visualizations**: Live packets-per-second (PPS) radial gauges, active 5-tuple flow tables, top IP bandwidth talkers, protocol breakdown charts, and real-time alert logs.
- **Firewall Rule Generator**: Generates one-click blocking commands for detected threat IPs formatted for Linux `iptables`, `nftables`, Windows `netsh`, and Cisco IOS ACLs.
- **Forensic Alert Persistence**: SQLite backend (`data/alerts.db`) storing historical alerts with multi-column filtering, search, and CSV/JSON export capabilities.

### 4. Website Security & Vulnerability Auditing (WebSec)
- **Automated TLS/SSL Inspections**: Real-time evaluation of certificate expiration dates, issuing authorities, and cryptographic cipher safety.
- **Security Header Grading**: Validates presence and configuration of `Strict-Transport-Security` (HSTS), `Content-Security-Policy` (CSP), `X-Frame-Options`, `X-Content-Type-Options`, and `Referrer-Policy`.
- **Latency & Uptime Tracking**: Continuous availability checks and executive summary JSON vulnerability report generation.

---

## ⚙️ How It Works

NAD employs a structured three-stage pipeline: **Eyes → Brain → Voice**.

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

### Stage 1: Telemetry Capture & Flow Normalization (Eyes)
- Raw network frames are captured from selected inputs (live NIC, PCAP file, or remote agents).
- Packet headers (IP, TCP, UDP, ICMP, DNS, HTTP) are parsed and aggregated into bidirectional **5-tuple flows** (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`).
- Inactive flows are expired and cleaned automatically using configurable sliding time windows.

### Stage 2: Dual-Engine Threat Fusion (Brain)
- **Heuristic Path**: Each flow and packet is evaluated against 30 stateful signatures. Packet burst rates, port traversal counts, login failure counts, and payload signatures are checked against threshold policies.
- **Machine Learning Path**: Each flow is vectorized into 41 numerical features capturing flow duration, packet length statistics, inter-arrival time distributions, and flag ratios. An unsupervised Isolation Forest assigns an anomaly score (0.0 to 1.0).
- **Correlation**: If a signature fires OR if the ML anomaly score exceeds the anomaly threshold (default 0.7), an enriched alert event is generated containing timestamp, attack taxonomy, MITRE ATT&CK mapping, severity, and flow telemetry.

### Stage 3: Operational Presentation & Mitigation (Voice)
- Alerts and live metrics (PPS, active flows, packet drop counts, top talkers) are broadcast to the React dashboard over WebSocket (`/ws`) every 1.0 second.
- The SOC interface presents actionable cards allowing operators to inspect payload details, examine packet flows, and copy targeted firewall rules to immediately drop malicious traffic.
- Historical alert data is persisted in SQLite with retention policies and export support.

---

## 📚 Project Documentation & Media Assets

- 🎥 **Video Presentation**: [Group Presentation Video (1080p)](Group%20presentation%20video%201080p.mp4)
- 📄 **Project Presentation Slides**: [NAD_Presentation.pdf](NAD_Presentation.pdf)
- 📖 **Technical Reference Manual**: [REFERENCE.md](REFERENCE.md)
