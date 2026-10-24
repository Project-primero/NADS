# Network Anomaly Detection (NAD) — Technical Reference Guide

A condensed reference for the REST/WebSocket API, environment configuration, detection catalog, and operational targets.

---

## 1. REST API & WebSocket Reference

Base URL: `http://localhost:8000`. Interactive docs: `/docs` (Swagger) and `/redoc`.

### Core & Analytics Endpoints
| Endpoint | Method | Description |
|---|---|---|
| `/` | `GET` | Health check, active capture mode, and source metadata |
| `/api/health` | `GET` | Service liveness probe (`{"status": "ok"}`) |
| `/api/system/health` | `GET` | Hardware telemetry (PPS, total packets, dropped packets, RAM MB) |
| `/api/stats` | `GET` | Aggregate stats: total packets, current PPS, active flows, alert counts |
| `/api/catalog` | `GET` | Full catalog of 30 signature rules with MITRE tactics & remediation |
| `/api/alerts` | `GET` | Recent in-memory alerts (`?limit=50`) |
| `/api/alerts/history` | `GET` | Historical alerts persisted in SQLite (`?limit=100`) |
| `/api/alerts/export` | `GET` | Download alerts as CSV or JSON (`?format=csv` / `?format=json`) |
| `/api/flows` | `GET` | Tracked 5-tuple active flows (`src_ip`, `dst_ip`, `ports`, `protocol`) |
| `/api/analytics/traffic` | `GET` | Throughput history series, protocol distribution, attack mix |
| `/api/analytics/top-talkers` | `GET` | Top IP talkers ranked by volume (`?limit=10`) |
| `/api/firewall/rule/{ip}` | `GET` | Copy-paste firewall rules (`iptables`, `nftables`, `netsh`, `cisco`) |

### Ingestion & Connect
| Endpoint | Method | Description |
|---|---|---|
| `/api/connect/interfaces` | `GET` | Enumerate host NICs (name, IP, MAC, carrier status, packet counts) |
| `/api/connect/status` | `GET` | Active capture mode, interface, PPS, baseline mode |
| `/api/connect/start` | `POST` | Switch capture mode dynamically (`simulate`, `live`, `pcap`, `agent`) |
| `/api/connect/stop` | `POST` | Stop active capture engine |
| `/api/connect/test` | `POST` | Run 10-second sniffer traffic verification check |
| `/api/pcap/upload` | `POST` | Upload `.pcap`/`.pcapng` for streaming replay (`?speed=instant\|1x\|5x\|10x`) |
| `/api/pcap/status/{id}` | `GET` | Check PCAP replay progress and alerts triggered |

### Agents, Assets & Allowlist
| Endpoint | Method | Description |
|---|---|---|
| `/api/agents` | `GET` | List connected remote computer agents, sites, PPS, and status |
| `/api/agents/tokens` | `POST` | Generate authenticated agent token (`{"name": "...", "site": "..."}`) |
| `/api/agents/verify` | `POST` | Remote agent authentication handshake |
| `/api/agents/ingest` | `POST` | Batch packet flow telemetry ingest from remote client |
| `/api/agents/{id}` | `DELETE`| Revoke remote agent access |
| `/api/agents/install.sh` | `GET` | Dynamic Bash installation script for Linux / macOS |
| `/api/agents/install.ps1`| `GET` | Dynamic PowerShell installation script for Windows |
| `/api/assets` | `GET` | Auto-discovered list of network IP/MAC devices |
| `/api/assets/{ip}` | `PUT` | Update asset metadata (hostname, owner, department, type) |
| `/api/allowlist` | `GET` | List trusted CIDRs / IPs exempt from alerting |
| `/api/allowlist` | `POST` | Add trusted CIDR/IP (`{"cidr_or_ip": "...", "port": 0}`) |
| `/api/allowlist/{id}` | `DELETE`| Delete allowlist entry |

### WebSec Platform
| Endpoint | Method | Description |
|---|---|---|
| `/api/sites` | `GET` | List monitored websites with security scores & uptime |
| `/api/sites` | `POST` | Register website for periodic TLS and header audits |
| `/api/sites/{id}` | `DELETE`| Remove website from monitoring |
| `/api/sites/{id}/scan-now` | `POST` | Trigger immediate on-demand security scan |
| `/api/sites/{id}/report` | `GET` | Download executive JSON vulnerability report |

### WebSocket Telemetry (`/ws`)
- **URL**: `ws://HOST:8000/ws`
- Pushes complete telemetry snapshot upon connect and broadcasts updates every 1.0 second:
  - `metrics`: PPS, total packets, active flows, drop counts
  - `alerts`: latest triggered security alerts
  - `top_talkers`: top IP bandwidth consumers
  - `protocol_distribution`: TCP, UDP, ICMP, DNS, HTTP percentage shares
  - `active_attacks`: active threat categories

---

## 2. Configuration Reference

Settings can be set via `.env` or system environment variables (`backend/config.py`).

| Variable | Default | Description |
|---|---|---|
| `AEGIS_MODE` / `NAD_CAPTURE_MODE` | `simulate` | Ingestion mode: `simulate`, `live`, `pcap`, `agent` |
| `AEGIS_IFACE` / `NAD_INTERFACE` | `lo` | Network interface for physical live sniffing (`eth0`, `wlan0`) |
| `AEGIS_BPF_FILTER` | `""` | Berkeley Packet Filter expression (e.g. `tcp port 80 or udp`) |
| `AEGIS_LEARNING_MODE` | `false` | Auto-allowlists observed traffic to build baseline |
| `NAD_FLOW_TIMEOUT` | `60` | Inactivity seconds before 5-tuple flow is expired |
| `NAD_DB_PATH` | `data/alerts.db` | Filepath for SQLite persistence |
| `NAD_RETENTION_DAYS` | `30` | Auto-prune age for stored alerts and telemetry |
| `NAD_MODEL_TYPE` | `hybrid` | ML engine model: `hybrid`, `isolation_forest`, `lstm`, `transformer` |
| `NAD_ANOMALY_THRESHOLD` | `0.7` | Minimum ML score (0.0–1.0) to qualify as anomalous |
| `NAD_WS_BROADCAST_INTERVAL`| `1.0` | Broadcast cadence (seconds) for `/ws` |
| `NAD_PORT_SCAN_PORTS` | `15` | Distinct dst ports probed per src / 60s window |
| `NAD_SWEEP_DSTS` | `10` | Distinct dst hosts targeted by ICMP / 60s window |
| `NAD_HORIZ_DSTS` | `10` | Distinct dst hosts on same port / 60s window |
| `NAD_SYN_FLOOD_COUNT` | `50` | SYN-without-ACK count / 10s window |
| `NAD_UDP_FLOOD_COUNT` | `200` | UDP packets per destination / 10s window |
| `NAD_ICMP_FLOOD_COUNT` | `100` | ICMP echo requests per destination / 10s window |
| `NAD_DDOS_PPS` | `1000` | Global aggregate packets-per-second threshold |
| `NAD_SLOWLORIS_COUNT` | `50` | Partial HTTP requests / 60s window |
| `NAD_AMP_COUNT` | `50` | UDP reflection packets (NTP/SSDP/Memcached) / 10s |
| `NAD_BRUTE_FORCE_FAILS` | `10` | Failed logins (SSH, FTP, RDP, Telnet, HTTP) / 300s |
| `NAD_SPRAY_DSTS` | `5` | Failed logins distributed across distinct hosts / 300s |
| `NAD_SMB_COUNT` | `20` | Port 445 connection burst / 60s window |
| `NAD_DNS_TUNNEL_LEN` | `53` | Subdomain character length for DNS tunneling |
| `NAD_EXFIL_BYTES` | `10000000` | 10 MB payload transfer with >80% one-sided volume |

---

## 3. Detection Catalog (30 Heuristic Rules + ML)

Defined in `backend/detection/signature_engine.py`:

| Category | Attack Name | Default Threshold | MITRE ATT&CK |
|---|---|---|---|
| **Reconnaissance** | Port Scan | 15 distinct ports / 60s | T1046 |
| | Null/Xmas Scan | TCP flags empty (`0`) or `F+P+U` | T1046 |
| | Ping Sweep | ICMP across 10 distinct hosts / 60s | T1595 |
| | Horizontal Scan | Same port probed across 10 hosts / 60s | T1046 |
| **Floods & DoS** | SYN Flood | 50 SYN-no-ACK / 10s | T1498 |
| | UDP Flood | 200 UDP packets / 10s | T1498 |
| | UDP Amplification | 50 reflection pkts (NTP/SSDP/Memcached) / 10s | T1498 |
| | Slowloris | 50 partial HTTP requests / 60s | T1498 |
| | ICMP Flood | 100 ICMP packets / 10s | T1498 |
| | Volumetric DDoS | 1000 aggregate PPS | T1498 |
| **Brute Force** | SSH Brute Force | 10 auth failures on Port 22 / 300s | T1110 |
| | FTP Brute Force | 10 auth failures on Port 21 / 300s | T1110 |
| | RDP Brute Force | 10 auth failures on Port 3389 / 300s | T1110 |
| | Telnet Brute Force| 10 auth failures on Port 23 / 300s | T1110 |
| | HTTP Brute Force | 10 auth failures on Port 80/443/8080 / 300s | T1110 |
| | Password Spraying | Auth failures across 5 distinct targets / 300s | T1110 |
| **DNS & Exfil** | DNS Tunneling | Subdomain length > 53 characters | T1071 |
| | DNS Exfiltration | Subdomain length > 106 characters | T1048 |
| | Bulk Data Exfil | Flow bytes > 10 MB (>80% egress) | T1041 |
| **C2 & Spoofing** | ARP Spoofing | ≥30 ARP replies / 5s | T1557 |
| | Malware C2 | DNS query matches known C2 domain list | T1071 |
| | C2 Beaconing | ≥20 periodic egress pkts (jitter < 5s) | T1071 |
| | SMB Lateral Move | ≥20 connections to Port 445 / 60s | T1021 |
| | Cryptomining | Stratum / mining pool signature strings | T1496 |
| **Web Exploits** | SQL Injection | SQL keywords (`union select`, `' OR 1=1--`, etc.) | T1190 |
| | XSS Attempt | Script tags, onerror handlers, DOM cookies | T1189 |
| | Path Traversal | Directory traversal (`../`, `/etc/passwd`) | T1083 |
| | Command Injection | Shell metacharacters (`;cat`, `\|whoami`, `$()`) | T1190 |
| | Log4Shell | JNDI exploit strings (`${jndi:`) | T1190 |
| | SSRF Attempt | Cloud metadata endpoints (`169.254.169.254`) | T1190 |
| **ML Engine** | Anomaly Detection | Isolation Forest + statistical scoring (score ≥ 0.7) | Defense-in-depth |

---

## 4. Operational Commands Cheatsheet

```bash
# Setup
make setup            # Install backend venv and frontend packages
make train            # Train baseline machine learning model weights

# Execution
make run              # Start backend API on http://localhost:8000
make run-frontend     # Start React SOC Dashboard on http://localhost:5174
make live IFACE=eth0  # Sniff raw physical NIC packets (requires sudo/root)

# Testing & Quality
pytest tests/         # Run automated unit and smoke test suite
make test             # Run test suite via Makefile
```
