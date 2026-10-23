# Network Anomaly Detection (NAD) — System Architecture

The system is a dual-engine cybersecurity platform combining a real-time **Security Operations Center (SOC) Network Anomaly Detection (NAD)** system with an automated **Web Application Security & Continuous Uptime Monitoring Platform (WebSec)**.

---

## 1. Unified Detection Pipeline

All network sources—local interfaces, hardware mirror ports, PCAP replays, the 14-class attack simulator, and distributed remote computer agents—feed into the exact same detection and correlation pipeline:

```
┌────────────────────────────────────────────────────────────────────────┐
│ 1. THE EYES — UNIVERSAL INGESTION LAYER                                │
│    [1. Simulator]  [2. Local NIC]  [3. PCAP Replay]  [4. Switch SPAN]  │
│    [5. Remote Multi-Computer Agents (Windows/Linux)]                   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Normalized Packet Dicts
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 2. PRE-PROCESSING & FILTERING                                          │
│    Asset Inventory Tracker (IP/MAC) ──► Trusted Allowlist Bypass Check │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Non-allowlisted packets
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 3. THE BRAIN — DUAL-ENGINE EVALUATION & CORRELATION                    │
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
                                    │ Correlated Verdict
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 4. THE VOICE — STORAGE, DISPATCH & RESPONSE                            │
│    AlertManager (60s Dedup) ──► SQLite DB + 1s WS Broadcast + REST UI  │
│    Remediation Hints ──► One-Click Safe Firewall Commands (iptables/ufw│
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Core Modules & Responsibilities

| Path | Module | Architectural Role |
|---|---|---|
| `backend/capture/packet_capture.py` | `PacketCapture` | Dynamic capture manager: hosts Scapy sniffer, 14-class simulator, BPF filtering, interface discovery (`get_host_interfaces`), and link test (`test_interface_traffic`). |
| `backend/capture/pcap_replayer.py` | `PcapReplayer` | Streamed replay of `.pcap` / `.pcapng` captures with variable speed controls (*Instant, Real-time, 5x, 10x*). |
| `scripts/aegis-agent.py` | Standalone Agent | Zero-dependency client deployed on external computers. Collects 5-tuple metrics and streams to central NAD server over HTTPS/WSS. |
| `backend/capture/packet_parser.py` | `parse_raw()` | Dissects L2 (Ethernet/ARP), L3 (IPv4/IPv6), L4 (TCP/UDP/ICMP), and L7 (HTTP/DNS/TLS) into flat packet dictionaries. |
| `backend/flow/flow_manager.py` | `FlowManager` | Groups packets into bi-directional conversations keyed by `(ip_low, ip_high, port_low, port_high, proto)`. Enforces 60-second idle expiration. |
| `backend/flow/feature_extractor.py` | `extract_features()` | Computes 41 CIC-IDS style features per flow (packet rates, byte rates, IAT statistics, flag counts, port entropy, payload signatures). |
| `backend/detection/signature_engine.py`| `SignatureEngine` | 30 stateful sliding-window detectors covering Scans, Floods, Brute Force, Web Injections, and C2. |
| `backend/detection/inference.py` | `DetectionEngine` | Evaluates flow vectors against the ML Isolation Forest model, producing normalized 0.00–1.00 anomaly scores. |
| `backend/detection/correlation.py` | `correlate()` | Fuses signature verdicts with ML anomaly confidence to produce unified 0–100 Threat Scores. |
| `backend/database/db.py` | `Database` | SQLite persistence for alerts, website targets, agent tokens, discovered assets, allowlists, and audit logs. |
| `backend/monitor/site_checker.py` | `SiteMonitor` | WebSec engine: automated TLS certificate expiration, security header scoring (CSP, HSTS), and OWASP vulnerability auditing. |
| `backend/api/routes.py` | REST API | REST routes for stats, alerts, connect modes, agents, assets, allowlists, export, and WebSec targets. |
| `backend/api/websocket.py` | WebSocket Engine | Real-time 1-second broadcast loop for dashboards (`/ws`) and authenticated telemetry ingest for remote agents (`/ws/agent`). |

---

## 3. Threat Scoring & Correlation Formula

The platform avoids alert fatigue by fusing fast signature hits with machine learning confidence:

$$\text{Threat Score} = \min\Big(100, \;\text{Base Score} + \text{ML Bonus (10)} + \text{Rate Weight}\Big)$$

1. **Known Attacks**: Signature matches establish an initial base score (Low: 30, Medium: 55, High: 75, Critical: 90).
2. **ML Confirmation**: If the Isolation Forest also flags the flow as statistically abnormal (anomaly score $\ge 0.50$), a **+10 confidence boost** is added.
3. **Pure Anomalies (Zero-Days)**: If an anomalous flow occurs with **no matching signature**, the engine still raises an `ML Anomaly` alert if the score exceeds the threshold (`NAD_ANOMALY_THRESHOLD=0.70`).
4. **Deduplication Window**: Identical alerts for `(attack_type, src_ip, dst_ip)` are deduplicated across a sliding **60-second window** to prevent alert flooding.

---

## 4. Multi-Computer Remote Agent Security

```
┌─────────────────────────────────┐                       ┌─────────────────────────────────┐
│     REMOTE COMPUTER / LAB       │                       │       CENTRAL NAD SERVER        │
│  (Windows 10 / Ubuntu Server)   │                       │       (FastAPI + SQLite DB)     │
└────────────────┬────────────────┘                       └────────────────┬────────────────┘
                 │                                                         │
                 │ 1. POST /api/agents/verify (Bearer Token)               │
                 ├────────────────────────────────────────────────────────►│ Verify SHA-256 Token
                 │                                                         │
                 │ 2. Handshake Ack (agent_id, site, status: ONLINE)       │
                 │◄────────────────────────────────────────────────────────┤
                 │                                                         │
                 │ 3. POST /api/agents/ingest OR WS /ws/agent              │
                 ├────────────────────────────────────────────────────────►│ Ingest flow metadata
                 │    (Batch of 5-tuples: IPs, ports, flags, sizes)        │ Pipeline: _on_packet()
                 │    (NO raw payload text transmitted — strict privacy)   │
```

- **Cryptographic Tokens**: Random 48-character tokens (`agt_...`) are generated. The central server stores only salted SHA-256 hashes.
- **Privacy-Safe Ingestion**: The agent inspects local packet headers and transmits only flow metadata (IPs, ports, flags, packet sizes). Internal application payloads, documents, and passwords are never transmitted.
- **Auto-Reconnect**: Agents use exponential backoff (2s, 4s, 8s, up to 30s) to handle network interruptions or server reboots.

---

## 5. Database Schema (`data/alerts.db`)

The system manages an embedded SQLite database using SQLAlchemy models:

1. **`alerts`**: `id`, `timestamp`, `attack_type`, `severity`, `description`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `engine`, `anomaly_score`.
2. **`agents`**: `id`, `agent_id`, `name`, `site`, `token_hash`, `ip`, `hostname`, `os`, `status`, `pps`, `total_packets`, `last_seen`, `created_at`.
3. **`assets`**: `id`, `ip`, `mac`, `hostname`, `owner`, `department`, `device_type`, `first_seen`, `last_seen`, `packet_count`.
4. **`allowlist`**: `id`, `cidr_or_ip`, `port`, `description`, `created_at`.
5. **`pcap_jobs`**: `id`, `filename`, `total_packets`, `processed_packets`, `alerts_count`, `status`, `speed`, `error`, `started_at`, `completed_at`.
6. **`audit_logs`**: `id`, `timestamp`, `action`, `user`, `details`.
7. **`sites`** & **`site_checks`**: WebSec target inventory, latency, TLS expiry, cipher suites, security scores, and vulnerability findings.

---

## 6. Frontend SOC Console Architecture

The dashboard is built with **React 18**, **TypeScript**, and **Vite**:
- **Platform Router**: Toggles seamlessly between the **NAD SOC Console** and the **WebSec Security Platform**.
- **Live WebSocket Hook (`useWebSocket`)**: Maintains a persistent connection to `ws://HOST:8000/ws` with automatic reconnection.
- **Connect & Ingest Page**: Interactive 5-card wizard for starting simulations, selecting local NICs, replaying PCAPs, viewing switch SPAN copy-paste syntax, and generating agent tokens.
- **Connected Computers Page**: Fleet view displaying all connected lab PCs and servers with real-time throughput, site tags, and token revocation.
- **Assets & Allowlist Page**: Auto-discovered network assets with editable labels and allowlist rule management.
