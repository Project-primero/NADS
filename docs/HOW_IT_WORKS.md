# Network Anomaly Detection (NAD) — How It Works & Validation Guide

A comprehensive architectural walkthrough of the Network Anomaly Detection (NAD) and Telemetry system.

---

## Part 1: The Inspection Pipeline

Every packet or telemetry event processed by the engine traverses a streamlined 6-stage pipeline orchestrated by [`backend/main.py`](file:///home/dereje/project/NAD/backend/main.py):

```
┌────────────────────────────────────────────────────────────────────────┐
│                        1. UNIVERSAL INGESTION                          │
│  [Simulator]  [Host NIC / SPAN]  [PCAP Replay]  [Remote PC Agents]     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Normalized Packet Dict / Flow
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        2. FLOW NORMALIZATION                           │
│  FlowManager groups packets into 5-tuple conversations                 │
│  (src_ip, dst_ip, src_port, dst_port, protocol). Auto-expires idle.   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                  ┌─────────────────┴─────────────────┐
                  ▼                                   ▼
┌───────────────────────────────────┐ ┌──────────────────────────────────┐
│       3. SIGNATURE ENGINE         │ │       4. ML ANOMALY ENGINE       │
│  30 sliding-window heuristic rules│ │  Extracts 41 CIC-IDS features.   │
│  (Port scans, SYN floods, Log4Shell│ │  HybridModel (IsolationForest +  │
│  SQLi, DNS tunneling, C2 beacons) │ │  Statistical z-score)            │
└─────────────────┬─────────────────┘ └──────────────────┬───────────────┘
                  │                                      │
                  └─────────────────┬────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                  5. FUSION, ALLOWLIST & SCORING                        │
│  - Allowlist Check: Suppresses alerts if src_ip is whitelisted.        │
│  - Threat Fusion: Signature confidence + ML anomaly confirmation.      │
│  - Threat Score Calculation: 0 to 100 severity metric.                 │
│  - MITRE ATT&CK Technique Mapping + Remediation Hint generation.       │
└───────────────────────────────────┬────────────────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   6. STORAGE, DISCOVERY & BROADCAST                    │
│  - Asset Discovery: Auto-indexes IP, MAC, hostname, OS in inventory.   │
│  - Alert Deduplication: 60s sliding window suppresses alert storms.    │
│  - SQLite Persistence: Saved to alerts.db for audit & forensic export. │
│  - Real-time Broadcast: Pushed to React Dashboard via WebSocket (/ws). │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Detailed Pipeline Stages

### Stage 1: Universal Ingestion
Traffic enters through one of five selectable ingestion engines:
1. **Attack Simulator**: Generates realistic multi-protocol benign traffic alongside 14 distinct attack classes with adjustable intensity (*Low, Medium, High, Stress*).
2. **Host NIC Capture**: Real-time packet capture on physical host adapters using Scapy / `af_packet` with optional BPF filter expressions.
3. **Switch SPAN / Mirroring**: Passive network monitoring on dedicated mirror ports, capturing department-wide switch traffic.
4. **PCAP / PCAPNG Replay**: Streaming replay of captured traffic files with instant or speed-scaled pacing (*1x, 5x, 10x*).
5. **Distributed Remote Agents**: Lightweight endpoint clients on remote Windows and Linux workstations streaming privacy-safe packet headers and network telemetry over HTTPS/WSS.

### Stage 2: 5-Tuple Flow Normalization
The [`FlowManager`](file:///home/dereje/project/NAD/backend/flow/flow_manager.py#L11-L68) tracks bi-directional conversations keyed by `(src_ip, dst_ip, src_port, dst_port, proto)`:
- Computes packet timing, jitter, byte counts, TCP flag distributions, and payload ratios.
- Automatically purges inactive flows after `NAD_FLOW_TIMEOUT` (default: 60s).

### Stage 3: 30-Rule Signature Engine
The [`SignatureEngine`](file:///home/dereje/project/NAD/backend/detection/signature_engine.py#L48-L230) checks packets against 30 stateful and payload-inspection detectors:
- Sliding-window frequency checks (Port scans, SYN/UDP floods, Ping sweeps, Password spraying).
- Layer 7 payload pattern matching (SQL injection, XSS, Log4Shell `${jndi:`, Path traversal, Command injection).
- Protocol abuse detection (DNS tunneling lengths, UDP amplification reflection, SMB lateral bursts).

### Stage 4: ML Anomaly Inference
For every 10th packet in a conversation, the [`DetectionEngine`](file:///home/dereje/project/NAD/backend/detection/inference.py#L11-L47) extracts a 41-dimensional feature vector matching CIC-IDS standards:
- Analyzed by [`HybridModel`](file:///home/dereje/project/NAD/backend/detection/models/hybrid_model.py#L8-L75) (unsupervised Isolation Forest + sequence statistical baseline).
- Emits continuous anomaly scores between `0.0` and `1.0`.

### Stage 5: Threat Correlation & Allowlist Filtering
The [`correlate()`](file:///home/dereje/project/NAD/backend/detection/correlation.py#L29-L97) engine evaluates signature hits alongside ML anomaly scores:
- **Allowlist Filter**: If source IP falls inside an allowlisted CIDR or IP range, the alert is suppressed.
- **Fusion Formula**:
  $$\text{Base Score} = \text{Severity Weight} \times \text{Signature Confidence}$$
  $$\text{Score} = \min(100, \text{Base Score} + (\text{Anomaly Score} \times 20))$$
- Maps the threat to MITRE ATT&CK techniques (e.g. `T1046`, `T1110`, `T1190`, `T1498`).
- Generates targeted mitigation instructions.

### Stage 6: Asset Discovery & Real-Time Broadcast
- **Auto-Discovery**: Any previously unseen IP or MAC address is logged in the network asset inventory.
- **Deduplication**: [`AlertManager`](file:///home/dereje/project/NAD/backend/alerts/alert_manager.py#L12-L73) prevents alert fatigue by throttling identical `(attack_type, src_ip, dst_ip)` alerts within 60 seconds.
- **Live Dispatch**: Alert and traffic snapshot payloads are pushed over `/ws` to connected analyst dashboards within 100 milliseconds.

---

## Part 2: How to Test & Validate the System

### Level 1: Web Dashboard Inspection (1 Minute)
1. Open `http://localhost:5174` in a browser.
2. Confirm the green **● LIVE** or **● SIMULATING** badge in the top bar.
3. Observe live packets-per-second (PPS) and active flows updating in the **Traffic Overview** chart.
4. Check the **Recent Alerts** table and verify that severity badges, MITRE codes, and remediation instructions are displayed.

### Level 2: API Sanity Check (2 Minutes)
Query the running backend to verify JSON response structure:
```bash
# General telemetry statistics
curl -s http://127.0.0.1:8000/api/stats | python3 -m json.tool

# Active connection status
curl -s http://127.0.0.1:8000/api/connect/status | python3 -m json.tool

# Latest security alerts
curl -s "http://127.0.0.1:8000/api/alerts?limit=5" | python3 -m json.tool
```

### Level 3: Automated Test Suite (30 Seconds)
Run the automated unit and integration tests:
```bash
# Verify Connect and Multi-Computer Agent logic
python3 -m unittest tests/test_connect.py -v

# Run smoke test suite against running backend
pytest tests/test_smoke.py -v
```

### Level 4: Trace a Specific Attack Packet via Python REPL
Simulate an attack packet manually in the Python interactive shell:
```python
from backend.flow.flow_manager import FlowManager
from backend.detection.signature_engine import SignatureEngine
from backend.detection.correlation import correlate

fm = FlowManager()
sig = SignatureEngine(port_scan_ports=3)

# Craft 4 SYN packets to different ports (Port Scan)
hits = []
for port in [80, 443, 22, 8080]:
    pkt = {
        "src_ip": "10.0.0.99",
        "dst_ip": "192.168.1.10",
        "src_port": 54321,
        "dst_port": port,
        "protocol": "TCP",
        "length": 60,
        "flags": "S",
        "payload_len": 0,
        "dns_query": "",
        "http_payload": ""
    }
    fm.ingest(pkt)
    hits += sig.check_packet(pkt)

print("Detected Attacks:", [h["attack_type"] for h in hits])
verdict = correlate(hits, None)
print("Correlated Threat Score:", verdict["threat_score"])
print("MITRE ATT&CK Code:", verdict["mitre"])
```

### Level 5: Real-World Multi-Computer Lab Testing
1. Deploy an agent to a Windows or Linux computer in your lab using the one-line installer from the **Connected Computers** tab.
2. From the remote computer, run an authorized penetration test tool (e.g. `nmap -sS <TARGET_IP>`).
3. Verify that the agent captures the outbound burst, transmits the telemetry to the central server, and triggers a `Port Scan` alert within 1 second.
