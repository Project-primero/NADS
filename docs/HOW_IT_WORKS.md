# How It Works & How to Test — one-page guide

> Deep dives: [ARCHITECTURE](ARCHITECTURE.md) · [DETECTION_CATALOG](DETECTION_CATALOG.md) ·
> [API](API.md) · [TESTING](TESTING.md) · [CONFIGURATION](CONFIGURATION.md) · [DEPLOYMENT](DEPLOYMENT.md)

## Part 1 — How it works (6 stages)

Every packet travels this pipeline (`backend/main.py::_on_packet`):

```
1. CAPTURE   PacketCapture grabs a packet (live Scapy sniff, or 14-class simulator)
2. TRACK     FlowManager files it into a 5-tuple flow (src/dst IP+port+proto)
3. SIGNATURE  SignatureEngine checks 30 sliding-window rules (scan? flood? brute force? SQLi? …)
4. ML        Every 10th packet of a flow → 41 features → HybridModel anomaly score
5. FUSE      correlate(): signature wins; ML confirmation adds +10; pure-ML → Anomaly alert
6. ALERT     AlertManager dedups (60s), stores in SQLite, pushes via WebSocket + REST
```

### Walked example (run it yourself — §Test 4)

10× `SSH Failed password` packets → `9.9.9.9 → 192.168.1.10:22`:

| Stage | Result |
|---|---|
| Flow | 10 packets in one flow, `failed_login=10` feature |
| Signature | `SSH Brute Force`, HIGH, confidence 0.9 |
| ML | score 0.5663 → **not anomaly** (too few packets to look weird statistically) |
| Fusion | signature wins → threat score **79**, engine `signature`, MITRE T1110 |
| Alert | stored + broadcast with remediation *"Block src IP, enforce key-auth + fail2ban"* |

Lesson: neither engine alone is enough — signatures catch known patterns fast,
ML catches zero-days with no signature. Fusion covers both.

### Where to read each stage

| Stage | File | Key symbol |
|---|---|---|
| 1 | `backend/capture/packet_capture.py` | `PacketCapture._simulate_loop` / `_live_loop` |
| 2 | `backend/flow/flow_manager.py` | `FlowManager.ingest` |
| 3 | `backend/detection/signature_engine.py` | `SignatureEngine.check_packet`, `CATALOG` |
| 4 | `backend/detection/inference.py`, `models/hybrid_model.py` | `DetectionEngine.analyze_flow` |
| 5 | `backend/detection/correlation.py` | `correlate()` |
| 6 | `backend/alerts/alert_manager.py`, `backend/api/` | `AlertManager.push`, WS broadcast |

## Part 2 — How to test (5 levels, easiest first)

### Level 1 — Look at the dashboard (1 min)

`http://localhost:5173` → LIVE badge green? Throughput chart moving?
Type `10.0.0.99` in alert search, set severity `CRITICAL`. Open Threat Intel tab.

### Level 2 — API spot-checks (2 min)

```bash
curl -s localhost:8000/api/stats | python3 -m json.tool
curl -s "localhost:8000/api/alerts?limit=3"
curl -s localhost:8000/api/catalog | python3 -c \
  "import json,sys; print([d['attack'] for d in json.load(sys.stdin)['detectors']])"
```

### Level 3 — Automated suite (30 s)

```bash
make test          # 6 pytest tests (needs backend on :8000)
make smoke         # endpoint check without pytest
```

### Level 4 — Trace one packet yourself (5 min, no root)

```bash
/tmp/nadvenv/bin/python
>>> from backend.capture.packet_capture import PacketCapture
>>> from backend.flow.flow_manager import FlowManager
>>> from backend.flow.feature_extractor import extract_features
>>> from backend.detection.signature_engine import SignatureEngine
>>> from backend.detection.inference import DetectionEngine
>>> from backend.detection.correlation import correlate
>>>
>>> fm, sig, ml = FlowManager(), SignatureEngine(port_scan_ports=3), DetectionEngine()
>>> pkt = {"src_ip":"9.9.9.9","dst_ip":"192.168.1.10","src_port":45678,
...        "dst_port":22,"protocol":"TCP","length":90,"flags":"PA",
...        "payload_len":40,"dns_query":"","http_payload":"SSH Failed password"}
>>> for _ in range(10):
...     flow = fm.ingest(dict(pkt)); hits = sig.check_packet(dict(pkt))
>>> print(extract_features(flow)["failed_login"])  # → 10
>>> print([(h["attack_type"], h["severity"]) for h in hits])  # → SSH Brute Force
>>> print(correlate(hits, ml.analyze_flow(flow))["threat_score"])  # → ~79
```

Swap `http_payload`/`dns_query`/`flags` to fire other detectors —
see [DETECTION_CATALOG](DETECTION_CATALOG.md) for trigger values.

### Level 5 — Real world (root + isolated lab)

```bash
make live IFACE=eth0   # victim: live capture (your own network only)
```

Attack **your own victim VM only**: `nmap -sS`, `hping3 -S --flood`,
`hydra ssh://…`, SQLi via curl. Each class must appear in attack-mix in ~1s.
For ML validation: `make train DATASET=data/cicids2017.csv` → check
precision/recall/F1. Full protocol in [TESTING](TESTING.md).
