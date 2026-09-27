# Testing Guide

## 1. Automated smoke tests (fastest)

```bash
make test   # or: /tmp/nadvenv/bin/python -m pytest tests/ -v
```

6 tests: health, stats shape, alert intel fields (MITRE/remediation/score),
catalog coverage (8 key detectors), analytics endpoints, signature-engine unit
(port scan + SQLi + correlation). Requires the backend running on :8000
(except the unit test).

One-shot endpoint check without pytest: `make smoke` (→ `scripts/smoke.sh`).

## 2. Manual dashboard + API testing

- Dashboard `http://localhost:5173`: LIVE badge, moving throughput chart,
  alert search (`10.0.0.99`) + severity filter, tabs Overview/Network/Threat Intel.
- `curl localhost:8000/api/stats`, `/api/alerts?limit=3`, `/api/catalog`,
  `/api/analytics/top-talkers` — compare against dashboard numbers.
- Trace one alert end-to-end: alert `src_ip` → top-talkers entry → row in
  `data/alerts.db` (`sqlite3 data/alerts.db "select * from alerts limit 1;"`).

## 3. Per-detector REPL tests

```bash
/tmp/nadvenv/bin/python
>>> from backend.detection.signature_engine import SignatureEngine
>>> sig = SignatureEngine(port_scan_ports=3)
>>> pkt = {"src_ip":"9.9.9.9","dst_ip":"1.1.1.1","src_port":1111,"dst_port":80,
...        "protocol":"TCP","length":60,"flags":"S","payload_len":0,
...        "dns_query":"","http_payload":""}
>>> # vary dst_port / http_payload / dns_query per docs/DETECTION_CATALOG.md
```

Boundary ideas: DNS query 52 vs 54 chars, 9 vs 11 SSH fails, `FPU` vs `PA` flags.

## 4. Real-packet pipeline (no root)

Craft Scapy packets → `parse_raw()` → engine; proven to fire SYN Flood,
Port Scan, DNS Tunneling, SQLi. See chat history / re-run the snippet in
`tests/test_smoke.py::test_signature_unit` style with Scapy objects.

## 5. Lab testing (needs root + 2 VMs, isolated host-only net)

Victim runs `make live IFACE=eth0`; attacker (Kali, **your VMs only**):
`nmap -sS`, `hping3 -S --flood`, `hydra ssh://…`, SQLi via curl.
Expect each class in attack-mix within ~1s; record detection rate,
false positives on benign-only runs, and latency (attack start → alert `timestamp`).

## 6. Datasets & regression

```bash
make train DATASET=data/cicids2017.csv   # prints precision/recall/F1 @ 0.5, 0.7
```

Keep a `lab.pcap` (`tcpdump -w`) per scenario and replay after threshold or
model changes — alerts must reproduce.
