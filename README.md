# 🛡️ Aegis — Network Anomaly Detection & Cyber Attack Monitoring

[![backend](https://img.shields.io/badge/backend-FastAPI-009688)]() [![ml](https://img.shields.io/badge/ML-IsolationForest%20%2B%20LSTM-orange)]() [![ui](https://img.shields.io/badge/UI-React%2018-61dafb)]() [![tests](https://img.shields.io/badge/tests-6%20passing-brightgreen)]()

Real-time SOC system: **capture → flow features → 30 signature detectors ⊕ ML → correlated alerts → live dashboard.**

Every alert carries severity, confidence, MITRE ATT&CK mapping, a 0–100 threat score, and a remediation hint.

## ⚡ Quickstart

```bash
make setup          # venv + backend deps + npm install
make train          # builds models/hybrid.pkl (synthetic data)
make run            # backend → http://127.0.0.1:8000/docs
make run-frontend   # dashboard → http://localhost:5173
make test           # 6 smoke tests
```

Or step by step — see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## 📚 Docs

| Doc | Contents |
|---|---|
| [HOW_IT_WORKS](docs/HOW_IT_WORKS.md) | ⭐ Start here: pipeline walkthrough + 5 test levels |
| [UNDERSTANDING](docs/UNDERSTANDING.md) | Plain-language guide: mental model + why it matters |
| [DATASET](docs/DATASET.md) | Built-in labeled CSV + public benchmarks + lab captures |
| [RUNNING](docs/RUNNING.md) | `make` target-by-target: first run, overrides, troubleshooting |
| [ARCHITECTURE](docs/ARCHITECTURE.md) | Pipeline, modules, data flow, WS protocol |
| [DETECTION_CATALOG](docs/DETECTION_CATALOG.md) | All 30 detectors: logic, thresholds, MITRE |
| [API](docs/API.md) | REST + WebSocket reference with examples |
| [CONFIGURATION](docs/CONFIGURATION.md) | Every `NAD_*` env var and tuning advice |
| [TESTING](docs/TESTING.md) | Manual, automated, lab and dataset testing |
| [DEPLOYMENT](docs/DEPLOYMENT.md) | Local, Docker, live-capture production notes |

## 🗂️ Structure

```
.
├── backend/
│   ├── main.py                 # FastAPI app: capture → detect → correlate → serve
│   ├── config.py               # Settings (NAD_* env vars)
│   ├── capture/
│   │   ├── packet_capture.py   # Scapy live sniffer + 14-class traffic simulator
│   │   └── packet_parser.py    # L2–L7 dissection → normalized packet dict
│   ├── flow/
│   │   ├── flow_manager.py     # 5-tuple tracking + expiry
│   │   └── feature_extractor.py# 41 CIC-IDS style flow features
│   ├── detection/
│   │   ├── signature_engine.py # 30 signature detectors + CATALOG
│   │   ├── correlation.py      # signature ⊕ ML fusion → threat score 0–100
│   │   ├── inference.py        # real-time ML flow scoring
│   │   ├── trainer.py          # synthetic/CSV training pipeline
│   │   └── models/             # hybrid / LSTM / transformer
│   ├── alerts/alert_manager.py # dedup + severity counts + persistence hook
│   ├── database/               # SQLite (SQLAlchemy) alert store
│   └── api/                    # REST routes + WebSocket broadcast
├── frontend/src/
│   ├── components/             # Dashboard, TrafficChart, ProtocolDonut,
│   │                           # AttackMix, AlertFeed, TopTalkers, ThreatMatrix
│   ├── hooks/useWebSocket.ts   # live snapshot feed (+ top-talkers polling)
│   └── types/                  # Alert / Stats / SeriesPoint
├── tests/test_smoke.py         # 6 pytest smoke tests
├── scripts/                    # run-backend/fronted, train, smoke helpers
├── docs/                       # guides (see table above)
├── Makefile                    # setup/train/run/test/live/docker targets
├── train_model.py              # CLI entry for training
└── docker-compose.yml + Dockerfile
```

## 🔍 Detection at a glance

Scans (Port, Horizontal, Ping Sweep, Null/Xmas) · Floods (SYN/UDP/ICMP/DDoS/Amplification/Slowloris) ·
Brute force (SSH/FTP/RDP/Telnet/HTTP) + Password Spraying · DNS Tunneling/Exfiltration ·
ARP Spoofing · Malware C2 + Beaconing · SMB Lateral Movement · Cryptominer ·
SQLi / XSS / Path Traversal / Command Injection / Log4Shell / SSRF · Data Exfiltration ·
ML Anomaly — full detail in
[docs/DETECTION_CATALOG.md](docs/DETECTION_CATALOG.md).

> **Authorized use only.** Capture only traffic you own or are permitted to monitor;
> run attack tools only against your own isolated lab VMs.
