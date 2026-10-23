# Running Network Anomaly Detection — Make Target Reference & Operational Guide

This document describes all operational commands and targets available in the Network Anomaly Detection (NAD) platform.

---

## 1. Quick Initial Launch (Fresh Machine)

```bash
# 1. Create Python environment and install frontend/backend dependencies
make setup

# 2. Train baseline detection model (saved to models/hybrid.pkl)
make train

# 3. Start backend API server & detection engine (starts on port 8000)
make run &

# 4. Start React SOC Dashboard (starts on port 5174)
make run-frontend

# 5. Run test suite to verify system integrity
make test
```

Access points:
- **SOC Web Dashboard**: `http://localhost:5174`
- **Swagger Interactive API**: `http://127.0.0.1:8000/docs`
- **API Health Endpoint**: `http://127.0.0.1:8000/api/health`

---

## 2. Make Target Directory

| Target | Command Executed | Purpose & Usage |
|---|---|---|
| `make help` | Lists Makefile commands | Quick command reference. |
| `make setup` | `python3 -m venv` + `pip install` + `npm install` | First-time installation and dependency updates. |
| `make train` | `train_model.py --model hybrid` | Trains IsolationForest and statistical anomaly detectors. |
| `make run` | Starts uvicorn backend on port `8000` | Standard backend launch. Supports `MODE=`, `IFACE=`, `FILE=`. |
| `make run-frontend` | `npm run dev` in `frontend/` | Starts Vite React frontend on port `5174`. |
| `make live` | `sudo uvicorn ... AEGIS_MODE=live` | Live packet sniffing on physical NIC (e.g. `IFACE=eth0`). |
| `make agent` | `python3 scripts/aegis-agent.py` | Runs remote telemetry client for remote PCs. |
| `make test` | `pytest tests/ -v` | Runs unit, smoke, and connect integration tests. |
| `make smoke` | `bash scripts/smoke.sh` | One-shot REST API sanity check. |
| `make docker-up` | `docker-compose up -d` | Containerized launch with host networking and `NET_RAW`. |
| `make docker-down` | `docker-compose down` | Stops Docker containers. |
| `make clean` | Cleans dist, caches, and temp files | Resets environment artifacts. |

---

## 3. Ingestion Modes & Command Overrides

You can switch the ingestion engine directly at startup using environment overrides:

### A. Synthetic Simulator (Demo Mode)
```bash
# Standard simulation
make run MODE=demo

# Or high-intensity flood stress testing
AEGIS_MODE=simulate make run
```

### B. Live Hardware Capture (Host NIC)
```bash
# Sniff wireless interface
make live IFACE=wlan0

# Sniff ethernet interface on port 8000
make live IFACE=eth0 PORT=8000
```

### C. Offline PCAP File Replay
```bash
# Replay captured network trace
make run MODE=pcap FILE=data/sample_attacks.pcap
```

### D. Run Distributed Remote Agent
```bash
# Run agent locally or on remote computer
make agent HOST=10.175.10.216 PORT=8000 TOKEN=agt_xxxxxxxx SITE="Computer Lab"
```

---

## 4. Parameter Customization

| Variable | Default | Example Usage |
|---|---|---|
| `HOST` | `127.0.0.1` | `make run HOST=0.0.0.0` (bind to all LAN addresses) |
| `PORT` | `8000` | `make run PORT=8080` |
| `MODE` | `simulate` | `make run MODE=live` or `make run MODE=pcap` |
| `IFACE` | `lo` | `make live IFACE=enp3s0` |
| `FILE` | `""` | `make run MODE=pcap FILE=/tmp/dump.pcap` |
| `TOKEN` | `""` | `make agent TOKEN=agt_abc123` |
| `SITE` | `Default Site` | `make agent SITE="Science Lab"` |
| `PY` | `/tmp/nadvenv/bin/python` | `make run PY=python3` |

---

## 5. Troubleshooting & FAQ

| Problem | Root Cause | Solution |
|---|---|---|
| **Port 8000 or 5174 in use** | An existing process is bound to the port. | `fuser -k 8000/tcp` or check running containers with `docker ps`. |
| **Agent 401 Unauthorized** | Token is incorrect, expired, or deleted. | Generate a fresh token via **Connected Computers** tab or `POST /api/agents/tokens`. |
| **Permission Denied on Capture** | Sniffing raw NICs requires root or capabilities. | Use `sudo make live IFACE=eth0` or assign capabilities: `sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)`. |
| **Frontend shows DISCONNECTED** | Backend API is stopped or port is blocked. | Verify backend with `curl http://127.0.0.1:8000/api/health`. Ensure firewall allows port 8000. |
| **PCAP Upload Error 413** | File exceeds reverse proxy payload limits. | Increase `client_max_body_size 100M;` in Nginx configuration. |
| **Tests Fail with Connection Refused** | Backend is not running for integration tests. | Run `make run &` before executing `make test`. |
