# System Configuration Reference

All settings in the Network Anomaly Detection (NAD) system are managed by [`Settings`](file:///home/dereje/project/NAD/backend/config.py#L6-L57) in [`backend/config.py`](file:///home/dereje/project/NAD/backend/config.py). Settings can be defined via environment variables or a `.env` file at the repository root. The system accepts standard `NAD_*` prefixes and `AEGIS_*` compatibility prefixes.

---

## 1. Universal Connect & Ingestion Settings

| Environment Variable | Default | Allowed Values | Description |
|---|---|---|---|
| `AEGIS_MODE` / `NAD_CAPTURE_MODE` | `simulate` | `simulate`, `live`, `pcap`, `agent` | Active packet capture engine. |
| `AEGIS_IFACE` / `NAD_INTERFACE` | `lo` | e.g. `eth0`, `enp3s0`, `wlan0`, `lo` | Network interface for physical live sniffing. |
| `AEGIS_PCAP` | `""` | e.g. `data/capture.pcap` | Default path to PCAP/PCAPNG file for offline replay. |
| `AEGIS_BPF_FILTER` | `""` | e.g. `tcp port 80 or udp`, `not port 22` | Berkeley Packet Filter expression applied to raw capture. |
| `AEGIS_LEARNING_MODE` | `false` | `true`, `false`, `1`, `0` | When enabled, auto-whitelists observed traffic to build baseline. |

---

## 2. Core Detection & Engine Settings

| Environment Variable | Default | Description |
|---|---|---|
| `NAD_APP_NAME` | `Network Anomaly Detection` | Application title displayed across API docs and UI. |
| `NAD_FLOW_TIMEOUT` | `60` | Inactivity seconds before an idle 5-tuple flow is expired and purged. |
| `NAD_DB_PATH` | `data/alerts.db` | Filepath for SQLite persistence (alerts, agents, assets, allowlists). |
| `NAD_RETENTION_DAYS` | `30` | Auto-prune age for stored alerts, audit logs, and telemetry history. |
| `NAD_MODEL_DIR` | `models` | Directory path containing trained pickle models. |
| `NAD_MODEL_TYPE` | `hybrid` | ML engine model selector: `isolation_forest`, `lstm`, `transformer`, `hybrid`. |
| `NAD_ANOMALY_THRESHOLD` | `0.7` | Minimum ML score (0.0–1.0) to qualify as an anomalous flow. |
| `NAD_WS_BROADCAST_INTERVAL` | `1.0` | Cadence (in seconds) for WebSocket live telemetry snapshots pushed to `/ws`. |

---

## 3. WebSec & Site Monitor Settings

| Environment Variable | Default | Description |
|---|---|---|
| `NAD_SITE_CHECK_DEFAULT_INTERVAL` | `60` | Default interval (seconds) for synthetic uptime & security header audits. |
| `NAD_SITE_CHECK_TIMEOUT` | `10.0` | Maximum HTTP request timeout (seconds) for site health checks. |
| `NAD_ALLOW_PRIVATE_TARGETS` | `false` | Prevent SSRF by rejecting probes against RFC 1918 / loopback addresses. |
| `NAD_SEED_SITE_URL` | `""` | Optional initial URL to seed site health monitoring upon startup. |

---

## 4. Attack Signature Thresholds

Thresholds for the 30 heuristic and behavioral detectors in [`backend/detection/signature_engine.py`](file:///home/dereje/project/NAD/backend/detection/signature_engine.py):

| Variable | Default | Window (s) | Detector & Trigger Condition |
|---|---|---|---|
| `NAD_PORT_SCAN_PORTS` | `15` | `60` (`NAD_PORT_SCAN_WINDOW`) | Distinct destination ports probed from one source. |
| `NAD_SWEEP_DSTS` | `10` | `60` (`NAD_SWEEP_WINDOW`) | Distinct destination IPs targeted by ICMP echo (Ping Sweep). |
| `NAD_HORIZ_DSTS` | `10` | `60` (`NAD_HORIZ_WINDOW`) | Distinct destination hosts probed on the exact same port. |
| `NAD_SYN_FLOOD_COUNT` | `50` | `10` (`NAD_SYN_FLOOD_WINDOW`) | TCP SYN packets without ACK completion per target. |
| `NAD_UDP_FLOOD_COUNT` | `200` | `10` (`NAD_UDP_FLOOD_WINDOW`) | Non-DNS UDP packets directed at a single destination. |
| `NAD_ICMP_FLOOD_COUNT` | `100` | `10` (`NAD_ICMP_FLOOD_WINDOW`) | ICMP echo request storm directed at a single destination. |
| `NAD_DDOS_PPS` | `1000` | Global | Global aggregate packets-per-second threshold. |
| `NAD_SLOWLORIS_COUNT` | `50` | `60` (`NAD_SLOWLORIS_WINDOW`) | Low-and-slow incomplete HTTP requests keeping sockets open. |
| `NAD_AMP_COUNT` | `50` | `10` (`NAD_AMP_WINDOW`) | Inbound packets from UDP reflection services (NTP/SSDP/Memcached). |
| `NAD_BRUTE_FORCE_FAILS`| `10` | `300` (`NAD_BRUTE_FORCE_WINDOW`) | Failed authentication attempts against SSH, FTP, RDP, Telnet, HTTP. |
| `NAD_SPRAY_DSTS` | `5` | `300` | Failed logins distributed across distinct hosts (Password Spraying). |
| `NAD_SMB_COUNT` | `20` | `60` (`NAD_SMB_WINDOW`) | Port 445 connection burst indicating lateral traversal. |
| `NAD_DNS_TUNNEL_LEN` | `53` | Per query | Character length of subdomain indicating base64/hex DNS tunneling. |
| `NAD_EXFIL_BYTES` | `10000000` | Per flow | 10 MB payload transfer with >80% one-sided outbound volume. |

---

## 5. Remote Telemetry Agent Configuration

The lightweight remote agent [`scripts/aegis-agent.py`](file:///home/dereje/project/NAD/scripts/aegis-agent.py) is configured via CLI arguments or environment variables:

| Parameter | Env Variable | Default | Description |
|---|---|---|---|
| `--server` | `NAD_SERVER` / `AEGIS_SERVER` | `http://127.0.0.1:8000` | Base URL of the central NAD server. |
| `--token` | `NAD_TOKEN` / `AEGIS_TOKEN` | *Required* | High-entropy authentication token issued via `/api/agents/tokens`. |
| `--name` | `NAD_AGENT_NAME` | Hostname | Human-readable identity (e.g. `University-PC-01`). |
| `--site` | `NAD_AGENT_SITE` | `Default Site` | Lab, room, branch, or department grouping. |
| `--interval` | `NAD_INTERVAL` | `5.0` | Telemetry report cadence in seconds. |
| `--iface` | `NAD_IFACE` | Default NIC | Specific network interface to monitor (Scapy / psutil). |

---

## 6. Tuning Advice & Best Practices

1. **Suppression & False Alarm Tuning:**
   - Rather than globally relaxing detection thresholds, navigate to the **Assets & Allowlist** tab in the UI or use `POST /api/allowlist` to whitelist legitimate vulnerability scanners (e.g. Nessus, OpenVAS) or jump-hosts.
2. **Learning Baseline Mode:**
   - Run `AEGIS_LEARNING_MODE=true` for 24 hours during normal business operations. The engine will observe recurring internal flows and flag deviations rather than known infrastructure traffic.
3. **High-Throughput Environments:**
   - If monitoring a physical gigabit switch SPAN port, set `NAD_DDOS_PPS=10000` and use `AEGIS_BPF_FILTER="not port 22 and not port 8000"` to avoid feedback loops.
4. **Validating Configuration Changes:**
   - After modifying thresholds in `.env`, test with `pytest tests/test_smoke.py` and `pytest tests/test_connect.py`.
