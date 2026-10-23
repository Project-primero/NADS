# API Reference

Base URL: `http://HOST:8000`. Interactive Swagger UI is available at `/docs` and ReDoc at `/redoc`.

---

## 1. System & Statistics

| Method & Path | Description | Response / Payload |
|---|---|---|
| `GET /` | Root health, app name, mode, active source info | `{"app": "...", "mode": "...", "source": "...", "detectors": [...]}` |
| `GET /api/health` | Service liveness probe | `{"status": "ok"}` |
| `GET /api/system/health` | Hardware telemetry (PPS, total packets, drops, RAM MB) | `{"status": "healthy", "pps": 120.0, "memory_mb": 142.5, ...}` |
| `GET /api/stats` | High-level metrics: total packets, current PPS, flows, alert counts | `{"packets": 48200, "pps": 85.0, "active_flows": 12, ...}` |
| `GET /api/catalog` | Full catalog of 30 signature rules with MITRE & remediation | `{"detectors": [{"attack": "SYN Flood", "severity": "HIGH", ...}]}` |

---

## 2. Threat Alerts & Analytics

| Method & Path | Description | Query Parameters / Payload |
|---|---|---|
| `GET /api/alerts` | Recent in-memory alerts (newest first, up to limit) | `?limit=50` (default: 50) |
| `GET /api/alerts/history` | Historical alerts persisted in SQLite store | `?limit=100` (default: 100) |
| `GET /api/alerts/export` | Download alerts as CSV or JSON format | `?format=csv` or `?format=json` (limit: 5000) |
| `GET /api/flows` | List of active 5-tuple tracked network flows | `{"flows": [{"src_ip": ..., "duration": ...}]}` |
| `GET /api/analytics/traffic` | Per-second throughput history, protocol mix, attack mix | `{"series": [...], "protocols": {...}, "attack_mix": {...}}` |
| `GET /api/analytics/top-talkers` | Top IP talkers ranked by bytes and packet counts | `?limit=10` |
| `GET /api/firewall/rule/{ip}` | Generate copy-paste firewall block commands | Returns commands for `iptables`, `ufw`, `nftables`, `cisco_ios`, `mikrotik` |

---

## 3. Universal Connect & Ingestion

| Method & Path | Description | Request Body |
|---|---|---|
| `GET /api/connect/interfaces` | Enumerate host network cards (name, IP, MAC, carrier status, packet counts) | None |
| `GET /api/connect/status` | Current active capture mode, interface, PPS, agent counts, baseline mode | None |
| `POST /api/connect/start` | Dynamically switch capture mode without restarting server | `{"mode": "simulate"\|"live"\|"pcap"\|"agent", "interface": "eth0", "intensity": "medium", "attacks": ["all"], "bpf_filter": "", "promiscuous": false}` |
| `POST /api/connect/stop` | Stop active capture engine | None |
| `POST /api/connect/test` | Run 10-second sniffer traffic verification check | `{"interface": "eth0", "duration": 10}` |

---

## 4. PCAP Replay Engine

| Method & Path | Description | Request Type |
|---|---|---|
| `POST /api/pcap/upload` | Upload `.pcap` / `.pcapng` file and begin streaming replay through pipeline | Multipart form data (`file`) or binary body; query `?speed=instant\|realtime\|5x\|10x` |
| `GET /api/pcap/status/{job_id}` | Check replay progress, packets processed, alerts triggered | None |

---

## 5. Remote Computer Agents (Multi-Site & Universities)

| Method & Path | Description | Details |
|---|---|---|
| `GET /api/agents` | List all registered remote computers, sites, live PPS, and status | Returns `[{"name": "...", "ip": "...", "status": "ONLINE", ...}]` |
| `POST /api/agents/tokens` | Generate a new agent token (SHA-256 hashed in database) | Body: `{"name": "Node-01", "site": "CS Lab"}` |
| `POST /api/agents/verify` | Handshake called by remote agent on boot | Body: `{"token": "agt_...", "hostname": "...", "ip": "...", "os": "..."}` |
| `POST /api/agents/ingest` | Ingest batch of packet flow metadata from remote agent | Header: `Authorization: Bearer <TOKEN>`<br>Body: `{"agent_id": "...", "site": "...", "packets": [...]}` |
| `DELETE /api/agents/{agent_id}` | Revoke and disconnect remote agent | None |
| `GET /api/agents/install.sh` | Dynamic Bash installation script for Linux / macOS | `curl -sSL http://HOST:8000/api/agents/install.sh \| bash -s -- <TOKEN>` |
| `GET /api/agents/install.ps1` | Dynamic PowerShell installation script for Windows | `Invoke-WebRequest ... \| iex` |
| `GET /api/agents/script` | Raw Python agent script source code | Standalone client executable |

---

## 6. Asset Inventory & Trusted Allowlist

| Method & Path | Description | Request Body |
|---|---|---|
| `GET /api/assets` | Auto-discovered list of all IP and MAC devices seen on wire | None |
| `PUT /api/assets/{ip}` | Update asset hostname label, owner, and department | `{"hostname": "...", "owner": "...", "department": "...", "device_type": "..."}` |
| `GET /api/allowlist` | List trusted CIDRs / IPs exempt from alerting | None |
| `POST /api/allowlist` | Add trusted scanner or backup server to allowlist | `{"cidr_or_ip": "192.168.1.50/32", "port": 0, "description": "Nessus Scanner"}` |
| `DELETE /api/allowlist/{id}` | Remove rule from allowlist | None |

---

## 7. WebSec Platform (Website Security & Uptime)

| Method & Path | Description | Details |
|---|---|---|
| `GET /api/sites` | List monitored web targets with security scores & uptime | Combined monitor snapshot & DB records |
| `POST /api/sites` | Add new URL target for security and uptime auditing | Body: `{"name": "...", "url": "https://example.com", "interval": 60}` |
| `DELETE /api/sites/{id}` | Remove website target | None |
| `POST /api/sites/{id}/scan-now` | Trigger immediate on-demand security audit & probe | None |
| `GET /api/sites/{id}/history` | Historical uptime, latency, and security trends | `?limit=50` |
| `PATCH /api/sites/{id}` | Update target name, check interval, or toggle monitoring | Body: `{"name": "...", "interval": 30, "enabled": true}` |
| `GET /api/sites/{id}/report` | Download executive JSON vulnerability assessment report | Attachment download |

---

## 8. WebSocket Protocols

### 8.1 Primary Broadcast Feed: `/ws`
Connect at `ws://HOST:8000/ws`. Upon connection, the server sends an immediate snapshot, followed by a broadcast message every 1 second:

```json
{
  "type": "stats",
  "packets": 54200,
  "pps": 124.0,
  "active_flows": 18,
  "alerts": [...],
  "counts": {"CRITICAL": 2, "HIGH": 5, "MEDIUM": 1, "LOW": 0},
  "attack_mix": {"Port Scan": 12, "SYN Flood": 4},
  "protocols": {"TCP": 41200, "UDP": 12000, "ICMP": 1000},
  "series": [{"ts": 1792681000, "pps": 120.0, "packets": 54000}],
  "sites": [...],
  "connect": {
    "mode": "simulate",
    "running": true,
    "interface": "lo",
    "intensity": "medium",
    "pps": 124.0,
    "source_info": "Simulator (Synthetic 14-Class Traffic)"
  },
  "online_agents": 2,
  "total_agents": 2,
  "learning_mode": false
}
```

Whenever an alert is triggered, it is pushed **instantly** without waiting for the 1-second interval:
```json
{
  "type": "alert",
  "attack_type": "SYN Flood",
  "severity": "HIGH",
  "threat_score": 85,
  "src_ip": "10.175.10.220",
  "dst_ip": "10.0.0.1",
  "src_port": 54321,
  "dst_port": 80,
  "protocol": "TCP",
  "mitre": "T1498 — Network Denial of Service",
  "remediation": "Enable SYN cookies: sysctl -w net.ipv4.tcp_syncookies=1"
}
```

### 8.2 Remote Agent Bidirectional Stream: `/ws/agent`
Dedicated WebSocket for remote agents streaming packets and heartbeats with Bearer token authentication:
1. Agent connects: `GET /ws/agent`
2. Agent sends handshake: `{"type": "auth", "token": "agt_...", "hostname": "PC-01", "site": "Lab 1", "ip": "10.175.10.220", "os": "Windows 10"}`
3. Server responds: `{"ok": true, "agent_id": "agent-...", "site": "Lab 1"}`
4. Agent streams packet batches: `{"type": "packets", "packets": [...], "pps": 45.0}`
