# Detection Catalog — 30 live detectors

Tune via `NAD_*` vars ([CONFIGURATION](CONFIGURATION.md)). Source: `backend/detection/signature_engine.py::CATALOG`.

## Scans & reconnaissance

| Attack | Logic | Default threshold | MITRE |
|---|---|---|---|
| Port Scan | unique dst ports per src, sliding window | 15 ports / 60s | T1046 |
| Null/Xmas Scan | TCP flags empty/`0` or `F+P+U` | any single packet | T1046 |
| Ping Sweep | ICMP across distinct dsts per src | 10 hosts / 60s | T1595 |
| Horizontal Scan | one dst port probed across distinct hosts | 10 hosts / 60s | T1046 |

## Floods / DoS

| Attack | Logic | Default threshold | MITRE |
|---|---|---|---|
| SYN Flood | SYN-without-ACK per target | 50 / 10s | T1498 |
| UDP Flood | UDP (non-DNS) per target | 200 / 10s | T1498 |
| UDP Amplification | pkts to NTP/SSDP/memcached/mDNS ports per target | 50 / 10s | T1498 |
| Slowloris | many small partial HTTP requests from one src | 50 / 60s | T1498 |
| ICMP Flood | ICMP per target | 100 / 10s | T1498 |
| DDoS | global packets-per-second | 1000 pps | T1498 |

## Brute force (port-aware fail counting)

| Attack | Fail signal | Port | MITRE |
|---|---|---|---|
| SSH Brute Force | `failed password` / `login failed` / `401` / `authentication failure` | 22 | T1110 |
| FTP Brute Force | same | 21 | T1110 |
| RDP Brute Force | same | 3389 | T1110 |
| Telnet Brute Force | same (Mirai-style IoT botnets) | 23 / 2323 | T1110 |
| HTTP Brute Force | same | other web ports | T1110 |
| Password Spraying | fails spread across distinct targets | 5 hosts / 300s | T1110 |

Default: 10 fails / 300s (spraying: 5 distinct targets).

## DNS & exfiltration

| Attack | Logic | Threshold | MITRE |
|---|---|---|---|
| DNS Tunneling | query length > `dns_tunnel_len` | 53 chars | T1071 |
| DNS Exfiltration | query length > 2× threshold | 106 chars | T1048 |
| Data Exfiltration | flow bytes > `exfil_bytes`, >80% one-sided | 10 MB | T1041 |

## Spoofing & C2

| Attack | Logic | MITRE |
|---|---|---|
| ARP Spoofing | ≥30 ARP replies / 5s (MITM storm) | T1557 |
| Malware C2 | DNS query matches known C2 domain set | T1071 |
| C2 Beaconing | ≥20 periodic small egress pkts, interval jitter <5s | T1071 |
| SMB Lateral Movement | burst of port-445 connections from one src | 20 / 60s | T1021 |
| Cryptominer | stratum/mining pool strings on any port | T1496 |

## Web payloads (HTTP inspection)

| Attack | Tokens | MITRE |
|---|---|---|
| SQL Injection | `' or '1'='1`, `union select`, `; drop`, `sleep(`, `'--`, `information_schema` | T1190 |
| XSS Attempt | `<script`, `javascript:`, `onerror=`, `onload=`, `<img`, `document.cookie` | T1189 |
| Path Traversal | `../`, `..\`, `/etc/passwd`, `....//` | T1083 |
| Command Injection | `;cat`, `\|whoami`, `$(`, backticks, `&&`, `wget/curl http`, `/bin/sh` | T1190 |
| Log4Shell | `${jndi:` anywhere in payload | T1190 |
| SSRF Attempt | `169.254.169.254`, `metadata.google`, cloud instance-data URLs | T1190 |

Payload inspection covers HTTP plus a generic any-port snippet (`payload_text`),
so miners on 3333/4444 and exploits on 8080 are caught too.

## ML anomaly (engine #2)

`DetectionEngine` scores every 10th packet of a flow with the HybridModel
(IsolationForest on normal traffic + statistical ensemble). `correlate()` boosts
signature hits confirmed by ML (+10 threat score) and emits pure-ML alerts
(`Anomaly (MEDIUM/HIGH/CRITICAL)`) for zero-day patterns with no signature.

## Alert schema

`attack_type, severity, confidence, mitre, remediation, description, src_ip,
dst_ip, src_port, dst_port, protocol, engine (signature|ml|signature+ml),
anomaly_score?, threat_score, timestamp, id`.
