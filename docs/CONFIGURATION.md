# Configuration

All settings live in `backend/config.py` (`Settings`, prefix `NAD_`) and can be
set via environment or a `.env` file — copy [.env.example](../.env.example) to start.

| Variable | Default | Meaning |
|---|---|---|
| `NAD_CAPTURE_MODE` | `simulate` | `simulate` (synthetic traffic) or `live` (Scapy sniff, needs root) |
| `NAD_INTERFACE` | `lo` | NIC for live capture |
| `NAD_FLOW_TIMEOUT` | `60` | seconds before an idle flow expires |
| `NAD_DB_PATH` | `data/alerts.db` | SQLite file |
| `NAD_MODEL_DIR` / `NAD_MODEL_TYPE` | `models` / `hybrid` | model storage / selection |
| `NAD_ANOMALY_THRESHOLD` | `0.7` | ML score ≥ this → anomaly |
| `NAD_WS_BROADCAST_INTERVAL` | `1.0` | seconds between WS snapshots |
| `NAD_PORT_SCAN_PORTS` / `_WINDOW` | `15` / `60` | unique ports per src per window |
| `NAD_SYN_FLOOD_COUNT` / `_WINDOW` | `50` / `10` | SYNs per target per window |
| `NAD_UDP_FLOOD_COUNT` / `_WINDOW` | `200` / `10` | |
| `NAD_ICMP_FLOOD_COUNT` / `_WINDOW` | `100` / `10` | |
| `NAD_DDOS_PPS` | `1000` | global packets/sec |
| `NAD_BRUTE_FORCE_FAILS` / `_WINDOW` | `10` / `300` | failed logins per src |
| `NAD_DNS_TUNNEL_LEN` | `53` | DNS query chars (2× = exfiltration) |
| `NAD_EXFIL_BYTES` | `10000000` | one-sided flow bytes → exfiltration |
| `NAD_SWEEP_DSTS` / `_WINDOW` | `10` / `60` | distinct hosts pinged → sweep |
| `NAD_HORIZ_DSTS` / `_WINDOW` | `10` / `60` | distinct hosts, same port → horizontal scan |
| `NAD_SPRAY_DSTS` | `5` | distinct fail targets → password spraying |
| `NAD_SMB_COUNT` / `_WINDOW` | `20` / `60` | port-445 connections → lateral movement |
| `NAD_SLOWLORIS_COUNT` / `_WINDOW` | `50` / `60` | small HTTP requests → Slowloris |
| `NAD_AMP_COUNT` / `_WINDOW` | `50` / `10` | pkts to amplifier ports → UDP amplification |

## Tuning advice

- **Alert fatigue?** Raise counts/windows (e.g. `SYN_FLOOD_COUNT=100`) or `ANOMALY_THRESHOLD=0.8`.
- **Missing slow scans?** Lower `PORT_SCAN_PORTS` or widen `PORT_SCAN_WINDOW`.
- **Noisy lab?** Raise `DDOS_PPS` to match your baseline pps (check `/api/stats`).
- After changes, restart the backend and re-run `make test` + a PCAP replay
  ([TESTING](TESTING.md)) to confirm detection rate holds.
