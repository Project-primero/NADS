# Architecture

## Pipeline

```
NIC / simulator
      │ packet dicts
      ▼
PacketCapture ──► FlowManager (5-tuple, 60s expiry)
      │                  │ 41-feature vector
      ▼                  ▼
SignatureEngine ──► correlate() ◄── DetectionEngine (HybridModel)
 (30 detectors)         │  threat score 0–100
                        ▼
              AlertManager (60s dedup) ──► SQLite + WebSocket + REST
```

`backend/main.py` wires it: `_on_packet()` timestamps each packet, updates
analytics ring buffers, runs signature checks per packet, ML checks every
10th packet of a flow, and pushes the correlated verdict.

## Modules

| Path | Role |
|---|---|
| `backend/capture/packet_capture.py` | `PacketCapture`: Scapy `sniff` thread in `live` mode; 14-class synthetic generator in `simulate` mode |
| `backend/capture/packet_parser.py` | `parse_raw()` / `dict_from_parsed()`: IP/TCP/UDP/ICMP/ARP/DNS/HTTP → flat dict |
| `backend/flow/flow_manager.py` | Direction-agnostic 5-tuple keying, timeout expiry |
| `backend/flow/feature_extractor.py` | 41 features (`FEATURE_NAMES`): rates, flag counts, IAT stats, port entropy, payload/SQLi/XSS signals |
| `backend/detection/signature_engine.py` | Stateful sliding-window rules + `CATALOG` (severity/MITRE/remediation) |
| `backend/detection/correlation.py` | `correlate(sig, ml)`: signature wins, ML confirms (+10), threat score mapping |
| `backend/detection/inference.py` | `DetectionEngine.analyze_flow()` → score, severity, 5-tuple passthrough |
| `backend/detection/models/hybrid_model.py` | IsolationForest + StandardScaler with statistical fallback (no sklearn) |
| `backend/detection/models/lstm_model.py`, `transformer_model.py` | PyTorch sequence models (optional, need `torch`) |
| `backend/detection/trainer.py` | Synthetic or CSV training, precision/recall/F1 report, pickle save |
| `backend/alerts/alert_manager.py` | Dedup window (60s), severity counts, bounded history |
| `backend/database/` | SQLAlchemy `Alert` model + `Database` helper (SQLite) |
| `backend/api/routes.py` | REST (stats/alerts/flows/analytics/catalog) |
| `backend/api/websocket.py` | 1s broadcast of full snapshot + instant `push_alert()` |

## Analytics state (`main.py`)

Per-second `traffic_series` ring (120 pts), `attack_mix` / `proto_counts` /
`talker_bytes` / `talker_packets` counters, and a 200-packet `recent_packets` deque.

## WebSocket protocol

- Client connects `GET /ws` → server immediately sends `{type:"stats", …snapshot}`.
- Every 1s: `{type:"stats", packets, pps, active_flows, alerts[25], counts, attack_mix, protocols, series[60]}`.
- On detection: `{type:"alert", …alert}` pushed instantly.
- Client should send any message every ~10s as keepalive.
