# API Reference

Base URL `http://HOST:8000`. Interactive docs at `/docs`.

## REST

| Method & path | Description |
|---|---|
| `GET /` | App info + detector list |
| `GET /api/health` | `{"status":"ok"}` |
| `GET /api/stats` | packets, pps, active/completed flows, alert counts, total |
| `GET /api/alerts?limit=50` | Recent in-memory alerts (newest first) |
| `GET /api/alerts/history?limit=100` | Persisted SQLite alerts |
| `GET /api/flows` | Up to 60 active flows (5-tuple, packets, duration) |
| `GET /api/analytics/traffic` | per-second series + protocols + attack mix + recent packets |
| `GET /api/analytics/top-talkers?limit=10` | IPs by bytes/packets |
| `GET /api/catalog` | All detectors with severity/MITRE/remediation |

### Examples

```bash
curl -s localhost:8000/api/stats | python3 -m json.tool
curl -s "localhost:8000/api/alerts?limit=3"
curl -s localhost:8000/api/catalog | python3 -c \
  "import json,sys; print([d['attack'] for d in json.load(sys.stdin)['detectors']])"
```

## WebSocket `/ws`

Connect, receive an instant snapshot, then one `{type:"stats"}` message per
second plus instant `{type:"alert"}` pushes. Send any keepalive every ~10s.

```python
import json
from websockets.sync.client import connect
with connect("ws://localhost:8000/ws") as ws:
    print(json.loads(ws.recv(timeout=10))["type"])  # stats
```

Snapshot fields: `packets, pps, active_flows, alerts[25], counts,
attack_mix, protocols, series[60]`. See [ARCHITECTURE](ARCHITECTURE.md#websocket-protocol).
