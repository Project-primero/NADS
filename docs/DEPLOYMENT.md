# Deployment

## Local (dev)

```bash
make setup   # venv /tmp/nadvenv + pip + npm install
make train   # models/hybrid.pkl
make run & make run-frontend
```

Backend `http://127.0.0.1:8000` (docs at `/docs`), dashboard `http://localhost:5173`.

## Docker

```bash
docker-compose up -d   # backend :8000 + frontend :5173
docker-compose down
```

`Dockerfile` builds the backend (`python:3.11-slim`); compose mounts
`./models` and `./data` so models and SQLite survive restarts.

## Live capture (production-ish)

```bash
make live IFACE=eth0 PORT=8000   # = sudo NAD_CAPTURE_MODE=live NAD_INTERFACE=eth0 …
```

Requirements & notes:

- **Root** (Scapy sniff needs it); run as a systemd unit with `Restart=always`.
- **Authorized tap/SPAN port or host NIC only** — never sniff third-party traffic.
- **TLS reality**: payload signatures only see plaintext (HTTP/DNS). Encrypted
  attack detection relies on flow metadata (rates, sizes, timing) — keep ML on.
- **Scale**: single-node Scapy suits ≤ few hundred Mbps. Beyond that, move to
  Zeek/Suricata sensors exporting flows and point this engine at them.
- **Behind reverse proxy**: terminate TLS at the proxy; `/ws` needs WS upgrade
  passthrough; restrict `/docs` in production.
- **Backups**: `data/alerts.db` + `models/*.pkl` are the only state — snapshot both.
