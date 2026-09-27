# Running with `make` — target-by-target guide

> Companion: [DEPLOYMENT](DEPLOYMENT.md) (environments) · [TESTING](TESTING.md) ·
> [CONFIGURATION](CONFIGURATION.md) (`NAD_*` vars). Run `make help` anytime.

## First run (fresh machine, in order)

```bash
make setup          # 1. venv at /tmp/nadvenv + pip install + npm install
make train          # 2. builds models/hybrid.pkl (synthetic data)
make run &          # 3. backend → http://127.0.0.1:8000/docs
make run-frontend   # 4. dashboard → http://localhost:5173
make test           # 5. confirm 7/7 green
```

## Every target

| Target | What it runs | When to use it |
|---|---|---|
| `make help` | lists targets | anytime you forget |
| `make setup` | `python3 -m venv` + `pip install -r requirements.txt` + `npm install` | once per machine (re-run after pulling new deps) |
| `make train` | `train_model.py --model hybrid` → `models/hybrid.pkl` | after cloning; after editing features/model code |
| `make run` | uvicorn backend on `127.0.0.1:8000` | normal backend start (simulate mode) |
| `make run-frontend` | `npm run dev` in `frontend/` | dashboard dev server |
| `make test` | `pytest tests/ -v` (needs backend on :8000) | after any backend change |
| `make smoke` | curl check of all 6 API endpoints | fastest "is it alive?" probe |
| `make live IFACE=eth0` | backend with real NIC capture (**needs sudo**, your network only) | production/lab sniffing |
| `make docker-up` / `make docker-down` | full stack via compose | containerized run |
| `make clean` | removes `dist`, `node_modules`, caches | disk cleanup / fresh frontend install |

## Overriding defaults

```bash
make run HOST=0.0.0.0 PORT=9000        # expose backend on LAN, port 9000
make train DATASET=data/nad_dataset.csv   # train on a real CSV
make live IFACE=wlan0 PORT=8000           # sniff Wi-Fi instead of eth0
make test PY=/usr/bin/python3             # use a different interpreter
```

Variables: `PY` (default `/tmp/nadvenv/bin/python`), `HOST`, `PORT`, `DATASET`, `IFACE`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `PY: No such file` / venv errors | run `make setup` first |
| `Address already in use :8000` | `fuser -k 8000/tcp`, or `make run PORT=8001` |
| `make test` fails on `/api/*` | backend must be running (`make run &`), then retry |
| `make live` asks for password | expected — live capture needs root (`sudo`) |
| dashboard shows CONNECTING… | backend down or wrong WS port — check `make smoke` |
| `npm` errors in `run-frontend` | `cd frontend && npm install`, then retry |
