.PHONY: help setup train run run-frontend test smoke docker-up docker-down live clean agent

PY ?= /tmp/nadvenv/bin/python
HOST ?= 127.0.0.1
PORT ?= 8000
MODE ?= simulate
IFACE ?= lo
FILE ?=
TOKEN ?=
SITE ?= Default Site

# Mode translation helper
ifeq ($(MODE),demo)
	CAPTURE_MODE := simulate
else
	CAPTURE_MODE := $(MODE)
endif

help:  ## Show targets
	@grep -E '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-14s %s\n", $$1, $$2}'

setup:  ## Create venv + install backend deps
	python3 -m venv /tmp/nadvenv
	/tmp/nadvenv/bin/pip install -r requirements.txt
	cd frontend && npm install

train:  ## Train anomaly model (DATASET=data/file.csv optional)
	$(PY) train_model.py --model hybrid $(if $(DATASET),--dataset $(DATASET))

run:  ## Run backend (supports MODE=demo|live|pcap IFACE=eth0 FILE=traffic.pcap)
	AEGIS_MODE=$(CAPTURE_MODE) AEGIS_IFACE=$(IFACE) AEGIS_PCAP=$(FILE) $(PY) -m uvicorn backend.main:app --host $(HOST) --port $(PORT)

run-frontend:  ## Run dashboard dev server
	cd frontend && npm run dev

live:  ## Live capture on physical NIC (needs root/CAP_NET_RAW; IFACE=eth0)
	sudo AEGIS_MODE=live AEGIS_IFACE=$(IFACE) $(PY) -m uvicorn backend.main:app --host 0.0.0.0 --port $(PORT)

agent:  ## Run remote computer telemetry agent (TOKEN=... SERVER=http://... SITE=...)
	python3 scripts/aegis-agent.py --server http://$(HOST):$(PORT) --token $(TOKEN) --site "$(SITE)"

test:  ## Backend smoke and regression tests
	$(PY) -m pytest tests/ -v

smoke:  ## One-shot API check against running backend
	bash scripts/smoke.sh $(HOST):$(PORT)

docker-up:  ## Full stack via compose (host networking & raw packet capture)
	docker-compose up -d

docker-down:
	docker-compose down

clean:  ## Remove build artefacts
	rm -rf frontend/dist frontend/node_modules .pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
