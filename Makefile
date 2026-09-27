.PHONY: help setup train run run-frontend test smoke docker-up docker-down live clean

PY ?= /tmp/nadvenv/bin/python
HOST ?= 127.0.0.1
PORT ?= 8000

help:  ## Show targets
	@grep -E '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-14s %s\n", $$1, $$2}'

setup:  ## Create venv + install backend deps
	python3 -m venv /tmp/nadvenv
	/tmp/nadvenv/bin/pip install -r requirements.txt
	cd frontend && npm install

train:  ## Train anomaly model (DATASET=data/file.csv optional)
	$(PY) train_model.py --model hybrid $(if $(DATASET),--dataset $(DATASET))

run:  ## Run backend API (HOST/PORT overridable)
	$(PY) -m uvicorn backend.main:app --host $(HOST) --port $(PORT)

run-frontend:  ## Run dashboard dev server
	cd frontend && npm run dev

live:  ## Live capture on NIC (needs root; IFACE=eth0)
	sudo NAD_CAPTURE_MODE=live NAD_INTERFACE=$(IFACE) $(PY) -m uvicorn backend.main:app --host 0.0.0.0 --port $(PORT)

test:  ## Backend smoke tests
	$(PY) -m pytest tests/ -v

smoke:  ## One-shot API check against running backend
	bash scripts/smoke.sh $(HOST):$(PORT)

docker-up:  ## Full stack via compose
	docker-compose up -d

docker-down:
	docker-compose down

clean:  ## Remove build artefacts
	rm -rf frontend/dist frontend/node_modules .pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
