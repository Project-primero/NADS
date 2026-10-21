#!/bin/sh
cd /home/dereje/project/NAD
exec python3 -m uvicorn backend.main:app --host 127.0.0.1 --port 8001
