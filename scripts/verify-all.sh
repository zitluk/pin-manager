#!/usr/bin/env bash
# Lokální / CI ověření před release (vyžaduje Docker)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "==> pytest (Python 3.12)"
docker run --rm -v "$ROOT/app:/app" -w /app python:3.12-slim bash -ec '
  pip install -q -r requirements-dev.txt
  pytest -q
'

echo "==> compose validate"
docker compose -f portainer-stack.yml config >/dev/null

echo "==> build + smoke"
docker build -t pin-manager:verify ./app
docker rm -f pin-verify 2>/dev/null || true
docker run -d --name pin-verify -p 9876:8080 \
  -e LISTEN_PORT=8080 \
  -e PORTAL_IP= \
  -e PIHOLE_SINKHOLE_MODE=file \
  -e PIHOLE_RESTART_DNS=false \
  -e PIN=1234 \
  -e SESSION_SECRET=verify \
  pin-manager:verify
sleep 2
curl -fsS http://127.0.0.1:9876/health
docker rm -f pin-verify

echo "OK – vše prošlo"
