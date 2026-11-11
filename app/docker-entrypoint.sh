#!/bin/sh
set -e

if [ "${DEPLOY_MODE:-}" = "vlan" ] && [ -n "${PORTAL_IP:-}" ]; then
  if command -v ip >/dev/null 2>&1; then
    if ! ip -4 addr show | grep -Fq "${PORTAL_IP}"; then
      echo "CHYBA: Kontejner NEMÁ IP ${PORTAL_IP} – macvlan nefunguje."
      echo "Zkontrolujte MACVLAN_PARENT, MACVLAN_GATEWAY a redeploy stacku."
      ip -4 addr show || true
    else
      echo "OK: Kontejner má IP ${PORTAL_IP}"
    fi
  fi
fi

LISTEN_PORT="${LISTEN_PORT:-8080}"

# Volitelně HTTPS :443 (u HSTS webů stejně často nepomůže zobrazit PIN na jejich jménu)
if [ "${PORTAL_HTTPS:-true}" = "true" ] && [ "$LISTEN_PORT" = "80" ]; then
  CERT_DIR="/tmp/pin-tls"
  mkdir -p "$CERT_DIR"
  if openssl req -x509 -nodes -days 825 -newkey rsa:2048 \
      -keyout "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" \
      -subj "/CN=pin-manager-local" >/dev/null 2>&1; then
    echo "Spouštím HTTPS na :443 (volitelný fallback)"
    uvicorn pin_manager.main:app --host 0.0.0.0 --port 443 \
      --ssl-keyfile "$CERT_DIR/key.pem" --ssl-certfile "$CERT_DIR/cert.pem" &
  fi
fi

exec uvicorn pin_manager.main:app --host 0.0.0.0 --port "$LISTEN_PORT"
