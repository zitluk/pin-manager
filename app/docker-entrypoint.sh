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

# HTTPS :443 – cert se SAN pro blokované domény (/data/tls), viz PORTAL_TLS_AUTO
if [ "${PORTAL_HTTPS:-true}" = "true" ] && [ "$LISTEN_PORT" = "80" ]; then
  if [ "${PORTAL_TLS_AUTO:-true}" = "true" ]; then
    python -c "from pin_manager.tls_certs import ensure_tls_material; ensure_tls_material()" 2>/dev/null || true
  fi
  CERT_KEY="/data/tls/server.key.pem"
  CERT_CRT="/data/tls/server.crt.pem"
  if [ -f "$CERT_KEY" ] && [ -f "$CERT_CRT" ]; then
    echo "Spouštím HTTPS na :443 (cert se jmény blokovaných domén)"
    uvicorn pin_manager.main:app --host 0.0.0.0 --port 443 \
      --ssl-keyfile "$CERT_KEY" --ssl-certfile "$CERT_CRT" &
  else
    echo "VAROVÁNÍ: chybí $CERT_CRT – HTTPS vypnuto, jen HTTP :$LISTEN_PORT"
  fi
fi

exec uvicorn pin_manager.main:app --host 0.0.0.0 --port "$LISTEN_PORT"
