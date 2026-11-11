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

exec uvicorn pin_manager.main:app --host 0.0.0.0 --port "${LISTEN_PORT:-8080}"
