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

export LISTEN_PORT="${LISTEN_PORT:-8080}"

# HTTP (LISTEN_PORT) + HTTPS :443 v jednom procesu; certifikáty pro blokované
# domény se vystavují za běhu (SNI) z domácí CA v /data/tls – restart po přidání
# domény už není potřeba.
exec python -m pin_manager.serve
