#!/usr/bin/env bash
# Odstraní překrývající se macvlan sítě a znovu vytvoří jednu docker_vlan.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SUBNET="${MACVLAN_SUBNET:-192.168.39.0/24}"

echo "Sítě s subnetem ${SUBNET}:"
docker network ls -q | while read -r id; do
  sn="$(docker network inspect "$id" --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null || true)"
  if [ "$sn" = "$SUBNET" ]; then
    name="$(docker network inspect "$id" --format '{{.Name}}')"
    echo "  - $name ($id)"
  fi
done

echo "Stop pin-manager…"
docker stop pin-manager 2>/dev/null || true
docker rm pin-manager 2>/dev/null || true

for net in pin-manager-macvlan docker_vlan; do
  if docker network inspect "$net" &>/dev/null; then
    echo "Mažu síť $net"
    docker network rm "$net" || true
  fi
done

PARENT="${1:-}"
GW="${2:-192.168.39.1}"
exec bash "$ROOT/scripts/create-docker-vlan.sh" "$PARENT" "$GW"
