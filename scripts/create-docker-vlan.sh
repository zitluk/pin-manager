#!/usr/bin/env bash
# Vytvoří macvlan síť docker_vlan pro PIN manažer (192.168.39.0/24).
# Použití: sudo bash scripts/create-docker-vlan.sh [parent_interface] [gateway]
set -euo pipefail

PARENT="${1:-}"
GATEWAY="${2:-192.168.39.1}"
SUBNET="192.168.39.0/24"
NAME="${MACVLAN_NETWORK_NAME:-docker_vlan}"

if [[ -z "$PARENT" ]]; then
  PARENT="$(ip -4 route show default 2>/dev/null | awk '{print $5}' | head -1)"
fi

if [[ -z "$PARENT" ]]; then
  echo "Nelze zjistit síťové rozhraní. Zadejte: $0 eth0 [gateway]" >&2
  exit 1
fi

if ! ip link show "$PARENT" &>/dev/null; then
  echo "Rozhraní '$PARENT' neexistuje. Dostupná: $(ip -o link show | awk -F': ' '{print $2}' | tr '\n' ' ')" >&2
  exit 1
fi

echo "Parent: $PARENT"
echo "Subnet: $SUBNET"
echo "Gateway: $GATEWAY"
echo "Název sítě: $NAME"

if docker network inspect "$NAME" &>/dev/null; then
  echo "Síť $NAME už existuje. Pro převytvoření nejdřív: docker stop pin-manager; docker network rm $NAME"
  docker network inspect "$NAME" --format 'Driver={{.Driver}} Subnet={{(index .IPAM.Config 0).Subnet}} Parent={{index .Options "parent"}}'
  exit 0
fi

docker network create -d macvlan \
  --subnet="$SUBNET" \
  --gateway="$GATEWAY" \
  -o parent="$PARENT" \
  "$NAME"

echo "Hotovo. Portainer → Pull and redeploy stack pin-manager."
