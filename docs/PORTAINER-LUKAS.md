# Portainer – nasazení (Lukas, VLAN)

## Stack z Gitu

| Pole | Hodnota |
|------|---------|
| Repository | `https://github.com/zitluk/pin-manager` |
| Reference | `refs/heads/main` |
| **Compose path** | **`portainer-stack.yml`** |

Žádné `ports:` – kontejner má IP **192.168.39.207** na síti **docker_vlan**, HTTP port **80 jen na té IP**.

## Env ve stacku (vyplňte tajné údaje)

```
PORTAL_IP=192.168.39.207
VLAN_IP=192.168.39.207
VLAN_NETWORK_NAME=docker_vlan
DNSMASQ_SYNC_HOST_PATH=/opt/pin-manager/dnsmasq-sync
PIHOLE_URL=http://<IP vašeho Pi-hole>
PIHOLE_PASSWORD=<heslo Pi-hole web>
PIN=<rodičovský PIN>
ADMIN_TOKEN=<dlouhý token>
SESSION_SECRET=<jiný dlouhý secret>
```

`PORTAL_IP`, `VLAN_IP` a `VLAN_NETWORK_NAME` mohou zůstat prázdné – v compose jsou výchozí `192.168.39.207` / `docker_vlan`.

## Pi-hole (sinkhole)

Na hostiteli:

```bash
sudo mkdir -p /opt/pin-manager/dnsmasq-sync
```

V Pi-hole stacku volume:

```yaml
- /opt/pin-manager/dnsmasq-sync:/etc/dnsmasq.d/pin-manager:ro
```

```yaml
FTLCONF_misc_etc_dnsmasq_d: "true"
```

## Po deployi

- Admin: **http://192.168.39.207/admin/**
- Port 80 na **hostiteli RPi** se neobsazuje – konflikt s Pi-hole na host:80 tím pádem nevzniká.

## Časté chyby

1. **Compose path** `docker-compose.yml` → mapuje host :80 → použijte `portainer-stack.yml`.
2. **Síť docker_vlan** musí v Portaineru existovat (macvlan, subnet 192.168.39.0/24).
