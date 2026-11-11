# Nasazení: GitHub + Portainer

## 0. Interaktivní volba sítě (doporučeno)

Na RPi nebo před push na Git:

```bash
cd pin-manager
python3 scripts/configure.py
```

Skript se zeptá:

1. **VLAN (macvlan)** – vlastní IP (např. `192.168.39.207`), síť `docker_vlan`, **bez mapování portů**
2. **Server + port** – `PORTAL_IP` hostitele a mapování např. `80:8080`

Vygeneruje `.env`, `portainer-stack.yml` a doporučený **Compose path** pro Portainer.

### VLAN – síť v Portaineru (vaše nastavení)

| Pole | Hodnota |
|------|---------|
| Driver | `macvlan` |
| Subnet | `192.168.39.0/24` |
| Gateway | `192.168.39.1` |
| Název | `docker_vlan` |

Kontejner PIN manažer: IP **`192.168.39.207`**, `LISTEN_PORT=80`, sinkhole `PORTAL_IP=192.168.39.207`.

V stacku env:

| Klíč | Hodnota |
|------|---------|
| `VLAN_NETWORK_NAME` | `docker_vlan` |
| `VLAN_IP` | `192.168.39.207` |
| `PORTAL_IP` | `192.168.39.207` |

**Compose path v Portaineru:** `portainer-stack.vlan.yml`

Macvlan síť musí používat parent interface (v Dockeru / na hostu) – obvykle už máte síť vytvořenou jako na screenshotu v Portaineru.

### Režim server + port

**Compose path:** `portainer-stack.bridge.yml`

Env: `PORTAL_IP`, `HOST_PORT` (např. 80).

---

## 1. Repozitář na GitHubu

Kořen repa = obsah složky `pin-manager`.

```bash
python3 scripts/configure.py   # volba vlan vs bridge
git init -b main
git add .
git commit -m "PIN manažer: sidecar pro Pi-hole"
git remote add origin https://github.com/VAS-ORG/pin-manager.git
git push -u origin main
```

**Nikdy necommitujte `.env`.**

## 2. Sdílená složka s Pi-hole (sinkhole)

```yaml
volumes:
  - /opt/pin-manager/dnsmasq-sync:/etc/dnsmasq.d/pin-manager:ro
environment:
  FTLCONF_misc_etc_dnsmasq_d: "true"
```

`DNSMASQ_SYNC_HOST_PATH=/opt/pin-manager/dnsmasq-sync`

## 3. Portainer – stack z Gitu

1. **Stacks** → **Add stack** → **Git repository**
2. **Compose path:**  
   - VLAN: `portainer-stack.vlan.yml`  
   - Bridge: `portainer-stack.bridge.yml`
3. Environment z `.env` (včetně `VLAN_IP` / `HOST_PORT` podle režimu)
4. **Deploy**

## 4. Administrace

- VLAN: `http://192.168.39.207/admin/`
- Bridge: `http://PORTAL_IP:HOST_PORT/admin/`

## 5. Pi-hole URL

V macvlan režimu často `PIHOLE_URL=http://192.168.39.x` (IP Pi-hole v LAN), nejméně přes docker network name – záleží kde Pi-hole běží.

## 6. Port 80 ve VLAN režimu

Kontejner naslouchá přímo na **80** na dedicované IP – není potřeba mapovat porty na hostiteli. Pi-hole admin držte na jiné IP/portu.
