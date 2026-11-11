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

### VLAN – macvlan a IP `.207`

Stack **`portainer-stack.yml`** sám vytvoří síť `docker_vlan` a přidělí IP (už nemusíte síť zakládat ručně v Portaineru).

V stacku env:

| Klíč | Hodnota |
|------|---------|
| `VLAN_IP` / `PORTAL_IP` | `192.168.39.207` |
| `MACVLAN_PARENT` | `eth0` nebo `end0` (`ip route \| grep default`) |
| `MACVLAN_GATEWAY` | Mikrotik ve 39.x |
| `MACVLAN_SUBNET` | `192.168.39.0/24` |

**Compose path v Portaineru:** `portainer-stack.yml` (nebo `portainer-stack.vlan.yml` – stejné chování).

Když kontejner nemá IP: [SIT-NEJDE-207.md](./SIT-NEJDE-207.md).

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
(Výchozí v compose je `/opt/pin-manager/dnsmasq-sync` – Docker složku vytvoří sám (`create_host_path`). **Nepoužívejte** relativní `./dnsmasq-sync` v Portaineru, pokud složka v repu není na disku hostitele.)

### Chyba „address already in use“ na portu 80

Port **80 na hostiteli** už používá jiná služba (často **Pi-hole** nebo nginx).

| Režim | Řešení |
|--------|--------|
| **VLAN** (`192.168.39.207`) | Compose path musí být **`portainer-stack.vlan.yml`** – **žádné** `ports:` na hostiteli. Kontejner má vlastní IP a port 80 jen na ní. |
| **Bridge** | Nepublikujte 80, pokud je obsazený – u PIN sinkhole je VLAN vhodnější. Bridge dává smysl jen když host port 80 volný. |

V Portaineru zkontrolujte **Compose path** – nepoužívejte `docker-compose.yml` ani `portainer-stack.bridge.yml`, pokud chcete macvlan.

Po změně path: stack **Remove** → znovu **Deploy** (nebo Pull and redeploy).

### Chyba „no such file or directory“ u volume

Starší compose používal named volume s `device: ./dnsmasq-sync` → Portainer mapoval na `/data/compose/<id>/dnsmasq-sync`, která neexistovala. Řešení: **Pull and redeploy** nového commitu, nebo nastavte absolutní cestu:

```bash
sudo mkdir -p /opt/pin-manager/dnsmasq-sync
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
