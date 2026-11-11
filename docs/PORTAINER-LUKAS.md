# Portainer – nasazení (Lukas, VLAN)

## Stack z Gitu

| Pole | Hodnota |
|------|---------|
| Repository | `https://github.com/zitluk/pin-manager` |
| Reference | `refs/heads/main` |
| **Compose path** | **`portainer-stack.yml`** |

Žádné `ports:` – kontejner má IP **192.168.39.207** na síti **docker_vlan**, HTTP port **80 jen na té IP**.

**`ERR_ADDRESS_UNREACHABLE` u 192.168.39.207?**

IP v síti **vůbec neexistuje** (ne chyba aplikace). Podrobný postup: **[SIT-NEJDE-207.md](./SIT-NEJDE-207.md)**.

Zkráceně:

1. PC/telefon musí být ve **stejné síti 192.168.39.x** (ne jiná podsíť).
2. Portainer: kontejner **pin-manager** = **running**.
3. Na RPi: síť **`docker_vlan`** (macvlan) – skript `scripts/create-docker-vlan.sh`.
4. Mikrotik: **.207** nevydávat jinému zařízení přes DHCP.
5. Test z PC: `ping 192.168.39.207`, pak `http://192.168.39.207/health`.
6. Z **prohlížeče na RPi** macvlan často nejde – testujte z jiného zařízení.

## Env ve stacku (vyplňte tajné údaje)

```
PORTAL_IP=192.168.39.207
VLAN_IP=192.168.39.207
VLAN_NETWORK_NAME=docker_vlan
MACVLAN_PARENT=eth0
MACVLAN_SUBNET=192.168.39.0/24
MACVLAN_GATEWAY=192.168.39.1
DNSMASQ_SYNC_HOST_PATH=/opt/pin-manager/dnsmasq-sync
PIHOLE_URL=http://<IP vašeho Pi-hole>
PIHOLE_PASSWORD=<heslo Pi-hole web>
PIN=<rodičovský PIN>
SESSION_SECRET=<volitelné; jinak se vygeneruje v /data při první registraci>
```

`PORTAL_IP` a `VLAN_IP` = stejná IP (**192.168.39.207**).

**Před prvním deployem** (nebo po chybě sítě) na RPi jednou:

```bash
cd /cesta/k/repu/pin-manager   # nebo stáhněte jen skript
sudo bash scripts/fix-macvlan-overlap.sh end0 192.168.39.1
```

(`end0` / gateway upravte.) Stack pak používá **existující** síť `docker_vlan` (`MACVLAN_NETWORK_NAME=docker_vlan`).

**`MACVLAN_PARENT`** – rozhraní k síti. Na novém RPi často **`end0`**, ne `eth0`:

```bash
ip -4 route show default | awk '{print $5}'
```

Tu hodnotu vložte do env stacku jako `MACVLAN_PARENT`.

### Chyba: `Pool overlaps with other one on this address space`

Docker už má **jinou síť** se subnetem `192.168.39.0/24` (typicky starý `docker_vlan` + nový `pin-manager-macvlan`).

```bash
sudo bash scripts/fix-macvlan-overlap.sh end0 192.168.39.1
```

Pak **Pull and redeploy** stacku `portainer-stack.yml` (síť je **external**, stack ji znovu nevytváří).

### Chyba: `network docker_vlan was found but has incorrect label com.docker.compose.network`

Na RPi dříve existovala síť **`docker_vlan`** vytvořená ručně – nesedí s Portainer compose.

**Oprava (jednou):**

```bash
docker stop pin-manager 2>/dev/null; docker rm pin-manager 2>/dev/null
docker network rm docker_vlan 2>/dev/null || true
```

**Pull and redeploy** – nový stack používá síť **`pin-manager-macvlan`** (ne `docker_vlan`).

Volitelně smažte i starou, pokud deploy hlásí konflikt:

```bash
docker network rm pin-manager-macvlan
```

### `docker_vlan: invalid IP`

Na RPi:

```bash
# Kolize IP v LAN?
ping -c 1 192.168.39.207
arp -a | grep 192.168.39.207

docker network inspect docker_vlan --format '{{json .IPAM.Config}}'

# Znovu připojit
docker stop pin-manager && docker rm pin-manager
# Portainer → Pull and redeploy
```

IP `.207` nesmí používat jiné zařízení ani druhý kontejner. Síť `docker_vlan` musí mít subnet **192.168.39.0/24**.

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

## Chyba „pull access denied for pin-manager“

Image **není na Docker Hubu** – vzniká **buildem** ze složky `app/` v Gitu. V compose je `pull_policy: build`.

Ve stacku: **Pull and redeploy** po novém commitu. Pokud Portainer stále táhne z registru, v nastavení stacku vypněte **Pull latest image** / nechte jen **Build** (podle verze UI: *Deployment* → build from repository).

Ručně na RPi (v adresáři, kam Portainer klonuje repo):

```bash
cd /data/compose/<id>
docker compose -f portainer-stack.yml build --no-cache
docker compose -f portainer-stack.yml up -d
```

## Automatický redeploy po `git push`

Nastavení webhooku + GitHub secret: **[AUTO-DEPLOY.md](AUTO-DEPLOY.md)**.

## Po deployi

- Admin: **http://192.168.39.207/admin/** → při prvním návštěvě **registrace administrátora** (jméno + heslo)
- **API token** se zobrazí jednou po registraci; uložte ho pro REST (`Authorization: Bearer …`)

`ADMIN_TOKEN` v Portaineru už **nepotřebujete** (volitelný legacy).
- Port 80 na **hostiteli RPi** se neobsazuje – konflikt s Pi-hole na host:80 tím pádem nevzniká.

## Časté chyby

1. **„address already in use“ :8080 nebo :80** – stack stále drží starý compose s `ports:` (např. dřívější `docker-compose.yml`). **Stacks → Remove stack** (včetně kontejneru), znovu **Add stack** z Gitu, compose **`portainer-stack.yml`**. Nepoužívejte `portainer-stack.bridge.yml`.
2. **Síť docker_vlan** musí v Portaineru existovat (macvlan, subnet 192.168.39.0/24).
3. Ve stacku vypněte / neskládejte **Web editor** přes starý YAML s `ports:` – musí platit jen soubor z Gitu.
