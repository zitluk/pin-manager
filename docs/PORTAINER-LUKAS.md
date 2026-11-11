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

`PORTAL_IP` nastavte `192.168.39.207` (nebo nechte v compose default). **Nenastavujte** prázdné `VLAN_IP` – dříve způsobilo `invalid IP`; IP je teď v compose natvrdo.

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

- Admin: **http://192.168.39.207/admin/**
- Port 80 na **hostiteli RPi** se neobsazuje – konflikt s Pi-hole na host:80 tím pádem nevzniká.

## Časté chyby

1. **„address already in use“ :8080 nebo :80** – stack stále drží starý compose s `ports:` (např. dřívější `docker-compose.yml`). **Stacks → Remove stack** (včetně kontejneru), znovu **Add stack** z Gitu, compose **`portainer-stack.yml`**. Nepoužívejte `portainer-stack.bridge.yml`.
2. **Síť docker_vlan** musí v Portaineru existovat (macvlan, subnet 192.168.39.0/24).
3. Ve stacku vypněte / neskládejte **Web editor** přes starý YAML s `ports:` – musí platit jen soubor z Gitu.
