# PIN manažer (Pi-hole sidecar)

DNS blacklist s PIN autorizací: blokovaná doména se přesměruje na portál, po PINu a výběru délky povolení se uživatel vrátí na původní URL.

## Jak to funguje

1. Domény udržujete v **PIN manažeru** (admin `/admin/`).
2. Blokovaná doména **i všechny její poddomény** (`m.youtube.com`, `i.ytimg.com`…) vedou v DNS na **PORTAL_IP** (Pi-hole `misc.dnsmasq_lines` → `address=/doména/PORTAL_IP`) → v prohlížeči formulář **PIN**.
   Záznamy AAAA a HTTPS/SVCB vracejí pro blokované domény prázdnou odpověď – jinak by Safari z HTTPS záznamu vzalo skutečnou IP a portál obešlo.
3. **HTTPS bez varování:** na každém zařízení jednou otevřete **`http://PORTAL_IP/setup`** – stáhne profil/certifikát domácí CA a ověří, že zařízení jde přes Pi-hole a CA důvěřuje. Certifikát pro konkrétní doménu se vystaví automaticky při prvním přístupu (bez restartu).
   Bez důvěryhodné CA se weby s HSTS (YouTube) v Safari **neotevřou vůbec** – to nejde obejít jinak.
4. Po úspěchu: dočasné povolení, doména zmizí z DNS blokace, po vypršení času se vše vrátí.
5. Obchvaty: iCloud Soukromý přenos a automatické DoH ve Firefoxu síť blokuje (NXDOMAIN pro `mask.icloud.com`, `use-application-dns.net`; vypnout `BLOCK_DNS_BYPASS=false`).

## Požadavky

- Pi-hole v6 (Docker), DNS už používají klienti v síti (Mikrotik DHCP).
- **Port 80 na RPi** pro `pin-manager` (Pi-hole admin raději na jiném portu, např. `8080:80`).
- Pi-hole: `FTLCONF_misc_etc_dnsmasq_d=true` a sdílený soubor:

```yaml
volumes:
  - /cesta/k/pin-manager/dnsmasq-sync:/etc/dnsmasq.d/pin-manager:ro
```

Soubor `dnsmasq-sync/pin-sinkhole.conf` generuje kontejner `pin-manager`.

## Administrace (web)

- URL: `http://PORTAL_IP/admin/`
- První návštěva: **registrace administrátora** (jméno + heslo), pak přihlášení
- Správa blacklistu, dočasná povolení a **protokol** (`/admin/logs`) – kdo (IP), kdy a co

**Před nasazením** spusťte `python3 scripts/configure.py` – zeptá se na **VLAN (macvlan, vlastní IP bez portů)** nebo **IP serveru + port**.

Nasazení přes GitHub a Portainer: viz [docs/PORTAINER-GITHUB.md](docs/PORTAINER-GITHUB.md).  
**Lukas (produkce):** VLAN `docker_vlan`, IP **`192.168.39.207`** → Portainer compose path **`portainer-stack.yml`**. Auto deploy po push: [docs/AUTO-DEPLOY.md](docs/AUTO-DEPLOY.md). Viz [docs/PORTAINER-LUKAS.md](docs/PORTAINER-LUKAS.md).

**Ověření:** po každém push běží GitHub Actions [`.github/workflows/ci.yml`](.github/workflows/ci.yml) (pytest, build, smoke `/health`). Lokálně: `bash scripts/verify-all.sh` (potřebuje Docker).

## Rychlý start

```bash
cp .env.example .env
# upravte PIHOLE_URL, PORTAL_IP, PIN, PIHOLE_PASSWORD, ADMIN_TOKEN

docker compose up -d --build
```

### Přidání domény na blacklist

```bash
curl -X POST http://192.168.x.x/admin/blacklist \
  -H "Authorization: Bearer VÁŠ_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com"}'
```

### Pi-hole síť v Dockeru

Pokud Pi-hole běží ve stejném Docker hostu, přidejte do `docker-compose.yml` externí síť nebo nastavte `PIHOLE_URL=http://IP_RPi:8080` (nebo hostname kontejneru přes `extra_hosts` / sdílenou network).

## Proměnné prostředí

| Proměnná | Význam |
|----------|--------|
| `PORTAL_IP` | LAN IP RPi – musí sedět s `address=` v dnsmasq |
| `PIHOLE_URL` | Base URL Pi-hole (bez lomítka na konci) |
| `PIHOLE_PASSWORD` | Heslo do webu Pi-hole |
| `PIN` nebo `PIN_HASH` | Rodičovský PIN (`python -c "import bcrypt; print(bcrypt.hashpw(b'1234', bcrypt.gensalt()).decode())"`) |
| `DURATION_OPTIONS` | Minuty v UI, např. `15,30,60,120` |
| `ADMIN_TOKEN` | Bearer token pro správu blacklistu |

## HTTPS a HSTS

Prohlížeč nejdřív často volá **HTTPS**. U blokované domény uvidíte chybu certifikátu, dokud DNS neukáže na portál a neproběhne **HTTP** (nebo dokud po odblokování DNS neukáže na reálný server). Po PINu stránka s krátkým čekáním přesměruje na `https://…`.

## Omezení

- Obcházení jiným DNS / VPN / mobilními daty – řeší firewall, ne tento projekt.
- IPv6 u vás vypnuto – není potřeba `local=/` pro AAAA.

## Struktura

```
pin-manager/
  docker-compose.yml
  dnsmasq-sync/          # sdílet s Pi-hole
  app/                   # FastAPI služba
```
