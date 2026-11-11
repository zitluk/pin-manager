# PIN manažer (Pi-hole sidecar)

DNS blacklist s PIN autorizací: blokovaná doména se přesměruje na portál, po PINu a výběru délky povolení se uživatel vrátí na původní URL.

## Jak to funguje

1. Domény udržujete v **PIN manažeru** (REST API `/admin/blacklist`).
2. Služba vygeneruje `pin-sinkhole.conf` (`address=/domena/PORTAL_IP`). **Nepoužívá Pi-hole deny** – ten by vracel `0.0.0.0` a portál by se neukázal. Při povolení volitelně přidá **allow**, pokud je doména i na gravity listu.
3. Klient otevře stránku → DNS vrátí IP RPi → HTTP požadavek s hlavičkou `Host: domena` zachytí portál (modal PIN + délka).
4. Po úspěchu: dočasné **allow** v Pi-hole, doména zmizí ze sinkhole, po vypršení času se vše vrátí.

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
- Přihlášení hodnotou `ADMIN_TOKEN` (nastavená v Portaineru / `.env`)
- Správa blacklistu, dočasná povolení a **protokol** (`/admin/logs`) – kdo (IP), kdy a co

**Před nasazením** spusťte `python3 scripts/configure.py` – zeptá se na **VLAN (macvlan, vlastní IP bez portů)** nebo **IP serveru + port**.

Nasazení přes GitHub a Portainer: viz [docs/PORTAINER-GITHUB.md](docs/PORTAINER-GITHUB.md).  
VLAN příklad: síť `docker_vlan`, IP `192.168.39.207`, compose `portainer-stack.vlan.yml`.

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
