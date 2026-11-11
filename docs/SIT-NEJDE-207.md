# „ERR_ADDRESS_UNREACHABLE“ u 192.168.39.207

Prohlížeč tím říká: **v síti nikdo na té IP neodpovídá** (je to ještě před načtením stránky). Nejde o špatné heslo ani Pi-hole – **počítač se k `.207` vůbec nedostane**.

PIN portál musí běžet na **vlastní IP** (macvlan), aby na portu 80 mohl být zároveň Pi-hole na RPi.

---

## Rychlá kontrola (z PC nebo telefonu ve Wi‑Fi)

1. V terminálu: `ipconfig` (Windows) / nastavení sítě – jste v rozsahu **192.168.39.x**?
   - Když máte třeba **192.168.1.x**, adresa **192.168.39.207** bude vždy „nedostupná“ → připojte se do stejné sítě jako RPi (39.x).
2. `ping 192.168.39.207`
   - **Timeout / nedostupné** → pokračujte níže (Docker / macvlan).
   - **Odpověď** → síť OK, zkuste `http://192.168.39.207/health`.

---

## Diagnostika na Raspberry Pi (SSH nebo konzole)

Spusťte a uložte výstup (nebo ho pošlete do chatu):

```bash
docker ps -a --filter name=pin-manager --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'

docker inspect pin-manager --format 'Sítě: {{json .NetworkSettings.Networks}}' 2>/dev/null | python3 -m json.tool

docker network inspect docker_vlan 2>/dev/null | head -80

ip -4 addr show
ip -4 route show default
```

### Co hledat

| Stav | Význam |
|------|--------|
| Kontejner **není** `Up` | Stack nenaběhl – v Portaineru **Logs**, často restart nebo chyba sítě. |
| V síti **není** `192.168.39.207` | Macvlan se nepřipojil – špatná síť `docker_vlan` nebo kolize IP. |
| `docker network inspect docker_vlan` **chyba** | Síť neexistuje – vytvořte (viz níže). |
| `ping 192.168.39.207` z RPi **nejde** | U macvlan je to **normální** – zkoušejte z **jiného** zařízení v LAN. |
| Z PC ve 39.x **ping nejde** | Macvlan špatně (parent rozhraní), nebo **.207 drží jiné zařízení** (Mikrotik DHCP). |

---

## Oprava 1: Volná IP a Mikrotik

1. V Mikrotiku: **vylučte 192.168.39.207 z DHCP poolu** nebo dejte **statickou rezervaci** jen pro PIN manažer.
2. Z PC: `ping 192.168.39.207` – před deployem by **neměl** odpovídat jiný stroj (nebo odpovídá jen krátce staré ARP).

---

## Oprava 2: Znovu vytvořit síť `docker_vlan`

Na RPi zjistěte rozhraní do LAN (většinou `eth0` nebo `end0`):

```bash
ip -4 route show default | awk '{print $5}'
```

Skript z repozitáře (po `git pull`):

```bash
cd /cesta/k/pin-manager   # nebo kde máte klon
sudo bash scripts/create-docker-vlan.sh eth0
```

Nebo ručně (upravte `parent=` a `gateway=` podle Mikrotiku):

```bash
docker stop pin-manager 2>/dev/null
docker network rm docker_vlan 2>/dev/null || true

docker network create -d macvlan \
  --subnet=192.168.39.0/24 \
  --gateway=192.168.39.1 \
  -o parent=eth0 \
  docker_vlan
```

Pak **Portainer → stack pin-manager → Pull and redeploy**.

Gateway musí být **Mikrotik v 39.x** (často `.1`, u vás může být jiná – zkontrolujte v routeru).

---

## Oprava 3: Portainer stack

| Pole | Hodnota |
|------|---------|
| Compose path | **`portainer-stack.yml`** |
| Env | `PORTAL_IP=192.168.39.207` (bez prázdného `VLAN_IP`) |

Ve stacku **nesmí** být `ports:` mapující 80 na hostitele – IP má být jen na macvlan.

---

## Když macvlan nechcete řešit (dočasně jen admin)

**Plný PIN portál přes DNS potřebuje funkční IP na portu 80** (typicky `.207`).  
Dočasně můžete otevřít **jen administraci** přes bridge stack a jiný port – viz `portainer-stack.bridge.yml` a nastavte `PORTAL_IP` na IP, která **opravdu** odpovídá na port 80 (jinak blokované domény na portál nepůjdou).

Produkce = opravit macvlan podle kroků výše.

---

## Shrnutí jednou větou

**ERR_ADDRESS_UNREACHABLE** = zařízení v síti **192.168.39.207 nevidí** → opravte **docker_vlan + běžící kontejner + volnou IP**, testujte z PC ve **192.168.39.x**, ne z prohlížeče na samotném RPi.
