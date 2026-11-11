# Kam v Portaineru dát PIHOLE_URL, heslo a PORTAL_IP

Tyto hodnoty **nejsou** v Pi-hole. Patří do **stacku pin-manager** v Portaineru jako **proměnné prostředí** (Environment variables).

---

## Krok za krokem (Portainer 2.x)

1. V levém menu klikněte **Stacks** (Správa zásobníků / Zásobníky).
2. V seznamu otevřete stack **`pin-manager`** (název může být i trochu jiný – ten, kde běží Git repozitář `zitluk/pin-manager`).
3. Nahoře uvidíte záložky, typicky:
   - **Editor** nebo **Stack**
   - **Environment variables** / **Proměnné prostředí**
4. Klikněte na **Environment variables** (někdy je až po rozkliknutí **Advanced mode** / **Pokročilé** při úpravě stacku).

Tam přidávejte řádky jako v tabulce níže (**Add an environment variable** / **Přidat proměnnou**).

5. Po každé změně dole **Update the stack** / **Aktualizovat zásobník** (nebo **Pull and redeploy**, pokud jen stáhnete Git).

---

## Když záložku „Environment variables“ nevidíte

### Varianta A – úprava stacku

1. **Stacks** → váš stack → tři tečky **⋮** → **Editor** nebo **Edit**.
2. Zapněte **Advanced mode**.
3. Sekce **Environment variables** – přidat klíč a hodnotu.

### Varianta B – jen kontejner (nouzově, nedoporučeno)

1. **Containers** → **pin-manager** → **Duplicate / Edit** (nebo **Recreate**).
2. Sekce **Env** – přidat proměnné.
3. Lepší je **opravit stack** (varianta A), jinak po redeploy z Gitu změny zmizí.

### Varianta C – stack jste zakládali bez Gitu

Při **Add stack** je nahoře záložka **Environment variables** ještě **před** deployem. U existujícího stacku použijte variantu A.

---

## Co přesně přidat (klíč = jméno, hodnota = value)

| Jméno (name) | Hodnota (value) – příklad |
|--------------|---------------------------|
| `PIHOLE_URL` | `http://192.168.39.5` ← vaše reálná IP Pi-hole |
| `PIHOLE_PASSWORD` | vaše heslo do Pi-hole webu |
| `PORTAL_IP` | `192.168.39.207` |
| `VLAN_IP` | `192.168.39.207` |
| `PIN` | rodičovský PIN (4–8 znaků) |
| `MACVLAN_NETWORK_NAME` | `docker_vlan` |
| `MACVLAN_PARENT` | `end0` nebo `eth0` (viz `ip route` na RPi) |
| `MACVLAN_GATEWAY` | IP Mikrotiku ve 39.x, často `192.168.39.1` |

**Pozor:** pište **jméno bez** `=` a hodnotu zvlášť – v Portaineru jsou to dvě kolonky (name / value), ne jeden řádek `PIHOLE_URL=http://...` do compose souboru (pokud to UI neumožňuje jinak).

---

## Jak poznáte, že to funguje

1. **Containers** → **pin-manager** → **Logs** – po startu by neměly být chyby auth k Pi-hole.
2. **http://192.168.39.207/admin/** → **Znovu synchronizovat Pi-hole** → **API OK**.

---

## Kontrola, že proměnné v kontejneru jsou

Na RPi (SSH), jen pro kontrolu – **heslo neukazuje**:

```bash
docker inspect pin-manager --format '{{range .Config.Env}}{{println .}}{{end}}' | grep -E '^PIHOLE_|^PORTAL'
```

Měli byste vidět např. `PIHOLE_URL=http://192.168.39.5` a `PORTAL_IP=192.168.39.207`.

Když tam **nic není** → env v Portaineru u stacku opravdu nejsou nastavené.

---

## Shrnutí

| Kde | Co |
|-----|-----|
| **Portainer → Stacks → pin-manager → Environment variables** | `PIHOLE_URL`, `PIHOLE_PASSWORD`, `PORTAL_IP`, … |
| **Pi-hole web** | nic nepřidáváte |
| **Compose soubor v Gitu** | nemusíte editovat ručně |
