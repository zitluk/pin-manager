# Kam v Portaineru dát PIHOLE_URL, heslo a PORTAL_IP

Máte stránku **Stack details** u **pin-manager** a sekci **Environment variables** – **přesně tam**.

---

## Co udělat na obrazovce, kterou vidíte

1. V sekci **Environment variables** klikněte na **Switch to simple mode** (přepnout na jednoduchý režim).
2. Do velkého pole (kde je nápověda `e.g. key=value`) **smažte** starý obsah a **vložte** např.:

```env
PIHOLE_URL=http://192.168.39.5
PIHOLE_PASSWORD=vaše_heslo_do_pihole
PORTAL_IP=192.168.39.207
VLAN_IP=192.168.39.207
PIN=1234
MACVLAN_NETWORK_NAME=docker_vlan
MACVLAN_PARENT=end0
MACVLAN_SUBNET=192.168.39.0/24
MACVLAN_GATEWAY=192.168.39.1
```

- `PIHOLE_URL` – IP Pi-hole v prohlížeči (bez `/admin`).
- `MACVLAN_PARENT` – na RPi: `ip route | grep default` (často `end0`).
- `MACVLAN_GATEWAY` – Mikrotik ve 39.x.

Šablona v Gitu: soubor **`stack.env.example`** (jen kopírovat do Portaineru, neukládat heslo do Gitu).

3. **Uložit** stránku stacku (pokud je tlačítko **Update stack** / změny se jen automaticky pamatují – záleží na verzi).

4. Nahoře na stejné stránce: **Pull and redeploy** / **Redeploy from git repository** – **bez toho se env nepoužije** (Portainer to píše: *Environment changes will not take effect until redeployment*).

5. Po chvíli v sekci **Containers** musí být kontejner **`pin-manager`** ve stavu **running**.  
   Když je **No items available** → deploy spadl (síť / compose) – po redeploy zkontrolujte **Notifications** nebo log deploye.

---

## Git + stack.env (nepovinné)

Portainer píše, že **`stack.env` v repu** je potřeba jen pokud na něj compose **odkazuje**.  
Náš **`portainer-stack.yml`** používá `${PIHOLE_URL}` z **pole Environment variables** výše – **stack.env v Gitu nepotřebujete**.

---

## Kontrola na RPi

```bash
docker ps -a --filter name=pin-manager
docker inspect pin-manager --format '{{range .Config.Env}}{{println .}}{{end}}' | grep -E '^PIHOLE_|^PORTAL'
```

---

## Shrnutí

| Kde na stránce | Co |
|----------------|-----|
| **Environment variables** → **simple mode** | řádky `PIHOLE_URL=...` atd. |
| **Pull and redeploy** | po vyplnění env |
| **Containers** (dole) | musí být `pin-manager` running |

| Kde **ne** | |
|-------------|--|
| Pi-hole web | nic |
| docker-compose.yml v Gitu ručně | nemusíte |
