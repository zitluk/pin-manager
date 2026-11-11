# Pi-hole napojení – jednoduše (bez sdílené složky)

## Proč to **není** odkaz jako reklamní blacklist?

V Pi-hole u „Group Management → Adlists“ vkládáte **URL seznamu reklamních domén**. Pi-hole je stáhne a zablokuje je (většinou na `0.0.0.0`).

PIN manažer ale potřebuje něco jiného: když někdo otevře `youtube.com`, DNS musí vrátit **IP portálu** (`192.168.39.207`), aby se zobrazila stránka s PINem – ne černá díra.

To Pi-hole umí jako **Local DNS / DNS records** (v API `dns.hosts`):  
„`youtube.com` → `192.168.39.207`“.

PIN manažer to zapisuje **sám přes API** – vy **nic** do Pi-hole ručně nevkládáte a **žádný GitHub odkaz** tam dávat nemusíte.

---

## Co musíte udělat vy (Portainer)

Ve stacku **pin-manager** nastavte jen tyto proměnné:

| Proměnná | Příklad |
|----------|---------|
| `PIHOLE_URL` | `http://192.168.1.10` (IP nebo hostname webu Pi-hole) |
| `PIHOLE_PASSWORD` | heslo z webu Pi-hole |
| `PORTAL_IP` | `192.168.39.207` (IP kontejneru pin-manager ve VLAN) |

Volitelně (výchozí je už správně):

- `PIHOLE_SINKHOLE_MODE=api` – jen API (doporučeno)
- `PIHOLE_SINKHOLE_MODE=file` – starý režim se sdíleným souborem (viz `AKTIVACE-BLOKOVANI.md`)

**Pi-hole stack neměňte** – žádný mount, žádný extra config.

---

## Co se děje po přidání domény v adminu

1. PIN manažer se přihlásí k Pi-hole API.
2. Do **Local DNS records** doplní řádky typu `192.168.39.207 youtube.com`.
3. V Pi-hole uvidíte záznamy v nastavení DNS (podle verze: *Local DNS* / *DNS records*).

Po odemčení PINem se doména dočasně odebere z těchto záznamů a přidá se allow v gravity (pokud to verze podporuje).

---

## Jak ověřit, že to funguje

Na PC v síti (kde je DNS = Pi-hole):

```bash
nslookup youtube.com
```

Mělo by vrátit **`192.168.39.207`**, ne veřejnou IP YouTube.

Pak v prohlížeči otevřete `http://youtube.com` – měl by se ukázat PIN portál (nebo HTTPS varování; u YouTube často potřebujete i další domény jako `googlevideo.com`).

---

## Když to nefunguje

1. **Špatné `PIHOLE_URL`** – z kontejneru pin-manager musí být Pi-hole dostupné (zkuste IP LAN, ne `localhost`).
2. **Špatné heslo** – v logu kontejneru pin-manager uvidíte chybu přihlášení.
3. **Starý režim `file`** – bez sdílené složky s Pi-hole DNS nefunguje; přepněte na `api`.

Github repozitář **pin-manager** slouží jen pro **nasazení stacku v Portaineru** (Git repository URL), ne jako blacklist adlist v Pi-hole.
