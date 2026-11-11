# Jak aktivovat blokování (proč stránka „normálně funguje“)

PIN manažer **nesleduje URL v prohlížeči sám**. Funguje jen když platí **řetězec DNS → sinkhole → portál**.

## Co musí platit (kontrolní seznam)

### 1. Blacklist v adminu

- Zadávejte jen **doménu**: `youtube.com` (ne `https://www.youtube.com/`).
- Po přidání se vygeneruje soubor sinkhole (viz bod 2).

### 2. Sdílená složka Pi-hole + PIN manažer

Na hostiteli (RPi) musí existovat např. **`/opt/pin-manager/dnsmasq-sync`**.

- **PIN manažer** (Portainer env): `DNSMASQ_SYNC_HOST_PATH=/opt/pin-manager/dnsmasq-sync`
- Po přidání domény tam musí být **`pin-sinkhole.conf`** s řádkem:

```text
address=/youtube.com/192.168.39.207
```

### 3. Pi-hole musí soubor načíst

V stacku **Pi-hole**:

```yaml
volumes:
  - /opt/pin-manager/dnsmasq-sync:/etc/dnsmasq.d/pin-manager:ro
environment:
  FTLCONF_misc_etc_dnsmasq_d: "true"
```

Po změně: **Restart DNS** v Pi-hole (nebo restart kontejneru).

### 4. Klient musí používat Pi-hole jako DNS

- DHCP (Mikrotik) → DNS = IP Pi-hole.
- Test z PC: `nslookup youtube.com` → odpověď musí být **`192.168.39.207`**, ne IP Google/YouTube.

Když nslookup vrátí reálnou IP YouTube → blokování **neběží** (špatný DNS nebo sinkhole se nenačetl).

### 5. PORTAL_IP v Portaineru

`PORTAL_IP=192.168.39.207` (stejná IP jako v `address=`).

### 6. Pi-hole API (volitelně)

`PIHOLE_URL` a `PIHOLE_PASSWORD` – pokud špatně, sinkhole soubor se stejně zapisuje z PIN manažeru, ale restart DNS v Pi-hole z API může selhat → ručně restart DNS.

---

## Proč YouTube „projde“ i s blacklistem

| Příčina | Řešení |
|--------|--------|
| DNS neukazuje na portál | Bod 2–4 |
| Zadaná celá URL místo domény | Jen `youtube.com` |
| **HTTPS** / HSTS | Prohlížeč jde na HTTPS → certifikátová chyba místo PIN stránky; zkuste **http://youtube.com** nebo vyčkat na HTTP redirect |
| **Mobilní app** / jiné domény | Appky volají `googlevideo.com`, `youtubei.googleapis.com` – je potřeba přidat i tyto domény |
| Jiný DNS (8.8.8.8, DoH) | Vynutit Pi-hole v Mikrotiku |
| Dočasné povolení po PINu | Záložka **Aktivní povolení** – počkat na expiraci |

---

## YouTube jako „soubor“ domén (doporučení)

Pro lepší pokrytí webu v prohlížeči často stačí:

- `youtube.com`
- `googlevideo.com`
- `ytimg.com`

Plná appka na mobilu = další hosty.

---

## Ověření bez SSH (Portainer / prohlížeč)

1. Admin → blacklist obsahuje `youtube.com`
2. V Pi-hole **Query log** – dotaz na `youtube.com` z IP vašeho PC
3. `nslookup` z PC (terminál) – očekávané `192.168.39.207`
4. V prohlížeči: **http://youtube.com** (nejdřív HTTP) – měl by se zobrazit PIN portál
