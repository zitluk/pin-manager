# PIN při otevření YouTube / HSTS stránek

## Doporučený režim (rodina)

1. V Portaineru: **`SINKHOLE_HTTPS_SILENT=false`**, **`SINKHOLE_ALL_SILENT=false`**, **`PORTAL_HTTPS=true`**, **`PORTAL_TLS_AUTO=true`**.
2. Na každém telefonu/PC **jednou** nainstalujte CA z **`http://192.168.39.207/ca.crt`** (odkaz v adminu).
3. V adminu **Znovu synchronizovat Pi-hole** (po změně env nebo po starém tichém režimu).
4. Ověření: `nslookup www.youtube.com` musí vrátit **`192.168.39.207`** (ne `0.0.0.0`).
5. Otevřete **https://www.youtube.com** → formulář s PIN (bez červeného varování certifikátu).

---

## Kdy PIN „nevyskočí“

| Příčina | Co udělat |
|---------|-----------|
| DNS vrací `0.0.0.0` | Vypněte tichý režim, sync Pi-hole (viz výše) |
| Varování certifikátu místo PIN | Nainstalujte domácí CA na zařízení |
| `SINKHOLE_ALL_SILENT=true` | Nastavit `false` – jinak jen odpadá připojení |
| IPv6 (AAAA) obchází A záznam | Pi-hole regex AAAA je sync automaticky; případně IPv6 vypnout na Wi‑Fi |

Záložní cesta bez otevření YouTube URL: **`http://192.168.39.207/unlock-for?domain=youtube.com`**

---

## Starý režim (tichý blok)

`SINKHOLE_HTTPS_SILENT=true` = YouTube „nefunguje“, PIN jen přes IP portálu. Pro PIN přímo na doméně tento režim **nepoužívejte**.
