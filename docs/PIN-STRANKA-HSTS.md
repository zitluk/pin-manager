# Proč nevidím PIN po kliknutí na YouTube?

**Blokování DNS funguje** – web se nenačte nebo hlásí chybu připojení.

**PIN okno** se u velkých služeb (YouTube, Google, …) **často neukáže samo**, protože:

1. Prohlížeč jde rovnou na **HTTPS** (port 443).
2. YouTube má **HSTS** – nepustí vás na „neoficiální“ certifikát na jménu `youtube.com`.

PIN portál u vás běží na **192.168.39.207** – to není skutečný YouTube server.

---

## Jak zadat PIN (doporučený postup)

Na telefonu / PC otevřete **přímo** (není to YouTube URL):

**http://192.168.39.207/**

- uvidíte seznam blokovaných domén,
- klik na **youtube.com** → formulář s PINem,
- po správném PINu se doména na zvolenou dobu odblokuje v Pi-hole.

Přímo: **http://192.168.39.207/unlock-for?domain=youtube.com**

---

## Kdy PIN stránku uvidíte „samo“

U webů **bez HSTS**, pokud otevřete **http://** (ne https) a DNS ukazuje na portál – zobrazí se `block.html`.

---

## `nslookup` ukazuje `.207` a ping jde, ale Brave hlásí ERR_ADDRESS_UNREACHABLE

Často prohlížeč zkusí **IPv6 (AAAA)**. Ověření:

```bash
nslookup -type=AAAA www.centrum.cz
```

Když vrátí nějaké IPv6 → na Macu dočasně vypněte IPv6 na Wi‑Fi, nebo použijte PIN přes **http://192.168.39.207/unlock-for?domain=centrum.cz**.

---

## Shrnutí

| Co vidíte | Význam |
|-----------|--------|
| YouTube „nefunguje“ | blokování OK |
| Žádné PIN okno na youtube.com | normální u HSTS |
| PIN přes **192.168.39.207** | správný postup |
