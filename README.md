# Internet access (pin-manager pro Pi-hole)

Jednoduchá webová stránka: vybrané domény jsou v Pi-hole blokované a kdo zná **PIN**,
může je na chvíli povolit.

## Jak to funguje

1. Ve **správě** (`/admin`, přihlášení stejným PINem) přidáte domény, např. `youtube.com`.
   Pin-manager je zapíše do Pi-hole jako regex `(\.|^)youtube\.com$` (blokuje se i každá poddoména).
   Známé **alternativy** se přidají samy (u YouTube např. `googlevideo.com`, `ytimg.com`, `youtu.be`,
   seznam je v `app/pin_manager/aliases.py`) a další lze zadat ručně. Doména se blokuje
   i povoluje vždy spolu se svými alternativami.
2. Kdo chce stránku použít, otevře **hlavní stránku** pin-manageru, vybere doménu
   a dobu (15/30/60/120 min) a zadá **PIN**.
3. Pin-manager pravidlo v Pi-hole dočasně smaže a po vypršení ho vrátí (kontrola každých 30 s).

Pin-manager mění v Pi-hole jen svá pravidla (komentář `pin-manager`) v seznamu domén
a nastavení Pi-hole nechává být. Pravidla se pravidelně ověřují (`PIHOLE_RESYNC_SECONDS`),
takže po reinstalaci Pi-hole se sama doplní.
Po 5 špatných pokusech o PIN (na stránce i ve správě dohromady) se daná IP adresa na 5 minut zablokuje.

## Nasazení

Proměnné (viz `.env.example`):

| Proměnná | Význam |
|---|---|
| `PIHOLE_URL` | adresa Pi-hole v6, např. `http://192.168.39.5` |
| `PIHOLE_PASSWORD` | heslo do Pi-hole (nebo heslo aplikace) |
| `PIN` | PIN pro povolení stránky a zároveň přihlášení do správy |
| `DURATION_OPTIONS` | nabízené doby v minutách, výchozí `15,30,60,120` |

Portainer stack z Gitu, compose path `docker-compose.yml`. Kontejner dostane IP `VLAN_IP`
ve stávající macvlan síti `docker_vlan` a stránka běží na `http://192.168.39.207/`
(na hostiteli se nemapují žádné porty).

Stav (seznam domén, povolení) je ve volume `/data/state.json`.

## Vývoj

```bash
cd app
pip install -r requirements-dev.txt
pytest -q
```

## Přechod ze starší verze

Starší verze přesměrovávala blokované domény na portál s vlastní certifikační autoritou.
To už neplatí:

- Při prvním spuštění pin-manager sám smaže svá stará pravidla v Pi-hole
  (regexy, `allow` povolení, tichý blok). Seznam domén v `state.json` zůstává.
- Záznamy v *Local DNS*, které vedou na IP kontejneru nebo na spravované domény
  (`192.168.39.207 doména`), maže pin-manager při každé synchronizaci sám. Jinak by povolená
  stránka dál mířila na portál („odmítl připojení“).
- Sdílený soubor `pin-sinkhole.conf` v Pi-hole (pokud ho Pi-hole načítá) smažte ručně.
- Proměnné `PORTAL_IP`, `SESSION_SECRET`, `SINKHOLE_*`, `PORTAL_*`, `ADMIN_TOKEN` a mount `/sync`
  se už nepoužívají. Do správy se přihlašuje PINem (registrace zmizela).
- Domácí CA nainstalovaná na zařízeních už není potřeba a můžete ji odinstalovat.
