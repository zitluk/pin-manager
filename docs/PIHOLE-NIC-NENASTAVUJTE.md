# Pi-hole – nemusíte tam nic nastavovat (pro PIN manažer)

PIN manažer **není** další seznam reklam v Pi-hole. **Nic** nedáváte do Adlists, Group Management ani ručně do Local DNS.

Všechno dělá **kontejner pin-manager** přes **API** (heslo z webu Pi-hole).

---

## Co musí Pi-hole už dělat dnes (to asi máte)

| Věc | Kde |
|-----|-----|
| V síti jste nastavili **DNS na Pi-hole** (Mikrotik DHCP) | Router / Pi-hole |
| Znát **heslo** do webu Pi-hole | To stejné použijete v Portaineru |
| Vědět **IP adresu** Pi-hole v síti 39.x | Např. `192.168.39.5` |

To je celé „nastavení Pi-hole“ z vaše strany.

---

## Co vyplníte jen v Portaineru (stack pin-manager)

| Proměnná | Co tam dát |
|----------|------------|
| `PIHOLE_URL` | `http://` + **IP Pi-hole** (bez lomítka na konci). Když web otevíráte v prohlížeči jako `http://192.168.39.5/admin/`, pište `http://192.168.39.5`. Má port? Např. `http://192.168.39.5:8080` |
| `PIHOLE_PASSWORD` | Heslo z přihlášení do Pi-hole |
| `PORTAL_IP` | `192.168.39.207` |
| `VLAN_IP` | `192.168.39.207` |

**Nepotřebujete:** žádný odkaz z GitHubu, žádný blacklist v Pi-hole UI.

---

## Co se stane po přidání domény v adminu PIN manažeru

1. pin-manager se **přihlásí** k Pi-hole (heslo výše).
2. Sám doplní záznamy typu **`192.168.39.207` + `youtube.com`** (Local DNS).
3. Restartuje DNS v Pi-hole.

Až pak můžete v Pi-hole v nastavení DNS **uvidět** ty řádky – ale **vy je tam psát nemusíte**.

---

## Jak zjistit správné `PIHOLE_URL`

Na počítači, kde Pi-hole normálně otevíráte:

- Podívejte se do **adresního řádku** – to je základ URL (bez `/admin`).

Na Raspberry Pi:

```bash
hostname -I
```

První IP ve **192.168.39.x** často patří Pi-hole / RPi – tu zkuste v `PIHOLE_URL`.

---

## Ověření (bez nastavování v Pi-hole)

1. Redeploy stacku, otevřete **http://192.168.39.207/admin/**
2. Přidejte `youtube.com` nebo klikněte **„Znovu synchronizovat Pi-hole“**
   - Má být **API OK** (ne červená chyba).
3. Na PC v síti:

   ```bash
   nslookup youtube.com
   ```

   Odpověď má být **`192.168.39.207`**.

Když je tam reálná IP Google → buď špatné `PIHOLE_URL`/heslo, nebo PC nepoužívá Pi-hole jako DNS.

---

## Volitelné (jen když API nejde)

Mount složky `/opt/pin-manager/dnsmasq-sync` do Pi-hole – viz [AKTIVACE-BLOKOVANI.md](./AKTIVACE-BLOKOVANI.md).  
**Normálně to nechte na API** – v Pi-hole nic nepřidáváte.

---

## Shrnutí jednou větou

**Pi-hole nechte jak je; v Portaineru jen `PIHOLE_URL` + `PIHOLE_PASSWORD`; blokování zapíše PIN manažer sám.**
