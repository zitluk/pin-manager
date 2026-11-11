# Automatické nasazení (GitHub → Portainer)

Cíl: **push na `main`** → bez ručního *Pull and redeploy* se stack sám aktualizuje.

## Jednorázové nastavení (5 minut)

### 1. Stack v Portaineru už musí existovat

- Git: `https://github.com/zitluk/pin-manager`
- Compose: **`portainer-stack.yml`**
- Env proměnné vyplněné (PIN, tokeny, Pi-hole, …)

### 2. Webhook ve stacku Portainer

1. **Stacks** → váš stack **pin-manager** (nebo jak se jmenuje)
2. **Webhooks** (nebo ⋮ → **Create a webhook** / **Service webhook**)
3. **Add webhook** → typ obvykle **Update stack** / **Redeploy**
4. Zkopírujte URL (vypadá např. jako  
   `https://<portainer>:9443/api/stacks/webhooks/<uuid>`)

> U starších Portainerů: *Stack details* → záložka s webhookem pro „Pull and redeploy“.

### 3. Secret v GitHubu

1. https://github.com/zitluk/pin-manager → **Settings** → **Secrets and variables** → **Actions**
2. **New repository secret**
   - Name: `PORTAINER_STACK_WEBHOOK`
   - Value: celá URL webhooku z kroku 2

### 4. Ověření

```bash
git commit --allow-empty -m "test auto deploy"
git push
```

V **Actions** u repa uvidíte workflow **Portainer auto deploy**. Ve Portaineru by stack měl projít novým deployem (log / čas poslední aktualizace).

---

## Alternativa bez GitHub Actions (jen webhook z GitHubu)

GitHub **Settings** → **Webhooks** → **Add webhook**:

- **Payload URL:** stejná URL jako Portainer webhook
- **Content type:** `application/json`
- **Events:** Just the push event
- **Branch:** `main`

Pak Portainer reaguje přímo na push (GitHub Actions není nutný). Můžete nechat i workflow – obojí volá stejné URL (zbytečné 2× deploy); používejte **buď** GitHub Webhook **nebo** Actions secret, ne obojí naráz.

---

## Automatická kontrola v Portaineru (polling)

Některé verze Portaineru u Git stacku nabízejí **Automatic updates** / polling interval. Zapněte u stacku, pokud webhook zvenku nechcete – repozitář se kontroluje každých X minut.

---

## Co se automaticky neděje

- **První** vytvoření stacku a vyplnění hesel – jednorázově ručně v Portaineru.
- Změna **env** v Portaineru – webhook jen stáhne nový compose/kód; env upravujete v UI stacku nebo přes Portainer API.

## Env na RPi

Sinkhole složka:

```bash
sudo mkdir -p /opt/pin-manager/dnsmasq-sync
```

Pi-hole mount na stejnou cestu – viz [PORTAINER-LUKAS.md](PORTAINER-LUKAS.md).
