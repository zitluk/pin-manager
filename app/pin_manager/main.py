from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode, urlsplit

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI, Form, Header, HTTPException, Request
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from pin_manager.admin_auth import (
    clear_admin_cookie,
    is_admin_authenticated,
    set_admin_cookie,
    verify_legacy_admin_token,
)
from pin_manager.admin_users import get_admin_store
from pin_manager.audit import log_event, read_recent
from pin_manager.blacklist_ops import add_domain, remove_domain
from pin_manager.config import get_settings
from pin_manager.pin_auth import (
    MIN_PIN_LEN,
    MAX_PIN_LEN,
    has_stored_pin,
    set_family_pin,
    verify_family_pin,
)
from pin_manager.security import (
    SCOPE_ADMIN,
    clear_attempts,
    is_locked,
    record_failed_attempt,
    verify_pin,
)
from pin_manager.store import get_store, _normalize_domain
from pin_manager.sinkhole import publish_sinkhole
from pin_manager.sync import apply_relock, apply_unlock, relock_expired
from pin_manager.sync_status import read as read_sync_status
from pin_manager.tls_certs import ca_cert_path, ensure_tls_material

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def _build_target_url(host: str, path: str, query: str) -> str:
    host = host.split(":")[0]
    path = path or "/"
    q = f"?{query}" if query else ""
    # Po odblokování preferujeme HTTPS (většina stránek)
    return f"https://{host}{path}{q}"


def _admin_redirect(path: str, *, message: str | None = None, error: str | None = None):
    """Redirect se zprávou – text se kóduje (dřív ho rozbily znaky & # + z výjimek)."""
    params = {k: v for k, v in (("message", message), ("error", error)) if v}
    url = f"{path}?{urlencode(params)}" if params else path
    return RedirectResponse(url, status_code=303)


def _safe_target_url(target_url: str | None, domain: str) -> str:
    """target_url z formuláře jen když míří na stejnou (blokovanou) doménu, jinak výchozí."""
    fallback = _build_target_url(domain, "/", "")
    if not target_url:
        return fallback
    # Zpětné lomítko a řídicí znaky prohlížeče čtou jinak než urlsplit (https://evil\@yt.com)
    if "\\" in target_url or any(ord(c) < 33 or ord(c) == 127 for c in target_url):
        return fallback
    try:
        parts = urlsplit(target_url)
        hostname = parts.hostname
    except ValueError:
        return fallback
    if parts.scheme not in ("http", "https") or not hostname:
        return fallback
    store = get_store()
    target_host = _normalize_domain(hostname)
    domain = _normalize_domain(domain)
    if not target_host or not domain:
        return fallback
    if (store.blacklist_match(target_host) or target_host) != (
        store.blacklist_match(domain) or domain
    ):
        return fallback
    return target_url


def _host_from_request(request: Request) -> str:
    host = request.headers.get("host", "")
    return _normalize_domain(host.split(":")[0])


async def _startup_tls() -> None:
    settings = get_settings()
    if not settings.portal_tls_auto:
        return
    try:
        ensure_tls_material()
    except Exception as e:
        logger.warning("TLS cert při startu: %s", e)


async def _startup_pihole_sync(portal_ip: str) -> None:
    try:
        await publish_sinkhole(portal_ip)
        logger.info("Po startu dokončena synchronizace Pi-hole DNS")
    except Exception as e:
        logger.warning("Po startu se nepodařilo synchronizovat Pi-hole DNS: %s", e)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    portal_ip = settings.portal_ip
    await _startup_tls()
    startup_sync_task: asyncio.Task | None = None
    if portal_ip:
        startup_sync_task = asyncio.create_task(_startup_pihole_sync(portal_ip))

    scheduler = AsyncIOScheduler()

    async def expire_grants():
        portal_ip = get_settings().portal_ip
        if not portal_ip:
            return
        try:
            relocked = await relock_expired(portal_ip)
        except Exception as e:
            logger.error("Relock po vypršení selhal (zkusím znovu): %s", e)
            return
        for domain in relocked:
            log_event("grant_expired", domain=domain)
            logger.info("Platnost povolení vypršela: %s", domain)

    scheduler.add_job(
        expire_grants, "interval", seconds=30, id="expire_grants", max_instances=1, coalesce=True
    )

    async def resync_pihole():
        """Po výpadku nebo čisté reinstalaci Pi-hole pravidla sama doplní."""
        portal_ip = get_settings().portal_ip
        if not portal_ip:
            return
        try:
            await publish_sinkhole(portal_ip)
        except Exception as e:
            logger.warning("Pravidelný sync Pi-hole selhal: %s", e)

    scheduler.add_job(
        resync_pihole,
        "interval",
        seconds=get_settings().pihole_resync_seconds,
        id="resync_pihole",
        max_instances=1,
        coalesce=True,
    )
    scheduler.start()
    yield
    if startup_sync_task and not startup_sync_task.done():
        startup_sync_task.cancel()
    scheduler.shutdown(wait=False)


app = FastAPI(title="PIN manažer", lifespan=lifespan)
static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


def _admin_redirect_if_needed(request: Request) -> RedirectResponse | None:
    admins = get_admin_store()
    if not admins.has_admin():
        path = request.url.path
        if path.startswith("/admin/register"):
            return None
        return RedirectResponse("/admin/register", status_code=303)
    if not is_admin_authenticated(request):
        return RedirectResponse("/admin/login", status_code=303)
    return None


@app.get("/ca.crt")
async def download_home_ca():
    """Jednou nainstalovat na každé zařízení (dítě + rodič) – pak HTTPS bez varování."""
    path = ca_cert_path()
    if not path.is_file():
        raise HTTPException(404, "CA certifikát ještě nebyl vytvořen – proveďte sync Pi-hole.")
    return FileResponse(
        path,
        media_type="application/x-x509-ca-cert",
        filename="pin-manager-ca.crt",
    )


@app.get("/health")
async def health():
    settings = get_settings()
    detected = "unknown"
    gw = settings.portal_ip.rsplit(".", 1)[0] + ".1" if settings.portal_ip else ""
    if gw:
        try:
            import socket

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect((gw, 1))
                detected = s.getsockname()[0]
        except OSError:
            pass
    return {
        "status": "ok",
        "detected_ip": detected,
        "portal_ip": settings.portal_ip,
        "deploy_mode": settings.deploy_mode,
    }


def _check_admin(request: Request | None, authorization: str | None) -> None:
    if request and is_admin_authenticated(request):
        return
    got = (authorization or "").removeprefix("Bearer ").strip()
    if got and get_admin_store().verify_api_token(got):
        return
    if got and verify_legacy_admin_token(got):
        return
    raise HTTPException(401, "Neplatná autorizace (přihlášení nebo Bearer API token)")


@app.get("/admin/blacklist")
async def admin_list(request: Request, authorization: str | None = Header(None)):
    _check_admin(request, authorization)
    return {"blacklist": get_store().list_blacklist(), "grants": get_store().active_grants()}


@app.post("/admin/blacklist")
async def admin_add(
    request: Request,
    authorization: str | None = Header(None),
):
    _check_admin(request, authorization)
    body = await request.json()
    domain = body.get("domain", "").strip()
    if not domain:
        raise HTTPException(400, "Chybí domain")
    bl = await add_domain(domain)
    log_event("blacklist_add", request=request, domain=_normalize_domain(domain))
    return {"ok": True, "blacklist": bl}


@app.delete("/admin/blacklist/{domain}")
async def admin_remove(domain: str, request: Request, authorization: str | None = Header(None)):
    _check_admin(request, authorization)
    domain = _normalize_domain(domain)
    bl = await remove_domain(domain)
    log_event("blacklist_remove", request=request, domain=domain)
    return {"ok": True, "blacklist": bl}


@app.get("/admin/register")
async def admin_register_get(request: Request):
    if get_admin_store().has_admin():
        return RedirectResponse("/admin/login", status_code=303)
    if is_admin_authenticated(request):
        return RedirectResponse("/admin/", status_code=303)
    return templates.TemplateResponse(
        request,
        "admin_register.html",
        {"show_nav": False, "error": None},
    )


@app.post("/admin/register")
async def admin_register_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    password2: str = Form(...),
):
    if get_admin_store().has_admin():
        return RedirectResponse("/admin/login", status_code=303)
    if password != password2:
        return templates.TemplateResponse(
            request,
            "admin_register.html",
            {"show_nav": False, "error": "Hesla se neshodují."},
            status_code=400,
        )
    try:
        api_token = get_admin_store().register(username, password)
    except ValueError as e:
        return templates.TemplateResponse(
            request,
            "admin_register.html",
            {"show_nav": False, "error": str(e)},
            status_code=400,
        )
    log_event("admin_register", request=request, detail=username.strip().lower())
    return templates.TemplateResponse(
        request,
        "admin_register_done.html",
        {
            "show_nav": False,
            "username": username.strip().lower(),
            "api_token": api_token,
        },
    )


@app.get("/admin/login")
async def admin_login_get(request: Request):
    if not get_admin_store().has_admin():
        return RedirectResponse("/admin/register", status_code=303)
    if is_admin_authenticated(request):
        return RedirectResponse("/admin/", status_code=303)
    return templates.TemplateResponse(
        request,
        "admin_login.html",
        {"show_nav": False, "error": None},
    )


@app.post("/admin/login")
async def admin_login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    admins = get_admin_store()
    ip = request.client.host if request.client else ""
    locked, remain = is_locked(ip, SCOPE_ADMIN)
    if locked:
        log_event("admin_login_lockout", request=request, detail=f"zbývá {remain} s")
        return templates.TemplateResponse(
            request,
            "admin_login.html",
            {
                "show_nav": False,
                "error": f"Příliš mnoho pokusů – zkuste znovu za {remain} s.",
            },
            status_code=429,
        )
    if not admins.verify(username, password):
        locked_now, sec = record_failed_attempt(ip, SCOPE_ADMIN)
        log_event("admin_login_fail", request=request, detail=username.strip().lower())
        err = "Neplatné jméno nebo heslo."
        if locked_now:
            log_event("admin_login_lockout", request=request, detail=f"{sec // 60} min")
            err += f" Příliš mnoho pokusů – uzamčeno na {sec // 60} min."
        return templates.TemplateResponse(
            request,
            "admin_login.html",
            {"show_nav": False, "error": err},
            status_code=401,
        )
    clear_attempts(ip, SCOPE_ADMIN)
    log_event("admin_login_ok", request=request, detail=username.strip().lower())
    resp = RedirectResponse("/admin/", status_code=303)
    set_admin_cookie(resp, username.strip().lower())
    return resp


@app.post("/admin/logout")
async def admin_logout():
    resp = RedirectResponse("/admin/login", status_code=303)
    clear_admin_cookie(resp)
    return resp


@app.get("/admin")
@app.get("/admin/")
async def admin_dashboard(request: Request, message: str | None = None, error: str | None = None):
    redir = _admin_redirect_if_needed(request)
    if redir:
        return redir
    store = get_store()
    settings = get_settings()
    ip = settings.portal_ip or "PORTAL_IP"
    if settings.deploy_mode == "bridge" and settings.host_port not in ("", "80"):
        admin_url = f"http://{ip}:{settings.host_port}/admin/"
    else:
        admin_url = f"http://{ip}/admin/"
    sync_st = read_sync_status()
    return templates.TemplateResponse(
        request,
        "admin_dashboard.html",
        {
            "show_nav": True,
            "blacklist": store.list_blacklist(),
            "portal_ip": ip,
            "deploy_mode": settings.deploy_mode,
            "admin_url": admin_url,
            "message": message,
            "error": error,
            "sync_status": sync_st,
            "pihole_url": settings.pihole_url,
            "sinkhole_mode": settings.pihole_sinkhole_mode,
            "sinkhole_https_silent": settings.sinkhole_https_silent,
            "sinkhole_all_silent": settings.sinkhole_all_silent,
            "portal_https": settings.portal_https,
            "portal_tls_auto": settings.portal_tls_auto,
        },
    )


@app.post("/admin/sync-now")
async def admin_sync_now(request: Request):
    redir = _admin_redirect_if_needed(request)
    if redir:
        return redir
    settings = get_settings()
    if not settings.portal_ip:
        return _admin_redirect("/admin/", error="Chybí PORTAL_IP")
    try:
        await publish_sinkhole(settings.portal_ip)
    except Exception as e:
        logger.exception("admin sync-now")
        return _admin_redirect("/admin/", error=str(e))
    return _admin_redirect("/admin/", message="Pi-hole synchronizováno")


@app.get("/admin/grants")
async def admin_grants(
    request: Request,
    message: str | None = None,
    error: str | None = None,
):
    redir = _admin_redirect_if_needed(request)
    if redir:
        return redir
    store = get_store()
    grants_raw = store.active_grants()
    grants = [
        (d, datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S"))
        for d, ts in sorted(grants_raw.items())
    ]
    return templates.TemplateResponse(
        request,
        "admin_grants.html",
        {"show_nav": True, "grants": grants, "message": message, "error": error},
    )


@app.post("/admin/grants/revoke")
async def admin_grants_revoke(request: Request, domain: str = Form(...)):
    redir = _admin_redirect_if_needed(request)
    if redir:
        return redir
    domain = _normalize_domain(domain)
    settings = get_settings()
    if not domain:
        return _admin_redirect("/admin/grants", error="Neplatná doména")
    grants = get_store().active_grants()
    if domain not in grants:
        return _admin_redirect("/admin/grants", error=f"Doména {domain} nemá aktivní povolení")
    if not settings.portal_ip:
        return _admin_redirect("/admin/grants", error="Chybí PORTAL_IP")
    try:
        await apply_relock(domain, settings.portal_ip)
    except Exception as e:
        logger.exception("admin revoke grant")
        return _admin_redirect("/admin/grants", error=str(e))
    log_event("grant_revoked", request=request, domain=domain)
    return _admin_redirect("/admin/grants", message=f"Povolení pro {domain} zrušeno")


@app.get("/admin/pin")
async def admin_pin_get(
    request: Request, message: str | None = None, error: str | None = None
):
    redir = _admin_redirect_if_needed(request)
    if redir:
        return redir
    return templates.TemplateResponse(
        request,
        "admin_pin.html",
        {
            "show_nav": True,
            "message": message,
            "error": error,
            "uses_stored": has_stored_pin(),
            "min_len": MIN_PIN_LEN,
            "max_len": MAX_PIN_LEN,
        },
    )


@app.post("/admin/pin")
async def admin_pin_post(
    request: Request,
    current_pin: str = Form(...),
    new_pin: str = Form(...),
    new_pin2: str = Form(...),
):
    redir = _admin_redirect_if_needed(request)
    if redir:
        return redir
    if new_pin != new_pin2:
        return _admin_redirect("/admin/pin", error="Nový PIN se nerovná potvrzení")
    if not verify_family_pin(current_pin):
        return _admin_redirect("/admin/pin", error="Špatný současný PIN")
    try:
        set_family_pin(new_pin)
    except ValueError as e:
        return _admin_redirect("/admin/pin", error=str(e))
    log_event("family_pin_changed", request=request)
    return _admin_redirect("/admin/pin", message="PIN uložen")


@app.get("/admin/logs")
async def admin_logs(request: Request):
    redir = _admin_redirect_if_needed(request)
    if redir:
        return redir
    return templates.TemplateResponse(
        request,
        "admin_logs.html",
        {"show_nav": True, "entries": read_recent()},
    )


@app.get("/admin/audit")
async def admin_audit_api(request: Request, authorization: str | None = Header(None)):
    _check_admin(request, authorization)
    return {"entries": read_recent()}


@app.post("/admin/domains/add")
async def admin_ui_add(request: Request, domain: str = Form(...)):
    redir = _admin_redirect_if_needed(request)
    if redir:
        return redir
    domain = domain.strip()
    if not domain:
        return _admin_redirect("/admin/", error="Prázdná doména")
    try:
        await add_domain(domain)
        log_event("blacklist_add", request=request, domain=_normalize_domain(domain))
    except Exception as e:
        logger.exception("add_domain")
        return _admin_redirect("/admin/", error=str(e))
    return _admin_redirect("/admin/", message="Doména přidána")


@app.post("/admin/domains/remove")
async def admin_ui_remove(request: Request, domain: str = Form(...)):
    redir = _admin_redirect_if_needed(request)
    if redir:
        return redir
    try:
        await remove_domain(domain)
        log_event("blacklist_remove", request=request, domain=_normalize_domain(domain))
    except Exception as e:
        logger.exception("remove_domain")
        return _admin_redirect("/admin/", error=str(e))
    return _admin_redirect("/admin/", message="Doména odebrána")


@app.get("/setup")
async def device_setup(request: Request):
    """Návod + živá kontrola zařízení (DNS přes Pi-hole, důvěra v domácí CA)."""
    from pin_manager.domain_expand import HSTS_SIMPLE_BLOCK_APEX
    from pin_manager.tls_certs import CA_NAME

    blocked = get_store().blocked_domains_for_sinkhole()
    # Přednostně doména bez HSTS – u ní jde DNS ověřit i bez certifikátu
    test_domain = next((d for d in blocked if d not in HSTS_SIMPLE_BLOCK_APEX), None) or (
        blocked[0] if blocked else None
    )
    return templates.TemplateResponse(
        request, "setup.html", {"test_domain": test_domain, "ca_name": CA_NAME}
    )


@app.get("/ca.mobileconfig")
async def download_apple_profile():
    """Konfigurační profil pro iPhone/iPad/Mac – nainstaluje domácí CA."""
    import hashlib
    import plistlib
    import uuid

    from pin_manager.tls_certs import CA_NAME, ca_der

    der = ca_der()
    fp = hashlib.sha256(der).hexdigest()
    ns = uuid.UUID("6f1c2f9e-7a1e-4d55-9f0b-5e2a3c1d9b01")
    profile = {
        "PayloadContent": [
            {
                "PayloadCertificateFileName": "pin-manager-ca.cer",
                "PayloadContent": der,
                "PayloadDescription": "Domácí certifikát PIN manažeru",
                "PayloadDisplayName": CA_NAME,
                "PayloadIdentifier": f"local.pin-manager.ca.{fp[:16]}",
                "PayloadType": "com.apple.security.root",
                "PayloadUUID": str(uuid.uuid5(ns, "cert-" + fp)).upper(),
                "PayloadVersion": 1,
            }
        ],
        "PayloadDescription": "Umožní zobrazit formulář s PINem i u HTTPS stránek.",
        "PayloadDisplayName": "PIN manažer – domácí certifikát",
        "PayloadIdentifier": "local.pin-manager.profile",
        "PayloadRemovalDisallowed": False,
        "PayloadType": "Configuration",
        "PayloadUUID": str(uuid.uuid5(ns, "profile-" + fp)).upper(),
        "PayloadVersion": 1,
    }
    return Response(
        content=plistlib.dumps(profile),
        media_type="application/x-apple-aspen-config",
        headers={"Content-Disposition": 'attachment; filename="pin-manager.mobileconfig"'},
    )


@app.get("/__pin/check")
async def pin_check(request: Request):
    """Kontrola ze stránky /setup: odpověď znamená, že DNS jména vede na portál
    (a u https:// že zařízení důvěřuje certifikátu)."""
    host = _host_from_request(request)
    return JSONResponse(
        {
            "portal": True,
            "host": host,
            "blocked": get_store().is_blocked(host) if host else False,
            "scheme": request.url.scheme,
        },
        headers={"Access-Control-Allow-Origin": "*", "Cache-Control": "no-store"},
    )


@app.get("/preview/block")
async def preview_block(request: Request):
    if not get_settings().preview_enabled:
        raise HTTPException(404)
    host = "example.com"
    target_url = _build_target_url(host, "/", "")
    return templates.TemplateResponse(
        request,
        "block.html",
        {
            "target_display": target_url,
            "target_url": target_url,
            "host": host,
            "duration_options": get_settings().duration_minutes_list,
            "error": None,
        },
    )


@app.get("/preview/redirect")
async def preview_redirect(request: Request):
    if not get_settings().preview_enabled:
        raise HTTPException(404)
    dest = "https://example.com/"
    return templates.TemplateResponse(
        request,
        "redirect.html",
        {"target_url": dest, "target_display": dest},
    )


def _block_page_context(domain: str, error: str | None = None):
    target_url = _build_target_url(domain, "/", "")
    return {
        "target_display": target_url,
        "target_url": target_url,
        "host": domain,
        "duration_options": get_settings().duration_minutes_list,
        "error": error,
    }


@app.get("/unlock-for")
async def unlock_for(request: Request, domain: str = ""):
    """PIN stránka přes IP portálu (kvůli HSTS u YouTube atd.)."""
    domain = _normalize_domain(domain)
    store = get_store()
    if not domain:
        return RedirectResponse("/", status_code=303)
    if not store.is_blocked(domain):
        until = store.active_grant_until(domain)
        if store.blacklist_match(domain) and until:
            return templates.TemplateResponse(
                request,
                "grant_active.html",
                {
                    "host": store.blacklist_match(domain) or domain,
                    "target_url": _build_target_url(domain, "/", ""),
                    "expires_at": datetime.fromtimestamp(
                        until, tz=timezone.utc
                    ).astimezone().strftime("%d.%m.%Y %H:%M"),
                },
            )
        return RedirectResponse("/", status_code=303)
    log_event("blocked_access", request=request, domain=domain, detail="unlock-for")
    return templates.TemplateResponse(
        request,
        "block.html",
        _block_page_context(domain),
    )


@app.api_route("/unlock", methods=["GET", "POST"])
async def unlock(
    request: Request,
    pin: str | None = Form(None),
    minutes: int | None = Form(None),
    target_url: str | None = Form(None),
    host: str | None = Form(None),
):
    client_ip = request.client.host if request.client else ""
    locked, remain = is_locked(client_ip)
    if locked:
        dom = _normalize_domain(host) if host else ""
        log_event(
            "pin_lockout",
            request=request,
            domain=dom or None,
            detail=f"zbývá {remain} s",
        )
        return HTMLResponse(
            f"<h1>Dočasně uzamčeno</h1><p>Zkuste znovu za {remain} s.</p>",
            status_code=429,
        )

    if request.method == "GET":
        return RedirectResponse("/", status_code=302)

    if not pin or minutes is None or not host:
        raise HTTPException(400, "Chybí údaje formuláře")
    # Jen délky nabízené v UI – jinak by šlo poslat např. minutes=999999
    if minutes not in get_settings().duration_minutes_list:
        raise HTTPException(400, "Neplatná délka povolení")

    domain = _normalize_domain(host)
    if not domain:
        raise HTTPException(400, "Neplatná doména")
    # Přesměrovat jen na odemykanou doménu (jinak open redirect přes podvržený formulář)
    target_url = _safe_target_url(target_url, domain)
    if not get_store().is_blocked(domain) and domain not in get_store().list_blacklist():
        # už povoleno
        return RedirectResponse(target_url, status_code=302)

    if not verify_pin(pin):
        locked_now, sec = record_failed_attempt(client_ip)
        log_event(
            "pin_failed",
            request=request,
            domain=domain,
            detail="uzamčení po pokusu" if locked_now else None,
        )
        if locked_now:
            log_event("pin_lockout", request=request, domain=domain, detail=f"{sec // 60} min")
        err = "Nesprávný PIN."
        if locked_now:
            err += f" Příliš mnoho pokusů – uzamčeno na {sec // 60} min."
        return templates.TemplateResponse(
            request,
            "block.html",
            {
                "target_display": target_url,
                "target_url": target_url,
                "host": domain,
                "duration_options": get_settings().duration_minutes_list,
                "error": err,
            },
            status_code=401,
        )

    clear_attempts(client_ip)
    settings = get_settings()
    if not settings.portal_ip:
        raise HTTPException(500, "Není nastaveno PORTAL_IP")

    try:
        await apply_unlock(domain, int(minutes), settings.portal_ip)
    except Exception as e:
        logger.exception("apply_unlock")
        raise HTTPException(502, f"Pi-hole synchronizace selhala: {e}") from e

    log_event(
        "pin_unlock",
        request=request,
        domain=domain,
        detail=f"povoleno na {int(minutes)} min",
    )
    return templates.TemplateResponse(
        request,
        "redirect.html",
        {"target_url": target_url, "target_display": target_url},
    )


@app.api_route("/{path:path}", methods=["GET", "POST", "HEAD"])
async def catch_all(request: Request, path: str):
    host = _host_from_request(request)
    store = get_store()
    target_url = _build_target_url(
        host,
        "/" + path if path else "/",
        str(request.url.query) if request.url.query else "",
    )

    bl_entry = store.blacklist_match(host)
    if not store.is_blocked(host):
        grant_until = store.active_grant_until(host)
        if bl_entry and grant_until and path in ("", "favicon.ico"):
            return templates.TemplateResponse(
                request,
                "grant_active.html",
                {
                    "host": bl_entry,
                    "target_url": _build_target_url(bl_entry, "/", ""),
                    "expires_at": datetime.fromtimestamp(
                        grant_until, tz=timezone.utc
                    ).astimezone().strftime("%d.%m.%Y %H:%M"),
                },
            )
        if path in ("", "favicon.ico"):
            return templates.TemplateResponse(
                request,
                "portal_home.html",
                {"blacklist": store.list_blacklist()},
            )
        raise HTTPException(404)

    canonical = store.blacklist_match(host) or host
    log_event(
        "blocked_access",
        request=request,
        domain=canonical,
        detail=target_url,
    )
    return templates.TemplateResponse(
        request,
        "block.html",
        _block_page_context(canonical),
    )
