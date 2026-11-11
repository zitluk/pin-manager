from __future__ import annotations

import asyncio
import logging
import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI, Form, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
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
from pin_manager.security import clear_attempts, is_locked, record_failed_attempt, verify_pin
from pin_manager.store import get_store, _normalize_domain
from pin_manager.sinkhole import publish_sinkhole
from pin_manager.sync import apply_relock, apply_unlock
from pin_manager.sync_status import read as read_sync_status

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def _build_target_url(host: str, path: str, query: str) -> str:
    host = host.split(":")[0]
    path = path or "/"
    q = f"?{query}" if query else ""
    # Po odblokování preferujeme HTTPS (většina stránek)
    return f"https://{host}{path}{q}"


def _host_from_request(request: Request) -> str:
    host = request.headers.get("host", "")
    return _normalize_domain(host.split(":")[0])


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
    startup_sync_task: asyncio.Task | None = None
    if portal_ip:
        startup_sync_task = asyncio.create_task(_startup_pihole_sync(portal_ip))

    scheduler = AsyncIOScheduler()

    async def expire_grants():
        settings = get_settings()
        portal_ip = settings.portal_ip
        if not portal_ip:
            return
        store = get_store()
        grants = store.active_grants()
        now = time.time()
        for domain, exp in list(grants.items()):
            if exp <= now:
                try:
                    await apply_relock(domain, portal_ip)
                    log_event("grant_expired", domain=domain)
                    logger.info("Platnost povolení vypršela: %s", domain)
                except Exception as e:
                    logger.error("Relock %s failed: %s", domain, e)

    scheduler.add_job(expire_grants, "interval", seconds=30, id="expire_grants")
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
    if not admins.verify(username, password):
        log_event("admin_login_fail", request=request, detail=username.strip().lower())
        return templates.TemplateResponse(
            request,
            "admin_login.html",
            {"show_nav": False, "error": "Neplatné jméno nebo heslo."},
            status_code=401,
        )
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
        },
    )


@app.post("/admin/sync-now")
async def admin_sync_now(request: Request):
    redir = _admin_redirect_if_needed(request)
    if redir:
        return redir
    settings = get_settings()
    if not settings.portal_ip:
        return RedirectResponse("/admin/?error=Chybí+PORTAL_IP", status_code=303)
    try:
        await publish_sinkhole(settings.portal_ip)
    except Exception as e:
        logger.exception("admin sync-now")
        return RedirectResponse(f"/admin/?error={e}", status_code=303)
    return RedirectResponse("/admin/?message=Pi-hole+synchronizováno", status_code=303)


@app.get("/admin/grants")
async def admin_grants(request: Request):
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
        {"show_nav": True, "grants": grants},
    )


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
        return RedirectResponse("/admin/?error=Prázdná+doména", status_code=303)
    try:
        await add_domain(domain)
        log_event("blacklist_add", request=request, domain=_normalize_domain(domain))
    except Exception as e:
        logger.exception("add_domain")
        return RedirectResponse(f"/admin/?error={e}", status_code=303)
    return RedirectResponse("/admin/?message=Doména+přidána", status_code=303)


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
        return RedirectResponse(f"/admin/?error={e}", status_code=303)
    return RedirectResponse("/admin/?message=Doména+odebrána", status_code=303)


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
    if not domain or not get_store().is_blocked(domain):
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

    domain = _normalize_domain(host)
    if not get_store().is_blocked(domain) and domain not in get_store().list_blacklist():
        # už povoleno
        dest = target_url or _build_target_url(domain, "/", "")
        return RedirectResponse(dest, status_code=302)

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
                "target_display": target_url or domain,
                "target_url": target_url or _build_target_url(domain, "/", ""),
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
    dest = target_url or _build_target_url(domain, "/", "")
    return templates.TemplateResponse(
        request,
        "redirect.html",
        {"target_url": dest, "target_display": dest},
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

    if not store.is_blocked(host):
        if path in ("", "favicon.ico"):
            store = get_store()
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
