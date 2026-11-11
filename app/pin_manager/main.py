from __future__ import annotations

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
    verify_admin_token,
)
from pin_manager.audit import log_event, read_recent
from pin_manager.blacklist_ops import add_domain, remove_domain
from pin_manager.config import get_settings
from pin_manager.pihole import PiHoleClient
from pin_manager.security import clear_attempts, is_locked, record_failed_attempt, verify_pin
from pin_manager.store import get_store, _normalize_domain
from pin_manager.sync import apply_relock, apply_unlock, write_sinkhole_conf

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


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    store = get_store()
    portal_ip = settings.portal_ip
    if portal_ip:
        write_sinkhole_conf(
            portal_ip,
            store.blocked_domains_for_sinkhole(),
            Path(settings.dnsmasq_sinkhole_path),
        )
        ph = PiHoleClient()
        try:
            await ph.restart_dns()
        except Exception as e:
            logger.warning("Po startu se nepodařilo restartovat DNS v Pi-hole: %s", e)

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
    scheduler.shutdown(wait=False)


app = FastAPI(title="PIN manažer", lifespan=lifespan)
static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


def _admin_redirect_if_needed(request: Request) -> RedirectResponse | None:
    if not get_settings().admin_token:
        return None
    if not is_admin_authenticated(request):
        return RedirectResponse("/admin/login", status_code=303)
    return None


@app.get("/health")
async def health():
    return {"status": "ok"}


def _check_admin(authorization: str | None) -> None:
    token = get_settings().admin_token
    if not token:
        raise HTTPException(403, "ADMIN_TOKEN není nastaven")
    got = (authorization or "").removeprefix("Bearer ").strip()
    if not got or not secrets.compare_digest(got, token):
        raise HTTPException(401, "Neplatný token")


@app.get("/admin/blacklist")
async def admin_list(authorization: str | None = Header(None)):
    _check_admin(authorization)
    return {"blacklist": get_store().list_blacklist(), "grants": get_store().active_grants()}


@app.post("/admin/blacklist")
async def admin_add(
    request: Request,
    authorization: str | None = Header(None),
):
    _check_admin(authorization)
    body = await request.json()
    domain = body.get("domain", "").strip()
    if not domain:
        raise HTTPException(400, "Chybí domain")
    bl = await add_domain(domain)
    log_event("blacklist_add", request=request, domain=_normalize_domain(domain))
    return {"ok": True, "blacklist": bl}


@app.delete("/admin/blacklist/{domain}")
async def admin_remove(domain: str, request: Request, authorization: str | None = Header(None)):
    _check_admin(authorization)
    domain = _normalize_domain(domain)
    bl = await remove_domain(domain)
    log_event("blacklist_remove", request=request, domain=domain)
    return {"ok": True, "blacklist": bl}


@app.get("/admin/login")
async def admin_login_get(request: Request):
    if is_admin_authenticated(request):
        return RedirectResponse("/admin/", status_code=303)
    return templates.TemplateResponse(
        request,
        "admin_login.html",
        {"show_nav": False, "error": None},
    )


@app.post("/admin/login")
async def admin_login_post(request: Request, token: str = Form(...)):
    if not verify_admin_token(token):
        log_event("admin_login_fail", request=request)
        return templates.TemplateResponse(
            request,
            "admin_login.html",
            {"show_nav": False, "error": "Neplatný token."},
            status_code=401,
        )
    log_event("admin_login_ok", request=request)
    resp = RedirectResponse("/admin/", status_code=303)
    set_admin_cookie(resp)
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
        },
    )


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
async def admin_audit_api(authorization: str | None = Header(None)):
    _check_admin(authorization)
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

    grants = store.active_grants()
    if host in grants:
        return RedirectResponse(target_url, status_code=302)

    if host not in store.list_blacklist():
        if path in ("", "favicon.ico"):
            settings = get_settings()
            admin_hint = ""
            if settings.portal_ip:
                admin_hint = f'<p><a href="/admin/">Administrace blacklistu</a> (http://{settings.portal_ip}/admin/)</p>'
            return HTMLResponse(
                f"<h1>PIN manažer</h1><p>Blacklisted domény se zobrazí zde po DNS sinkhole.</p>{admin_hint}",
                status_code=200,
            )
        raise HTTPException(404)

    log_event(
        "blocked_access",
        request=request,
        domain=host,
        detail=target_url,
    )
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
