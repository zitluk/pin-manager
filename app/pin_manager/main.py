"""Internet access: stránka, kde se PINem dočasně povolí doména blokovaná v Pi-hole."""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from contextlib import asynccontextmanager, suppress
from datetime import datetime
from pathlib import Path
from urllib.parse import urlencode

from fastapi import FastAPI, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeTimedSerializer

from pin_manager import pihole
from pin_manager.config import get_settings
from pin_manager.store import Lockout, get_store, normalize_domain

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE / "templates"))
templates.env.filters["time"] = lambda ts: datetime.fromtimestamp(ts).strftime("%H:%M")

ADMIN_COOKIE = "pin_admin"
ADMIN_MAX_AGE = 12 * 3600
# Nový klíč při každém startu – po restartu se správce jen znovu přihlásí
_signer = URLSafeTimedSerializer(secrets.token_hex(32), salt="pin-manager-admin")
lockout = Lockout()
sync_state: dict = {"ok": None, "error": "", "at": 0.0}


async def sync_now() -> None:
    """Promítne aktuální stav (blokované domény) do Pi-hole."""
    try:
        store = get_store()
        await pihole.sync(store.blocked_hosts(), store.all_hosts())
        sync_state.update(ok=True, error="", at=time.time())
    except Exception as e:
        sync_state.update(ok=False, error=str(e), at=time.time())
        raise


async def _sync_loop() -> None:
    """Každých 30 s: po vypršení povolení doménu znovu zablokuje; občas ověří celý stav."""
    last_blocked: list[str] | None = None
    last_full = 0.0
    while True:
        blocked = get_store().blocked_hosts()
        due = time.time() - last_full >= get_settings().pihole_resync_seconds
        if blocked != last_blocked or due or not sync_state["ok"]:
            try:
                await sync_now()
                last_blocked, last_full = blocked, time.time()
            except Exception as e:
                logger.warning("Synchronizace Pi-hole selhala: %s", e)
        await asyncio.sleep(30)


@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(_sync_loop())
    yield
    task.cancel()
    with suppress(asyncio.CancelledError):
        await task


app = FastAPI(title="Internet access", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")


def _ip(request: Request) -> str:
    return request.client.host if request.client else "?"


def _redirect(path: str, **msg: str) -> RedirectResponse:
    params = {k: v for k, v in msg.items() if v}
    return RedirectResponse(f"{path}?{urlencode(params)}" if params else path, status_code=303)


def _is_admin(request: Request) -> bool:
    try:
        return _signer.loads(request.cookies.get(ADMIN_COOKIE, ""), max_age=ADMIN_MAX_AGE) == "admin"
    except BadSignature:
        return False


def _pin_ok(pin: str) -> bool:
    expected = get_settings().pin
    return bool(expected) and secrets.compare_digest(pin.encode(), expected.encode())


@app.get("/health")
async def health():
    return {"status": "ok", "pihole_sync": sync_state["ok"]}


# ---------- PIN stránka ----------


@app.get("/")
async def home(request: Request, message: str = "", error: str = "", opened: str = ""):
    store = get_store()
    grants = store.active_grants()
    return templates.TemplateResponse(
        request,
        "pin.html",
        {
            "blocked": store.blocked(),
            "aliases": store.aliases(),
            "grants": sorted(grants.items()),
            "opened": opened if opened in grants else "",
            "durations": get_settings().duration_minutes_list,
            "message": message,
            "error": error,
        },
    )


@app.post("/unlock")
async def unlock(request: Request, domain: str = Form(...), pin: str = Form(...), minutes: int = Form(...)):
    ip = _ip(request)
    if wait := lockout.remaining(ip):
        return _redirect("/", error=f"Příliš mnoho pokusů, zkuste to za {wait} s.")
    store = get_store()
    s = get_settings()
    if domain not in store.blocked() or minutes not in s.duration_minutes_list:
        return _redirect("/", error="Neplatný požadavek.")
    if not _pin_ok(pin):
        lockout.fail(ip)
        logger.info("Špatný PIN z %s pro %s", ip, domain)
        return _redirect("/", error="Nesprávný PIN.")
    lockout.clear(ip)
    store.grant(domain, minutes)
    try:
        await sync_now()
    except Exception as e:
        store.set_grant(domain, None)
        return _redirect("/", error=f"Pi-hole se nepodařilo upravit: {e}")
    logger.info("Povoleno %s na %s min (z %s)", domain, minutes, ip)
    return _redirect("/", message=f"{domain} je povolená na {minutes} min.", opened=domain)


# ---------- Správa ----------


@app.get("/admin")
async def admin(request: Request, message: str = "", error: str = ""):
    if not _is_admin(request):
        return templates.TemplateResponse(
            request, "login.html", {"error": error, "configured": bool(get_settings().pin)}
        )
    store = get_store()
    return templates.TemplateResponse(
        request,
        "admin.html",
        {
            "blacklist": store.blacklist(),
            "aliases": store.aliases(),
            "grants": store.active_grants(),
            "sync": sync_state,
            "pihole_url": get_settings().pihole_url,
            "message": message,
            "error": error,
        },
    )


@app.post("/admin/login")
async def admin_login(request: Request, pin: str = Form(...)):
    # Stejný PIN i stejné počítadlo pokusů jako na stránce povolení
    ip = _ip(request)
    if wait := lockout.remaining(ip):
        return _redirect("/admin", error=f"Příliš mnoho pokusů, zkuste to za {wait} s.")
    if not _pin_ok(pin):
        lockout.fail(ip)
        return _redirect("/admin", error="Nesprávný PIN.")
    lockout.clear(ip)
    resp = _redirect("/admin")
    resp.set_cookie(ADMIN_COOKIE, _signer.dumps("admin"), max_age=ADMIN_MAX_AGE, httponly=True, samesite="strict")
    return resp


@app.post("/admin/logout")
async def admin_logout():
    resp = _redirect("/admin")
    resp.delete_cookie(ADMIN_COOKIE)
    return resp


async def _admin_action(request: Request, action, ok_message: str) -> RedirectResponse:
    if not _is_admin(request):
        return _redirect("/admin")
    try:
        action()
    except ValueError as e:
        return _redirect("/admin", error=str(e))
    try:
        await sync_now()
    except Exception as e:
        return _redirect("/admin", error=f"Uloženo, ale Pi-hole selhal (zkusím znovu): {e}")
    return _redirect("/admin", message=ok_message)


@app.post("/admin/add")
async def admin_add(request: Request, domain: str = Form(...), extra: str = Form("")):
    d = normalize_domain(domain)
    return await _admin_action(request, lambda: get_store().add(domain, extra), f"Blokováno: {d}")


@app.post("/admin/remove")
async def admin_remove(request: Request, domain: str = Form(...)):
    return await _admin_action(request, lambda: get_store().remove(domain), f"Odebráno: {domain}")


@app.post("/admin/revoke")
async def admin_revoke(request: Request, domain: str = Form(...)):
    return await _admin_action(
        request, lambda: get_store().set_grant(domain, None), f"Povolení zrušeno: {domain}"
    )


@app.post("/admin/sync")
async def admin_sync(request: Request):
    return await _admin_action(request, lambda: None, "Pi-hole synchronizován")
