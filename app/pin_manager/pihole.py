"""Pi-hole v6 API: pin-manager drží v seznamu „deny regex“ jen svá pravidla (comment=pin-manager).

Blokovaná doména = regex `(\\.|^)doména$` (i se všemi poddoménami). Povolení = pravidlo
dočasně smazat. Nastavení Pi-hole se nemění, jen seznam domén.
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket
from urllib.parse import quote

import httpx

from pin_manager.config import get_settings

logger = logging.getLogger(__name__)

COMMENT = "pin-manager"

# Apple i Mozilla doporučují síťům vrátit NXDOMAIN – zařízení pak použije místní DNS
BYPASS_RULES = (
    r"^mask(-h2)?\.icloud\.com$;reply=nxdomain",
    r"^use-application-dns\.net$;reply=nxdomain",
)

_lock = asyncio.Lock()
_legacy_cleaned = False


def block_rule(domain: str) -> str:
    return rf"(\.|^){re.escape(domain)}$"


def desired_rules(blocked: list[str]) -> set[str]:
    rules = {block_rule(d) for d in blocked}
    if get_settings().block_dns_bypass:
        rules |= set(BYPASS_RULES)
    return rules


class PiHole:
    def __init__(self, client: httpx.AsyncClient) -> None:
        s = get_settings()
        self.base = s.pihole_url.rstrip("/") + "/api"
        self.http = client
        self.sid = ""

    async def login(self) -> None:
        r = await self.http.post(f"{self.base}/auth", json={"password": get_settings().pihole_password})
        if r.status_code == 401:
            raise RuntimeError("Pi-hole: špatné heslo")
        if r.status_code == 429:
            raise RuntimeError("Pi-hole: příliš mnoho přihlášení k API, zkuste to za chvíli")
        r.raise_for_status()
        self.sid = (r.json().get("session") or {}).get("sid") or ""
        if not self.sid:
            raise RuntimeError("Pi-hole: přihlášení nevrátilo session")
        self.http.headers["X-FTL-SID"] = self.sid

    async def logout(self) -> None:
        if self.sid:
            try:
                await self.http.delete(f"{self.base}/auth")
            except httpx.HTTPError as e:
                logger.debug("Pi-hole logout: %s", e)

    async def list_ours(self, kind: str) -> set[str]:
        """kind = deny/regex, deny/exact, allow/exact, allow/regex."""
        r = await self.http.get(f"{self.base}/domains/{kind}")
        r.raise_for_status()
        return {
            item["domain"]
            for item in r.json().get("domains") or []
            if str(item.get("comment") or "").startswith(COMMENT) and item.get("domain")
        }

    async def add(self, kind: str, domain: str) -> None:
        r = await self.http.post(
            f"{self.base}/domains/{kind}", json={"domain": domain, "comment": COMMENT, "groups": [0]}
        )
        if r.status_code >= 400:
            raise RuntimeError(f"Pi-hole nepřijal {domain}: {r.status_code} {r.text[:200]}")

    async def delete(self, kind: str, domain: str) -> None:
        r = await self.http.delete(f"{self.base}/domains/{kind}/{quote(domain, safe='')}")
        if r.status_code >= 400 and r.status_code != 404:
            raise RuntimeError(f"Pi-hole nesmazal {domain}: {r.status_code} {r.text[:200]}")

    async def restart_dns(self) -> None:
        r = await self.http.post(f"{self.base}/action/restartdns")
        if r.status_code >= 400:
            logger.warning("Pi-hole restartdns: %s %s", r.status_code, r.text[:200])

    async def cleanup_legacy(self) -> bool:
        """Smaže záznamy starší verze pin-manageru (allow povolení, tichý blok)."""
        changed = False
        for kind in ("allow/exact", "allow/regex", "deny/exact"):
            for domain in await self.list_ours(kind):
                await self.delete(kind, domain)
                changed = True
        return changed

    async def cleanup_portal_hosts(self, domains: list[str]) -> bool:
        """Smaže Local DNS záznamy, které starší verze směrovala na svůj portál.

        Jinak by povolená doména dál vedla na IP pin-manageru a prohlížeč hlásil
        „odmítl připojení“. Maže jen záznamy pro spravované domény (a poddomény)
        nebo mířící na IP tohoto kontejneru.
        """
        r = await self.http.get(f"{self.base}/config/dns/hosts")
        r.raise_for_status()
        cfg = r.json().get("config", {})
        hosts = (cfg.get("dns") or {}).get("hosts") or []
        own_ip = _own_ip(self.base)
        changed = False
        for entry in hosts:
            if not isinstance(entry, str) or not entry.split():
                continue
            ip, *names = entry.split()
            if ip == own_ip or any(_under(n.lower().rstrip("."), domains) for n in names):
                d = await self.http.delete(f"{self.base}/config/dns/hosts/{quote(entry, safe='')}")
                if d.status_code >= 400 and d.status_code != 404:
                    raise RuntimeError(f"Pi-hole nesmazal Local DNS {entry}: {d.status_code}")
                logger.info("Smazán starý Local DNS záznam: %s", entry)
                changed = True
        return changed


def _under(name: str, domains: list[str]) -> bool:
    return any(name == d or name.endswith("." + d) for d in domains)


def _own_ip(base: str) -> str:
    """IP, ze které kontejner mluví s Pi-hole (u macvlan = jeho adresa v LAN)."""
    host = httpx.URL(base).host
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((host, 53))
            ip = s.getsockname()[0]
    except OSError:
        return ""
    return "" if ip.startswith("127.") else ip


async def sync(blocked: list[str], managed: list[str] | None = None) -> bool:
    """Srovná pravidla v Pi-hole se seznamem `blocked`. Vrací True, pokud se něco změnilo.

    `managed` = všechny spravované domény (i právě povolené) – kvůli úklidu Local DNS.
    """
    try:
        return await _sync(blocked, managed if managed is not None else blocked)
    except httpx.TimeoutException:
        raise RuntimeError(f"Pi-hole na {get_settings().pihole_url} neodpovídá") from None
    except httpx.TransportError:
        raise RuntimeError(f"Pi-hole na {get_settings().pihole_url} není dostupný") from None
    except httpx.HTTPStatusError as e:
        raise RuntimeError(f"Pi-hole vrátil chybu {e.response.status_code}") from None


async def _sync(blocked: list[str], managed: list[str]) -> bool:
    global _legacy_cleaned
    desired = desired_rules(blocked)
    async with _lock, httpx.AsyncClient(timeout=30) as client:
        ph = PiHole(client)
        await ph.login()
        try:
            existing = await ph.list_ours("deny/regex")
            for rule in sorted(existing - desired):
                await ph.delete("deny/regex", rule)
            for rule in sorted(desired - existing):
                await ph.add("deny/regex", rule)
            changed = existing != desired
            changed = await ph.cleanup_portal_hosts(managed) or changed
            if not _legacy_cleaned:
                changed = await ph.cleanup_legacy() or changed
                _legacy_cleaned = True
            if changed and get_settings().pihole_restart_dns:
                await ph.restart_dns()
            return changed
        finally:
            await ph.logout()
