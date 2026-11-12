"""Pi-hole v6 API: pin-manager drží v seznamu „deny regex“ jen svá pravidla (comment=pin-manager).

Blokovaná doména = regex `(\\.|^)doména$` (i se všemi poddoménami). Povolení = pravidlo
dočasně smazat. Nastavení Pi-hole se nemění, jen seznam domén.
"""

from __future__ import annotations

import asyncio
import logging
import re
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


async def sync(blocked: list[str]) -> bool:
    """Srovná pravidla v Pi-hole se seznamem `blocked`. Vrací True, pokud se něco změnilo."""
    try:
        return await _sync(blocked)
    except httpx.TimeoutException:
        raise RuntimeError(f"Pi-hole na {get_settings().pihole_url} neodpovídá") from None
    except httpx.TransportError:
        raise RuntimeError(f"Pi-hole na {get_settings().pihole_url} není dostupný") from None
    except httpx.HTTPStatusError as e:
        raise RuntimeError(f"Pi-hole vrátil chybu {e.response.status_code}") from None


async def _sync(blocked: list[str]) -> bool:
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
            if not _legacy_cleaned:
                changed = await ph.cleanup_legacy() or changed
                _legacy_cleaned = True
            if changed and get_settings().pihole_restart_dns:
                await ph.restart_dns()
            return changed
        finally:
            await ph.logout()
