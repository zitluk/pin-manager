from __future__ import annotations

import logging
from urllib.parse import quote

import httpx

from pin_manager.config import get_settings

logger = logging.getLogger(__name__)


class PiHoleClient:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.base = self.settings.pihole_url.rstrip("/")
        self._sid: str | None = None

    async def _login(self, client: httpx.AsyncClient) -> str:
        if self._sid:
            return self._sid
        r = await client.post(
            f"{self.base}/api/auth",
            json={"password": self.settings.pihole_password},
            timeout=30.0,
        )
        r.raise_for_status()
        data = r.json()
        sid = data.get("session", {}).get("sid")
        if not sid:
            raise RuntimeError("Pi-hole login failed: no session sid")
        self._sid = sid
        return sid

    def _headers(self, sid: str) -> dict[str, str]:
        return {"X-FTL-SID": sid, "Content-Type": "application/json"}

    async def ensure_deny(self, domain: str) -> None:
        async with httpx.AsyncClient() as client:
            sid = await self._login(client)
            await client.post(
                f"{self.base}/api/domains/deny/exact",
                headers=self._headers(sid),
                json={"domain": domain, "comment": "pin-manager blacklist"},
                timeout=30.0,
            )

    async def remove_deny(self, domain: str) -> None:
        async with httpx.AsyncClient() as client:
            sid = await self._login(client)
            enc = quote(domain, safe="")
            await client.delete(
                f"{self.base}/api/domains/deny/exact/{enc}",
                headers=self._headers(sid),
                timeout=30.0,
            )

    async def grant_allow(self, domain: str, comment: str) -> None:
        async with httpx.AsyncClient() as client:
            sid = await self._login(client)
            await client.post(
                f"{self.base}/api/domains/allow/exact",
                headers=self._headers(sid),
                json={"domain": domain, "comment": comment},
                timeout=30.0,
            )

    async def remove_allow(self, domain: str) -> None:
        async with httpx.AsyncClient() as client:
            sid = await self._login(client)
            enc = quote(domain, safe="")
            await client.delete(
                f"{self.base}/api/domains/allow/exact/{enc}",
                headers=self._headers(sid),
                timeout=30.0,
            )

    async def get_dns_hosts(self, client: httpx.AsyncClient, sid: str) -> list[str]:
        r = await client.get(
            f"{self.base}/api/config/dns/hosts",
            headers=self._headers(sid),
            timeout=30.0,
        )
        r.raise_for_status()
        data = r.json()
        return list(data.get("config", {}).get("dns", {}).get("hosts", []) or [])

    async def sync_pin_dns_hosts(self, portal_ip: str, domains: list[str]) -> None:
        """Nastaví v Pi-hole Local DNS: portal_ip → doména (viditelné v UI)."""
        prefix = f"{portal_ip} "
        async with httpx.AsyncClient() as client:
            sid = await self._login(client)
            existing = await self.get_dns_hosts(client, sid)
            kept = [h for h in existing if not h.startswith(prefix)]
            for domain in sorted(set(domains)):
                kept.append(f"{portal_ip} {domain}")
            r = await client.patch(
                f"{self.base}/api/config",
                headers=self._headers(sid),
                json={"config": {"dns": {"hosts": kept}}},
                timeout=60.0,
            )
            if r.status_code >= 400:
                logger.warning("PATCH dns.hosts failed %s: %s", r.status_code, r.text)
                r.raise_for_status()

    async def restart_dns(self) -> None:
        if not self.settings.pihole_restart_dns:
            return
        async with httpx.AsyncClient() as client:
            sid = await self._login(client)
            r = await client.post(
                f"{self.base}/api/action/restartdns",
                headers=self._headers(sid),
                timeout=60.0,
            )
            if r.status_code >= 400:
                logger.warning("restartdns returned %s: %s", r.status_code, r.text)
