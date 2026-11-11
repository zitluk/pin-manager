from __future__ import annotations

import logging
from types import TracebackType
from urllib.parse import quote

import httpx

from pin_manager.config import get_settings

logger = logging.getLogger(__name__)


class PiHoleClient:
    """Jedna HTTP session na Pi-hole API – po skončení vždy odhlásit (kvůli api_seats_exceeded)."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self.base = self.settings.pihole_url.rstrip("/")
        self._sid: str | None = None
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> PiHoleClient:
        self._client = httpx.AsyncClient()
        await self._login()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.logout()
        if self._client:
            await self._client.aclose()
        self._client = None

    def _http(self) -> httpx.AsyncClient:
        if not self._client:
            raise RuntimeError("PiHoleClient: použijte async with PiHoleClient()")
        return self._client

    async def _login(self) -> str:
        if self._sid:
            return self._sid
        r = await self._http().post(
            f"{self.base}/api/auth",
            json={"password": self.settings.pihole_password},
            timeout=30.0,
        )
        if r.status_code == 401:
            raise RuntimeError("Pi-hole: špatné heslo (401)")
        if r.status_code == 429:
            raise RuntimeError(
                "Pi-hole: příliš mnoho API session (429). "
                "Restartujte Pi-hole FTL nebo zvyšte webserver.api.max_sessions."
            )
        if r.status_code >= 400:
            raise RuntimeError(f"Pi-hole auth {r.status_code}: {r.text[:200]}")
        data = r.json()
        sid = data.get("session", {}).get("sid")
        if not sid:
            raise RuntimeError("Pi-hole login failed: no session sid")
        self._sid = sid
        return sid

    async def logout(self) -> None:
        if not self._sid or not self._client:
            return
        try:
            await self._client.delete(
                f"{self.base}/api/auth",
                headers=self._headers(),
                timeout=15.0,
            )
        except Exception as e:
            logger.debug("Pi-hole logout: %s", e)
        finally:
            self._sid = None

    def _headers(self) -> dict[str, str]:
        if not self._sid:
            raise RuntimeError("Pi-hole: chybí session")
        return {"X-FTL-SID": self._sid, "Content-Type": "application/json"}

    async def remove_deny(self, domain: str) -> None:
        enc = quote(domain, safe="")
        await self._http().delete(
            f"{self.base}/api/domains/deny/exact/{enc}",
            headers=self._headers(),
            timeout=30.0,
        )

    async def grant_allow(self, domain: str, comment: str) -> None:
        await self._http().post(
            f"{self.base}/api/domains/allow/exact",
            headers=self._headers(),
            json={"domain": domain, "comment": comment},
            timeout=30.0,
        )

    async def remove_allow(self, domain: str) -> None:
        enc = quote(domain, safe="")
        await self._http().delete(
            f"{self.base}/api/domains/allow/exact/{enc}",
            headers=self._headers(),
            timeout=30.0,
        )

    @staticmethod
    def _parse_dns_hosts_payload(data: dict) -> list[str]:
        if not isinstance(data, dict):
            return []
        cfg = data.get("config", data)
        if not isinstance(cfg, dict):
            return []
        dns = cfg.get("dns") or {}
        if not isinstance(dns, dict):
            return []
        hosts = dns.get("hosts") or []
        if not isinstance(hosts, list):
            return []
        return [h for h in hosts if isinstance(h, str) and h.strip()]

    async def get_dns_hosts(self) -> list[str]:
        r = await self._http().get(
            f"{self.base}/api/config/dns/hosts",
            headers=self._headers(),
            timeout=30.0,
        )
        r.raise_for_status()
        return self._parse_dns_hosts_payload(r.json())

    async def sync_pin_dns_hosts(self, portal_ip: str, domains: list[str]) -> None:
        prefix = f"{portal_ip} "
        desired = {f"{portal_ip} {d}" for d in set(domains)}
        existing = await self.get_dns_hosts()
        pin_managed = {h for h in existing if h.startswith(prefix)}
        for entry in sorted(pin_managed - desired):
            enc = quote(entry, safe="")
            r = await self._http().delete(
                f"{self.base}/api/config/dns/hosts/{enc}",
                headers=self._headers(),
                timeout=30.0,
            )
            if r.status_code >= 400:
                logger.warning("DELETE dns.hosts %s → %s: %s", entry, r.status_code, r.text)
        failed_add: list[str] = []
        for entry in sorted(desired - pin_managed):
            host_part = entry.split(" ", 1)[1] if " " in entry else ""
            if "://" in entry or not host_part or "." not in host_part:
                failed_add.append(entry)
                continue
            enc = quote(entry, safe="")
            r = await self._http().put(
                f"{self.base}/api/config/dns/hosts/{enc}",
                headers=self._headers(),
                timeout=30.0,
            )
            if r.status_code >= 400:
                logger.warning("PUT dns.hosts %s → %s: %s", entry, r.status_code, r.text)
                failed_add.append(entry)
        if failed_add:
            raise RuntimeError(
                f"Pi-hole neuložil DNS záznamy: {', '.join(failed_add)}"
            )

    async def probe(self) -> dict:
        out: dict = {"url": self.base, "ok": False}
        try:
            async with PiHoleClient() as ph:
                hosts = await ph.get_dns_hosts()
                out["ok"] = True
                out["local_dns_count"] = len(hosts)
        except Exception as e:
            out["error"] = str(e)
        return out

    async def restart_dns(self) -> None:
        if not self.settings.pihole_restart_dns:
            return
        r = await self._http().post(
            f"{self.base}/api/action/restartdns",
            headers=self._headers(),
            timeout=60.0,
        )
        if r.status_code >= 400:
            logger.warning("restartdns returned %s: %s", r.status_code, r.text)
