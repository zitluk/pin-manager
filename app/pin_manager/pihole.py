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
        if r.status_code == 401:
            raise RuntimeError("Pi-hole: špatné heslo (401)")
        if r.status_code >= 400:
            raise RuntimeError(f"Pi-hole auth {r.status_code}: {r.text[:200]}")
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

    async def get_dns_hosts(self, client: httpx.AsyncClient, sid: str) -> list[str]:
        r = await client.get(
            f"{self.base}/api/config/dns/hosts",
            headers=self._headers(sid),
            timeout=30.0,
        )
        r.raise_for_status()
        return self._parse_dns_hosts_payload(r.json())

    async def sync_pin_dns_hosts(self, portal_ip: str, domains: list[str]) -> None:
        """Local DNS v Pi-hole: „IP doména“ – pouze PUT/DELETE, bez PATCH celého seznamu."""
        prefix = f"{portal_ip} "
        desired = {f"{portal_ip} {d}" for d in set(domains)}
        async with httpx.AsyncClient() as client:
            sid = await self._login(client)
            existing = await self.get_dns_hosts(client, sid)
            pin_managed = {h for h in existing if h.startswith(prefix)}
            for entry in sorted(pin_managed - desired):
                enc = quote(entry, safe="")
                r = await client.delete(
                    f"{self.base}/api/config/dns/hosts/{enc}",
                    headers=self._headers(sid),
                    timeout=30.0,
                )
                if r.status_code >= 400:
                    logger.warning("DELETE dns.hosts %s → %s: %s", entry, r.status_code, r.text)
            failed_add: list[str] = []
            for entry in sorted(desired - pin_managed):
                host_part = entry.split(" ", 1)[1] if " " in entry else ""
                if "://" in entry or not host_part or "." not in host_part:
                    failed_add.append(entry)
                    logger.warning("Neplatný DNS záznam pro Pi-hole: %s", entry)
                    continue
                enc = quote(entry, safe="")
                r = await client.put(
                    f"{self.base}/api/config/dns/hosts/{enc}",
                    headers=self._headers(sid),
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
        """Rychlá kontrola dostupnosti API z kontejneru."""
        out: dict = {"url": self.base, "ok": False}
        try:
            async with httpx.AsyncClient() as client:
                sid = await self._login(client)
                hosts = await self.get_dns_hosts(client, sid)
                out["ok"] = True
                out["local_dns_count"] = len(hosts)
        except Exception as e:
            out["error"] = str(e)
        return out

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
