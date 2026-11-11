from __future__ import annotations

import asyncio
import logging
import re
from contextlib import asynccontextmanager
from types import TracebackType
from urllib.parse import quote

import httpx

from pin_manager.config import get_settings
from pin_manager.store import _normalize_domain

logger = logging.getLogger(__name__)

_API_LOCK = asyncio.Lock()
AAAA_DENY_COMMENT = "pin-manager-aaaa"
SILENT_DENY_COMMENT = "pin-manager-silent"


# Typy dotazů, které u blokované domény musí vrátit NODATA:
#  AAAA  – jinak prohlížeč jede přes IPv6 na skutečný server
#  HTTPS/SVCB (TYPE65/64) – obsahují ipv4hint/ipv6hint se skutečnými IP; Safari je
#        používá a portál úplně obejde (takhle se otevíralo centrum.cz bez PINu)
NODATA_QTYPES: tuple[str, ...] = ("AAAA", "HTTPS", "SVCB")

# Obchvaty DNS: iCloud Private Relay a automatické DoH ve Firefoxu.
# Apple i Mozilla doporučují síťům vrátit NXDOMAIN – zařízení pak použije místní DNS.
ANTI_BYPASS_REGEX: tuple[str, ...] = (
    r"^mask(-h2)?\.icloud\.com$;reply=nxdomain",
    r"^use-application-dns\.net$;reply=nxdomain",
)


def qtype_nodata_regex(apex: str, qtype: str) -> str:
    d = _normalize_domain(apex)
    if not d:
        raise ValueError("prázdná doména pro regex")
    return f"(\\.|^){re.escape(d)}$;querytype={qtype};reply=nodata"


def desired_pin_regex_rules(apex_domains: list[str], *, anti_bypass: bool) -> set[str]:
    rules = {
        qtype_nodata_regex(d, qt)
        for d in {_normalize_domain(x) for x in apex_domains}
        if d
        for qt in NODATA_QTYPES
    }
    if anti_bypass:
        rules |= set(ANTI_BYPASS_REGEX)
    return rules


def _is_pin_address_line(line: str, portal_ip: str) -> bool:
    return (
        isinstance(line, str)
        and line.startswith("address=/")
        and line.rstrip().endswith(f"/{portal_ip}")
    )


def merge_dnsmasq_lines(existing: list[str], portal_ip: str, apex_domains: list[str]) -> list[str]:
    """Ponechá cizí řádky, nahradí naše address=/<doména>/<PORTAL_IP>.

    address=/youtube.com/IP platí i pro všechny poddomény (m.youtube.com,
    rr1---sn-….googlevideo.com) – Local DNS záznamy (dns.hosts) uměly jen přesná jména.
    """
    keep = [ln for ln in existing if not _is_pin_address_line(ln, portal_ip)]
    ours = [
        f"address=/{d}/{portal_ip}"
        for d in sorted({_normalize_domain(x) for x in apex_domains} - {""})
    ]
    return keep + ours


def aaaa_nodata_regex(apex: str) -> str:
    """Pi-hole regex + extension: jen AAAA → NODATA (viz docs.pi-hole.net/regex/pi-hole)."""
    d = _normalize_domain(apex)
    if not d:
        raise ValueError("prázdná doména pro AAAA regex")
    escaped = re.escape(d)
    return f"(\\.|^){escaped}$;querytype=AAAA;reply=nodata"


@asynccontextmanager
async def pihole_api():
    """Jedna Pi-hole session najednou (Pi-hole default max ~16)."""
    async with _API_LOCK:
        async with PiHoleClient() as client:
            yield client


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
            sid_q = quote(self._sid, safe="")
            await self._client.delete(
                f"{self.base}/api/auth?sid={sid_q}",
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

    async def add_deny_exact(self, domain: str, comment: str = SILENT_DENY_COMMENT) -> None:
        r = await self._http().post(
            f"{self.base}/api/domains/deny/exact",
            headers=self._headers(),
            json={"domain": domain, "comment": comment, "groups": [0]},
            timeout=30.0,
        )
        if r.status_code >= 400:
            raise RuntimeError(
                f"Pi-hole deny exact ({r.status_code}): {r.text[:300]}"
            )
        try:
            errs = self._api_errors(r.json())
        except Exception:
            errs = []
        if errs and "already" not in errs[0].lower():
            raise RuntimeError(f"Pi-hole deny exact: {errs[0]}")

    async def _list_pin_silent_exact_denies(self) -> set[str]:
        out: set[str] = set()
        r = await self._http().get(
            f"{self.base}/api/domains/deny/exact",
            headers=self._headers(),
            timeout=30.0,
        )
        r.raise_for_status()
        data = r.json()
        items = data.get("domains")
        if not isinstance(items, list):
            return out
        for item in items:
            if not isinstance(item, dict):
                continue
            if item.get("comment") != SILENT_DENY_COMMENT:
                continue
            dom = item.get("domain")
            if isinstance(dom, str) and dom:
                out.add(dom)
        return out

    async def sync_pin_silent_block(self, apex_domains: list[str]) -> int:
        from pin_manager.domain_expand import expand_sinkhole_domains

        desired = set(expand_sinkhole_domains(apex_domains))
        existing = await self._list_pin_silent_exact_denies()
        for dom in sorted(existing - desired):
            await self.remove_deny(dom)
        for dom in sorted(desired - existing):
            await self.add_deny_exact(dom)
        return len(desired)

    def _api_errors(self, data: dict) -> list[str]:
        proc = data.get("processed") if isinstance(data, dict) else None
        if not isinstance(proc, dict):
            return []
        errors = proc.get("errors") or []
        out: list[str] = []
        for item in errors:
            if isinstance(item, dict):
                msg = item.get("error") or item.get("message") or str(item)
                out.append(str(msg))
        return out

    async def add_deny_regex(self, rule: str, comment: str = AAAA_DENY_COMMENT) -> None:
        r = await self._http().post(
            f"{self.base}/api/domains/deny/regex",
            headers=self._headers(),
            json={"domain": rule, "comment": comment, "groups": [0]},
            timeout=30.0,
        )
        if r.status_code >= 400:
            raise RuntimeError(
                f"Pi-hole regex deny ({r.status_code}): {r.text[:300]}"
            )
        try:
            errs = self._api_errors(r.json())
        except Exception:
            errs = []
        if errs and "already" not in errs[0].lower():
            raise RuntimeError(f"Pi-hole regex deny: {errs[0]}")

    async def remove_deny_regex(self, rule: str) -> None:
        enc = quote(rule, safe="")
        r = await self._http().delete(
            f"{self.base}/api/domains/deny/regex/{enc}",
            headers=self._headers(),
            timeout=30.0,
        )
        if r.status_code >= 400:
            logger.debug("DELETE deny regex %s → %s", rule, r.status_code)

    async def _list_pin_aaaa_regex_rules(self) -> set[str]:
        out: set[str] = set()
        r = await self._http().get(
            f"{self.base}/api/domains/deny/regex",
            headers=self._headers(),
            timeout=30.0,
        )
        r.raise_for_status()
        data = r.json()
        items = data.get("domains")
        if items is None and isinstance(data.get("regex"), list):
            items = data.get("regex")
        if not isinstance(items, list):
            return out
        for item in items:
            if not isinstance(item, dict):
                continue
            if item.get("comment") != AAAA_DENY_COMMENT:
                continue
            rule = item.get("domain") or item.get("regex")
            if isinstance(rule, str) and rule:
                out.add(rule)
        return out

    async def sync_pin_aaaa_nodata(self, apex_domains: list[str]) -> int:
        """Regex pravidla: NODATA pro AAAA/HTTPS/SVCB u blokovaných domén + anti-obchvat.

        Mění jen rozdíl proti stavu v Pi-hole (dřív vše mazalo a znovu přidávalo)."""
        desired = desired_pin_regex_rules(
            apex_domains, anti_bypass=self.settings.block_dns_bypass
        )
        existing = await self._list_pin_aaaa_regex_rules()
        for rule in sorted(existing - desired):
            await self.remove_deny_regex(rule)
        for rule in sorted(desired - existing):
            await self.add_deny_regex(rule)
        return len(desired)

    async def get_dnsmasq_lines(self) -> list[str]:
        r = await self._http().get(
            f"{self.base}/api/config/misc/dnsmasq_lines",
            headers=self._headers(),
            timeout=30.0,
        )
        r.raise_for_status()
        data = r.json()
        cfg = data.get("config", data) if isinstance(data, dict) else {}
        lines = (cfg.get("misc") or {}).get("dnsmasq_lines") if isinstance(cfg, dict) else None
        if not isinstance(lines, list):
            raise RuntimeError("Pi-hole: neočekávaná odpověď misc.dnsmasq_lines")
        return [ln for ln in lines if isinstance(ln, str)]

    async def sync_pin_dnsmasq_lines(self, portal_ip: str, apex_domains: list[str]) -> bool:
        """Zapíše address=/doména/PORTAL_IP do misc.dnsmasq_lines. Vrací True při změně."""
        existing = await self.get_dnsmasq_lines()
        desired = merge_dnsmasq_lines(existing, portal_ip, apex_domains)
        if desired == existing:
            return False
        r = await self._http().patch(
            f"{self.base}/api/config",
            headers=self._headers(),
            json={"config": {"misc": {"dnsmasq_lines": desired}}},
            timeout=60.0,
        )
        if r.status_code >= 400:
            raise RuntimeError(f"Pi-hole dnsmasq_lines ({r.status_code}): {r.text[:300]}")
        return True

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
        return await probe_pihole_api()

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


async def probe_pihole_api() -> dict:
    settings = get_settings()
    base = settings.pihole_url.rstrip("/")
    out: dict = {"url": base, "ok": False}
    try:
        async with pihole_api() as ph:
            hosts = await ph.get_dns_hosts()
            out["ok"] = True
            out["local_dns_count"] = len(hosts)
    except Exception as e:
        out["error"] = str(e)
    return out
