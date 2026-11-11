from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

from pin_manager.config import get_settings
from pin_manager.fileutil import json_snapshot, json_transaction


def _default() -> dict[str, Any]:
    return {"blacklist": [], "grants": {}}


class DataStore:
    """Úložiště blacklistu a aktivních povolení.

    Každá operace čte aktuální stav z disku pod zámkem (sdílí ho HTTP i HTTPS proces)
    a zápis je atomický.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._sanitize_domains()

    def _read(self) -> dict[str, Any]:
        return json_snapshot(self._path, _default)

    def _sanitize_domains(self) -> None:
        """Opraví staré záznamy typu https://www.youtube.com v blacklistu."""
        with json_transaction(self._path, _default) as data:
            bl = list(data.get("blacklist", []))
            data["blacklist"] = sorted({d for x in bl if (d := _normalize_domain(x))})
            new_grants: dict[str, float] = {}
            for k, v in dict(data.get("grants", {})).items():
                nk = _normalize_domain(k)
                if nk:
                    new_grants[nk] = v
            data["grants"] = new_grants

    def list_blacklist(self) -> list[str]:
        return sorted(set(self._read().get("blacklist", [])))

    def add_blacklist(self, domain: str) -> None:
        domain = _normalize_domain(domain)
        if not domain:
            return
        with json_transaction(self._path, _default) as data:
            bl = set(data.get("blacklist", []))
            bl.add(domain)
            data["blacklist"] = sorted(bl)

    def remove_blacklist(self, domain: str) -> None:
        domain = _normalize_domain(domain)
        with json_transaction(self._path, _default) as data:
            bl = set(data.get("blacklist", []))
            bl.discard(domain)
            data["blacklist"] = sorted(bl)

    def set_grant(self, domain: str, expires_at: float) -> None:
        domain = _normalize_domain(domain)
        if not domain:
            return
        with json_transaction(self._path, _default) as data:
            data.setdefault("grants", {})[domain] = expires_at

    def clear_grant(self, domain: str) -> None:
        domain = _normalize_domain(domain)
        with json_transaction(self._path, _default) as data:
            data.setdefault("grants", {}).pop(domain, None)

    def grant_until_raw(self, domain: str) -> float | None:
        """Uložený čas vypršení (i prošlý) – kvůli návratu stavu po chybě."""
        domain = _normalize_domain(domain)
        return self._read().get("grants", {}).get(domain)

    def active_grants(self) -> dict[str, float]:
        """Jen platná povolení. Prošlá NEMAŽE – to dělá pop_expired_grants() v plánovači,
        který zároveň vrátí blokování v Pi-hole."""
        now = time.time()
        grants = self._read().get("grants", {})
        return {d: ts for d, ts in grants.items() if ts > now}

    def pop_expired_grants(self, now: float | None = None) -> dict[str, float]:
        """Atomicky odebere prošlá povolení a vrátí je (doména → čas vypršení)."""
        now = time.time() if now is None else now
        with json_transaction(self._path, _default) as data:
            grants = data.setdefault("grants", {})
            expired = {d: ts for d, ts in grants.items() if ts <= now}
            for d in expired:
                grants.pop(d, None)
        return expired

    def blacklist_match(self, domain: str) -> str | None:
        """Najde položku blacklistu pro host (www ↔ apex, poddomény typu m.youtube.com)."""
        domain = _normalize_domain(domain)
        if not domain:
            return None
        bl = sorted({_normalize_domain(d) for d in self.list_blacklist()}, key=len, reverse=True)
        if domain in bl:
            return domain
        if domain.startswith("www."):
            apex = domain[4:]
            if apex in bl:
                return apex
        elif f"www.{domain}" in bl:
            return domain
        for d in bl:
            if domain.endswith("." + d):
                return d
        return None

    def active_grant_until(self, domain: str) -> float | None:
        """Čas vypršení grantu pro host (včetně www/apex)."""
        domain = _normalize_domain(domain)
        if not domain:
            return None
        grants = self.active_grants()
        canonical = self.blacklist_match(domain)
        keys = set(_domain_variants(domain))
        if canonical:
            keys |= _domain_variants(canonical)
        for k in keys:
            if k in grants:
                return grants[k]
        return None

    def is_blocked(self, domain: str) -> bool:
        domain = _normalize_domain(domain)
        if not domain:
            return False
        grants = self.active_grants()
        for variant in _domain_variants(domain):
            if variant in grants:
                return False
        return self.blacklist_match(domain) is not None

    def blocked_domains_for_sinkhole(self) -> list[str]:
        grants = self.active_grants()
        out: list[str] = []
        for d in self.list_blacklist():
            nd = _normalize_domain(d)
            if nd and nd not in grants:
                out.append(nd)
        return sorted(set(out))


def _domain_variants(domain: str) -> set[str]:
    domain = _normalize_domain(domain)
    if not domain:
        return set()
    if domain.startswith("www."):
        apex = domain[4:]
        return {domain, apex}
    return {domain, f"www.{domain}"}


def _normalize_domain(domain: str) -> str:
    domain = domain.strip().lower().rstrip(".")
    if not domain:
        return ""
    # Opakovaně: https://www.https://… z formátů zkopírovaných z adresního řádku
    for _ in range(5):
        before = domain
        for prefix in ("https://", "http://"):
            if domain.startswith(prefix):
                domain = domain[len(prefix) :]
        if domain.startswith("www."):
            domain = domain[4:]
        if domain == before:
            break
    if "/" in domain:
        domain = domain.split("/", 1)[0]
    if "?" in domain:
        domain = domain.split("?", 1)[0]
    if "#" in domain:
        domain = domain.split("#", 1)[0]
    if "@" in domain:
        domain = domain.split("@", 1)[-1]
    if ":" in domain and not domain.startswith("["):  # neřešíme raw IPv6
        domain = domain.split(":", 1)[0]
    domain = domain.strip(".")
    if "://" in domain or "/" in domain or " " in domain:
        return ""
    if "." not in domain:
        return ""
    return domain


_stores: dict[str, DataStore] = {}
_stores_guard = threading.Lock()


def get_store() -> DataStore:
    path = Path(get_settings().data_dir) / "state.json"
    with _stores_guard:
        store = _stores.get(str(path))
        if store is None:
            store = _stores[str(path)] = DataStore(path)
        return store
