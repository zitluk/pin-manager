import json
import threading
import time
from pathlib import Path
from typing import Any

from pin_manager.config import get_settings


class DataStore:
    """Jednoduché úložiště blacklistu a aktivních povolení."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._load()

    def _default(self) -> dict[str, Any]:
        return {"blacklist": [], "grants": {}}

    def _load(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if self._path.exists():
            with open(self._path, encoding="utf-8") as f:
                self._data = json.load(f)
            self._sanitize_domains()
        else:
            self._data = self._default()
            self._save()

    def _sanitize_domains(self) -> None:
        """Opraví staré záznamy typu https://www.youtube.com v blacklistu."""
        with self._lock:
            bl = list(self._data.get("blacklist", []))
            new_bl = sorted({d for x in bl if (d := _normalize_domain(x))})
            grants = dict(self._data.get("grants", {}))
            new_grants: dict[str, float] = {}
            for k, v in grants.items():
                nk = _normalize_domain(k)
                if nk:
                    new_grants[nk] = v
            if new_bl != sorted(set(bl)) or new_grants != grants:
                self._data["blacklist"] = new_bl
                self._data["grants"] = new_grants
                self._save()

    def _save(self) -> None:
        with open(self._path, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2, ensure_ascii=False)

    def list_blacklist(self) -> list[str]:
        with self._lock:
            return sorted(set(self._data.get("blacklist", [])))

    def add_blacklist(self, domain: str) -> None:
        domain = _normalize_domain(domain)
        with self._lock:
            bl = set(self._data.get("blacklist", []))
            bl.add(domain)
            self._data["blacklist"] = sorted(bl)
            self._save()

    def remove_blacklist(self, domain: str) -> None:
        domain = _normalize_domain(domain)
        with self._lock:
            bl = set(self._data.get("blacklist", []))
            bl.discard(domain)
            self._data["blacklist"] = sorted(bl)
            self._save()

    def set_grant(self, domain: str, expires_at: float) -> None:
        domain = _normalize_domain(domain)
        with self._lock:
            grants = self._data.setdefault("grants", {})
            grants[domain] = expires_at
            self._save()

    def clear_grant(self, domain: str) -> None:
        domain = _normalize_domain(domain)
        with self._lock:
            grants = self._data.setdefault("grants", {})
            grants.pop(domain, None)
            self._save()

    def active_grants(self) -> dict[str, float]:
        now = time.time()
        with self._lock:
            grants = dict(self._data.get("grants", {}))
            expired = [d for d, ts in grants.items() if ts <= now]
            for d in expired:
                grants.pop(d, None)
            if expired:
                self._data["grants"] = grants
                self._save()
            return grants

    def blacklist_match(self, domain: str) -> str | None:
        """Najde položku blacklistu pro host (včetně www ↔ apex)."""
        domain = _normalize_domain(domain)
        if not domain:
            return None
        bl = {_normalize_domain(d) for d in self.list_blacklist()}
        if domain in bl:
            return domain
        if domain.startswith("www."):
            apex = domain[4:]
            if apex in bl:
                return apex
        elif f"www.{domain}" in bl:
            return domain
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


def get_store() -> DataStore:
    settings = get_settings()
    return DataStore(Path(settings.data_dir) / "state.json")
