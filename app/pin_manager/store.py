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
        else:
            self._data = self._default()
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

    def is_blocked(self, domain: str) -> bool:
        domain = _normalize_domain(domain)
        grants = self.active_grants()
        if domain in grants:
            return False
        return domain in self.list_blacklist()

    def blocked_domains_for_sinkhole(self) -> list[str]:
        grants = self.active_grants()
        return [d for d in self.list_blacklist() if d not in grants]


def _normalize_domain(domain: str) -> str:
    domain = domain.strip().lower().rstrip(".")
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix) :]
    if "/" in domain:
        domain = domain.split("/", 1)[0]
    if "@" in domain:
        domain = domain.split("@", 1)[-1]
    if domain.startswith("www."):
        domain = domain[4:]
    if ":" in domain:
        domain = domain.split(":", 1)[0]
    return domain


def get_store() -> DataStore:
    settings = get_settings()
    return DataStore(Path(settings.data_dir) / "state.json")
