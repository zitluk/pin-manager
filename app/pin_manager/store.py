"""Seznam blokovaných domén a aktivní povolení – jeden JSON soubor v DATA_DIR."""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any

from pin_manager.aliases import KNOWN_GROUPS, known_aliases
from pin_manager.config import get_settings


def normalize_domain(value: str) -> str:
    """„https://www.YouTube.com/watch?v=1“ → „youtube.com“; neplatné → ""."""
    d = (value or "").strip().lower()
    for prefix in ("https://", "http://"):
        if d.startswith(prefix):
            d = d[len(prefix):]
    for sep in "/?#":
        d = d.split(sep, 1)[0]
    d = d.split("@")[-1].split(":")[0].strip(".")
    if d.startswith("www."):
        d = d[4:]
    if "." not in d or not all(c.isalnum() or c in "-." for c in d):
        return ""
    return d


class Store:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()

    def _read(self) -> dict[str, Any]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            data = {}
        return _fold(
            {
                "blacklist": list(data.get("blacklist", [])),
                "grants": dict(data.get("grants", {})),
                "aliases": {k: list(v) for k, v in dict(data.get("aliases", {})).items()},
            }
        )

    def _write(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, self.path)

    def blacklist(self) -> list[str]:
        """Hlavní domény (alternativy jsou v aliases())."""
        with self._lock:
            return sorted(set(self._read()["blacklist"]))

    def aliases(self) -> dict[str, list[str]]:
        with self._lock:
            data = self._read()
        return {d: data["aliases"].get(d, []) for d in data["blacklist"]}

    def active_grants(self) -> dict[str, float]:
        now = time.time()
        with self._lock:
            return {d: ts for d, ts in self._read()["grants"].items() if ts > now}

    def blocked(self) -> list[str]:
        """Hlavní domény, které jsou právě blokované (nabídka na stránce s PINem)."""
        grants = self.active_grants()
        return [d for d in self.blacklist() if d not in grants]

    def blocked_hosts(self) -> list[str]:
        """Vše, co má být v Pi-hole blokované: blokované domény i s alternativami."""
        aliases = self.aliases()
        return _expand(self.blocked(), aliases)

    def all_hosts(self) -> list[str]:
        """Všechny spravované domény i s alternativami (blokované i povolené)."""
        aliases = self.aliases()
        return _expand(list(aliases), aliases)

    def add(self, domain: str, extra: str = "") -> str:
        """Přidá doménu se známými alternativami (a `extra` – další čárkou oddělené).

        U už blokované domény jen doplní alternativy z `extra`.
        """
        domain = normalize_domain(domain)
        if not domain:
            raise ValueError("Neplatná doména")
        extras = [d for d in (normalize_domain(x) for x in extra.split(",")) if d and d != domain]
        with self._lock:
            data = self._read()
            for main in data["blacklist"]:
                if domain in data["aliases"].get(main, []):
                    raise ValueError(f"{domain} už je alternativou k {main}")
            alts = data["aliases"].get(domain) or known_aliases(domain)
            data["aliases"][domain] = list(dict.fromkeys([*alts, *extras]))
            data["blacklist"] = sorted(set(data["blacklist"]) | {domain})
            self._write(_fold(data))
        return domain

    def remove(self, domain: str) -> None:
        with self._lock:
            data = self._read()
            data["blacklist"] = [d for d in data["blacklist"] if d != domain]
            data["grants"].pop(domain, None)
            data["aliases"].pop(domain, None)
            self._write(data)

    def grant(self, domain: str, minutes: int) -> None:
        self.set_grant(domain, time.time() + minutes * 60)

    def set_grant(self, domain: str, expires_at: float | None) -> None:
        with self._lock:
            data = self._read()
            if expires_at is None:
                data["grants"].pop(domain, None)
            else:
                data["grants"][domain] = expires_at
            # Prošlá povolení zahodit, ať soubor neroste
            now = time.time()
            data["grants"] = {d: ts for d, ts in data["grants"].items() if ts > now}
            self._write(data)


def _expand(domains: list[str], aliases: dict[str, list[str]]) -> list[str]:
    out: list[str] = []
    for d in domains:
        out += [d, *aliases.get(d, [])]
    return sorted(set(out))


def _fold(data: dict[str, Any]) -> dict[str, Any]:
    """Doplní známé alternativy a samostatné záznamy, které jsou alternativou jiné
    blokované domény, přesune pod ni (např. googlevideo.com → youtube.com)."""
    aliases = data["aliases"]
    # Nejdřív „hlavní“ domény známých skupin (youtube.com před googlevideo.com)
    heads = {g[0] for g in KNOWN_GROUPS}
    order = sorted(set(data["blacklist"]), key=lambda d: (d not in heads, d))
    kept: list[str] = []
    for d in order:
        if any(d in aliases.get(k, []) for k in kept):
            aliases.pop(d, None)
            data["grants"].pop(d, None)
            continue
        if d not in aliases:
            aliases[d] = known_aliases(d)
        kept.append(d)
    data["blacklist"] = sorted(kept)
    data["aliases"] = {d: aliases.get(d, []) for d in kept}
    return data


class Lockout:
    """Omezení pokusů o PIN / heslo podle IP (v paměti procesu)."""

    def __init__(self) -> None:
        self._failures: dict[str, list[float]] = {}
        self._until: dict[str, float] = {}

    def remaining(self, key: str) -> int:
        return max(0, int(self._until.get(key, 0) - time.time()))

    def fail(self, key: str) -> bool:
        s = get_settings()
        now = time.time()
        attempts = [t for t in self._failures.get(key, []) if now - t < s.lockout_seconds]
        attempts.append(now)
        if len(attempts) >= s.max_pin_attempts:
            self._until[key] = now + s.lockout_seconds
            attempts = []
        self._failures[key] = attempts
        return self.remaining(key) > 0

    def clear(self, key: str) -> None:
        self._failures.pop(key, None)
        self._until.pop(key, None)


_store: Store | None = None


def get_store() -> Store:
    global _store
    path = Path(get_settings().data_dir) / "state.json"
    if _store is None or _store.path != path:
        _store = Store(path)
    return _store
