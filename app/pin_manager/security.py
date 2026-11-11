"""Omezení pokusů (PIN i admin login).

Stav je v /data/lockout.json pod zámkem souboru – sdílí ho HTTP (:80) i HTTPS (:443)
proces a přežije restart kontejneru. Dříve byl jen v paměti procesu, takže šlo
střídáním http/https zdvojnásobit počet pokusů.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from pin_manager.config import get_settings
from pin_manager.fileutil import json_snapshot, json_transaction
from pin_manager.pin_auth import verify_family_pin

SCOPE_PIN = "pin"
SCOPE_ADMIN = "admin"


def verify_pin(pin_input: str) -> bool:
    return verify_family_pin(pin_input)


def _path() -> Path:
    return Path(get_settings().data_dir) / "lockout.json"


def _key(client_ip: str, scope: str) -> str:
    return f"{scope}:{client_ip or 'unknown'}"


def _prune(data: dict[str, Any], now: float, window: int) -> None:
    """Zahodí staré záznamy, ať soubor neroste."""
    for k in list(data):
        entry = data[k]
        entry["attempts"] = [t for t in entry.get("attempts", []) if now - t < window]
        if not entry["attempts"] and entry.get("until", 0) <= now:
            del data[k]


def is_locked(client_ip: str, scope: str = SCOPE_PIN) -> tuple[bool, int]:
    entry = json_snapshot(_path(), dict).get(_key(client_ip, scope)) or {}
    until = float(entry.get("until", 0))
    now = time.time()
    if until > now:
        return True, max(1, int(until - now))
    return False, 0


def record_failed_attempt(client_ip: str, scope: str = SCOPE_PIN) -> tuple[bool, int]:
    settings = get_settings()
    window = settings.lockout_seconds
    now = time.time()
    with json_transaction(_path(), dict) as data:
        _prune(data, now, window)
        entry = data.setdefault(_key(client_ip, scope), {"attempts": [], "until": 0})
        entry["attempts"].append(now)
        if len(entry["attempts"]) >= settings.max_pin_attempts:
            entry["attempts"] = []
            entry["until"] = now + window
            return True, window
    return False, 0


def clear_attempts(client_ip: str, scope: str = SCOPE_PIN) -> None:
    with json_transaction(_path(), dict) as data:
        data.pop(_key(client_ip, scope), None)
