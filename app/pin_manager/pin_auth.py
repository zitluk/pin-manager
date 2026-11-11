"""Rodinný PIN – uložený v /data (bcrypt); env PIN jen jako výchozí před první změnou."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

import bcrypt

from pin_manager.config import get_settings

_lock = threading.Lock()
MIN_PIN_LEN = 4
MAX_PIN_LEN = 12


def _path() -> Path:
    return Path(get_settings().data_dir) / "family_pin.json"


def _read() -> dict[str, Any]:
    p = _path()
    if not p.is_file():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def has_stored_pin() -> bool:
    data = _read()
    return bool(data.get("pin_hash"))


def effective_pin_hash() -> str | None:
    """Hash z disku má přednost před env."""
    data = _read()
    h = data.get("pin_hash")
    if isinstance(h, str) and h.startswith("$2"):
        return h
    settings = get_settings()
    if settings.pin_hash:
        return settings.pin_hash
    return None


def effective_pin_plain() -> str | None:
    if has_stored_pin():
        return None
    settings = get_settings()
    if settings.pin_hash:
        return None
    pin = (settings.pin or "").strip()
    return pin or None


def verify_family_pin(pin_input: str) -> bool:
    pin_hash = effective_pin_hash()
    if pin_hash:
        try:
            return bcrypt.checkpw(
                pin_input.encode("utf-8"),
                pin_hash.encode("utf-8"),
            )
        except (ValueError, TypeError):
            return False
    plain = effective_pin_plain()
    if plain is not None:
        return pin_input == plain
    return False


def set_family_pin(new_pin: str) -> None:
    new_pin = new_pin.strip()
    if not new_pin.isdigit():
        raise ValueError("PIN musí obsahovat jen číslice.")
    if not (MIN_PIN_LEN <= len(new_pin) <= MAX_PIN_LEN):
        raise ValueError(
            f"PIN musí mít {MIN_PIN_LEN}–{MAX_PIN_LEN} číslic."
        )
    pin_hash = bcrypt.hashpw(
        new_pin.encode("utf-8"),
        bcrypt.gensalt(),
    ).decode("utf-8")
    p = _path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        p.write_text(
            json.dumps({"pin_hash": pin_hash}, indent=2),
            encoding="utf-8",
        )
