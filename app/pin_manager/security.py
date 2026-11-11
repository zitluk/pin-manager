import time
from collections import defaultdict

import bcrypt

from pin_manager.config import get_settings

_attempts: dict[str, list[float]] = defaultdict(list)
_lock_until: dict[str, float] = defaultdict(float)


def verify_pin(pin_input: str) -> bool:
    settings = get_settings()
    if settings.pin_hash:
        return bcrypt.checkpw(
            pin_input.encode("utf-8"),
            settings.pin_hash.encode("utf-8"),
        )
    if settings.pin:
        return pin_input == settings.pin
    return False


def _client_key(ip: str) -> str:
    return ip or "unknown"


def is_locked(client_ip: str) -> tuple[bool, int]:
    settings = get_settings()
    key = _client_key(client_ip)
    until = _lock_until.get(key, 0)
    now = time.time()
    if until > now:
        return True, int(until - now)
    return False, 0


def record_failed_attempt(client_ip: str) -> tuple[bool, int]:
    settings = get_settings()
    key = _client_key(client_ip)
    now = time.time()
    window = _attempts[key]
    window = [t for t in window if now - t < settings.lockout_seconds]
    window.append(now)
    _attempts[key] = window
    if len(window) >= settings.max_pin_attempts:
        _lock_until[key] = now + settings.lockout_seconds
        _attempts[key] = []
        return True, settings.lockout_seconds
    return False, 0


def clear_attempts(client_ip: str) -> None:
    key = _client_key(client_ip)
    _attempts.pop(key, None)
    _lock_until.pop(key, None)
