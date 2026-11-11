import time
from collections import defaultdict

from pin_manager.pin_auth import verify_family_pin

_attempts: dict[str, list[float]] = defaultdict(list)
_lock_until: dict[str, float] = defaultdict(float)


def verify_pin(pin_input: str) -> bool:
    return verify_family_pin(pin_input)


def _client_key(ip: str) -> str:
    return ip or "unknown"


def is_locked(client_ip: str) -> tuple[bool, int]:
    from pin_manager.config import get_settings

    settings = get_settings()
    key = _client_key(client_ip)
    until = _lock_until.get(key, 0)
    now = time.time()
    if until > now:
        return True, int(until - now)
    return False, 0


def record_failed_attempt(client_ip: str) -> tuple[bool, int]:
    from pin_manager.config import get_settings

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
