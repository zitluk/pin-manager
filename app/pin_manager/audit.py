from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Request

from pin_manager.config import get_settings

_lock = threading.Lock()

ACTION_LABELS: dict[str, str] = {
    "blocked_access": "Požadavek na blokovanou stránku (PIN)",
    "pin_failed": "Neplatný PIN",
    "pin_lockout": "PIN uzamčen (příliš pokusů)",
    "pin_unlock": "Přístup povolen po PIN",
    "grant_expired": "Platnost povolení vypršela",
    "admin_login_ok": "Přihlášení administrace",
    "admin_login_fail": "Neúspěšné přihlášení administrace",
    "blacklist_add": "Doména přidána na blacklist",
    "blacklist_remove": "Doména odebrána z blacklistu",
}


def client_ip(request: Request | None) -> str:
    if request is None:
        return "systém"
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "?"


def _audit_path() -> Path:
    settings = get_settings()
    path = Path(settings.data_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path / "audit.jsonl"


def log_event(
    action: str,
    *,
    request: Request | None = None,
    client_ip_value: str | None = None,
    domain: str | None = None,
    detail: str | None = None,
) -> None:
    entry: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S"),
        "client_ip": client_ip_value if client_ip_value is not None else client_ip(request),
        "action": action,
        "action_label": ACTION_LABELS.get(action, action),
        "domain": domain or "",
        "detail": detail or "",
    }
    if request is not None:
        ua = request.headers.get("user-agent", "")
        if ua:
            entry["user_agent"] = ua[:240]

    line = json.dumps(entry, ensure_ascii=False) + "\n"
    path = _audit_path()
    with _lock:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line)
        _trim_if_needed(path)


def _trim_if_needed(path: Path) -> None:
    settings = get_settings()
    max_lines = settings.audit_log_max_lines
    if max_lines <= 0:
        return
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
        if len(lines) <= max_lines:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(lines[-max_lines:])
    except OSError:
        pass


def read_recent(limit: int | None = None) -> list[dict[str, Any]]:
    settings = get_settings()
    cap = limit if limit is not None else settings.audit_log_display_limit
    path = _audit_path()
    if not path.exists():
        return []
    with _lock:
        lines = path.read_text(encoding="utf-8").splitlines()
    tail = lines[-cap:] if cap else lines
    out: list[dict[str, Any]] = []
    for line in tail:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    out.reverse()
    return out
