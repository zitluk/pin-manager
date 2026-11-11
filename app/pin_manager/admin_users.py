from __future__ import annotations

import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import bcrypt

from pin_manager.config import get_settings
from pin_manager.fileutil import file_lock, json_snapshot, json_transaction

MIN_PASSWORD_LEN = 8


class AdminAccountStore:
    """Jeden administrátor – registrace jen dokud účet neexistuje."""

    def __init__(self, path: Path) -> None:
        self._path = path

    def _read(self) -> dict[str, Any]:
        return json_snapshot(self._path, dict)

    def has_admin(self) -> bool:
        return bool(self._read().get("password_hash"))

    def username(self) -> str | None:
        return self._read().get("username")

    def register(self, username: str, password: str) -> str:
        username = username.strip().lower()
        if not username:
            raise ValueError("Zadejte uživatelské jméno.")
        if len(password) < MIN_PASSWORD_LEN:
            raise ValueError(f"Heslo musí mít alespoň {MIN_PASSWORD_LEN} znaků.")
        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        api_token = secrets.token_urlsafe(32)
        with json_transaction(self._path, dict) as data:
            if data.get("password_hash"):
                raise ValueError("Administrator je již zaregistrován.")
            data.clear()
            data.update(
                {
                    "username": username,
                    "password_hash": password_hash,
                    "api_token": api_token,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }
            )
        return api_token

    def verify(self, username: str, password: str) -> bool:
        username = username.strip().lower()
        data = self._read()
        if not data.get("password_hash"):
            return False
        if data.get("username") != username:
            return False
        return bcrypt.checkpw(
            password.encode("utf-8"),
            data["password_hash"].encode("utf-8"),
        )

    def verify_api_token(self, token: str) -> bool:
        stored = self._read().get("api_token") or ""
        if not stored or not token:
            return False
        return secrets.compare_digest(token, stored)

    def api_token(self) -> str | None:
        return self._read().get("api_token")


def get_session_secret_path() -> Path:
    return Path(get_settings().data_dir) / "session_secret"


def get_or_create_session_secret() -> str:
    settings = get_settings()
    if settings.session_secret:
        return settings.session_secret
    path = get_session_secret_path()
    # Pod zámkem: HTTP i HTTPS proces musí sdílet stejný secret (jinak neplatné cookies)
    with file_lock(path):
        if path.exists():
            existing = path.read_text(encoding="utf-8").strip()
            if existing:
                return existing
        secret = secrets.token_urlsafe(48)
        path.write_text(secret, encoding="utf-8")
        return secret


def get_admin_store() -> AdminAccountStore:
    return AdminAccountStore(Path(get_settings().data_dir) / "admin.json")
