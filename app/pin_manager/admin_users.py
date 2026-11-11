from __future__ import annotations

import json
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import bcrypt

from pin_manager.config import get_settings

MIN_PASSWORD_LEN = 8


class AdminAccountStore:
    """Jeden administrátor – registrace jen dokud účet neexistuje."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._load()

    def _load(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if self._path.exists():
            with open(self._path, encoding="utf-8") as f:
                self._data: dict[str, Any] = json.load(f)
        else:
            self._data = {}

    def _save(self) -> None:
        with open(self._path, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2, ensure_ascii=False)

    def has_admin(self) -> bool:
        with self._lock:
            return bool(self._data.get("password_hash"))

    def username(self) -> str | None:
        with self._lock:
            return self._data.get("username")

    def register(self, username: str, password: str) -> str:
        username = username.strip().lower()
        if not username:
            raise ValueError("Zadejte uživatelské jméno.")
        if len(password) < MIN_PASSWORD_LEN:
            raise ValueError(f"Heslo musí mít alespoň {MIN_PASSWORD_LEN} znaků.")
        with self._lock:
            if self._data.get("password_hash"):
                raise ValueError("Administrator je již zaregistrován.")
            api_token = secrets.token_urlsafe(32)
            self._data = {
                "username": username,
                "password_hash": bcrypt.hashpw(
                    password.encode("utf-8"),
                    bcrypt.gensalt(),
                ).decode("utf-8"),
                "api_token": api_token,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            self._save()
            return api_token

    def verify(self, username: str, password: str) -> bool:
        username = username.strip().lower()
        with self._lock:
            if not self._data.get("password_hash"):
                return False
            if self._data.get("username") != username:
                return False
            return bcrypt.checkpw(
                password.encode("utf-8"),
                self._data["password_hash"].encode("utf-8"),
            )

    def verify_api_token(self, token: str) -> bool:
        with self._lock:
            stored = self._data.get("api_token") or ""
            if not stored or not token:
                return False
            return secrets.compare_digest(token, stored)

    def api_token(self) -> str | None:
        with self._lock:
            return self._data.get("api_token")


def get_session_secret_path() -> Path:
    return Path(get_settings().data_dir) / "session_secret"


def get_or_create_session_secret() -> str:
    settings = get_settings()
    if settings.session_secret:
        return settings.session_secret
    path = get_session_secret_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    secret = secrets.token_urlsafe(48)
    path.write_text(secret, encoding="utf-8")
    return secret


def get_admin_store() -> AdminAccountStore:
    return AdminAccountStore(Path(get_settings().data_dir) / "admin.json")
