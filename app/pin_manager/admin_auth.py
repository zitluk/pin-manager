from __future__ import annotations

import secrets

from fastapi import Request, Response
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from pin_manager.admin_users import get_or_create_session_secret

COOKIE_NAME = "pin_admin"
MAX_AGE = 60 * 60 * 12  # 12 h


def _serializer() -> URLSafeTimedSerializer:
    secret = get_or_create_session_secret()
    return URLSafeTimedSerializer(secret, salt="pin-manager-admin")


def set_admin_cookie(response: Response, username: str) -> None:
    payload = _serializer().dumps({"role": "admin", "user": username})
    response.set_cookie(
        COOKIE_NAME,
        payload,
        httponly=True,
        samesite="lax",
        max_age=MAX_AGE,
        path="/",
    )


def clear_admin_cookie(response: Response) -> None:
    response.delete_cookie(COOKIE_NAME, path="/")


def is_admin_authenticated(request: Request) -> bool:
    raw = request.cookies.get(COOKIE_NAME)
    if not raw:
        return False
    try:
        data = _serializer().loads(raw, max_age=MAX_AGE)
        return data.get("role") == "admin"
    except (BadSignature, SignatureExpired):
        return False


def verify_legacy_admin_token(token: str) -> bool:
    from pin_manager.config import get_settings

    expected = get_settings().admin_token
    if not expected:
        return False
    return secrets.compare_digest(token, expected)
