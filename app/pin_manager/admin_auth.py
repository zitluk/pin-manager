import secrets

from fastapi import Request, Response
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from pin_manager.config import get_settings

COOKIE_NAME = "pin_admin"
MAX_AGE = 60 * 60 * 12  # 12 h


def _serializer() -> URLSafeTimedSerializer:
    settings = get_settings()
    secret = settings.session_secret or settings.admin_token or "change-me"
    return URLSafeTimedSerializer(secret, salt="pin-manager-admin")


def verify_admin_token(token: str) -> bool:
    expected = get_settings().admin_token
    if not expected:
        return False
    return secrets.compare_digest(token, expected)


def set_admin_cookie(response: Response) -> None:
    payload = _serializer().dumps({"role": "admin"})
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

