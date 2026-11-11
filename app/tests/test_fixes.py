"""Regresní testy: vypršení povolení, délka povolení, zámek pokusů, atomické úložiště."""

import json
import time
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from pin_manager.config import get_settings


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    get_settings.cache_clear()
    yield tmp_path
    get_settings.cache_clear()


@pytest.fixture
def client(data_dir):
    from pin_manager.main import app

    with patch("pin_manager.main.publish_sinkhole", new=AsyncMock()):
        with TestClient(app) as c:
            yield c


# --- Bod 1: vypršení povolení ------------------------------------------------


def test_pop_expired_grants_returns_and_removes(data_dir):
    from pin_manager.store import get_store

    store = get_store()
    store.add_blacklist("youtube.com")
    store.set_grant("youtube.com", time.time() - 5)
    store.set_grant("example.com", time.time() + 600)

    # active_grants() prošlá povolení nesmí potichu smazat
    assert "youtube.com" not in store.active_grants()
    assert store.is_blocked("youtube.com")

    expired = store.pop_expired_grants()
    assert list(expired) == ["youtube.com"]
    assert store.pop_expired_grants() == {}
    assert "example.com" in store.active_grants()


class _FakePh:
    def __init__(self):
        self.removed = []

    async def remove_allow(self, domain):
        self.removed.append(domain)


async def test_relock_expired_removes_allow_and_republishes(data_dir):
    from pin_manager import sync
    from pin_manager.store import get_store

    store = get_store()
    store.add_blacklist("youtube.com")
    store.set_grant("youtube.com", time.time() - 1)
    ph = _FakePh()

    @asynccontextmanager
    async def fake_api():
        yield ph

    publish = AsyncMock()
    with patch.object(sync, "pihole_api", fake_api), patch.object(sync, "publish_sinkhole", publish):
        relocked = await sync.relock_expired("192.168.39.207")

    assert relocked == ["youtube.com"]
    assert ph.removed == ["youtube.com"]
    publish.assert_awaited_once()
    assert "youtube.com" in store.blocked_domains_for_sinkhole()


async def test_relock_expired_retries_when_pihole_fails(data_dir):
    from pin_manager import sync
    from pin_manager.store import get_store

    store = get_store()
    store.add_blacklist("youtube.com")
    store.set_grant("youtube.com", time.time() - 1)

    @asynccontextmanager
    async def broken_api():
        raise RuntimeError("Pi-hole nedostupný")
        yield  # pragma: no cover

    with patch.object(sync, "pihole_api", broken_api):
        with pytest.raises(RuntimeError):
            await sync.relock_expired("192.168.39.207")

    # Povolení se vrátilo → příští běh plánovače to zkusí znovu
    assert "youtube.com" in store.pop_expired_grants()


# --- Bod 2: délka povolení ---------------------------------------------------


def test_unlock_rejects_minutes_not_offered(client):
    from pin_manager.store import get_store

    get_store().add_blacklist("youtube.com")
    with patch("pin_manager.main.apply_unlock", new=AsyncMock()) as unlock:
        r = client.post(
            "/unlock",
            data={"pin": "4242", "minutes": "999999", "host": "youtube.com"},
        )
    assert r.status_code == 400
    unlock.assert_not_awaited()


def test_unlock_accepts_offered_minutes(client):
    from pin_manager.store import get_store

    get_store().add_blacklist("youtube.com")
    with patch("pin_manager.main.apply_unlock", new=AsyncMock()) as unlock:
        r = client.post(
            "/unlock",
            data={"pin": "4242", "minutes": "15", "host": "youtube.com"},
        )
    assert r.status_code == 200
    unlock.assert_awaited_once()
    assert unlock.await_args.args[1] == 15


# --- Bod 3: zámek PIN je na disku (sdílený mezi procesy, přežije restart) ----


def test_pin_lockout_persisted_on_disk(data_dir):
    from pin_manager import security

    ip = "192.168.1.50"
    for _ in range(get_settings().max_pin_attempts):
        locked, _ = security.record_failed_attempt(ip)
    assert locked
    # Jiný proces / restart vidí stejný stav jen ze souboru
    data = json.loads((data_dir / "lockout.json").read_text())
    assert data[f"pin:{ip}"]["until"] > time.time()
    assert security.is_locked(ip)[0]
    # Admin zámek je oddělený
    assert not security.is_locked(ip, security.SCOPE_ADMIN)[0]
    security.clear_attempts(ip)
    assert not security.is_locked(ip)[0]


# --- Bod 4: zámek přihlášení do administrace ---------------------------------


def test_admin_login_lockout(client):
    from pin_manager.admin_users import get_admin_store

    get_admin_store().register("admin", "spravne-heslo")
    for _ in range(get_settings().max_pin_attempts):
        r = client.post("/admin/login", data={"username": "admin", "password": "spatne"})
        assert r.status_code == 401
    # I se správným heslem je teď zamčeno
    r = client.post(
        "/admin/login",
        data={"username": "admin", "password": "spravne-heslo"},
        follow_redirects=False,
    )
    assert r.status_code == 429


def test_admin_login_ok_clears_attempts(client):
    from pin_manager import security
    from pin_manager.admin_users import get_admin_store

    get_admin_store().register("admin", "spravne-heslo")
    client.post("/admin/login", data={"username": "admin", "password": "spatne"})
    r = client.post(
        "/admin/login",
        data={"username": "admin", "password": "spravne-heslo"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert "pin_admin" in r.cookies
    assert not security.is_locked("testclient", security.SCOPE_ADMIN)[0]


# --- Bod 5: atomické úložiště ------------------------------------------------


def test_store_survives_corrupt_file(data_dir):
    from pin_manager.store import get_store

    (data_dir / "state.json").write_text("{ rozbitý json")
    store = get_store()
    assert store.list_blacklist() == []
    assert list(data_dir.glob("state.json.corrupt-*"))
    store.add_blacklist("example.com")
    assert json.loads((data_dir / "state.json").read_text())["blacklist"] == ["example.com"]


def test_store_sees_writes_from_other_instance(data_dir):
    """Dva procesy (HTTP/HTTPS) = dvě instance nad stejným souborem."""
    from pathlib import Path

    from pin_manager.store import DataStore

    a = DataStore(Path(data_dir) / "state.json")
    b = DataStore(Path(data_dir) / "state.json")
    a.add_blacklist("one.com")
    b.add_blacklist("two.com")
    assert a.list_blacklist() == ["one.com", "two.com"]


def test_session_secret_shared(data_dir, monkeypatch):
    monkeypatch.setenv("SESSION_SECRET", "")
    get_settings.cache_clear()
    from pin_manager.admin_users import get_or_create_session_secret

    first = get_or_create_session_secret()
    assert first and get_or_create_session_secret() == first


# --- Bod 6: povolení se nevytvoří, když Pi-hole selže -----------------------


@asynccontextmanager
async def _broken_pihole():
    raise RuntimeError("Pi-hole nedostupný")
    yield  # pragma: no cover


async def test_apply_unlock_rolls_back_on_pihole_failure(data_dir):
    from pin_manager import sync
    from pin_manager.store import get_store

    store = get_store()
    store.add_blacklist("youtube.com")
    with patch.object(sync, "pihole_api", _broken_pihole):
        with pytest.raises(RuntimeError):
            await sync.apply_unlock("youtube.com", 15, "192.168.39.207")
    assert store.is_blocked("youtube.com")
    assert store.grant_until_raw("youtube.com") is None


async def test_apply_unlock_keeps_previous_grant_on_failure(data_dir):
    from pin_manager import sync
    from pin_manager.store import get_store

    store = get_store()
    store.add_blacklist("youtube.com")
    previous = time.time() + 300
    store.set_grant("youtube.com", previous)
    with patch.object(sync, "pihole_api", _broken_pihole):
        with pytest.raises(RuntimeError):
            await sync.apply_unlock("youtube.com", 120, "192.168.39.207")
    assert store.grant_until_raw("youtube.com") == previous


async def test_apply_relock_failure_leaves_expired_grant_for_retry(data_dir):
    from pin_manager import sync
    from pin_manager.store import get_store

    store = get_store()
    store.add_blacklist("youtube.com")
    store.set_grant("youtube.com", time.time() + 600)
    with patch.object(sync, "pihole_api", _broken_pihole):
        with pytest.raises(RuntimeError):
            await sync.apply_relock("youtube.com", "192.168.39.207")
    # Aplikace doménu hned blokuje a plánovač relock zopakuje
    assert store.is_blocked("youtube.com")
    assert "youtube.com" in store.pop_expired_grants()


# --- Bod 7: target_url jen na odemykanou doménu ------------------------------


@pytest.mark.parametrize(
    "target, expected",
    [
        ("https://www.youtube.com/watch?v=abc", "https://www.youtube.com/watch?v=abc"),
        ("https://m.youtube.com/", "https://m.youtube.com/"),
        ("https://evil.example/", "https://youtube.com/"),
        ("https://youtube.com@evil.example/", "https://youtube.com/"),
        ("https://evil.example\\@youtube.com/", "https://youtube.com/"),
        ("javascript:alert(1)", "https://youtube.com/"),
        ("//evil.example/", "https://youtube.com/"),
        ("", "https://youtube.com/"),
    ],
)
def test_safe_target_url(data_dir, target, expected):
    from pin_manager.main import _safe_target_url
    from pin_manager.store import get_store

    get_store().add_blacklist("youtube.com")
    assert _safe_target_url(target, "youtube.com") == expected


def test_unlock_ignores_foreign_target_url(client):
    from pin_manager.store import get_store

    get_store().add_blacklist("youtube.com")
    with patch("pin_manager.main.apply_unlock", new=AsyncMock()):
        r = client.post(
            "/unlock",
            data={
                "pin": "4242",
                "minutes": "15",
                "host": "youtube.com",
                "target_url": "https://evil.example/phish",
            },
        )
    assert r.status_code == 200
    assert "evil.example" not in r.text


# --- Bod 8: zprávy v URL jsou kódované ---------------------------------------


def test_admin_redirect_encodes_message():
    from urllib.parse import parse_qs, urlsplit

    from pin_manager.main import _admin_redirect

    r = _admin_redirect("/admin/", error="Chyba & #1 + 2=3")
    loc = r.headers["location"]
    assert parse_qs(urlsplit(loc).query) == {"error": ["Chyba & #1 + 2=3"]}
    assert "#" not in loc
