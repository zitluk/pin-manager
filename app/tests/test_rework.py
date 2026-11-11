"""Přepracované DNS (wildcard, HTTPS/SVCB, anti-obchvat) a TLS (SNI certifikáty)."""

import plistlib
import subprocess
from unittest.mock import AsyncMock, patch

import pytest
from cryptography import x509
from fastapi.testclient import TestClient

from pin_manager.config import get_settings


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    get_settings.cache_clear()
    from pin_manager import tls_certs

    tls_certs._ctx_cache.clear()
    yield tmp_path
    tls_certs._ctx_cache.clear()
    get_settings.cache_clear()


@pytest.fixture
def client(data_dir):
    from pin_manager.main import app

    with patch("pin_manager.main.publish_sinkhole", new=AsyncMock()):
        with TestClient(app) as c:
            yield c


# --- DNS: jen seznamy domén v Pi-hole, žádné nastavení ----------------------


def test_regex_rules_cover_redirect_nodata_silent_and_bypass():
    from pin_manager.pihole import desired_pin_regex_rules

    rules = desired_pin_regex_rules(
        ["centrum.cz", "tiktok.com"],
        anti_bypass=True,
        portal_ip="192.168.39.207",
        portal_apex=["centrum.cz"],
        silent_apex=["tiktok.com"],
    )
    assert "(\\.|^)centrum\\.cz$;querytype=A;reply=192.168.39.207" in rules
    assert "(\\.|^)tiktok\\.com$;querytype=A" in rules
    for d in ("centrum\\.cz", "tiktok\\.com"):
        for qt in ("AAAA", "HTTPS", "SVCB"):
            assert f"(\\.|^){d}$;querytype={qt};reply=nodata" in rules
    assert r"^mask(-h2)?\.icloud\.com$;reply=nxdomain" in rules
    assert not any("icloud" in r for r in desired_pin_regex_rules([], anti_bypass=False))


def test_old_aaaa_rule_text_unchanged():
    """Pravidla starší verze (komentář pin-manager-aaaa) se nesmí zbytečně přepisovat."""
    from pin_manager.pihole import aaaa_nodata_regex, qtype_nodata_regex

    assert aaaa_nodata_regex("youtube.com") == qtype_nodata_regex("youtube.com", "AAAA")


class _FakePh:
    def __init__(self, regex_ok=True, regex_changed=True):
        self.regex_ok = regex_ok
        self.regex_changed = regex_changed
        self.calls = []

    async def sync_pin_regex(self, desired):
        if not self.regex_ok:
            raise RuntimeError("Pi-hole regex deny (400)")
        self.calls.append(("regex", frozenset(desired)))
        return self.regex_changed

    async def sync_pin_dns_hosts(self, ip, hosts):
        self.calls.append(("hosts", tuple(hosts)))
        return False

    async def sync_pin_silent_block(self, apex):
        self.calls.append(("silent", tuple(apex)))
        return 0

    async def sync_pin_allows(self, granted):
        self.calls.append(("allows", frozenset(granted)))
        return False

    async def restart_dns(self):
        self.calls.append(("restart",))


async def _run(ph, granted=frozenset()):
    from pin_manager.sinkhole import _sync_pihole_api

    return await _sync_pihole_api(
        ph, "192.168.39.207", ["youtube.com", "www.youtube.com"], ["youtube.com"],
        silent_apex=[], portal_apex=["youtube.com"], granted=set(granted),
    )


async def test_sync_writes_only_lists_and_cleans_legacy():
    ph = _FakePh()
    await _run(ph, granted={"centrum.cz"})
    kinds = [c[0] for c in ph.calls]
    assert kinds[0] == "regex"  # nejdřív nová pravidla
    rules = ph.calls[0][1]
    assert "(\\.|^)youtube\\.com$;querytype=A;reply=192.168.39.207" in rules
    assert ("hosts", ()) in ph.calls  # úklid starých Local DNS záznamů
    assert ("allows", frozenset({"centrum.cz"})) in ph.calls
    assert kinds[-1] == "restart"


async def test_no_restart_when_nothing_changed():
    ph = _FakePh(regex_changed=False)
    await _run(ph)
    assert ("restart",) not in ph.calls


async def test_regex_failure_keeps_legacy_entries():
    """Když Pi-hole pravidla nepřijme, staré záznamy se nesmí smazat (blok by zmizel)."""
    ph = _FakePh(regex_ok=False)
    with pytest.raises(RuntimeError):
        await _run(ph)
    assert not any(c[0] == "hosts" for c in ph.calls)


async def test_cleanup_failure_does_not_break_sync():
    ph = _FakePh()

    async def boom(*a):
        raise RuntimeError("timeout")

    ph.sync_pin_dns_hosts = boom
    await _run(ph)
    assert ("restart",) in ph.calls


async def test_sync_pin_regex_only_diff():
    from pin_manager.pihole import PiHoleClient

    calls = []

    class Resp:
        status_code, text = 200, ""

        def __init__(self, data=None):
            self._d = data or {}

        def json(self):
            return self._d

        def raise_for_status(self):
            pass

    class Http:
        async def get(self, url, **kw):
            return Resp({"domains": [
                {"domain": "keep", "comment": "pin-manager-aaaa"},
                {"domain": "old", "comment": "pin-manager"},
                {"domain": "user-rule", "comment": "moje"},
            ]})

        async def delete(self, url, **kw):
            calls.append(("DELETE", url.rsplit("/", 1)[1]))
            return Resp()

        async def post(self, url, **kw):
            calls.append(("POST", kw["json"]["domain"]))
            return Resp()

    ph = PiHoleClient()
    ph._client, ph._sid = Http(), "sid"
    changed = await ph.sync_pin_regex({"keep", "new"})
    assert changed
    assert calls == [("DELETE", "old"), ("POST", "new")]  # cizí pravidlo nedotčeno


def test_scheduler_has_periodic_resync(data_dir):
    from pin_manager.main import app

    with patch("pin_manager.main.publish_sinkhole", new=AsyncMock()):
        with patch("pin_manager.main.AsyncIOScheduler") as sched_cls:
            with TestClient(app):
                pass
    ids = [c.kwargs.get("id") for c in sched_cls.return_value.add_job.call_args_list]
    assert "resync_pihole" in ids and "expire_grants" in ids


# --- TLS -------------------------------------------------------------------


def _verify_signed_by(leaf: x509.Certificate, ca: x509.Certificate) -> None:
    leaf.verify_directly_issued_by(ca)


def test_existing_openssl_ca_is_kept_and_used(data_dir):
    """Produkční CA vznikla přes openssl – musí zůstat stejná (zařízení jí důvěřují)."""
    from pin_manager import tls_certs

    d = data_dir / "tls"
    d.mkdir()
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
         "-keyout", str(d / "ca.key.pem"), "-out", str(d / "ca.crt.pem"),
         "-subj", "/CN=PIN Manager Home CA"],
        check=True, capture_output=True,
    )
    before = (d / "ca.crt.pem").read_bytes()
    tls_certs.ensure_tls_material()
    tls_certs.host_context("m.youtube.com")
    assert (d / "ca.crt.pem").read_bytes() == before

    ca = x509.load_pem_x509_certificate(before)
    leaf = x509.load_pem_x509_certificate((d / "hosts" / "m.youtube.com.crt.pem").read_bytes())
    _verify_signed_by(leaf, ca)
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert set(san.get_values_for_type(x509.DNSName)) == {
        "m.youtube.com", "*.youtube.com", "youtube.com"
    }
    assert (leaf.not_valid_after_utc - leaf.not_valid_before_utc).days <= 398


def test_default_cert_not_reissued_when_valid(data_dir, monkeypatch):
    monkeypatch.setenv("PORTAL_IP", "192.168.39.207")
    get_settings.cache_clear()
    from pin_manager import tls_certs

    tls_certs.ensure_tls_material()
    _, crt = tls_certs.server_cert_paths()
    first = crt.read_bytes()
    tls_certs.ensure_tls_material(["youtube.com"])
    assert crt.read_bytes() == first


def test_sni_callback_only_for_blacklisted(data_dir):
    from pin_manager import tls_certs

    class Sock:
        context = None

    cb = tls_certs.make_sni_callback(lambda n: n.endswith("youtube.com"))
    s1, s2 = Sock(), Sock()
    cb(s1, "m.youtube.com", None)
    cb(s2, "example.org", None)
    assert s1.context is not None
    assert s2.context is None
    # cache
    assert tls_certs.host_context("m.youtube.com") is s1.context


# --- Stránky -----------------------------------------------------------------


def test_pin_check_has_cors(client):
    r = client.get("/__pin/check", headers={"host": "centrum.cz"})
    assert r.status_code == 200
    assert r.json()["portal"] is True
    assert r.headers["access-control-allow-origin"] == "*"


def test_mobileconfig_contains_ca(client, data_dir):
    from pin_manager.tls_certs import ca_der

    r = client.get("/ca.mobileconfig")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/x-apple-aspen-config")
    prof = plistlib.loads(r.content)
    payload = prof["PayloadContent"][0]
    assert payload["PayloadType"] == "com.apple.security.root"
    assert payload["PayloadContent"] == ca_der()


def test_setup_page_picks_non_hsts_domain(client):
    from pin_manager.store import get_store

    get_store().add_blacklist("youtube.com")
    get_store().add_blacklist("centrum.cz")
    r = client.get("/setup")
    assert r.status_code == 200
    assert '"centrum.cz"' in r.text

