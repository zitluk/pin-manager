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


# --- DNS -------------------------------------------------------------------


def test_merge_dnsmasq_lines_keeps_foreign_and_replaces_ours():
    from pin_manager.pihole import merge_dnsmasq_lines

    existing = [
        "server=/lan/192.168.39.1",
        "address=/old.example/192.168.39.207",
        "address=/nas.lan/192.168.39.5",
    ]
    out = merge_dnsmasq_lines(existing, "192.168.39.207", ["youtube.com", "www.centrum.cz"])
    assert out == [
        "server=/lan/192.168.39.1",
        "address=/nas.lan/192.168.39.5",
        "address=/centrum.cz/192.168.39.207",
        "address=/youtube.com/192.168.39.207",
    ]


def test_regex_rules_cover_https_svcb_aaaa_and_bypass():
    from pin_manager.pihole import desired_pin_regex_rules

    rules = desired_pin_regex_rules(["centrum.cz"], anti_bypass=True)
    for qt in ("AAAA", "HTTPS", "SVCB"):
        assert f"(\\.|^)centrum\\.cz$;querytype={qt};reply=nodata" in rules
    assert r"^mask(-h2)?\.icloud\.com$;reply=nxdomain" in rules
    assert r"^use-application-dns\.net$;reply=nxdomain" in rules
    assert not any("icloud" in r for r in desired_pin_regex_rules([], anti_bypass=False))


class _FakePh:
    def __init__(self, dnsmasq_ok=True):
        self.dnsmasq_ok = dnsmasq_ok
        self.calls = []

    async def remove_deny(self, d):
        pass

    async def sync_pin_dnsmasq_lines(self, ip, apex):
        if not self.dnsmasq_ok:
            raise RuntimeError("404")
        self.calls.append(("dnsmasq", tuple(apex)))

    async def sync_pin_dns_hosts(self, ip, hosts):
        self.calls.append(("hosts", tuple(hosts)))

    async def sync_pin_silent_block(self, apex):
        return 0

    async def sync_pin_aaaa_nodata(self, apex):
        self.calls.append(("regex", tuple(apex)))
        return 0

    async def restart_dns(self):
        pass


async def test_sync_uses_wildcard_and_clears_old_hosts():
    from pin_manager.sinkhole import _sync_pihole_api

    ph = _FakePh()
    await _sync_pihole_api(
        ph, "192.168.39.207", ["youtube.com", "www.youtube.com"], ["youtube.com"],
        silent_apex=[], portal_apex=["youtube.com"],
    )
    assert ("dnsmasq", ("youtube.com",)) in ph.calls
    assert ("hosts", ()) in ph.calls  # staré přesné záznamy pryč


async def test_sync_falls_back_to_hosts_without_dnsmasq_api():
    from pin_manager.sinkhole import _sync_pihole_api

    ph = _FakePh(dnsmasq_ok=False)
    await _sync_pihole_api(
        ph, "192.168.39.207", ["youtube.com", "www.youtube.com"], ["youtube.com"],
        silent_apex=[], portal_apex=["youtube.com"],
    )
    assert ("hosts", ("youtube.com", "www.youtube.com")) in ph.calls


async def test_sync_pin_dnsmasq_lines_patches_config():
    from pin_manager.pihole import PiHoleClient

    sent = {}

    class Resp:
        def __init__(self, data=None, status=200):
            self._d, self.status_code, self.text = data, status, ""

        def json(self):
            return self._d

        def raise_for_status(self):
            pass

    class Http:
        async def get(self, url, **kw):
            return Resp({"config": {"misc": {"dnsmasq_lines": ["server=/lan/1.1.1.1"]}}})

        async def patch(self, url, **kw):
            sent["url"], sent["json"] = url, kw["json"]
            return Resp({})

    ph = PiHoleClient()
    ph._client, ph._sid = Http(), "sid"
    changed = await ph.sync_pin_dnsmasq_lines("192.168.39.207", ["youtube.com"])
    assert changed
    assert sent["url"].endswith("/api/config")
    assert sent["json"]["config"]["misc"]["dnsmasq_lines"] == [
        "server=/lan/1.1.1.1",
        "address=/youtube.com/192.168.39.207",
    ]


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


async def test_regex_failure_does_not_break_sync():
    from pin_manager.sinkhole import _sync_pihole_api

    ph = _FakePh()

    async def boom(apex):
        raise RuntimeError("Invalid regex querytype")

    ph.sync_pin_aaaa_nodata = boom
    await _sync_pihole_api(
        ph, "192.168.39.207", ["youtube.com"], ["youtube.com"],
        silent_apex=[], portal_apex=["youtube.com"],
    )
    assert ("dnsmasq", ("youtube.com",)) in ph.calls
