import time

import pytest

from pin_manager.pihole import BYPASS_RULES, block_rule
from pin_manager.store import get_store, normalize_domain

YT = block_rule("youtube.com")


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("youtube.com", "youtube.com"),
        ("https://www.YouTube.com/watch?v=1", "youtube.com"),
        ("m.youtube.com:443", "m.youtube.com"),
        ("localhost", ""),
        ("bad domain.com", ""),
        ("", ""),
    ],
)
def test_normalize_domain(raw, expected):
    assert normalize_domain(raw) == expected


def test_block_rule_covers_subdomains():
    import re

    rx = re.compile(YT)
    assert rx.search("youtube.com") and rx.search("m.youtube.com")
    assert not rx.search("notyoutube.com") and not rx.search("youtube.com.evil.cz")


def test_admin_requires_login(client):
    r = client.post("/admin/add", data={"domain": "youtube.com"}, follow_redirects=False)
    assert r.status_code == 303
    assert get_store().blacklist() == []
    assert "/admin/login" in client.get("/admin").text


def test_admin_wrong_password(client):
    r = client.post("/admin/login", data={"pin": "0000"})
    assert "Nesprávný PIN" in r.text


def test_add_domain_blocks_in_pihole(admin, pihole):
    r = admin.post("/admin/add", data={"domain": "https://www.youtube.com/"})
    assert "Blokováno: youtube.com" in r.text
    assert pihole.ours() == {YT, *BYPASS_RULES}
    assert pihole.lists["deny/regex"][YT] == "pin-manager"


def test_unlock_with_pin_removes_rule_and_relock(admin, pihole):
    admin.post("/admin/add", data={"domain": "youtube.com"})
    admin.cookies.clear()

    r = admin.post("/unlock", data={"domain": "youtube.com", "pin": "4242", "minutes": 15})
    assert "povolená na 15 min" in r.text
    assert YT not in pihole.ours()
    assert "youtube.com" in get_store().active_grants()

    # Vypršení: grant v minulosti → další sync doménu znovu zablokuje
    get_store().set_grant("youtube.com", None)
    import asyncio
    from pin_manager.main import sync_now

    asyncio.run(sync_now())
    assert YT in pihole.ours()


def test_wrong_pin_and_lockout(admin, pihole):
    admin.post("/admin/add", data={"domain": "youtube.com"})
    for _ in range(5):
        r = admin.post("/unlock", data={"domain": "youtube.com", "pin": "0000", "minutes": 15})
    assert "Nesprávný PIN" in r.text
    r = admin.post("/unlock", data={"domain": "youtube.com", "pin": "4242", "minutes": 15})
    assert "Příliš mnoho pokusů" in r.text
    assert YT in pihole.ours()


def test_unlock_rejects_unknown_domain_and_duration(admin, pihole):
    admin.post("/admin/add", data={"domain": "youtube.com"})
    r = admin.post("/unlock", data={"domain": "seznam.cz", "pin": "4242", "minutes": 15})
    assert "Neplatný požadavek" in r.text
    r = admin.post("/unlock", data={"domain": "youtube.com", "pin": "4242", "minutes": 99999})
    assert "Neplatný požadavek" in r.text
    assert get_store().active_grants() == {}


def test_unlock_reverted_when_pihole_down(admin, pihole):
    admin.post("/admin/add", data={"domain": "youtube.com"})
    pihole.fail = True
    r = admin.post("/unlock", data={"domain": "youtube.com", "pin": "4242", "minutes": 15})
    assert "Pi-hole se nepodařilo" in r.text
    assert get_store().active_grants() == {}


def test_revoke_and_remove(admin, pihole):
    admin.post("/admin/add", data={"domain": "youtube.com"})
    admin.post("/unlock", data={"domain": "youtube.com", "pin": "4242", "minutes": 15})
    assert "Zrušit povolení" in admin.get("/admin").text

    admin.post("/admin/revoke", data={"domain": "youtube.com"})
    assert YT in pihole.ours()

    admin.post("/admin/remove", data={"domain": "youtube.com"})
    assert pihole.ours() == set(BYPASS_RULES)
    assert get_store().blacklist() == []


def test_foreign_rules_untouched_and_legacy_cleaned(admin, pihole):
    pihole.lists["deny/regex"]["(\\.|^)tiktok\\.com$"] = "ručně"
    pihole.lists["deny/regex"]["(\\.|^)old\\.cz$;querytype=A;reply=1.2.3.4"] = "pin-manager"
    pihole.lists["allow/exact"]["youtube.com"] = "pin-manager until 2025-01-01"
    pihole.lists["allow/exact"]["seznam.cz"] = "rodina"

    admin.post("/admin/sync")

    assert "(\\.|^)tiktok\\.com$" in pihole.ours()
    assert not any("old" in r for r in pihole.ours())
    assert pihole.ours("allow/exact") == {"seznam.cz"}


def test_home_page_lists_blocked_and_granted(admin):
    admin.post("/admin/add", data={"domain": "youtube.com"})
    admin.post("/admin/add", data={"domain": "tiktok.com"})
    get_store().set_grant("tiktok.com", time.time() + 600)
    html = admin.get("/").text
    assert '<option value="youtube.com">' in html
    assert "Právě povoleno" in html and "tiktok.com" in html


def test_health(client):
    assert client.get("/health").json()["status"] == "ok"


def test_admin_login_shares_pin_lockout(client):
    for _ in range(5):
        client.post("/admin/login", data={"pin": "0000"})
    r = client.post("/admin/login", data={"pin": "4242"})
    assert "Příliš mnoho pokusů" in r.text
    r = client.post("/unlock", data={"domain": "x.cz", "pin": "4242", "minutes": 15})
    assert "Příliš mnoho pokusů" in r.text


def test_old_portal_local_dns_removed(admin, pihole, monkeypatch):
    from pin_manager import pihole as ph

    monkeypatch.setattr(ph, "_own_ip", lambda base: "192.168.39.207")
    pihole.hosts = [
        "192.168.39.207 www.centrum.cz",  # míří na tento kontejner
        "10.0.0.9 m.youtube.com",  # spravovaná doména (poddoména)
        "192.168.39.10 nas.lan",  # cizí záznam – zůstane
    ]
    admin.post("/admin/add", data={"domain": "youtube.com"})
    assert pihole.hosts == ["192.168.39.10 nas.lan"]


def test_granted_domain_has_link(admin):
    admin.post("/admin/add", data={"domain": "youtube.com"})
    admin.post("/unlock", data={"domain": "youtube.com", "pin": "4242", "minutes": 15})
    assert 'href="https://youtube.com/"' in admin.get("/").text


def test_pihole_session_reused_and_renewed(admin, pihole):
    admin.post("/admin/add", data={"domain": "youtube.com"})
    admin.post("/unlock", data={"domain": "youtube.com", "pin": "4242", "minutes": 15})
    assert pihole.logins == 1  # druhá změna už bez nového přihlášení

    pihole.sessions.clear()  # session v Pi-hole vypršela
    admin.post("/admin/revoke", data={"domain": "youtube.com"})
    assert pihole.logins == 2
    assert YT in pihole.ours()
