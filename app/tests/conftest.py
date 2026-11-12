import os

import pytest

# Musí být před importem aplikace
os.environ.update(
    PIHOLE_URL="http://pihole.test",
    PIHOLE_PASSWORD="test",
    PIN="4242",
    PIHOLE_RESTART_DNS="false",
)


class FakePiHole:
    """Pi-hole v6 API v paměti: {kind: {domain: comment}}."""

    def __init__(self):
        self.lists = {k: {} for k in ("deny/regex", "deny/exact", "allow/exact", "allow/regex")}
        self.fail = False
        self.hosts: list[str] = []  # Local DNS (config dns.hosts)

    def ours(self, kind="deny/regex"):
        return set(self.lists[kind])

    def install(self, router):
        import httpx
        from urllib.parse import unquote

        base = "http://pihole.test/api"

        def auth(request):
            if self.fail:
                return httpx.Response(500, text="down")
            return httpx.Response(200, json={"session": {"sid": "sid1"}})

        def handle(request):
            path = request.url.raw_path.decode().split("?")[0][len("/api/domains/"):]
            parts = path.split("/", 2)
            kind = "/".join(parts[:2])
            if request.method == "GET":
                return httpx.Response(
                    200, json={"domains": [{"domain": d, "comment": c} for d, c in self.lists[kind].items()]}
                )
            if request.method == "POST":
                import json

                body = json.loads(request.content)
                self.lists[kind][body["domain"]] = body["comment"]
                return httpx.Response(201, json={})
            if request.method == "DELETE":
                self.lists[kind].pop(unquote(parts[2]), None)
                return httpx.Response(204)
            return httpx.Response(405)

        def hosts(request):
            if request.method == "GET":
                return httpx.Response(200, json={"config": {"dns": {"hosts": list(self.hosts)}}})
            entry = unquote(request.url.raw_path.decode().rsplit("/", 1)[1])
            if entry in self.hosts:
                self.hosts.remove(entry)
                return httpx.Response(204)
            return httpx.Response(404)

        router.route(url__startswith=f"{base}/config/dns/hosts").mock(side_effect=hosts)
        router.post(f"{base}/auth").mock(side_effect=auth)
        router.delete(f"{base}/auth").mock(return_value=httpx.Response(204))
        router.post(f"{base}/action/restartdns").mock(return_value=httpx.Response(200))
        router.route(url__startswith=f"{base}/domains/").mock(side_effect=handle)


@pytest.fixture
def pihole():
    import respx

    fake = FakePiHole()
    with respx.mock(assert_all_called=False) as router:
        fake.install(router)
        yield fake


@pytest.fixture
def client(tmp_path, monkeypatch, pihole):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    from pin_manager import main, pihole as ph
    from pin_manager.config import get_settings

    get_settings.cache_clear()
    monkeypatch.setattr(ph, "_legacy_cleaned", False)
    monkeypatch.setattr(main, "lockout", main.Lockout())
    from fastapi.testclient import TestClient

    # Bez `with` neběží lifespan (synchronizační smyčka) – testy volají sync přes endpointy
    yield TestClient(main.app)
    get_settings.cache_clear()


@pytest.fixture
def admin(client):
    r = client.post("/admin/login", data={"pin": "4242"}, follow_redirects=False)
    assert r.status_code == 303
    return client
