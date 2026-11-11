import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    from pin_manager.main import app

    with TestClient(app) as c:
        yield c


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["portal_ip"] == "192.168.39.207"


def test_preview_disabled_by_default(client):
    assert client.get("/preview/block").status_code == 404
