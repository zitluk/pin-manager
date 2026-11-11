from unittest.mock import AsyncMock, patch

import httpx
import pytest

from pin_manager.pihole import PiHoleClient


@pytest.mark.asyncio
async def test_sync_pin_dns_hosts_put_and_delete():
    client = PiHoleClient()
    existing = ["192.168.39.207 old.example", "10.0.0.1 router.lan"]
    calls: list[tuple[str, str]] = []

    class MockClient(httpx.AsyncClient):
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def delete(self, url, **kwargs):
            calls.append(("DELETE", str(url)))
            return httpx.Response(200, json={"took": 0.01})

        async def put(self, url, **kwargs):
            calls.append(("PUT", str(url)))
            return httpx.Response(200, json={"took": 0.01})

    with (
        patch("pin_manager.pihole.httpx.AsyncClient", MockClient),
        patch.object(client, "get_dns_hosts", new=AsyncMock(return_value=existing)),
        patch.object(client, "_login", new=AsyncMock(return_value="sid-test")),
    ):
        await client.sync_pin_dns_hosts("192.168.39.207", ["new.example"])

    joined = " ".join(u for _, u in calls)
    assert any(m == "DELETE" for m, _ in calls)
    assert "old.example" in joined
    assert any(m == "PUT" for m, _ in calls)
    assert "new.example" in joined
