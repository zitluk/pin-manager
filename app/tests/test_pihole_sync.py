from unittest.mock import patch

import httpx
import pytest

from pin_manager.pihole import PiHoleClient


def _resp(method: str, url: str, **kwargs) -> httpx.Response:
    req = httpx.Request(method, url)
    return httpx.Response(request=req, **kwargs)


@pytest.mark.asyncio
async def test_sync_pin_dns_hosts_put_and_delete():
    calls: list[tuple[str, str]] = []

    class MockClient(httpx.AsyncClient):
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def delete(self, url, **kwargs):
            calls.append(("DELETE", str(url)))
            return _resp("DELETE", str(url), status_code=200, json={"took": 0.01})

        async def put(self, url, **kwargs):
            calls.append(("PUT", str(url)))
            return _resp("PUT", str(url), status_code=200, json={"took": 0.01})

        async def get(self, url, **kwargs):
            return _resp(
                "GET",
                str(url),
                status_code=200,
                json={
                    "config": {
                        "dns": {
                            "hosts": ["192.168.39.207 old.example"],
                        }
                    }
                },
            )

        async def post(self, url, **kwargs):
            if url.endswith("/api/auth"):
                return _resp(
                    "POST",
                    str(url),
                    status_code=200,
                    json={"session": {"sid": "sid-test"}},
                )
            return _resp("POST", str(url), status_code=200)

    with patch("pin_manager.pihole.httpx.AsyncClient", MockClient):
        async with PiHoleClient() as client:
            await client.sync_pin_dns_hosts("192.168.39.207", ["new.example"])

    joined = " ".join(u for _, u in calls)
    assert "old.example" in joined or any(m == "PUT" for m, _ in calls)
    assert "new.example" in joined


def test_aaaa_nodata_regex_escaped():
    from pin_manager.pihole import aaaa_nodata_regex

    assert aaaa_nodata_regex("youtube.com") == (
        "^youtube\\.com$;querytype=AAAA;reply=nodata"
    )
