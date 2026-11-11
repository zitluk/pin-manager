"""Spuštění portálu: HTTP (LISTEN_PORT) a HTTPS (:443) v jednom procesu.

Dřív běžely dva samostatné uvicorny – každý s vlastním plánovačem a stavem, a HTTPS
měl certifikát jen pro domény známé při startu. Teď jeden proces, jeden plánovač
a certifikát pro každé jméno se vystaví za běhu (SNI).
"""

from __future__ import annotations

import asyncio
import logging
import os

import uvicorn

from pin_manager.config import get_settings
from pin_manager.store import get_store
from pin_manager.tls_certs import ensure_tls_material, make_sni_callback, server_cert_paths

logger = logging.getLogger("pin_manager.serve")


def _should_issue(name: str) -> bool:
    """Certifikát jen pro blokované domény (a jejich poddomény)."""
    return get_store().blacklist_match(name) is not None


def build_servers() -> list[uvicorn.Server]:
    settings = get_settings()
    http_port = int(os.environ.get("LISTEN_PORT") or settings.listen_port or 8080)
    servers = [
        uvicorn.Server(
            uvicorn.Config("pin_manager.main:app", host="0.0.0.0", port=http_port)
        )
    ]
    if settings.portal_https and http_port == 80:
        try:
            ensure_tls_material()
            key_p, crt_p = server_cert_paths()
            https_cfg = uvicorn.Config(
                "pin_manager.main:app",
                host="0.0.0.0",
                port=443,
                ssl_keyfile=str(key_p),
                ssl_certfile=str(crt_p),
                lifespan="off",  # plánovač a start běží jen v HTTP serveru
            )
            https_cfg.load()
            https_cfg.ssl.sni_callback = make_sni_callback(_should_issue)
            https_cfg.ssl.set_alpn_protocols(["http/1.1"])
            servers.append(uvicorn.Server(https_cfg))
            logger.info("HTTPS :443 zapnuto (certifikáty za běhu podle SNI)")
        except Exception:
            logger.exception("HTTPS se nepodařilo spustit – běží jen HTTP :%s", http_port)
    return servers


async def main() -> None:
    logging.basicConfig(level=logging.INFO)
    servers = build_servers()
    await asyncio.gather(*(s.serve() for s in servers))


if __name__ == "__main__":
    asyncio.run(main())
