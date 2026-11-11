import logging
from pathlib import Path

from pin_manager.config import get_settings
from pin_manager.pihole import PiHoleClient
from pin_manager.store import get_store
from pin_manager.sync import write_sinkhole_conf

logger = logging.getLogger(__name__)


async def publish_sinkhole(portal_ip: str) -> None:
    store = get_store()
    domains = store.blocked_domains_for_sinkhole()
    settings = get_settings()
    mode = (settings.pihole_sinkhole_mode or "both").lower()

    api_ok = False
    file_ok = False
    api_err: Exception | None = None
    file_err: Exception | None = None

    if mode in ("api", "both"):
        try:
            ph = PiHoleClient()
            await ph.sync_pin_dns_hosts(portal_ip, domains)
            await ph.restart_dns()
            api_ok = True
        except Exception as e:
            api_err = e
            logger.exception("Pi-hole API dns.hosts sync")

    if mode in ("file", "both"):
        try:
            write_sinkhole_conf(
                portal_ip,
                domains,
                Path(settings.dnsmasq_sinkhole_path),
            )
            await PiHoleClient().restart_dns()
            file_ok = True
        except Exception as e:
            file_err = e
            logger.exception("dnsmasq sinkhole file sync")

    if mode == "api" and not api_ok:
        raise RuntimeError(f"Pi-hole API: {api_err}") from api_err
    if mode == "file" and not file_ok:
        raise RuntimeError(f"Sinkhole soubor: {file_err}") from file_err
    if mode == "both" and not api_ok and not file_ok:
        raise RuntimeError(
            f"Pi-hole API: {api_err}; soubor: {file_err}"
        ) from (api_err or file_err)
