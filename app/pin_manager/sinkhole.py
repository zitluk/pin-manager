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
    mode = (settings.pihole_sinkhole_mode or "api").lower()

    if mode in ("api", "both"):
        try:
            await PiHoleClient().sync_pin_dns_hosts(portal_ip, domains)
        except Exception as e:
            logger.exception("Pi-hole API dns.hosts sync")
            if mode == "api":
                raise

    if mode in ("file", "both"):
        write_sinkhole_conf(
            portal_ip,
            domains,
            Path(settings.dnsmasq_sinkhole_path),
        )
        try:
            await PiHoleClient().restart_dns()
        except Exception as e:
            logger.warning("restart_dns after file sinkhole: %s", e)
