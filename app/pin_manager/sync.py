import logging
from datetime import datetime, timezone

from pin_manager.pihole import PiHoleClient
from pin_manager.sinkhole import publish_sinkhole
from pin_manager.store import get_store

logger = logging.getLogger(__name__)


async def apply_unlock(domain: str, minutes: int, portal_ip: str) -> None:
    import time

    store = get_store()
    expires = time.time() + minutes * 60
    store.set_grant(domain, expires)
    until = datetime.fromtimestamp(expires, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    comment = f"pin-manager until {until}"
    async with PiHoleClient() as ph:
        try:
            await ph.grant_allow(domain, comment=comment)
        except Exception as e:
            logger.info("allow optional (gravity kolize): %s", e)
    await publish_sinkhole(portal_ip)


async def apply_relock(domain: str, portal_ip: str) -> None:
    store = get_store()
    store.clear_grant(domain)
    async with PiHoleClient() as ph:
        try:
            await ph.remove_allow(domain)
        except Exception as e:
            logger.info("remove allow: %s", e)
    await publish_sinkhole(portal_ip)
