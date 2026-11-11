import logging
from datetime import datetime, timezone

from pin_manager.pihole import pihole_api
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
    async with pihole_api() as ph:
        try:
            await ph.grant_allow(domain, comment=comment)
        except Exception as e:
            logger.info("allow optional (gravity kolize): %s", e)
        await publish_sinkhole(portal_ip, ph=ph)


async def apply_relock(domain: str, portal_ip: str) -> None:
    store = get_store()
    store.clear_grant(domain)
    async with pihole_api() as ph:
        try:
            await ph.remove_allow(domain)
        except Exception as e:
            logger.info("remove allow: %s", e)
        await publish_sinkhole(portal_ip, ph=ph)


async def relock_expired(portal_ip: str) -> list[str]:
    """Vrátí blokování pro všechna prošlá povolení (volá plánovač).

    Prošlá povolení se atomicky vyjmou z úložiště (jen jeden proces je dostane).
    Když Pi-hole selže, vrátí se zpět, aby je další běh zkusil znovu – jinak by
    doména zůstala odblokovaná natrvalo.
    """
    store = get_store()
    expired = store.pop_expired_grants()
    if not expired:
        return []
    try:
        async with pihole_api() as ph:
            for domain in expired:
                try:
                    await ph.remove_allow(domain)
                except Exception as e:
                    logger.info("remove allow %s: %s", domain, e)
            await publish_sinkhole(portal_ip, ph=ph)
    except Exception:
        for domain, ts in expired.items():
            # Mezitím mohlo vzniknout nové povolení (nový PIN) – to nepřepisujeme
            if store.active_grant_until(domain) is None:
                store.set_grant(domain, ts)
        raise
    return sorted(expired)
