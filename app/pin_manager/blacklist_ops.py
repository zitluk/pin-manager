from pin_manager.config import get_settings
from pin_manager.domain_expand import KNOWN_ALIASES
from pin_manager.pihole import pihole_api
from pin_manager.sinkhole import publish_sinkhole
from pin_manager.store import get_store, _normalize_domain


async def add_domain(domain: str) -> list[str]:
    domain = _normalize_domain(domain)
    if not domain:
        raise ValueError("Neplatná doména – zadejte např. youtube.com (bez https://)")
    store = get_store()
    store.add_blacklist(domain)
    for extra in KNOWN_ALIASES.get(domain, []):
        store.add_blacklist(extra)
    settings = get_settings()
    if settings.portal_ip:
        await publish_sinkhole(settings.portal_ip)
    return store.list_blacklist()


async def remove_domain(domain: str) -> list[str]:
    domain = _normalize_domain(domain)
    store = get_store()
    store.remove_blacklist(domain)
    store.clear_grant(domain)
    settings = get_settings()
    try:
        async with pihole_api() as ph:
            try:
                await ph.remove_allow(domain)
            except Exception:
                pass
            if settings.portal_ip:
                await publish_sinkhole(settings.portal_ip, ph=ph)
    except Exception:
        if settings.portal_ip:
            await publish_sinkhole(settings.portal_ip)
    return store.list_blacklist()
