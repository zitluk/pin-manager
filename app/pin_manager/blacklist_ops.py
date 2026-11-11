from pin_manager.config import get_settings
from pin_manager.pihole import PiHoleClient
from pin_manager.sinkhole import publish_sinkhole
from pin_manager.store import get_store, _normalize_domain


async def add_domain(domain: str) -> list[str]:
    domain = _normalize_domain(domain)
    store = get_store()
    store.add_blacklist(domain)
    settings = get_settings()
    if settings.portal_ip:
        await publish_sinkhole(settings.portal_ip)
    return store.list_blacklist()


async def remove_domain(domain: str) -> list[str]:
    domain = _normalize_domain(domain)
    store = get_store()
    store.remove_blacklist(domain)
    store.clear_grant(domain)
    try:
        await PiHoleClient().remove_allow(domain)
    except Exception:
        pass
    settings = get_settings()
    if settings.portal_ip:
        await publish_sinkhole(settings.portal_ip)
    return store.list_blacklist()
