import logging
from pathlib import Path

from pin_manager.config import get_settings
from pin_manager.dnsmasq_conf import write_sinkhole_conf
from pin_manager.domain_expand import expand_sinkhole_domains, partition_apex_for_sinkhole
from pin_manager.pihole import PiHoleClient, desired_pin_regex_rules, pihole_api
from pin_manager.store import get_store
from pin_manager.sync_status import record
from pin_manager.tls_certs import ensure_tls_material

logger = logging.getLogger(__name__)


async def _sync_pihole_api(
    ph: PiHoleClient,
    portal_ip: str,
    portal_hosts: list[str],
    apex_domains: list[str],
    *,
    silent_apex: list[str],
    portal_apex: list[str],
    granted: set[str] | None = None,
) -> int:
    """Zapíše blokování do Pi-hole – jen do seznamů domén přes API.

    Nastavení Pi-hole (dns.hosts, dnsmasq_lines…) se nemění; po čisté reinstalaci
    Pi-hole stačí, aby pin-manager znovu proběhl (dělá to sám každých pár minut).
    """
    settings = get_settings()
    desired = desired_pin_regex_rules(
        apex_domains,
        anti_bypass=settings.block_dns_bypass,
        portal_ip=portal_ip,
        portal_apex=portal_apex,
        silent_apex=silent_apex,
    )
    changed = await ph.sync_pin_regex(desired)  # selhání = sync selhal

    # Úklid po starších verzích – až když nová pravidla platí, ať blok nezmizí
    for label, step in (
        ("Local DNS (dns.hosts)", lambda: ph.sync_pin_dns_hosts(portal_ip, [])),
        ("tiché exact deny", lambda: ph.sync_pin_silent_block([])),
        ("prošlá povolení", lambda: ph.sync_pin_allows(granted or set())),
    ):
        try:
            changed = bool(await step()) or changed
        except Exception as e:
            logger.warning("Úklid %s selhal: %s", label, e)

    if changed:
        await ph.restart_dns()  # vyprázdní cache DNS, ať změna platí hned
    return len(desired)


def _current_lists() -> dict:
    """Aktuální stav z úložiště – volá se až uvnitř zámku Pi-hole API, aby pravidelný
    sync nepřepsal právě provedené odemčení starými daty."""
    store = get_store()
    settings = get_settings()
    apex_domains = store.blocked_domains_for_sinkhole()
    portal_apex, silent_apex = partition_apex_for_sinkhole(
        apex_domains,
        https_silent=settings.sinkhole_https_silent,
        all_silent=settings.sinkhole_all_silent,
        silent_extra=settings.sinkhole_silent_domains,
    )
    return {
        "apex_domains": apex_domains,
        "portal_apex": portal_apex,
        "silent_apex": silent_apex,
        "portal_hosts": expand_sinkhole_domains(portal_apex),
        "granted": set(store.active_grants()),
    }


async def _sync_with(ph: PiHoleClient, portal_ip: str) -> int:
    lists = _current_lists()
    return await _sync_pihole_api(
        ph,
        portal_ip,
        lists["portal_hosts"],
        lists["apex_domains"],
        silent_apex=lists["silent_apex"],
        portal_apex=lists["portal_apex"],
        granted=lists["granted"],
    )


async def publish_sinkhole(portal_ip: str, *, ph: PiHoleClient | None = None) -> None:
    settings = get_settings()
    lists = _current_lists()
    apex_domains = lists["apex_domains"]
    portal_hosts = lists["portal_hosts"]
    domains = expand_sinkhole_domains(apex_domains)
    mode = (settings.pihole_sinkhole_mode or "both").lower()

    api_ok = False
    file_ok = False
    api_err: str | None = None
    file_err: str | None = None
    hosts_written = 0

    if mode in ("api", "both"):
        try:
            if ph is not None:
                hosts_written = await _sync_with(ph, portal_ip)
            else:
                async with pihole_api() as client:
                    hosts_written = await _sync_with(client, portal_ip)
            api_ok = True
        except Exception as e:
            api_err = str(e)
            logger.exception("Pi-hole API sync")

    if mode in ("file", "both"):
        try:
            write_sinkhole_conf(
                portal_ip,
                portal_hosts,
                Path(settings.dnsmasq_sinkhole_path),
            )
            file_ok = True
        except Exception as e:
            file_err = str(e)
            logger.exception("dnsmasq sinkhole file sync")

    if settings.portal_tls_auto and (api_ok or file_ok):
        try:
            ensure_tls_material(domains)
        except Exception as e:
            logger.warning("TLS cert po sync: %s", e)

    record(
        ok=api_ok or file_ok,
        mode=mode,
        api_ok=api_ok,
        file_ok=file_ok,
        api_error=api_err,
        file_error=file_err,
        portal_ip=portal_ip,
        domain_count=len(domains),
        domains=domains,
        hosts_written=hosts_written,
    )

    if mode == "api" and not api_ok:
        raise RuntimeError(f"Pi-hole API: {api_err}")
    if mode == "file" and not file_ok:
        raise RuntimeError(f"Sinkhole soubor: {file_err}")
    if mode == "both":
        require_api = settings.pihole_require_api
        if require_api and not api_ok:
            raise RuntimeError(
                f"Pi-hole API nefunguje ({api_err}). "
                "Zkontrolujte PIHOLE_URL z kontejneru (IP Pi-hole v LAN) a heslo."
            )
        if not api_ok and not file_ok:
            raise RuntimeError(f"Pi-hole API: {api_err}; soubor: {file_err}")
