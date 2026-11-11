import logging
from pathlib import Path

from pin_manager.config import get_settings
from pin_manager.dnsmasq_conf import write_sinkhole_conf
from pin_manager.domain_expand import expand_sinkhole_domains, partition_apex_for_sinkhole
from pin_manager.pihole import PiHoleClient, pihole_api
from pin_manager.store import get_store
from pin_manager.sync_status import record
from pin_manager.tls_certs import ensure_tls_material

logger = logging.getLogger(__name__)


async def _clear_gravity_denies(ph: PiHoleClient, domains: list[str]) -> None:
    for domain in domains:
        for candidate in {domain, f"www.{domain}"}:
            try:
                await ph.remove_deny(candidate)
            except Exception:
                pass


async def _sync_pihole_api(
    ph: PiHoleClient,
    portal_ip: str,
    portal_hosts: list[str],
    apex_domains: list[str],
    *,
    silent_apex: list[str],
    portal_apex: list[str],
) -> int:
    await _clear_gravity_denies(ph, portal_hosts)
    try:
        # Hlavní cesta: address=/doména/PORTAL_IP – blokuje i všechny poddomény
        await ph.sync_pin_dnsmasq_lines(portal_ip, portal_apex)
        # Staré přesné Local DNS záznamy z předchozích verzí uklidit
        await ph.sync_pin_dns_hosts(portal_ip, [])
        written = len(portal_apex)
    except Exception as e:
        # Starší Pi-hole bez misc.dnsmasq_lines v API → aspoň přesná jména
        logger.warning("dnsmasq_lines nejde (%s) – záložně Local DNS záznamy", e)
        await ph.sync_pin_dns_hosts(portal_ip, portal_hosts)
        written = len(portal_hosts)
    # Vždy sync (i prázdný seznam) – odstraní staré pin-manager-silent deny po vypnutí tichého režimu.
    silent_count = await ph.sync_pin_silent_block(silent_apex)
    try:
        regex_rules = await ph.sync_pin_aaaa_nodata(apex_domains)
    except Exception as e:
        # Nesmí shodit sync (a tím odemykání PINem) – A záznamy už platí
        logger.warning("Regex pravidla (AAAA/HTTPS/SVCB/anti-obchvat) selhala: %s", e)
        regex_rules = 0
    await ph.restart_dns()
    return written + silent_count + regex_rules


async def publish_sinkhole(portal_ip: str, *, ph: PiHoleClient | None = None) -> None:
    store = get_store()
    settings = get_settings()
    apex_domains = store.blocked_domains_for_sinkhole()
    portal_apex, silent_apex = partition_apex_for_sinkhole(
        apex_domains,
        https_silent=settings.sinkhole_https_silent,
        all_silent=settings.sinkhole_all_silent,
        silent_extra=settings.sinkhole_silent_domains,
    )
    portal_hosts = expand_sinkhole_domains(portal_apex)
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
                hosts_written = await _sync_pihole_api(
                    ph,
                    portal_ip,
                    portal_hosts,
                    apex_domains,
                    silent_apex=silent_apex,
                        portal_apex=portal_apex,
                )
            else:
                async with pihole_api() as client:
                    hosts_written = await _sync_pihole_api(
                        client,
                        portal_ip,
                        portal_hosts,
                        apex_domains,
                        silent_apex=silent_apex,
                        portal_apex=portal_apex,
                    )
            api_ok = True
        except Exception as e:
            api_err = str(e)
            logger.exception("Pi-hole API dns.hosts sync")

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
