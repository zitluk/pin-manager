import logging
from pathlib import Path

from pin_manager.config import get_settings
from pin_manager.dnsmasq_conf import write_sinkhole_conf
from pin_manager.domain_expand import expand_sinkhole_domains
from pin_manager.pihole import PiHoleClient
from pin_manager.store import get_store
from pin_manager.sync_status import record

logger = logging.getLogger(__name__)


async def _clear_gravity_denies(ph: PiHoleClient, domains: list[str]) -> None:
    """Gravity deny vrací 0.0.0.0 – maže portál. Před sinkhole na PORTAL_IP deny odstraníme."""
    for domain in domains:
        for candidate in {domain, f"www.{domain}"}:
            try:
                await ph.remove_deny(candidate)
            except Exception:
                pass


async def publish_sinkhole(portal_ip: str) -> None:
    store = get_store()
    domains = expand_sinkhole_domains(store.blocked_domains_for_sinkhole())
    settings = get_settings()
    mode = (settings.pihole_sinkhole_mode or "both").lower()

    api_ok = False
    file_ok = False
    api_err: str | None = None
    file_err: str | None = None
    hosts_written = 0

    ph = PiHoleClient()

    if mode in ("api", "both"):
        try:
            await _clear_gravity_denies(ph, domains)
            await ph.sync_pin_dns_hosts(portal_ip, domains)
            api_ok = True
            hosts_written = len(domains)
        except Exception as e:
            api_err = str(e)
            logger.exception("Pi-hole API dns.hosts sync")

    if mode in ("file", "both"):
        try:
            write_sinkhole_conf(
                portal_ip,
                domains,
                Path(settings.dnsmasq_sinkhole_path),
            )
            file_ok = True
        except Exception as e:
            file_err = str(e)
            logger.exception("dnsmasq sinkhole file sync")

    if api_ok or file_ok:
        try:
            await ph.restart_dns()
        except Exception as e:
            logger.warning("restart_dns po sinkhole sync: %s", e)

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
                "Zkontrolujte PIHOLE_URL z kontejneru (IP Pi-hole v LAN) a heslo. "
                "Samotný soubor v /sync u Pi-hole nenasadíte bez mountu – viz docs/AKTIVACE-BLOKOVANI.md."
            )
        if not api_ok and not file_ok:
            raise RuntimeError(f"Pi-hole API: {api_err}; soubor: {file_err}")
