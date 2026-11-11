"""Lokální CA + TLS certifikát se jmény blokovaných domén (bez varování v prohlížeči po důvěře CA)."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from pin_manager.config import get_settings
from pin_manager.domain_expand import expand_sinkhole_domains
from pin_manager.store import get_store

logger = logging.getLogger(__name__)


def tls_dir() -> Path:
    return Path(get_settings().data_dir) / "tls"


def ca_cert_path() -> Path:
    return tls_dir() / "ca.crt.pem"


def server_cert_paths() -> tuple[Path, Path]:
    d = tls_dir()
    return d / "server.key.pem", d / "server.crt.pem"


def _collect_sans(portal_ip: str, domains: list[str]) -> list[str]:
    sans: set[str] = set()
    for raw in domains:
        d = raw.strip().lower().rstrip(".")
        if not d or "://" in d:
            continue
        sans.add(d)
    if portal_ip:
        sans.add(portal_ip.strip())
    return sorted(sans)


def _write_openssl_san_conf(path: Path, sans: list[str]) -> None:
    lines = [
        "[req]",
        "distinguished_name = req_dn",
        "req_extensions = v3_req",
        "prompt = no",
        "[req_dn]",
        "CN = PIN portal",
        "[v3_req]",
        "subjectAltName = @alt_names",
        "basicConstraints = CA:FALSE",
        "keyUsage = digitalSignature, keyEncipherment",
        "extendedKeyUsage = serverAuth",
        "[v3_ca]",
        "basicConstraints = critical, CA:TRUE",
        "keyUsage = critical, keyCertSign, cRLSign",
        "[alt_names]",
    ]
    for i, name in enumerate(sans, start=1):
        if name.replace(".", "").isdigit() or name.count(".") == 3:
            try:
                parts = [int(x) for x in name.split(".")]
                if len(parts) == 4 and all(0 <= x <= 255 for x in parts):
                    lines.append(f"IP.{i} = {name}")
                    continue
            except ValueError:
                pass
        lines.append(f"DNS.{i} = {name}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _run(cmd: list[str]) -> None:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"openssl selhalo ({proc.returncode}): {proc.stderr[:500] or proc.stdout[:500]}"
        )


def ensure_tls_material(domains: list[str] | None = None) -> Path:
    """Vytvoří/obnoví CA (jednou) a server cert se SAN pro blokované domény."""
    settings = get_settings()
    portal_ip = settings.portal_ip or ""
    store = get_store()
    if domains is None:
        domains = expand_sinkhole_domains(store.list_blacklist())
    sans = _collect_sans(portal_ip, domains)
    if not sans:
        sans = ["pin-manager.local"]
        if portal_ip:
            sans.append(portal_ip)

    d = tls_dir()
    d.mkdir(parents=True, exist_ok=True)
    ca_key = d / "ca.key.pem"
    ca_crt = d / "ca.crt.pem"
    srv_key = d / "server.key.pem"
    srv_crt = d / "server.crt.pem"
    san_conf = d / "openssl-san.cnf"
    csr = d / "server.csr.pem"

    if not ca_key.exists():
        _run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "3650",
                "-keyout",
                str(ca_key),
                "-out",
                str(ca_crt),
                "-subj",
                "/CN=PIN Manager Home CA",
            ]
        )
        logger.info("Vytvořena lokální CA: %s", ca_crt)

    _write_openssl_san_conf(san_conf, sans)
    _run(
        [
            "openssl",
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(srv_key),
            "-out",
            str(csr),
            "-config",
            str(san_conf),
        ]
    )
    serial = d / "ca.srl"
    if not serial.exists():
        serial.write_text("01\n", encoding="utf-8")
    _run(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(csr),
            "-CA",
            str(ca_crt),
            "-CAkey",
            str(ca_key),
            "-CAserial",
            str(serial),
            "-out",
            str(srv_crt),
            "-days",
            "825",
            "-extensions",
            "v3_req",
            "-extfile",
            str(san_conf),
        ]
    )
    csr.unlink(missing_ok=True)
    logger.info("Server TLS cert obnoven pro %d SAN záznamů", len(sans))
    return ca_crt
