"""Domácí CA + TLS certifikáty pro portál.

Dřív: jeden certifikát se seznamem domén z doby startu → nová doména na blacklistu
nebo poddoména (m.youtube.com) = chyba certifikátu, u HSTS webů (YouTube) Safari
stránku vůbec neotevře. Teď: certifikát se vystaví za běhu pro jméno, o které
prohlížeč požádá (SNI), podepsaný stávající CA – zařízení nic nového neinstalují.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import logging
import ssl
import threading
from pathlib import Path
from typing import Callable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from pin_manager.config import get_settings
from pin_manager.fileutil import file_lock

logger = logging.getLogger(__name__)

CA_NAME = "PIN Manager Home CA"
# Apple: certifikát serveru max. 825 dní (u veřejných CA 398) – držíme se pod oběma
LEAF_DAYS = 397
RENEW_BEFORE = dt.timedelta(days=30)


def tls_dir() -> Path:
    return Path(get_settings().data_dir) / "tls"


def ca_cert_path() -> Path:
    return tls_dir() / "ca.crt.pem"


def ca_key_path() -> Path:
    return tls_dir() / "ca.key.pem"


def server_cert_paths() -> tuple[Path, Path]:
    d = tls_dir()
    return d / "server.key.pem", d / "server.crt.pem"


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    tmp.chmod(0o600)
    tmp.replace(path)


def ensure_ca() -> tuple[x509.Certificate, rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey]:
    """Načte CA z /data/tls; vytvoří ji jen když neexistuje (stávající CA se nikdy nemění)."""
    key_p, crt_p = ca_key_path(), ca_cert_path()
    with file_lock(key_p):
        if not key_p.exists() or not crt_p.exists():
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CA_NAME)])
            now = _now()
            cert = (
                x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(minutes=5))
                .not_valid_after(now + dt.timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        key_cert_sign=True,
                        crl_sign=True,
                        content_commitment=False,
                        key_encipherment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
                .sign(key, hashes.SHA256())
            )
            _write_private(
                key_p,
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ),
            )
            crt_p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            logger.info("Vytvořena nová domácí CA: %s", crt_p)
    cert = x509.load_pem_x509_certificate(crt_p.read_bytes())
    key = serialization.load_pem_private_key(key_p.read_bytes(), password=None)
    return cert, key  # type: ignore[return-value]


def ca_der() -> bytes:
    cert, _ = ensure_ca()
    return cert.public_bytes(serialization.Encoding.DER)


def _san_entries(names: list[str]) -> list[x509.GeneralName]:
    out: list[x509.GeneralName] = []
    for n in names:
        try:
            out.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            out.append(x509.DNSName(n))
    return out


def issue_leaf(names: list[str]) -> tuple[bytes, bytes]:
    """Vystaví certifikát serveru (EC P-256) pro dané názvy. Vrací (cert_pem+ca_pem, key_pem)."""
    ca_cert, ca_key = ensure_ca()
    key = ec.generate_private_key(ec.SECP256R1())
    now = _now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0][:64])]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=LEAF_DAYS))
        .add_extension(x509.SubjectAlternativeName(_san_entries(names)), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    chain = cert.public_bytes(serialization.Encoding.PEM) + ca_cert.public_bytes(
        serialization.Encoding.PEM
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return chain, key_pem


def _cert_valid(path: Path, names: list[str]) -> bool:
    try:
        cert = x509.load_pem_x509_certificate(path.read_bytes())
        ca_cert, _ = ensure_ca()
    except Exception:
        return False
    if cert.issuer != ca_cert.subject:
        return False
    if cert.not_valid_after_utc - _now() < RENEW_BEFORE:
        return False
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return False
    have = {str(v) for v in san.get_values_for_type(x509.DNSName)} | {
        str(v) for v in san.get_values_for_type(x509.IPAddress)
    }
    return set(names) <= have


def ensure_tls_material(domains: list[str] | None = None) -> Path:
    """CA + výchozí certifikát portálu (IP + pin-manager.local).

    `domains` se už nepoužívá – jména blokovaných domén řeší SNI za běhu.
    Výchozí certifikát se obnoví jen když chybí, končí nebo nesedí IP.
    """
    ensure_ca()
    portal_ip = (get_settings().portal_ip or "").strip()
    names = [n for n in (portal_ip, "pin-manager.local") if n]
    key_p, crt_p = server_cert_paths()
    with file_lock(crt_p):
        if not (key_p.exists() and _cert_valid(crt_p, names)):
            chain, key_pem = issue_leaf(names)
            _write_private(key_p, key_pem)
            crt_p.write_bytes(chain)
            logger.info("Výchozí TLS certifikát portálu obnoven (%s)", ", ".join(names))
    return ca_cert_path()


# --- SNI: certifikát pro jméno, které prohlížeč chce --------------------------

# host → (kontext, kdy obnovit)
_ctx_cache: dict[str, tuple[ssl.SSLContext, dt.datetime]] = {}
_ctx_lock = threading.Lock()


def _cert_names_for(host: str) -> list[str]:
    """host + *.parent, ať jeden certifikát pokryje i sourozence (m./www./i.)."""
    names = [host]
    parent = host.split(".", 1)[1] if host.count(".") >= 2 else host
    names.append(f"*.{parent}")
    if parent != host:
        names.append(parent)
    return list(dict.fromkeys(names))


def host_context(host: str) -> ssl.SSLContext:
    host = host.lower().rstrip(".")
    with _ctx_lock:
        cached = _ctx_cache.get(host)
        if cached is not None and _now() < cached[1]:
            return cached[0]
        d = tls_dir() / "hosts"
        d.mkdir(parents=True, exist_ok=True)
        crt_p = d / f"{host}.crt.pem"
        key_p = d / f"{host}.key.pem"
        names = _cert_names_for(host)
        if not (key_p.exists() and _cert_valid(crt_p, names)):
            chain, key_pem = issue_leaf(names)
            _write_private(key_p, key_pem)
            crt_p.write_bytes(chain)
            logger.info("TLS certifikát vystaven pro %s", host)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_alpn_protocols(["http/1.1"])
        ctx.load_cert_chain(str(crt_p), str(key_p))
        not_after = x509.load_pem_x509_certificate(crt_p.read_bytes()).not_valid_after_utc
        _ctx_cache[host] = (ctx, not_after - RENEW_BEFORE)
        return ctx


def make_sni_callback(
    should_issue: Callable[[str], bool],
) -> Callable[[ssl.SSLObject, str | None, ssl.SSLContext], None]:
    """sni_callback pro ssl.SSLContext – jen pro jména, která `should_issue` povolí
    (blokované domény); ostatní dostanou výchozí certifikát portálu."""

    def callback(sock, server_name, _ctx):  # noqa: ANN001
        if not server_name:
            return None
        name = server_name.lower().rstrip(".")
        try:
            if should_issue(name):
                sock.context = host_context(name)
        except Exception:
            logger.exception("SNI certifikát pro %s", name)
        return None

    return callback
