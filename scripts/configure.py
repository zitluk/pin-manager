#!/usr/bin/env python3
"""Interaktivní konfigurace před nasazením (VLAN macvlan vs. IP serveru + port)."""

from __future__ import annotations

import re
import secrets
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = Path(__file__).resolve().parent / "templates"
ENV_FILE = ROOT / ".env"
COMPOSE_ACTIVE = ROOT / "portainer-stack.yml"
DOCKER_COMPOSE = ROOT / "docker-compose.yml"


def ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    while True:
        raw = input(f"{prompt}{suffix}: ").strip()
        if not raw and default is not None:
            return default
        if raw:
            return raw
        print("Zadejte hodnotu nebo stiskněte Enter pro výchozí.")


def ask_bool(prompt: str, default: bool = True) -> bool:
    default_s = "a" if default else "n"
    mapping = {"a": True, "ano": True, "y": True, "yes": True, "n": False, "ne": False, "no": False}
    while True:
        raw = input(f"{prompt} (a/n) [{default_s}]: ").strip().lower()
        if not raw:
            return default
        if raw in mapping:
            return mapping[raw]
        print("Odpovězte a (ano) nebo n (ne).")


def valid_ip(ip: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip))


def load_template(name: str) -> str:
    return (TEMPLATES / name).read_text(encoding="utf-8")


def write_env(lines: dict[str, str]) -> None:
    ordered = [
        "# Vygenerováno scripts/configure.py – upravte tajné hodnoty",
        f"DEPLOY_MODE={lines['DEPLOY_MODE']}",
        f"PORTAINER_COMPOSE_PATH={lines['PORTAINER_COMPOSE_PATH']}",
        "",
        f"PIHOLE_URL={lines['PIHOLE_URL']}",
        f"PIHOLE_PASSWORD={lines['PIHOLE_PASSWORD']}",
        f"PORTAL_IP={lines['PORTAL_IP']}",
        f"PIN={lines['PIN']}",
        f"ADMIN_TOKEN={lines['ADMIN_TOKEN']}",
        f"SESSION_SECRET={lines['SESSION_SECRET']}",
        f"DNSMASQ_SYNC_HOST_PATH={lines['DNSMASQ_SYNC_HOST_PATH']}",
        f"DURATION_OPTIONS={lines.get('DURATION_OPTIONS', '15,30,60,120')}",
        f"PIHOLE_RESTART_DNS={lines.get('PIHOLE_RESTART_DNS', 'true')}",
    ]
    if lines["DEPLOY_MODE"] == "vlan":
        ordered.extend(
            [
                "",
                f"VLAN_NETWORK_NAME={lines['VLAN_NETWORK_NAME']}",
                f"VLAN_IP={lines['VLAN_IP']}",
            ]
        )
    else:
        ordered.extend(
            [
                "",
                f"HOST_PORT={lines['HOST_PORT']}",
            ]
        )
    ENV_FILE.write_text("\n".join(ordered) + "\n", encoding="utf-8")
    print(f"Uloženo: {ENV_FILE}")


def main() -> None:
    print("=" * 60)
    print("PIN manažer – konfigurace nasazení")
    print("=" * 60)
    print()
    print("1) VLAN (macvlan) – kontejner má vlastní IP v síti, bez mapování portů")
    print("   Příklad: 192.168.39.207 na síti docker_vlan")
    print("2) Server – IP hostitele + mapování portu (např. 80:8080)")
    print()

    use_vlan = ask_bool("Chcete použít VLAN (macvlan) s vlastní IP?", default=True)

    pihole_url = ask("URL Pi-hole", "http://192.168.39.1")
    pihole_password = ask("Heslo webu Pi-hole")
    sync_path = ask("Cesta sinkhole na hostu (sdílená s Pi-hole)", "/opt/pin-manager/dnsmasq-sync")
    pin = ask("Rodičovský PIN", "1234")

    admin_token = secrets.token_urlsafe(32)
    session_secret = secrets.token_urlsafe(32)
    print(f"Vygenerován ADMIN_TOKEN (uložen do .env)")
    print(f"Vygenerován SESSION_SECRET (uložen do .env)")

    cfg: dict[str, str] = {
        "PIHOLE_URL": pihole_url,
        "PIHOLE_PASSWORD": pihole_password,
        "DNSMASQ_SYNC_HOST_PATH": sync_path,
        "PIN": pin,
        "ADMIN_TOKEN": admin_token,
        "SESSION_SECRET": session_secret,
    }

    if use_vlan:
        vlan_name = ask("Název Docker sítě (macvlan)", "docker_vlan")
        vlan_ip = ask("IP kontejneru ve VLAN", "192.168.39.207")
        if not valid_ip(vlan_ip):
            raise SystemExit(f"Neplatná IP: {vlan_ip}")

        cfg["DEPLOY_MODE"] = "vlan"
        cfg["PORTAINER_COMPOSE_PATH"] = "portainer-stack.vlan.yml"
        cfg["VLAN_NETWORK_NAME"] = vlan_name
        cfg["VLAN_IP"] = vlan_ip
        cfg["PORTAL_IP"] = vlan_ip

        template = load_template("portainer-stack.vlan.yml")
        vlan_doc = (
            f"# Aktivní režim: VLAN (vygenerováno configure.py)\n"
            f"# Portainer Compose path: portainer-stack.vlan.yml\n\n"
        )
        COMPOSE_ACTIVE.write_text(vlan_doc + template, encoding="utf-8")
        shutil.copy(TEMPLATES / "portainer-stack.vlan.yml", ROOT / "portainer-stack.vlan.yml")
        bridge_tpl = load_template("portainer-stack.bridge.yml")
        (ROOT / "portainer-stack.bridge.yml").write_text(bridge_tpl, encoding="utf-8")

        print()
        print("VLAN režim:")
        print(f"  – IP portálu / sinkhole (PORTAL_IP): {vlan_ip}")
        print(f"  – Externí síť: {vlan_name}")
        print("  – Bez publikování portů na hostiteli")
        print("  – Kontejner naslouchá na portu 80 (LISTEN_PORT=80)")
    else:
        portal_ip = ask("IP serveru (PORTAL_IP pro DNS sinkhole)", "192.168.39.10")
        if not valid_ip(portal_ip):
            raise SystemExit(f"Neplatná IP: {portal_ip}")
        host_port = ask("Port na hostiteli (mapování na 8080 v kontejneru)", "80")

        cfg["DEPLOY_MODE"] = "bridge"
        cfg["PORTAINER_COMPOSE_PATH"] = "portainer-stack.bridge.yml"
        cfg["PORTAL_IP"] = portal_ip
        cfg["HOST_PORT"] = host_port

        template = load_template("portainer-stack.bridge.yml")
        bridge_doc = (
            f"# Aktivní režim: bridge (vygenerováno configure.py)\n"
            f"# Portainer Compose path: portainer-stack.bridge.yml\n\n"
        )
        COMPOSE_ACTIVE.write_text(bridge_doc + template, encoding="utf-8")
        shutil.copy(TEMPLATES / "portainer-stack.bridge.yml", ROOT / "portainer-stack.bridge.yml")
        vlan_tpl = load_template("portainer-stack.vlan.yml")
        (ROOT / "portainer-stack.vlan.yml").write_text(vlan_tpl, encoding="utf-8")

        print()
        print("Režim server + port:")
        print(f"  – PORTAL_IP: {portal_ip}")
        print(f"  – Mapování: {host_port} → 8080")
        print(f"  – Admin: http://{portal_ip}:{host_port}/admin/")

    # Lokální docker-compose pro vývoj
    shutil.copy(COMPOSE_ACTIVE, DOCKER_COMPOSE)

    write_env(cfg)

    compose_path = cfg["PORTAINER_COMPOSE_PATH"]
    print()
    print("=" * 60)
    print("Portainer (Git stack):")
    print(f"  Compose path: {compose_path}")
    print("  (nebo portainer-stack.yml – kopie aktivního režimu)")
    print()
    print("Env proměnné zkopírujte z .env do stacku v Portaineru.")
    print(f"Administrace: http://{cfg['PORTAL_IP']}/admin/")
    if cfg["DEPLOY_MODE"] == "bridge" and cfg.get("HOST_PORT", "80") != "80":
        print(f"  (s portem: http://{cfg['PORTAL_IP']}:{cfg['HOST_PORT']}/admin/)")
    print("=" * 60)


if __name__ == "__main__":
    main()
