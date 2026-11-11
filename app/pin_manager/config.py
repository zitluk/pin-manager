from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    pihole_url: str = "http://127.0.0.1"
    pihole_password: str = ""
    pin: str = ""
    pin_hash: str = ""
    duration_options: str = "15,30,60,120"
    dnsmasq_sinkhole_path: str = "/sync/pin-sinkhole.conf"
    pihole_restart_dns: bool = True
    # api = Local DNS přes Pi-hole API (bez sdíleného souboru); file = dnsmasq sync
    pihole_sinkhole_mode: str = "both"
    # V režimu both: bez API sync blokování v Pi-hole typicky nefunguje (soubor musí mountovat Pi-hole).
    pihole_require_api: bool = True
    # true = YouTube/HSTS jen „nejde načíst“ (PIN jen na PORTAL_IP). false = DNS → portál + PIN na doméně (s CA).
    sinkhole_https_silent: bool = False  # env: SINKHOLE_HTTPS_SILENT
    # Všechny blokované domény jen „nejde načíst“ (žádný falešný certifikát) – PIN jen na PORTAL_IP.
    sinkhole_all_silent: bool = False  # true = jen „nejde načíst“, bez PIN na doméně
    portal_tls_auto: bool = True  # env: PORTAL_TLS_AUTO – cert se SAN pro blacklist
    portal_https: bool = True  # env: PORTAL_HTTPS – TLS :443 s domácí CA
    # Další domény k tichému bloku (čárkou), jen když SINKHOLE_HTTPS_SILENT=true
    sinkhole_silent_domains: str = ""  # env: SINKHOLE_SILENT_DOMAINS
    # NXDOMAIN pro iCloud Private Relay a Firefox DoH canary – jinak zařízení obchází Pi-hole
    block_dns_bypass: bool = True  # env: BLOCK_DNS_BYPASS
    admin_token: str = ""
    session_secret: str = ""
    portal_ip: str = ""
    deploy_mode: str = "bridge"
    host_port: str = "80"
    listen_port: str = "8080"
    preview_enabled: bool = False
    audit_log_max_lines: int = 5000
    audit_log_display_limit: int = 250
    data_dir: str = "/data"
    max_pin_attempts: int = 5
    lockout_seconds: int = 300

    @property
    def duration_minutes_list(self) -> list[int]:
        return [int(x.strip()) for x in self.duration_options.split(",") if x.strip().isdigit()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
