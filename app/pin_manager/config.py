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
    pihole_sinkhole_mode: str = "api"
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
