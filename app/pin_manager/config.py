from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    pihole_url: str = "http://127.0.0.1"
    pihole_password: str = ""
    # PIN: dočasné povolení domény (stránka /) a zároveň přihlášení do správy (/admin)
    pin: str = ""
    duration_options: str = "15,30,60,120"
    data_dir: str = "/data"
    # Po změně pravidel vyprázdnit DNS cache Pi-hole, ať změna platí hned
    pihole_restart_dns: bool = True
    # Jak často pravidla v Pi-hole ověřit a doplnit (po výpadku, reinstalaci)
    pihole_resync_seconds: int = 300
    # NXDOMAIN pro iCloud Soukromý přenos a DoH ve Firefoxu – jinak obcházejí Pi-hole
    block_dns_bypass: bool = True
    max_pin_attempts: int = 5
    lockout_seconds: int = 300

    @property
    def duration_minutes_list(self) -> list[int]:
        return [int(x.strip()) for x in self.duration_options.split(",") if x.strip().isdigit()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
