import os
from pathlib import Path

import pytest

# Musí být před importem aplikace
os.environ.setdefault("PORTAL_IP", "192.168.39.207")
os.environ.setdefault("PIHOLE_URL", "http://pihole.test")
os.environ.setdefault("PIHOLE_PASSWORD", "test")
os.environ.setdefault("PIHOLE_SINKHOLE_MODE", "api")
os.environ.setdefault("PIHOLE_RESTART_DNS", "false")
os.environ.setdefault("DATA_DIR", str(Path(__file__).resolve().parent / "_data"))
os.environ.setdefault("SESSION_SECRET", "test-secret")
os.environ.setdefault("PIN", "4242")
os.environ.setdefault("DEPLOY_MODE", "vlan")
os.environ.setdefault("DNSMASQ_SINKHOLE_PATH", str(Path(__file__).resolve().parent / "_sync" / "pin-sinkhole.conf"))


@pytest.fixture(autouse=True)
def _clear_settings_cache():
    from pin_manager.config import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()
