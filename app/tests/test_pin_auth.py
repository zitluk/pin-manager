from pin_manager.pin_auth import set_family_pin, verify_family_pin
from pin_manager.config import get_settings


def test_set_and_verify_family_pin(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    get_settings.cache_clear()
    set_family_pin("5678")
    assert verify_family_pin("5678")
    assert not verify_family_pin("0000")
    get_settings.cache_clear()
