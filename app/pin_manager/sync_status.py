import json
import threading
import time
from pathlib import Path
from typing import Any

from pin_manager.config import get_settings

_lock = threading.Lock()


def _path() -> Path:
    return Path(get_settings().data_dir) / "sync_status.json"


def record(**fields: Any) -> None:
    p = _path()
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "updated_at": time.time(),
        **fields,
    }
    with _lock:
        p.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def read() -> dict[str, Any]:
    p = _path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
