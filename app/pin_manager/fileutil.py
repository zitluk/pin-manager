"""Bezpečné čtení/zápis JSON v /data – sdílené mezi procesy (HTTP :80 a HTTPS :443)."""

from __future__ import annotations

import fcntl
import json
import logging
import os
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator

logger = logging.getLogger(__name__)

# flock chrání mezi procesy, threading.Lock mezi vlákny jednoho procesu
_thread_locks: dict[str, threading.Lock] = {}
_thread_locks_guard = threading.Lock()


def _thread_lock(path: Path) -> threading.Lock:
    key = str(path)
    with _thread_locks_guard:
        lock = _thread_locks.get(key)
        if lock is None:
            lock = _thread_locks[key] = threading.Lock()
        return lock


@contextmanager
def file_lock(path: Path, *, exclusive: bool = True) -> Iterator[None]:
    """Zámek přes vedlejší soubor <path>.lock (samotný JSON se nahrazuje přes rename)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(path.name + ".lock")
    with _thread_lock(path):
        with open(lock_path, "a+") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
            try:
                yield
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


def atomic_write_json(path: Path, data: Any) -> None:
    """Zápis přes dočasný soubor + os.replace – při pádu nezůstane rozbitý JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_json(path: Path, default: Callable[[], Any]) -> Any:
    """Načte JSON; poškozený soubor odloží stranou (*.corrupt-<ts>) a vrátí default."""
    if not path.exists():
        return default()
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        backup = path.with_name(f"{path.name}.corrupt-{int(time.time())}")
        logger.error("Poškozený %s (%s) – odkládám do %s", path, e, backup)
        try:
            os.replace(path, backup)
        except OSError:
            pass
        return default()


@contextmanager
def json_transaction(path: Path, default: Callable[[], Any]) -> Iterator[Any]:
    """Načti → uprav → atomicky ulož, celé pod výhradním zámkem."""
    with file_lock(path, exclusive=True):
        data = read_json(path, default)
        yield data
        atomic_write_json(path, data)


def json_snapshot(path: Path, default: Callable[[], Any]) -> Any:
    with file_lock(path, exclusive=False):
        return read_json(path, default)
