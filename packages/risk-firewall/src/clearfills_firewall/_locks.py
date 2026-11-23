"""Cross-process POSIX file locking helper (fcntl.flock) for ClearFills state files."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

try:
    import fcntl
except ImportError:  # pragma: no cover (Windows fallback)
    fcntl = None  # type: ignore[assignment]


@contextmanager
def file_lock(target_path: Path | None) -> Iterator[None]:
    """Acquire an exclusive cross-process flock on `<target_path>.lock`."""
    if target_path is None or fcntl is None:
        yield
        return
    lock_path = target_path.parent / f".{target_path.name}.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as lock_fh:
        fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)
